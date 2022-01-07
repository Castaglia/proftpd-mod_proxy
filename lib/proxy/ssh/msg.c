/*
 * ProFTPD - mod_proxy SSH message format
 * Copyright (c) 2021 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_proxy.h"
#include "proxy/session.h"
#include "proxy/ssh/ssh2.h"
#include "proxy/ssh/msg.h"
#include "proxy/ssh/crypto.h"
#include "proxy/ssh/disconnect.h"

#if defined(PR_USE_OPENSSL)

#if defined(PR_USE_OPENSSL_ECC)
/* Max GFp field length = 528 bits.  SEC1 uncompressed encoding uses 2
 * bitstring points.  SEC1 specifies a 1 byte point type header.
 */
# define MAX_ECPOINT_LEN		((528*2 / 8) + 1)
#endif /* PR_USE_OPENSSL_ECC */

static const char *trace_channel = "proxy.ssh.msg";

static conn_t *get_backend_conn(void) {
  const struct proxy_session *proxy_sess;

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  return proxy_sess->backend_ctrl_conn;
}

uint32_t proxy_ssh_msg_read_byte(pool *p, unsigned char **buf, uint32_t *buflen,
    unsigned char *byte) {
  (void) p;

  if (*buflen < sizeof(char)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read byte (buflen = %lu)",
      (unsigned long) *buflen);
    return 0;
  }

  memcpy(byte, *buf, sizeof(unsigned char));
  (*buf) += sizeof(unsigned char);
  (*buflen) -= sizeof(unsigned char);

  return sizeof(unsigned char);
}

uint32_t proxy_ssh_msg_read_bool(pool *p, unsigned char **buf, uint32_t *buflen,
    int *bool) {
  unsigned char byte = 0;
  uint32_t len;

  (void) p;

  len = proxy_ssh_msg_read_byte(p, buf, buflen, &byte);
  if (len == 0) {
    return 0;
  }

  *bool = byte;
  return len;
}

uint32_t proxy_ssh_msg_read_data(pool *p, unsigned char **buf,
    uint32_t *buflen, size_t datalen, unsigned char **data) {
  if (datalen == 0) {
    return 0;
  }

  if (*buflen < datalen) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read %lu bytes of raw data "
      "(buflen = %lu)", (unsigned long) datalen, (unsigned long) *buflen);
    return 0;
  }

  *data = palloc(p, datalen);

  memcpy(*data, *buf, datalen);
  (*buf) += datalen;
  (*buflen) -= datalen;

  return datalen;
}

uint32_t proxy_ssh_msg_read_int(pool *p, unsigned char **buf, uint32_t *buflen,
    uint32_t *val) {

  (void) p;

  if (*buflen < sizeof(uint32_t)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read int (buflen = %lu)",
      (unsigned long) *buflen);
    return 0;
  }

  memcpy(val, *buf, sizeof(uint32_t));
  (*buf) += sizeof(uint32_t);
  (*buflen) -= sizeof(uint32_t);

  *val = ntohl(*val);
  return sizeof(uint32_t);
}

uint32_t proxy_ssh_msg_read_long(pool *p, unsigned char **buf, uint32_t *buflen,
    uint64_t *val) {
  unsigned char data[8];

  if (*buflen < sizeof(data)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read long (buflen = %lu)",
      (unsigned long) *buflen);
    return 0;
  }

  memcpy(data, *buf, sizeof(data));
  (*buf) += sizeof(data);
  (*buflen) -= sizeof(data);

  (*val) = (uint64_t) data[0] << 56;
  (*val) |= (uint64_t) data[1] << 48;
  (*val) |= (uint64_t) data[2] << 40;
  (*val) |= (uint64_t) data[3] << 32;
  (*val) |= (uint64_t) data[4] << 24;
  (*val) |= (uint64_t) data[5] << 16;
  (*val) |= (uint64_t) data[6] << 8;
  (*val) |= (uint64_t) data[7];

  return sizeof(data);
}

uint32_t proxy_ssh_msg_read_mpint(pool *p, unsigned char **buf,
    uint32_t *buflen, const BIGNUM **mpint) {
  unsigned char *mpint_data = NULL;
  const unsigned char *data = NULL, *ptr = NULL;
  uint32_t datalen = 0, mpint_len = 0, len = 0, total_len = 0;

  len = proxy_ssh_msg_read_int(p, buf, buflen, &mpint_len);
  if (len == 0) {
    return 0;
  }

  if (*buflen < mpint_len) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read %lu bytes of mpint (buflen = %lu)",
      (unsigned long) len, (unsigned long) *buflen);
    return 0;
  }

  if (len > (1024 * 16)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to handle mpint of %lu bytes",
      (unsigned long) len);
    return 0;
  }

  total_len += len;

  len = proxy_ssh_msg_read_data(p, buf, buflen, mpint_len, &mpint_data);
  if (len == 0) {
    return 0;
  }

  total_len += len;

  ptr = (const unsigned char *) mpint_data;
  if ((ptr[0] & 0x80) != 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: negative mpint numbers not supported");
    return 0;
  }

  /* Trim any leading zeros. */
  data = ptr;
  datalen = mpint_len;
  while (datalen > 0 &&
         *data == 0x00) {
    pr_signals_handle();
    data++;
    datalen--;
  }

  *mpint = BN_bin2bn(data, (int) datalen, NULL);
  if (*mpint == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to convert binary mpint: %s",
      proxy_ssh_crypto_get_errors());
    return 0;
  }

  return total_len;
}

uint32_t proxy_ssh_msg_read_string(pool *p, unsigned char **buf,
    uint32_t *buflen, char **text) {
  uint32_t data_len = 0, len = 0;

  /* If there is no data remaining, treat this as if the string is empty
   * (see Bug#4093).
   */
  if (*buflen == 0) {
    pr_trace_msg(trace_channel, 9,
      "malformed message format (buflen = %lu) for reading text, using \"\"",
      (unsigned long) *buflen);
    *text = pstrdup(p, "");
    return 1;
  }

  len = proxy_ssh_msg_read_int(p, buf, buflen, &data_len);
  if (len == 0) {
    return 0;
  }

  /* We can't use proxy_ssh_msg_read_data() here, since we need to allocate and
   * populate a buffer that is one byte longer than the len just read in,
   * for the terminating NUL.
   */

  if (*buflen < data_len) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read %lu bytes of string data "
      "(buflen = %lu)", (unsigned long) data_len, (unsigned long) *buflen);
    return 0;
  }

  *text = palloc(p, data_len + 1);

  if (data_len > 0) {
    memcpy(*text, *buf, data_len);
    (*buf) += data_len;
    (*buflen) -= data_len;
  }
  (*text)[data_len] = '\0';

  return len + data_len;
}

#if defined(PR_USE_OPENSSL) && defined(PR_USE_OPENSSL_ECC)
uint32_t proxy_ssh_msg_read_ecpoint(pool *p, unsigned char **buf,
    uint32_t *buflen, const EC_GROUP *curve, EC_POINT **point) {
  BN_CTX *bn_ctx;
  unsigned char *data = NULL;
  uint32_t datalen = 0, len = 0, total_len = 0;

  len = proxy_ssh_msg_read_int(p, buf, buflen, &datalen);
  if (len == 0) {
    return 0;
  }

  if (*buflen < datalen) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read %lu bytes of EC point"
      " (buflen = %lu)", (unsigned long) datalen, (unsigned long) *buflen);
    return 0;
  }

  if (datalen > MAX_ECPOINT_LEN) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: EC point length too long (%lu > max %lu)",
      (unsigned long) datalen, (unsigned long) MAX_ECPOINT_LEN);
    return 0;
  }

  total_len += len;

  len = proxy_ssh_msg_read_data(p, buf, buflen, datalen, &data);
  if (len == 0) {
    return 0;
  }

  if (data == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to read %lu bytes of EC point data",
      (unsigned long) datalen);
    return 0;
  }

  total_len += len;

  if (data[0] != POINT_CONVERSION_UNCOMPRESSED) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: EC point data formatted incorrectly "
      "(leading byte 0x%02x should be 0x%02x)", data[0],
      POINT_CONVERSION_UNCOMPRESSED);
    return 0;
  }

  bn_ctx = BN_CTX_new();
  if (bn_ctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BN_CTX: %s", proxy_ssh_crypto_get_errors());
    return 0;
  }

  if (EC_POINT_oct2point(curve, *point, data, datalen, bn_ctx) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to convert binary EC point data: %s",
      proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    return 0;
  }

  BN_CTX_free(bn_ctx);
  pr_memscrub(data, datalen);

  return total_len;
}
#endif /* PR_USE_OPENSSL_ECC */

uint32_t proxy_ssh_msg_write_byte(unsigned char **buf, uint32_t *buflen,
    unsigned char byte) {
  uint32_t len = 0;

  if (*buflen < sizeof(char)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to write byte (buflen = %lu)",
      (unsigned long) *buflen);
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  len = sizeof(unsigned char);

  memcpy(*buf, &byte, len);
  (*buf) += len;
  (*buflen) -= len;

  return len;
}

uint32_t proxy_ssh_msg_write_bool(unsigned char **buf, uint32_t *buflen,
    unsigned char bool) {
  return proxy_ssh_msg_write_byte(buf, buflen, bool == 0 ? 0 : 1);
}

uint32_t proxy_ssh_msg_write_data(unsigned char **buf, uint32_t *buflen,
   const unsigned char *data, size_t datalen, int write_len) {
  uint32_t len = 0;

  if (write_len) {
    len += proxy_ssh_msg_write_int(buf, buflen, datalen);
  }

  if (*buflen < datalen) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to write %lu bytes of raw data "
      "(buflen = %lu)", (unsigned long) datalen, (unsigned long) *buflen);
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  if (datalen > 0) {
    memcpy(*buf, data, datalen);
    (*buf) += datalen;
    (*buflen) -= datalen;

    len += datalen;
  }

  return len;
}

uint32_t proxy_ssh_msg_write_int(unsigned char **buf, uint32_t *buflen,
    uint32_t val) {
  uint32_t len;

  if (*buflen < sizeof(uint32_t)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to write int (buflen = %lu)",
      (unsigned long) *buflen);
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  len = sizeof(uint32_t);

  val = htonl(val);
  memcpy(*buf, &val, len);
  (*buf) += len;
  (*buflen) -= len;

  return len;
}

uint32_t proxy_ssh_msg_write_long(unsigned char **buf, uint32_t *buflen,
    uint64_t val) {
  unsigned char data[8];

  if (*buflen < sizeof(uint64_t)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to write long (buflen = %lu)",
      (unsigned long) *buflen);
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  data[0] = (unsigned char) (val >> 56) & 0xFF;
  data[1] = (unsigned char) (val >> 48) & 0xFF;
  data[2] = (unsigned char) (val >> 40) & 0xFF;
  data[3] = (unsigned char) (val >> 32) & 0xFF;
  data[4] = (unsigned char) (val >> 24) & 0xFF;
  data[5] = (unsigned char) (val >> 16) & 0xFF;
  data[6] = (unsigned char) (val >> 8) & 0xFF;
  data[7] = (unsigned char) val & 0xFF;

  return proxy_ssh_msg_write_data(buf, buflen, data, sizeof(data), FALSE);
}

uint32_t proxy_ssh_msg_write_mpint(unsigned char **buf, uint32_t *buflen,
    const BIGNUM *mpint) {
  unsigned char *data = NULL;
  size_t datalen = 0;
  int res = 0;
  uint32_t len = 0;

  if (BN_is_zero(mpint)) {
    return proxy_ssh_msg_write_int(buf, buflen, 0);
  }

#if OPENSSL_VERSION_NUMBER >= 0x0090801fL
  if (BN_is_negative(mpint)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to write mpint (negative numbers not "
      "supported)");
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }
#endif /* OpenSSL-0.9.8a or later */

  datalen = BN_num_bytes(mpint) + 1;

  if (*buflen < datalen) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to write %lu bytes of mpint (buflen = %lu)",
      (unsigned long) datalen, (unsigned long) *buflen);
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  data = malloc(datalen);
  if (data == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_PROXY_VERSION ": Out of memory!");
    _exit(1);
  }

  data[0] = 0;

  res = BN_bn2bin(mpint, data + 1);
  if (res < 0 ||
      res != (int) (datalen - 1)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: BN_bn2bin() failed: expected %lu bytes, got %d",
      (unsigned long) (datalen - 1), res);
    pr_memscrub(data, datalen);
    free(data);

    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);

    /* Needed to avoid compiler (and static code analysis) complaints. */
    return 0;
  }

  if (data[1] & 0x80) {
    len += proxy_ssh_msg_write_data(buf, buflen, data, datalen, TRUE);

  } else {
    len += proxy_ssh_msg_write_data(buf, buflen, data + 1, datalen - 1,
      TRUE);
  }

  pr_memscrub(data, datalen);
  free(data);

  return len;
}

uint32_t proxy_ssh_msg_write_string(unsigned char **buf, uint32_t *buflen,
    const char *text) {
  uint32_t text_len = 0;

  text_len = strlen(text);
  return proxy_ssh_msg_write_data(buf, buflen, (const unsigned char *) text,
    text_len, TRUE);
}

#if defined(PR_USE_OPENSSL) && defined(PR_USE_OPENSSL_ECC)
uint32_t proxy_ssh_msg_write_ecpoint(unsigned char **buf, uint32_t *buflen,
    const EC_GROUP *curve, const EC_POINT *point) {
  unsigned char *data = NULL;
  size_t datalen = 0;
  uint32_t len = 0;
  BN_CTX *bn_ctx;

  bn_ctx = BN_CTX_new();
  if (bn_ctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BN_CTX: %s", proxy_ssh_crypto_get_errors());
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  datalen = EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED,
    NULL, 0, bn_ctx);
  if (datalen > MAX_ECPOINT_LEN) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: EC point length too long (%lu > max %lu)",
      (unsigned long) datalen, (unsigned long) MAX_ECPOINT_LEN);
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  if (*buflen < datalen) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "message format error: unable to write %lu bytes of EC point "
      "(buflen = %lu)", (unsigned long) datalen, (unsigned long) *buflen);
    pr_log_stacktrace(proxy_logfd, MOD_PROXY_VERSION);
    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  data = malloc(datalen);
  if (data == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_PROXY_VERSION ": Out of memory!");
    _exit(1);
  }

  if (EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED, data,
      datalen, bn_ctx) != datalen) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error writing EC point data: Length mismatch");
    pr_memscrub(data, datalen);
    free(data);
    BN_CTX_free(bn_ctx);

    PROXY_SSH_DISCONNECT_CONN(get_backend_conn(),
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);

    /* Needed to avoid compiler (and static code analysis) complaints. */
    return 0;
  }

  len = proxy_ssh_msg_write_data(buf, buflen, (const unsigned char *) data,
    datalen, TRUE);

  pr_memscrub(data, datalen);
  free(data);
  BN_CTX_free(bn_ctx);

  return len;
}
#endif /* PR_USE_OPENSSL_ECC */

#endif /* PR_USE_OPENSSL */
