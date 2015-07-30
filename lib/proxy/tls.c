/*
 * ProFTPD - mod_proxy TLS implementation
 * Copyright (c) 2015 TJ Saunders
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

#include "proxy/db.h"
#include "proxy/conn.h"
#include "proxy/netio.h"
#include "proxy/session.h"
#include "proxy/tls.h"

#ifdef HAVE_MLOCK
# include <sys/mman.h>
#endif

#ifdef PR_USE_OPENSSL

extern xaset_t *server_list;

static int proxy_tls_engine = PROXY_TLS_ENGINE_OFF;

static const char *trace_channel = "proxy.tls";
static const char *timing_channel = "timing";

#define PROXY_TLS_DEFAULT_CIPHER_SUITE		"DEFAULT:!ADH:!EXPORT:!DES"
#define PROXY_TLS_NEXT_PROTO			"ftp"

/* SSL record/buffer sizes */
#define PROXY_TLS_HANDSHAKE_WRITE_BUFFER_SIZE		1400

/* SSL adaptive buffer sizes/values */
#define PROXY_TLS_DATA_ADAPTIVE_WRITE_MIN_BUFFER_SIZE	(4 * 1024)
#define PROXY_TLS_DATA_ADAPTIVE_WRITE_MAX_BUFFER_SIZE	(16 * 1024)
#define PROXY_TLS_DATA_ADAPTIVE_WRITE_BOOST_THRESHOLD	(1024 * 1024)
#define PROXY_TLS_DATA_ADAPTIVE_WRITE_BOOST_INTERVAL_MS	1000

/* ProxyTLSProtocol handling */
#define PROXY_TLS_PROTO_SSL_V3		0x0001
#define PROXY_TLS_PROTO_TLS_V1		0x0002
#define PROXY_TLS_PROTO_TLS_V1_1	0x0004
#define PROXY_TLS_PROTO_TLS_V1_2	0x0008

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
# define PROXY_TLS_PROTO_DEFAULT	(PROXY_TLS_PROTO_TLS_V1|PROXY_TLS_PROTO_TLS_V1_1|PROXY_TLS_PROTO_TLS_V1_2)
#else
# define PROXY_TLS_PROTO_DEFAULT	(PROXY_TLS_PROTO_TLS_V1)
#endif /* OpenSSL 1.0.1 or later */

/* This is used for e.g. "ProxyTLSProtocol ALL -SSLv3 ...". */
#define PROXY_TLS_PROTO_ALL		(PROXY_TLS_PROTO_SSL_V3|PROXY_TLS_PROTO_TLS_V1|PROXY_TLS_PROTO_TLS_V1_1|PROXY_TLS_PROTO_TLS_V1_2)

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
static int proxy_tls_ssl_opts = (SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_SINGLE_DH_USE)^SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
#else
/* OpenSSL-0.9.6 and earlier (yes, it appears people still have these versions
 * installed) does not define the DONT_INSERT_EMPTY_FRAGMENTS option.
 */
static int proxy_tls_ssl_opts = SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_SINGLE_DH_USE;
#endif

static const char *proxy_tls_cipher_suite = NULL;
static const char *proxy_tls_cert_file = NULL;
static const char *proxy_tls_key_file = NULL;
static unsigned long proxy_tls_flags = 0UL;

/* ProxyTLSTimeoutHandshake */
static unsigned int handshake_timeout = 30;
static int handshake_timer_id = -1;
static int handshake_timed_out = FALSE;

#define PROXY_TLS_SHUTDOWN_BIDIRECTIONAL	0x001

/* OpenSSL's default is 9 as well. */
static int proxy_tls_verify_depth = 9;

/* Stream notes */
#define PROXY_TLS_NETIO_NOTE			"mod_proxy.SSL"
#define PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY	"mod_proxy.SSL.adaptive.bytes"
#define PROXY_TLS_ADAPTIVE_BYTES_MS_KEY		"mod_proxy.SSL.adaptive.ms"

static SSL_CTX *proxy_ssl_ctx = NULL;
static pr_netio_t *proxy_tls_ctrl_netio = NULL;
static pr_netio_t *proxy_tls_data_netio = NULL;
static SSL *proxy_tls_ctrl_ssl = NULL;

/* XXX TODO: Add info/msg callbacks! */

static int handshake_timeout_cb(CALLBACK_FRAME) {
  handshake_timed_out = TRUE;
  return 0;
}

static const char *get_errors(void) {
  unsigned int count = 0;
  unsigned long e = ERR_get_error();
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *str = "(unknown)";

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */
  if (e)
    bio = BIO_new(BIO_s_mem());

  while (e) {
    pr_signals_handle();
    BIO_printf(bio, "\n  (%u) %s", ++count, ERR_error_string(e, NULL));
    e = ERR_get_error();
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
    str = pstrdup(session.pool, data);
  }

  if (bio != NULL) {
    BIO_free(bio);
  }

  return str;
}

static char *proxy_tls_x509_name_oneline(X509_NAME *x509_name) {
  static char buf[1024] = {'\0'};

  /* If we are using OpenSSL 0.9.6 or newer, we want to use
   * X509_NAME_print_ex() instead of X509_NAME_oneline().
   */

#if OPENSSL_VERSION_NUMBER < 0x000906000L
  memset(&buf, '\0', sizeof(buf));
  return X509_NAME_oneline(x509_name, buf, sizeof(buf)-1);
#else

  /* Sigh...do it the hard way. */
  BIO *mem = BIO_new(BIO_s_mem());
  char *data = NULL;
  long datalen = 0;
  int ok;
  
  ok = X509_NAME_print_ex(mem, x509_name, 0, XN_FLAG_ONELINE);
  if (ok) {
    datalen = BIO_get_mem_data(mem, &data);

    if (data) {
      memset(&buf, '\0', sizeof(buf));

      if (datalen >= sizeof(buf)) {
        datalen = sizeof(buf)-1;
      }

      memcpy(buf, data, datalen);

      buf[datalen] = '\0';
      buf[sizeof(buf)-1] = '\0';

      BIO_free(mem);
      return buf;
    }
  }

  BIO_free(mem);
  return NULL;
#endif /* OPENSSL_VERSION_NUMBER >= 0x000906000 */
}

static char *proxy_tls_get_subj_name(SSL *ssl) {
  X509 *cert;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    char *subj_name;

    subj_name = proxy_tls_x509_name_oneline(X509_get_subject_name(cert));
    X509_free(cert);
    return subj_name;
  }

  errno = ENOENT;
  return NULL;
}

static int proxy_tls_get_block(conn_t *conn) {
  int flags;

  flags = fcntl(conn->rfd, F_GETFL);
  if (flags & O_NONBLOCK) {
    return FALSE;
  }

  return TRUE;
}

static void proxy_tls_fatal(long error, int lineno) {
  switch (error) {
    case SSL_ERROR_NONE:
      return;

    case SSL_ERROR_SSL:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR_SSL, line %d: %s", lineno, get_errors());
      break;

    case SSL_ERROR_WANT_READ:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR_WANT_READ, line %d", lineno);
      break;

    case SSL_ERROR_WANT_WRITE:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR_WANT_WRITE, line %d", lineno);
      break;

    case SSL_ERROR_WANT_X509_LOOKUP:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR_WANT_X509_LOOKUP, line %d", lineno);
      break;

    case SSL_ERROR_SYSCALL: {
      long xerrcode = ERR_get_error();

      if (errno == ECONNRESET) {
        return;
      }

      /* Check to see if the OpenSSL error queue has info about this. */
      if (xerrcode == 0) {
        /* The OpenSSL error queue doesn't have any more info, so we'll
         * examine the error value itself.
         */
        if (errno == EOF) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "panic: SSL_ERROR_SYSCALL, line %d: EOF that violates protocol",
            lineno);

        } else {
          /* Check errno */
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "panic: SSL_ERROR_SYSCALL, line %d: system error: %s", lineno,
            strerror(errno));
        }

      } else {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
         "panic: SSL_ERROR_SYSCALL, line %d: %s", lineno, get_errors());
      }

      break;
    }

    case SSL_ERROR_ZERO_RETURN:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR_ZERO_RETURN, line %d", lineno);
      break;

    case SSL_ERROR_WANT_CONNECT:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR_WANT_CONNECT, line %d", lineno);
      break;

    default:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR %ld, line %d", error, lineno);
      break;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "unexpected OpenSSL error, disconnecting");
  pr_log_pri(PR_LOG_WARNING, "%s", MOD_PROXY_VERSION
    ": unexpected OpenSSL error, disconnecting");

  pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION, NULL);
}

static void proxy_tls_end_sess(SSL *ssl, int strms, int flags) {
  int res = 0;
  int shutdown_state;
  BIO *rbio, *wbio;
  int bread, bwritten;
  unsigned long rbio_rbytes, rbio_wbytes, wbio_rbytes, wbio_wbytes;

  if (ssl == NULL) {
    return;
  }

  rbio = SSL_get_rbio(ssl);
  rbio_rbytes = BIO_number_read(rbio);
  rbio_wbytes = BIO_number_written(rbio);

  wbio = SSL_get_wbio(ssl);
  wbio_rbytes = BIO_number_read(wbio);
  wbio_wbytes = BIO_number_written(wbio);

  /* A 'close_notify' alert (SSL shutdown message) may have been previously
   * sent to the server via netio_shutdown_cb().
   */
  shutdown_state = SSL_get_shutdown(ssl);
  if (!(shutdown_state & SSL_SENT_SHUTDOWN)) {
    errno = 0;

    /* 'close_notify' not already sent; send it now. */
    res = SSL_shutdown(ssl);
  }

  if (res == 0) {
    /* Now call SSL_shutdown() again, but only if necessary. */
    if (flags & PROXY_TLS_SHUTDOWN_BIDIRECTIONAL) {
      shutdown_state = SSL_get_shutdown(ssl);

      res = 1;
      if (!(shutdown_state & SSL_RECEIVED_SHUTDOWN)) {
        errno = 0;
        res = SSL_shutdown(ssl);
      }
    }

    /* If SSL_shutdown() returned -1 here, an error occurred during the
     * shutdown.
     */
    if (res < 0) {
      long err_code;

      err_code = SSL_get_error(ssl, res);
      switch (err_code) {
        case SSL_ERROR_WANT_READ:
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "SSL_shutdown error: WANT_READ");
          pr_log_debug(DEBUG0, MOD_PROXY_VERSION
            ": SSL_shutdown error: WANT_READ");
          break;

        case SSL_ERROR_WANT_WRITE:
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "SSL_shutdown error: WANT_WRITE");
          pr_log_debug(DEBUG0, MOD_PROXY_VERSION
            ": SSL_shutdown error: WANT_WRITE");
          break;

        case SSL_ERROR_ZERO_RETURN:
          /* Clean shutdown, nothing we need to do. */
          break;

        case SSL_ERROR_SYSCALL:
          if (errno != 0 &&
              errno != EOF &&
              errno != EBADF &&
              errno != EPIPE &&
              errno != EPERM &&
              errno != ENOSYS) {
            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "SSL_shutdown syscall error: %s", strerror(errno));
          }
          break;

        default: {
          const char *errors;

          errors = get_errors();
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "SSL_shutdown error [%ld]: %s", err_code, errors);
          pr_log_debug(DEBUG0, MOD_PROXY_VERSION
            ": SSL_shutdown error [%ld]: %s", err_code, errors);
          break;
        }
      }
    }

  } else if (res < 0) {
    long err_code;

    err_code = SSL_get_error(ssl, res);
    switch (err_code) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
      case SSL_ERROR_ZERO_RETURN:
        /* Clean shutdown, nothing we need to do.  The WANT_READ/WANT_WRITE
         * error codes crept into OpenSSL 0.9.8m, with changes to make
         * SSL_shutdown() work properly for non-blocking sockets.  And
         * handling these error codes for older OpenSSL versions won't break
         * things.
         */
        break;

      case SSL_ERROR_SYSCALL:
        if (errno != 0 &&
            errno != EOF &&
            errno != EBADF &&
            errno != EPIPE &&
            errno != EPERM &&
            errno != ENOSYS) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "SSL_shutdown syscall error: %s", strerror(errno));
        }
        break;

      default:
        proxy_tls_fatal(err_code, __LINE__);
        break;
    }
  }

  bread = (BIO_number_read(rbio) - rbio_rbytes) +
    (BIO_number_read(wbio) - wbio_rbytes);
  bwritten = (BIO_number_written(rbio) - rbio_wbytes) +
    (BIO_number_written(wbio) - wbio_wbytes);

  /* Manually update session.total_raw_in/out, in order to have %I/%O be
   * accurately represented for the raw traffic.
   */
  if (bread > 0) {
    session.total_raw_in += bread;
  }

  if (bwritten > 0) {
    session.total_raw_out += bwritten;
  }

  SSL_free(ssl);
}

static int proxy_tls_readmore(int rfd) {
  fd_set rfds;
  struct timeval tv;

  FD_ZERO(&rfds);
  FD_SET(rfd, &rfds);

  /* Use a timeout of 15 seconds */
  tv.tv_sec = 15;
  tv.tv_usec = 0;

  return select(rfd + 1, &rfds, NULL, NULL, &tv);
}

static int proxy_tls_writemore(int wfd) {
  fd_set wfds;
  struct timeval tv;

  FD_ZERO(&wfds);
  FD_SET(wfd, &wfds);

  /* Use a timeout of 15 seconds */
  tv.tv_sec = 15;
  tv.tv_usec = 0;

  return select(wfd + 1, NULL, &wfds, NULL, &tv);
}

static ssize_t proxy_tls_read(SSL *ssl, void *buf, size_t len,
    int nstrm_type, pr_table_t *notes) {
  ssize_t count;

  read_retry:
  pr_signals_handle();
  count = SSL_read(ssl, buf, len);
  if (count < 0) {
    long err;
    int fd;

    err = SSL_get_error(ssl, count);
    fd = SSL_get_fd(ssl);

    /* read(2) returns only the generic error number -1 */
    count = -1;

    switch (err) {
      case SSL_ERROR_WANT_READ:
        /* OpenSSL needs more data from the wire to finish the current block,
         * so we wait a little while for it.
         */
        pr_trace_msg(trace_channel, 17,
          "WANT_READ encountered while reading SSL data on fd %d, "
          "waiting to read data", fd);
        err = proxy_tls_readmore(fd);
        if (err > 0) {
          goto read_retry;

        } else if (err == 0) {
          /* Still missing data after timeout. Simulate an EINTR and return.
           */
          errno = EINTR;

          /* If err < 0, i.e. some error from the select(), everything is
           * already in place; errno is properly set and this function
           * returns -1.
           */
          break;
        }

      case SSL_ERROR_WANT_WRITE:
        /* OpenSSL needs to write more data to the wire to finish the current
         * block, so we wait a little while for it.
         */
        pr_trace_msg(trace_channel, 17,
          "WANT_WRITE encountered while writing SSL data on fd %d, "
          "waiting to send data", fd);
        err = proxy_tls_writemore(fd);
        if (err > 0) {
          goto read_retry;

        } else if (err == 0) {
          /* Still missing data after timeout. Simulate an EINTR and return.
           */
          errno = EINTR;

          /* If err < 0, i.e. some error from the select(), everything is
           * already in place; errno is properly set and this function
           * returns -1.
           */
          break;
        }

      case SSL_ERROR_ZERO_RETURN:
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "read EOF from client during TLS");
        break;

      default:
        proxy_tls_fatal(err, __LINE__);
        break;
    }
  }

  return count;
}

static ssize_t proxy_tls_write(SSL *ssl, const void *buf, size_t len,
    int nstrm_type, pr_table_t *notes) {
  ssize_t count;

  count = SSL_write(ssl, buf, len);
  if (count < 0) {
    long err = SSL_get_error(ssl, count);

    /* write(2) returns only the generic error number -1 */
    count = -1;

    switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        /* Simulate an EINTR in case OpenSSL wants to write more. */
        errno = EINTR;
        break;

      default:
        proxy_tls_fatal(err, __LINE__);
        break;
    }
  }

  if (nstrm_type == PR_NETIO_STRM_DATA) {
    BIO *wbio;
    uint64_t *adaptive_bytes_written_ms = NULL, now;
    off_t *adaptive_bytes_written_count = NULL;
    void *v;

    v = pr_table_get(notes, PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY, NULL);
    if (v != NULL) {
      adaptive_bytes_written_count = v;
    }

    v = pr_table_get(notes, PROXY_TLS_ADAPTIVE_BYTES_MS_KEY, NULL);
    if (v != NULL) {
      adaptive_bytes_written_ms = v;
    }

    (void) pr_gettimeofday_millis(&now);
    
    (*adaptive_bytes_written_count) += count;
    wbio = SSL_get_wbio(ssl);

    if (*adaptive_bytes_written_count >= PROXY_TLS_DATA_ADAPTIVE_WRITE_BOOST_THRESHOLD) {
      /* Boost the buffer size if we've written more than the "boost"
       * threshold.
       */
      (void) BIO_set_write_buf_size(wbio,
        PROXY_TLS_DATA_ADAPTIVE_WRITE_MAX_BUFFER_SIZE);
    }

    if (now > (*adaptive_bytes_written_ms + PROXY_TLS_DATA_ADAPTIVE_WRITE_BOOST_INTERVAL_MS)) {
      /* If it's been longer than the boost interval since our last write,
       * then reset the buffer size to the smaller version, assuming
       * congestion (and thus closing of the TCP congestion window).
       */
      (void) BIO_set_write_buf_size(wbio,
        PROXY_TLS_DATA_ADAPTIVE_WRITE_MIN_BUFFER_SIZE);

      *adaptive_bytes_written_count = 0;
    }

    *adaptive_bytes_written_ms = now;
  }

  return count;
}

static const char *get_printable_san(pool *p, const char *data,
    size_t datalen) {
  register unsigned int i;
  char *ptr, *res;
  size_t reslen = 0;

  /* First, calculate the length of the resulting printable string we'll
   * be generating.
   */
  for (i = 0; i < datalen; i++) {
    if (PR_ISPRINT(data[i])) {
      reslen++;

    } else {
      reslen += 4;
    }
  }

  /* Leave one space in the allocated string for the terminating NUL. */
  ptr = res = pcalloc(p, reslen + 1);

  for (i = 0; i < datalen; i++) {
    if (PR_ISPRINT(data[i])) {
      *(ptr++) = data[i];

    } else {
      snprintf(ptr, reslen - (ptr - res), "\\x%02x", data[i]);
      ptr += 4;
    }
  }

  return res;
}

static int cert_match_dns_san(pool *p, X509 *cert, const char *dns_name) {
  int matched = 0;
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  STACK_OF(GENERAL_NAME) *sans;

  sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (sans != NULL) {
    register unsigned int i;
    int nsans = sk_GENERAL_NAME_num(sans);

    for (i = 0; i < nsans; i++) {
      GENERAL_NAME *alt_name = sk_GENERAL_NAME_value(sans, i);

      if (alt_name->type == GEN_DNS) {
        char *dns_san;
        size_t dns_sanlen;

        dns_san = (char *) ASN1_STRING_data(alt_name->d.ia5);
        dns_sanlen = strlen(dns_san);

        /* Check for subjectAltName values which contain embedded NULs.
         * This can cause verification problems (spoofing), e.g. if the
         * string is "www.goodguy.com\0www.badguy.com"; the use of strcmp()
         * only checks "www.goodguy.com".
         */

        if (ASN1_STRING_length(alt_name->d.ia5) != dns_sanlen) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "cert dNSName SAN contains embedded NULs, "
            "rejecting as possible spoof attempt");
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "suspicious dNSName SAN value: '%s'",
            get_printable_san(p, dns_san,
              ASN1_STRING_length(alt_name->d.dNSName)));

          GENERAL_NAME_free(alt_name);
          sk_GENERAL_NAME_free(sans);
          return 0;
        }

        if (strncasecmp(dns_name, dns_san, dns_sanlen + 1) == 0) {
          pr_trace_msg(trace_channel, 8,
            "found cert dNSName SAN matching '%s'", dns_name);
          matched = 1;

        } else {
          pr_trace_msg(trace_channel, 9,
            "cert dNSName SAN '%s' did not match '%s'", dns_san, dns_name);
        }
      }

      GENERAL_NAME_free(alt_name);

      if (matched == 1) {
        break;
      }
    }

    sk_GENERAL_NAME_free(sans);
  }
#endif /* OpenSSL-0.9.7 or later */

  return matched;
}

static int cert_match_ip_san(pool *p, X509 *cert, const char *ipstr) {
  int matched = 0;
  STACK_OF(GENERAL_NAME) *sans;

  sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (sans != NULL) {
    register unsigned int i;
    int nsans = sk_GENERAL_NAME_num(sans);

    for (i = 0; i < nsans; i++) {
      GENERAL_NAME *alt_name = sk_GENERAL_NAME_value(sans, i);

      if (alt_name->type == GEN_IPADD) {
        unsigned char *san_data = NULL;
        int have_ipstr = FALSE, san_datalen;
#ifdef PR_USE_IPV6
        char san_ipstr[INET6_ADDRSTRLEN + 1] = {'\0'};
#else
        char san_ipstr[INET_ADDRSTRLEN + 1] = {'\0'};
#endif /* PR_USE_IPV6 */

        san_data = ASN1_STRING_data(alt_name->d.ip);
        memset(san_ipstr, '\0', sizeof(san_ipstr));

        san_datalen = ASN1_STRING_length(alt_name->d.ip);
        if (san_datalen == 4) {
          /* IPv4 address */
          snprintf(san_ipstr, sizeof(san_ipstr)-1, "%u.%u.%u.%u",
            san_data[0], san_data[1], san_data[2], san_data[3]);
          have_ipstr = TRUE;

#ifdef PR_USE_IPV6
        } else if (san_datalen == 16) {
          /* IPv6 address */

          if (pr_inet_ntop(AF_INET6, san_data, san_ipstr,
              sizeof(san_ipstr)-1) == NULL) {
            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "unable to convert cert iPAddress SAN value (length %d) "
              "to IPv6 representation: %s", san_datalen, strerror(errno));

          } else {
            have_ipstr = TRUE;
          }

#endif /* PR_USE_IPV6 */
        } else {
          pr_trace_msg(trace_channel, 3,
            "unsupported cert SAN ipAddress length (%d), ignoring",
            san_datalen);
          continue;
        }

        if (have_ipstr) {
          size_t san_ipstrlen;

          san_ipstrlen = strlen(san_ipstr);

          if (strncmp(ipstr, san_ipstr, san_ipstrlen + 1) == 0) {
            pr_trace_msg(trace_channel, 8,
              "found cert iPAddress SAN matching '%s'", ipstr);
            matched = 1;

          } else {
            if (san_datalen == 16) {
              /* We need to handle the case where the iPAddress SAN might
               * have contained an IPv4-mapped IPv6 adress, and we're
               * comparing against an IPv4 address.
               */
              if (san_ipstrlen > 7 &&
                  strncasecmp(san_ipstr, "::ffff:", 7) == 0) {
                if (strncmp(ipstr, san_ipstr + 7, san_ipstrlen - 6) == 0) {
                  pr_trace_msg(trace_channel, 8,
                    "found cert iPAddress SAN '%s' matching '%s'",
                    san_ipstr, ipstr);
                    matched = 1;
                }
              }

            } else {
              pr_trace_msg(trace_channel, 9,
                "cert iPAddress SAN '%s' did not match '%s'", san_ipstr, ipstr);
            }
          }
        }
      }

      GENERAL_NAME_free(alt_name);

      if (matched == 1) {
        break;
      }
    }

    sk_GENERAL_NAME_free(sans);
  }

  return matched;
}

static int cert_match_cn(pool *p, X509 *cert, const char *name,
    int allow_wildcards) {
  int matched = 0, idx = -1;
  X509_NAME *subj_name = NULL;
  X509_NAME_ENTRY *cn_entry = NULL;
  ASN1_STRING *cn_asn1 = NULL;
  char *cn_str = NULL;
  size_t cn_len = 0;

  /* Find the position of the CommonName (CN) field within the Subject of
   * the cert.
   */
  subj_name = X509_get_subject_name(cert);
  if (subj_name == NULL) {
    pr_trace_msg(trace_channel, 12,
      "unable to check certificate CommonName against '%s': "
      "unable to get Subject", name);
    return 0;
  }

  idx = X509_NAME_get_index_by_NID(subj_name, NID_commonName, -1);
  if (idx < 0) {
    pr_trace_msg(trace_channel, 12,
      "unable to check certificate CommonName against '%s': "
      "no CommoName atribute found", name);
    return 0;
  }

  cn_entry = X509_NAME_get_entry(subj_name, idx);
  if (cn_entry == NULL) {
    pr_trace_msg(trace_channel, 12,
      "unable to check certificate CommonName against '%s': "
      "error obtaining CommoName atribute found: %s", name, get_errors());
    return 0;
  }

  /* Convert the CN field to a string, by way of an ASN1 object. */
  cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
  if (cn_asn1 == NULL) {
    X509_NAME_ENTRY_free(cn_entry);

    pr_trace_msg(trace_channel, 12,
      "unable to check certificate CommonName against '%s': "
      "error converting CommoName atribute to ASN.1: %s", name,
      get_errors());
    return 0;
  }

  cn_str = (char *) ASN1_STRING_data(cn_asn1);

  /* Check for CommonName values which contain embedded NULs.  This can cause
   * verification problems (spoofing), e.g. if the string is
   * "www.goodguy.com\0www.badguy.com"; the use of strcmp() only checks
   * "www.goodguy.com".
   */

  cn_len = strlen(cn_str);

  if (ASN1_STRING_length(cn_asn1) != cn_len) {
    X509_NAME_ENTRY_free(cn_entry);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "cert CommonName contains embedded NULs, rejecting as possible spoof "
      "attempt");
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "suspicious CommonName value: '%s'",
      get_printable_san(p, (const char *) cn_str, ASN1_STRING_length(cn_asn1)));
    return 0;
  }

  /* Yes, this is deliberately a case-insensitive comparison.  Most CNs
   * contain a hostname (case-insensitive); if they contain an IP address,
   * the case-insensitivity won't hurt anything.  In fact, it's needed for
   * e.g. IPv6 addresses.
   */
  if (strncasecmp(name, cn_str, cn_len + 1) == 0) {
    matched = 1;
  }

  if (matched == 0 &&
      allow_wildcards) {

    /* XXX Implement wildcard checking. */
  }

  X509_NAME_ENTRY_free(cn_entry);
  return matched;
}

static int proxy_tls_check_server_cert(SSL *ssl, conn_t *conn) {
  X509 *cert = NULL;
  int ok = -1;
  long verify_result;

  /* Only perform these more stringent checks if asked to verify servers. */
  if (!(proxy_tls_flags & PROXY_TLS_VERIFY_SERVER) &&
      !(proxy_tls_flags & PROXY_TLS_VERIFY_SERVER_NO_DNS)) {
    return 0;
  }

  /* Check SSL_get_verify_result */
  verify_result = SSL_get_verify_result(ssl);
  if (verify_result != X509_V_OK) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to verify '%s' server certificate: %s",
      conn->remote_name, X509_verify_cert_error_string(verify_result));
    return -1;
  }

  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    /* This can be null in the case where some anonymous (insecure)
     * cipher suite was used.
     */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to verify '%s': server did not provide certificate",
      conn->remote_name);
    return -1;
  }

  /* XXX If using OpenSSL-1.0.2/1.1.0, we might be able to use:
   * X509_match_host() and X509_match_ip()/X509_match_ip_asc().
   */

  ok = cert_match_ip_san(conn->pool, cert,
    pr_netaddr_get_ipstr(conn->remote_addr));
  if (ok == 0) {
    ok = cert_match_cn(conn->pool, cert,
      pr_netaddr_get_ipstr(conn->remote_addr), FALSE);
  }

  if (ok == 0 &&
      !(proxy_tls_flags & PROXY_TLS_VERIFY_SERVER_NO_DNS)) {
    int reverse_dns;
    const char *remote_name;

    reverse_dns = pr_netaddr_set_reverse_dns(TRUE);

    pr_netaddr_clear_ipcache(pr_netaddr_get_ipstr(conn->remote_addr));

    conn->remote_addr->na_have_dnsstr = FALSE;
    remote_name = pr_netaddr_get_dnsstr(conn->remote_addr);
    pr_netaddr_set_reverse_dns(reverse_dns);

    ok = cert_match_dns_san(conn->pool, cert, remote_name);
    if (ok == 0) {
      ok = cert_match_cn(conn->pool, cert, remote_name, TRUE);
    }
  }

  X509_free(cert);
  return ok;
}

static int proxy_tls_connect(conn_t *conn, const char *host_name,
    pr_netio_stream_t *nstrm) {
  int blocking, nstrm_type, res = 0, xerrno = 0;
  char *subj = NULL;
  SSL *ssl = NULL;
  BIO *rbio = NULL, *wbio = NULL;

  if (proxy_ssl_ctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to start session: null SSL_CTX");
    errno = EPERM;
    return -1;
  }

  ssl = SSL_new(proxy_ssl_ctx);
  if (ssl == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error: unable to allocate SSL session: %s", get_errors());
    return -2;
  }

  SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
/* XXX TODO: set verify callback function! */

  /* This works with either rfd or wfd (I hope). */
  rbio = BIO_new_socket(conn->rfd, FALSE);
  wbio = BIO_new_socket(conn->rfd, FALSE);
  SSL_set_bio(ssl, rbio, wbio);

#if !defined(OPENSSL_NO_TLSEXT)
  SSL_set_tlsext_host_name(ssl, conn->remote_name);
#endif /* OPENSSL_NO_TLSEXT */

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    /* If we're opening a data connection, reuse the SSL data from the
     * session on the control connection.
     */
    SSL_copy_session_id(ssl, proxy_tls_ctrl_ssl);
  }

  /* If configured, set a timer for the handshake. */
  if (handshake_timeout) {
    handshake_timer_id = pr_timer_add(handshake_timeout, -1,
      &proxy_module, handshake_timeout_cb, "SSL/TLS handshake");
  }

  /* Make sure that TCP_NODELAY is enabled for the handshake. */
  (void) pr_inet_set_proto_nodelay(conn->pool, conn, 1);

  connect_retry:

  blocking = proxy_tls_get_block(conn);
  if (blocking) {
    /* Put the connection in non-blocking mode for the duration of the
     * SSL handshake.  This lets us handle EAGAIN/retries better (i.e.
     * without spinning in a tight loop and consuming the CPU).
     */
    if (pr_inet_set_nonblock(conn->pool, conn) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error making connection nonblocking: %s", strerror(errno));
    }
  }

  pr_signals_handle();
  res = SSL_connect(ssl);
  if (res == -1) {
    xerrno = errno;
  }

  if (blocking) {
    /* Return the connection to blocking mode. */
    if (pr_inet_set_block(conn->pool, conn) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error making connection blocking: %s", strerror(errno));
    }
  }

  if (res < 1) {
    const char *msg = "unable to connect using TLS connection";
    int errcode = SSL_get_error(ssl, res);

    pr_signals_handle();

    if (handshake_timed_out) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "TLS negotiation timed out (%u seconds)", handshake_timeout);
      proxy_tls_end_sess(ssl, nstrm_type, 0);
      return -4;
    }

    switch (errcode) {
      case SSL_ERROR_WANT_READ:
        pr_trace_msg(trace_channel, 17,
          "WANT_READ encountered while connecting on fd %d, "
          "waiting to read data", conn->rfd);
        proxy_tls_readmore(conn->rfd);
        goto connect_retry;

      case SSL_ERROR_WANT_WRITE:
        pr_trace_msg(trace_channel, 17,
          "WANT_WRITE encountered while connecting on fd %d, "
          "waiting to read data", conn->rfd);
        proxy_tls_writemore(conn->rfd);
        goto connect_retry;

      case SSL_ERROR_ZERO_RETURN:
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "%s: TLS connection closed", msg);
        break;

      case SSL_ERROR_WANT_X509_LOOKUP:
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "%s: needs X509 lookup", msg);
        break;

      case SSL_ERROR_SYSCALL: {
        /* Check to see if the OpenSSL error queue has info about this. */
        int xerrcode = ERR_get_error();

        if (xerrcode == 0) {
          /* The OpenSSL error queue doesn't have any more info, so we'll
           * examine the SSL_connect() return value itself.
           */
          if (res == 0) {
            /* EOF */
            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "%s: received EOF that violates protocol", msg);

          } else if (res == -1) {
            /* Check errno */
            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "%s: system call error: [%d] %s", msg, xerrno,
              strerror(xerrno));
          }

        } else {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "%s: system call error: %s", msg, get_errors());
        }

        break;
      }

      case SSL_ERROR_SSL:
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "%s: protocol error: %s", msg, get_errors());
        break;
    }

    pr_event_generate("mod_proxy.tls-data-handshake-failed", &errcode);

    proxy_tls_end_sess(ssl, nstrm_type, 0);
    return -3;
  }

  /* Disable TCP_NODELAY, now that the handshake is done. */
  (void) pr_inet_set_proto_nodelay(conn->pool, conn, 0);

  /* Disable the handshake timer. */
  pr_timer_remove(handshake_timer_id, &proxy_module);

  /* Manually update the raw bytes counters with the network IO from the
   * SSL handshake.
   */
  session.total_raw_in += (BIO_number_read(rbio) +
    BIO_number_read(wbio));
  session.total_raw_out += (BIO_number_written(rbio) +
    BIO_number_written(wbio));

  if (pr_table_add(nstrm->notes,
      pstrdup(nstrm->strm_pool, PROXY_TLS_NETIO_NOTE), ssl,
      sizeof(SSL *)) < 0) {
    if (errno != EEXIST) {
      pr_trace_msg(trace_channel, 4,
        "error stashing '%s' note on data stream: %s",
        PROXY_TLS_NETIO_NOTE, strerror(errno));
    }
  }

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    pr_buffer_t *strm_buf;

    /* Clear any data from the NetIO stream buffers which may have been read
     * in before the SSL/TLS handshake occurred (Bug#3624).
     */
    strm_buf = nstrm->strm_buf;
    if (strm_buf != NULL) {
      strm_buf->current = NULL;
      strm_buf->remaining = strm_buf->buflen;
    }

  } else {
    /* Stash a pointer to the control connection SSL object. */
    proxy_tls_ctrl_ssl = ssl;
  }

  subj = proxy_tls_get_subj_name(ssl);
  if (subj != NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "Server: %s", subj);
  }

  if (proxy_tls_check_server_cert(ssl, conn) < 0) {
    proxy_tls_end_sess(ssl, nstrm_type, 0);
    return -1;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "%s connection created, using cipher %s (%d bits)",
    SSL_get_version(ssl), SSL_get_cipher_name(ssl),
    SSL_get_cipher_bits(ssl, NULL));

  return 0;
}

static int proxy_tls_seed_prng(void) {
  char *heapdata, stackdata[1024];
  FILE *fp = NULL;
  pid_t pid; 
  struct timeval tv;
 
#if OPENSSL_VERSION_NUMBER >= 0x00905100L
  if (RAND_status() == 1)
    /* PRNG already well-seeded. */
    return 0;
#endif

  pr_log_debug(DEBUG9, MOD_PROXY_VERSION
    ": PRNG not seeded with enough data, looking for entropy sources");

  /* If the device '/dev/urandom' is present, OpenSSL uses it by default.
   * Check if it's present, else we have to make random data ourselves.
   */
  fp = fopen("/dev/urandom", "r");
  if (fp != NULL) {
    fclose(fp);

    pr_log_debug(DEBUG9, MOD_PROXY_VERSION
      ": device /dev/urandom is present, assuming OpenSSL will use that "
      "for PRNG data");
    return 0;
  }

  /* Not enough entropy; trying providing some. */
  gettimeofday(&tv, NULL);
  RAND_seed(&(tv.tv_sec), sizeof(tv.tv_sec));
  RAND_seed(&(tv.tv_usec), sizeof(tv.tv_usec));

  pid = getpid();
  RAND_seed(&pid, sizeof(pid_t));
  RAND_seed(stackdata, sizeof(stackdata));

  heapdata = malloc(sizeof(stackdata));
  if (heapdata != NULL) {
    RAND_seed(heapdata, sizeof(stackdata));
    free(heapdata);
  }

#if OPENSSL_VERSION_NUMBER >= 0x00905100L
  if (RAND_status() == 0) {
     /* PRNG still badly seeded. */
     errno = EPERM;
     return -1;
  }
#endif

  return 0;
}

/* NetIO callbacks */

static void netio_abort_cb(pr_netio_stream_t *nstrm) {
  nstrm->strm_flags |= PR_NETIO_SESS_ABORT;
}

static int netio_close_cb(pr_netio_stream_t *nstrm) {
  int res = 0;
  SSL *ssl = NULL;

  ssl = pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
  if (ssl != NULL) {
    if (nstrm->strm_type == PR_NETIO_STRM_CTRL &&
        nstrm->strm_mode == PR_NETIO_IO_WR) {

      pr_table_remove(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
      proxy_tls_end_sess(ssl, nstrm->strm_type, 0);
    }

    if (nstrm->strm_type == PR_NETIO_STRM_DATA &&
        nstrm->strm_mode == PR_NETIO_IO_WR) {
      pr_table_remove(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
    }
  }

  res = close(nstrm->strm_fd);
  nstrm->strm_fd = -1;

  return res;
}

static pr_netio_stream_t *netio_open_cb(pr_netio_stream_t *nstrm, int fd,
    int mode) {
  nstrm->strm_fd = fd;
  nstrm->strm_mode = mode;

  return nstrm;
}

static int netio_poll_cb(pr_netio_stream_t *nstrm) {
  fd_set rfds, wfds;
  struct timeval tval;

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);

  if (nstrm->strm_mode == PR_NETIO_IO_RD) {
    FD_SET(nstrm->strm_fd, &rfds);

  } else {
    FD_SET(nstrm->strm_fd, &wfds);
  }

  tval.tv_sec = (nstrm->strm_flags & PR_NETIO_SESS_INTR) ?
    nstrm->strm_interval : 10;
  tval.tv_usec = 0;

  return select(nstrm->strm_fd + 1, &rfds, &wfds, NULL, &tval);
}

static int netio_postopen_cb(pr_netio_stream_t *nstrm) {

  /* If this is a data stream, and it's for writing, and TLS is required,
   * then do a TLS handshake.
   */

  if (proxy_tls_engine == PROXY_TLS_ENGINE_OFF) {
    return 0;
  }

  if (nstrm->strm_mode == PR_NETIO_IO_WR) {
    struct proxy_session *proxy_sess;
    uint64_t *adaptive_ms = NULL, start_ms;
    off_t *adaptive_bytes = NULL;

    proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);

    /* TODO: Handle SSCN_MODE CLIENT (connect), SERVER (accept) */

    pr_gettimeofday_millis(&start_ms);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "starting TLS negotiation on %s connection",
      nstrm->strm_type == PR_NETIO_STRM_CTRL ? "control" : "data");

    /* TODO: do SSL_connect() here?  Make sure to use SSL_set_session() for
     * the cached session ID, if found?  (Where to get a SSL_SESSION *?)
     *
     */
#if 0

    /* writing out SSL_SESSION, from apps/s_client.c: */

     Here, we can use a memory BIO to get the formatted SSL_SESSION.
     AND since we'd be using PEM, it means that we can use TEXT, not BLOB,
     in the schema.  Yay!

     We'll need to use SSL_SESSION_get_time() to get the time at which
     the session was established; we'll need to use this, and/or
     SSL_SESSION_set_timeout to set a time limit on sessions (or should we
     just let servers handle this?  What about buggy servers?).  We should
     have our own timeout: 24 hours by default.  This timeout would be
     enforced when we read sessions out of the db; expired sessions would
     be a) DELETED from db, and b) return NULL/none to the caller.  I suppose,
     if we wanted, we COULD use SESS_CACHE_CLIENT, and replace the cache
     callbacks to use our database; this would make our implementation
     more similar to mod_tls, AND it would mean being able to use e.g.
     SSL_CTX_flush_sessions.  Hmmm.

                    BIO *stmp = BIO_new_file(sess_out, "w");
                    if (stmp) {
                        PEM_write_bio_SSL_SESSION(stmp, SSL_get_session(con));
                        BIO_free(stmp);
                    } else
                        BIO_printf(bio_err, "Error writing session file %s\n",
                                   sess_out);

    /* reading in SSL_SESSION, from apps/s_client.c: */
        SSL_SESSION *sess;
        BIO *stmp = BIO_new_file(sess_in, "r");
        if (!stmp) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
        BIO_free(stmp);
        if (!sess) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        SSL_set_session(con, sess);
        SSL_SESSION_free(sess);

#endif

    if (proxy_tls_connect(proxy_sess->backend_data_conn,
        proxy_conn_get_host(proxy_sess->dst_pconn), nstrm) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to open %s connection: TLS negotiation failed",
        nstrm->strm_type == PR_NETIO_STRM_CTRL ? "control" : "data");
      errno = EPERM;
      return -1;
    }

    if (pr_trace_get_level(timing_channel) >= 4) {
      unsigned long elapsed_ms;
      uint64_t finish_ms;

      pr_gettimeofday_millis(&finish_ms);
      elapsed_ms = (unsigned long) (finish_ms - start_ms);

      pr_trace_msg(timing_channel, 4,
        "TLS data handshake duration: %lu ms", elapsed_ms);
    }

    adaptive_ms = pcalloc(nstrm->strm_pool, sizeof(uint64_t));
    if (pr_table_add(nstrm->notes, PROXY_TLS_ADAPTIVE_BYTES_MS_KEY,
        adaptive_ms, sizeof(uint64_t *)) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error stashing '%s' stream note: %s", PROXY_TLS_ADAPTIVE_BYTES_MS_KEY,
        strerror(errno));
    }

    adaptive_bytes = pcalloc(nstrm->strm_pool, sizeof(off_t));
    if (pr_table_add(nstrm->notes, PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY,
        adaptive_bytes, sizeof(off_t *)) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error stashing '%s' stream note: %s",
        PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY, strerror(errno));
    }

    if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
      proxy_sess_state |= PROXY_SESS_STATE_BACKEND_HAS_CTRL_TLS;
    }
  }

  return 0;
}

static int netio_read_cb(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  SSL *ssl;

  ssl = pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
  if (ssl != NULL) {
    BIO *rbio, *wbio;
    int bread = 0, bwritten = 0;
    ssize_t res = 0;
    unsigned long rbio_rbytes, rbio_wbytes, wbio_rbytes, wbio_wbytes;

    rbio = SSL_get_rbio(ssl);
    rbio_rbytes = BIO_number_read(rbio);
    rbio_wbytes = BIO_number_written(rbio);

    wbio = SSL_get_wbio(ssl);
    wbio_rbytes = BIO_number_read(wbio);
    wbio_wbytes = BIO_number_written(wbio);

    res = proxy_tls_read(ssl, buf, buflen, nstrm->strm_type, nstrm->notes);

    bread = (BIO_number_read(rbio) - rbio_rbytes) +
      (BIO_number_read(wbio) - wbio_rbytes);
    bwritten = (BIO_number_written(rbio) - rbio_wbytes) +
      (BIO_number_written(wbio) - wbio_wbytes);

    /* Manually update session.total_raw_in with the difference between
     * the raw bytes read in versus the non-SSL bytes read in, in order to
     * have %I be accurately represented for the raw traffic.
     */
    if (res > 0) {
      session.total_raw_in += (bread - res);
    }

    /* Manually update session.total_raw_out, in order to have %O be
     * accurately represented for the raw traffic.
     */
    if (bwritten > 0) {
      session.total_raw_out += bwritten;
    }

    return res;
  }

  return read(nstrm->strm_fd, buf, buflen);
}

static pr_netio_stream_t *netio_reopen_cb(pr_netio_stream_t *nstrm, int fd,
    int mode) {

  if (nstrm->strm_fd != -1) {
    (void) close(nstrm->strm_fd);
  }

  nstrm->strm_fd = fd;
  nstrm->strm_mode = mode;

  return nstrm;
}

static int netio_shutdown_cb(pr_netio_stream_t *nstrm, int how) {

  if (how == 1 ||
      how == 2) {
    /* Closing this stream for writing; we need to send the 'close_notify'
     * alert first, so that the client knows, at the application layer,
     * that the SSL/TLS session is shutting down.
     */

    if (nstrm->strm_mode == PR_NETIO_IO_WR &&
        (nstrm->strm_type == PR_NETIO_STRM_CTRL ||
         nstrm->strm_type == PR_NETIO_STRM_DATA)) {
      SSL *ssl;

      ssl = pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
      if (ssl != NULL) {
        BIO *rbio, *wbio;
        int bread = 0, bwritten = 0;
        unsigned long rbio_rbytes, rbio_wbytes, wbio_rbytes, wbio_wbytes;

        rbio = SSL_get_rbio(ssl);
        rbio_rbytes = BIO_number_read(rbio);
        rbio_wbytes = BIO_number_written(rbio);

        wbio = SSL_get_wbio(ssl);
        wbio_rbytes = BIO_number_read(wbio);
        wbio_wbytes = BIO_number_written(wbio);

        if (!(SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN)) {
          /* We haven't sent a 'close_notify' alert yet; do so now. */
          SSL_shutdown(ssl);
        }

        bread = (BIO_number_read(rbio) - rbio_rbytes) +
          (BIO_number_read(wbio) - wbio_rbytes);
        bwritten = (BIO_number_written(rbio) - rbio_wbytes) +
          (BIO_number_written(wbio) - wbio_wbytes);

        /* Manually update session.total_raw_in/out, in order to have %I/%O be
         * accurately represented for the raw traffic.
         */
        if (bread > 0) {
          session.total_raw_in += bread;
        }

        if (bwritten > 0) {
          session.total_raw_out += bwritten;
        }
      }
    }
  }

  return shutdown(nstrm->strm_fd, how);
}

static int netio_write_cb(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  SSL *ssl;

  ssl = pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
  if (ssl != NULL) {
    BIO *rbio, *wbio;
    int bread = 0, bwritten = 0;
    ssize_t res = 0;
    unsigned long rbio_rbytes, rbio_wbytes, wbio_rbytes, wbio_wbytes;

    rbio = SSL_get_rbio(ssl);
    rbio_rbytes = BIO_number_read(rbio);
    rbio_wbytes = BIO_number_written(rbio);

    wbio = SSL_get_wbio(ssl);
    wbio_rbytes = BIO_number_read(wbio);
    wbio_wbytes = BIO_number_written(wbio);

    res = proxy_tls_write(ssl, buf, buflen, nstrm->strm_type, nstrm->notes);

    bread = (BIO_number_read(rbio) - rbio_rbytes) +
      (BIO_number_read(wbio) - wbio_rbytes);
    bwritten = (BIO_number_written(rbio) - rbio_wbytes) +
      (BIO_number_written(wbio) - wbio_wbytes);

    /* Manually update session.total_raw_in, in order to have %I be
     * accurately represented for the raw traffic.
     */
    if (bread > 0) {
      session.total_raw_in += bread;
    }

    /* Manually update session.total_raw_out with the difference between
     * the raw bytes written out versus the non-SSL bytes written out,
     * in order to have %) be accurately represented for the raw traffic.
     */
    if (res > 0) {
      session.total_raw_out += (bwritten - res);
    }

    return res;
  }

  return write(nstrm->strm_fd, buf, buflen);
}

static int netio_install_ctrl(void) {
  pr_netio_t *netio;

  if (proxy_tls_ctrl_netio != NULL) {
    /* If we already have our ctrl netio, then it's been registered, and
     * we don't need to do anything more.
     */
    return 0;
  }

  netio = pr_alloc_netio2(permanent_pool, &proxy_module, "proxy.tls");

  netio->abort = netio_abort_cb;
  netio->close = netio_close_cb;
  netio->open = netio_open_cb;
  netio->poll = netio_poll_cb;
  netio->postopen = netio_postopen_cb;
  netio->read = netio_read_cb;
  netio->reopen = netio_reopen_cb;
  netio->shutdown = netio_shutdown_cb;
  netio->write = netio_write_cb;

  proxy_netio_use(PR_NETIO_STRM_CTRL, netio);
  return 0;
}

static int proxy_tls_netio_install_data(void) {
  pr_netio_t *netio;

  if (proxy_tls_data_netio != NULL) {
    /* If we already have our data netio, then it's been registered, and
     * we don't need to do anything more.
     */
    return 0;
  }

  netio = pr_alloc_netio2(permanent_pool, &proxy_module, "proxy.tls");

  netio->abort = netio_abort_cb;
  netio->close = netio_close_cb;
  netio->open = netio_open_cb;
  netio->poll = netio_poll_cb;
  netio->postopen = netio_postopen_cb;
  netio->read = netio_read_cb;
  netio->reopen = netio_reopen_cb;
  netio->shutdown = netio_shutdown_cb;
  netio->write = netio_write_cb;

  proxy_netio_use(PR_NETIO_STRM_DATA, netio);
  return 0;
}

/* Initialization routines */

#if !defined(OPENSSL_NO_TLSEXT)

struct proxy_tls_next_proto {
  const char *proto;
  unsigned char *encoded_proto;
  unsigned int encoded_protolen;
};

static int proxy_tls_npn_cb(SSL *ssl,
    unsigned char **npn_out, unsigned char *npn_outlen,
    const unsigned char *npn_in, unsigned int npn_inlen,
    void *data) {
  struct proxy_tls_next_proto *next_proto;

  next_proto = data;

  if (pr_trace_get_level(trace_channel) >= 12) {
    register unsigned int i;
    int res;

    pr_trace_msg(trace_channel, 12,
      "NPN protocols advertised by server:");
    for (i = 0; i < npn_inlen; i++) {
      pr_trace_msg(trace_channel, 12,
        " %*s", npn_in[i], &(npn_in[i+1]));
      i += npn_in[i] + 1;
    }

    res = SSL_select_next_proto(npn_out, npn_outlen, npn_in, npn_inlen,
      next_proto->encoded_proto, next_proto->encoded_protolen);
    if (res != OPENSSL_NPN_NEGOTIATED) {
      pr_trace_msg(trace_channel, 12,
        "failed to negotiate NPN protocol '%s': %s", PROXY_TLS_NEXT_PROTO,
        res == OPENSSL_NPN_UNSUPPORTED ? "NPN unsupported by server" :
          "No overlap with server protocols");
    }
  }

  return SSL_TLSEXT_ERR_OK;
}

static int set_next_protocol(SSL_CTX *ctx) {
  register unsigned int i;
  const char *proto = PROXY_TLS_NEXT_PROTO;
  struct proxy_tls_next_proto *next_proto;
  unsigned char *encoded_proto;
  size_t encoded_protolen, proto_len;

  proto_len = strlen(proto);
  encoded_protolen = proto_len + 1;
  encoded_proto = palloc(proxy_pool, encoded_protolen);
  encoded_proto[0] = proto_len;
  for (i = 0; i < proto_len; i++) {
    encoded_proto[i+1] = proto[i];
  }

  next_proto = palloc(proxy_pool, sizeof(struct proxy_tls_next_proto));
  next_proto->proto = pstrdup(proxy_pool, proto);
  next_proto->encoded_proto = encoded_proto;
  next_proto->encoded_protolen = encoded_protolen;

# if defined(PR_USE_OPENSSL_NPN)
  SSL_CTX_set_next_proto_select_cb(ctx, proxy_tls_npn_cb, &next_proto);
# endif /* NPN */

# if defined(PR_USE_OPENSSL_ALPN)
  SSL_CTX_set_alpn_protos(ctx, next_proto->encoded_proto,
    next_proto->encoded_protolen);
# endif /* ALPN */

  return 0;
}
#endif /* OPENSSL_NO_TLSEXT */

static int proxy_tls_init_ctx(void) {
  long ssl_mode = 0;
  int ssl_opts = proxy_tls_ssl_opts;

  if (proxy_ssl_ctx != NULL) {
    SSL_CTX_free(proxy_ssl_ctx);
    proxy_ssl_ctx = NULL;
  }

  proxy_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (proxy_ssl_ctx == NULL) {
    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error creating SSL_CTX: %s", get_errors());
    errno = EPERM;
    return -1;
  }

  /* Note that we explicitly do NOT use OpenSSL's internal cache for
   * client session caching; we'll use our own.
   */
  SSL_CTX_set_session_cache_mode(proxy_ssl_ctx, SSL_SESS_CACHE_OFF);

#if OPENSSL_VERSION_NUMBER > 0x000906000L
  /* The SSL_MODE_AUTO_RETRY mode was added in 0.9.6. */
  ssl_mode |= SSL_MODE_AUTO_RETRY;
#endif

#if OPENSSL_VERSION_NUMBER >= 0x1000001fL
  /* The SSL_MODE_RELEASE_BUFFERS mode was added in 1.0.0a. */
  ssl_mode |= SSL_MODE_RELEASE_BUFFERS;
#endif

  if (ssl_mode != 0) {
    SSL_CTX_set_mode(proxy_ssl_ctx, ssl_mode);
  }

  /* If using OpenSSL-0.9.7 or greater, prevent session resumptions on
   * renegotiations (more secure).
   */
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  ssl_opts |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#endif

  /* Disable SSL tickets, for now. */
#ifdef SSL_OP_NO_TICKET
  ssl_opts |= SSL_OP_NO_TICKET;
#endif

  /* Disable SSL compression. */
#ifdef SSL_OP_NO_COMPRESSION
  ssl_opts |= SSL_OP_NO_COMPRESSION;
#endif /* SSL_OP_NO_COMPRESSION */

#if defined(PR_USE_OPENSSL_ECC)
# if defined(SSL_OP_SINGLE_ECDH_USE)
  ssl_opts |= SSL_OP_SINGLE_ECDH_USE;
# endif
# if defined(SSL_OP_SAFARI_ECDHE_ECDSA_BUG)
  ssl_opts |= SSL_OP_SAFARI_ECDHE_ECDSA_BUG;
# endif
#endif /* ECC support */

  SSL_CTX_set_options(proxy_ssl_ctx, ssl_opts);

#if !defined(OPENSSL_NO_TLSEXT)
  if (set_next_protocol(proxy_ssl_ctx) < 0) {
    pr_trace_msg(trace_channel, 4,
      "error setting TLS next protocol: %s", strerror(errno));
  }
#endif /* OPENSSL_NO_TLSEXT */

  /* XXX TODO: do we need to set ECDH, tmp dh callbacks for clients? */

  if (proxy_tls_seed_prng() < 0) {
    pr_log_debug(DEBUG1, MOD_PROXY_VERSION ": unable to properly seed PRNG");
  }

  return 0;
}

/* Event listeners */

static void proxy_tls_postparse_ev(const void *event_data, void *user_data) {
  int res;

  res = proxy_tls_init_ctx();
  if (res < 0) {
    /* TODO: FATAL ERROR */
  }

  /* TODO: get passphrases for client certs, if any */
}

static void proxy_tls_shutdown_ev(const void *event_data, void *user_data) {
  RAND_cleanup();
}

static int tls_db_add_schema(pool *p, const char *db_path) {
  int res;
  const char *stmt, *errstr = NULL;

  /* CREATE TABLE proxy_tls_vhosts (
   *   vhost_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_name TEXT NOT NULL
   * );
   */
  stmt = "CREATE TABLE proxy_tls_vhosts (vhost_id INTEGER NOT NULL PRIMARY KEY, vhost_name TEXT NOT NULL);";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_tls_sessions (
   *   backend_uri STRING NOT NULL PRIMARY KEY,
   *   vhost_id INTEGER NOT NULL,
   *   session TEXT NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_tls_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE proxy_tls_sessions (backend_uri STRING NOT NULL PRIMARY KEY, vhost_id INTEGER NOT NULL, session TEXT NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_hosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int tls_db_add_vhost(pool *p, server_rec *s) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_tls_vhosts (vhost_id, vhost_name) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &(s->sid));
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) s->ServerName);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int tls_db_init(pool *p, const char *tables_dir) {
  int res, xerrno = 0;
  char *db_path;
  server_rec *s;

  if (p == NULL ||
      tables_dir == NULL) {
    errno = EINVAL;
    return -1;
  }

  db_path = pdircat(p, tables_dir, "proxy-tls.db", NULL);
  if (file_exists(db_path)) {
    pr_log_debug(DEBUG9, MOD_PROXY_VERSION
      ": deleting existing database file '%s'", db_path);
    if (unlink(db_path) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
        ": error deleting '%s': %s", db_path, strerror(errno));
    }
  }

  res = proxy_db_open(p, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening database '%s': %s", db_path, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = tls_db_add_schema(p, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error adding schema to database '%s': %s", db_path, strerror(xerrno));
    (void) proxy_db_close(p);
    errno = xerrno;
    return -1;
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    res = tls_db_add_vhost(p, s);
    if (res < 0) {
      xerrno = errno;
      (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": error adding database entry for server '%s': %s", s->ServerName,
        strerror(xerrno));
      (void) proxy_db_close(p);
      errno = xerrno;
      return -1;
    }
  }

  return 0;
}
#endif /* PR_USE_OPENSSL */

int proxy_tls_use_tls(void) {
  return proxy_tls_engine;
}

int proxy_tls_init(pool *p, const char *tables_dir) {
#ifdef PR_USE_OPENSSL
  if (tls_db_init(p, tables_dir) < 0) {
    return -1;
  }

  if (pr_module_exists("mod_tls.c") == FALSE) {
    OPENSSL_config(NULL);
    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
  }

  /* XXX TODO: register listener for module-unload event, to clean up OpenSSL
   * stuff?
   */

  pr_event_register(&proxy_module, "core.postparse", proxy_tls_postparse_ev,
    NULL);
  pr_event_register(&proxy_module, "core.shutdown", proxy_tls_shutdown_ev,
    NULL);
#endif /* PR_USE_OPENSSL */

  return 0;
}

int proxy_tls_free(pool *p) {
  return 0;
}

/* Construct the options value that disables all unsupported protocols. */
static int get_disabled_protocols(unsigned int supported_protocols) {
  int disabled_protocols;

  /* First, create an options value where ALL protocols are disabled. */
  disabled_protocols = (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);

#ifdef SSL_OP_NO_TLSv1_1
  disabled_protocols |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
  disabled_protocols |= SSL_OP_NO_TLSv1_2;
#endif

  /* Now, based on the given bitset of supported protocols, clear the
   * necessary bits.
   */

  if (supported_protocols & PROXY_TLS_PROTO_SSL_V3) {
    disabled_protocols &= ~SSL_OP_NO_SSLv3;
  }

  if (supported_protocols & PROXY_TLS_PROTO_TLS_V1) {
    disabled_protocols &= ~SSL_OP_NO_TLSv1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
  if (supported_protocols & PROXY_TLS_PROTO_TLS_V1_1) {
    disabled_protocols &= ~SSL_OP_NO_TLSv1_1;
  }

  if (supported_protocols & PROXY_TLS_PROTO_TLS_V1_2) {
    disabled_protocols &= ~SSL_OP_NO_TLSv1_2;
  }
#endif /* OpenSSL-1.0.1 or later */

  return disabled_protocols;
}

static const char *get_enabled_protocols_str(pool *p, unsigned int protos,
    unsigned int *count) {
  char *proto_str = "";
  unsigned int nproto = 0;

  if (protos & PROXY_TLS_PROTO_SSL_V3) {
    proto_str = pstrcat(p, proto_str, *proto_str ? ", " : "",
      "SSLv3", NULL);
    nproto++;
  }

  if (protos & PROXY_TLS_PROTO_TLS_V1) {
    proto_str = pstrcat(p, proto_str, *proto_str ? ", " : "",
      "TLSv1", NULL);
    nproto++;
  }

  if (protos & PROXY_TLS_PROTO_TLS_V1_1) {
    proto_str = pstrcat(p, proto_str, *proto_str ? ", " : "",
      "TLSv1.1", NULL);
    nproto++;
  }

  if (protos & PROXY_TLS_PROTO_TLS_V1_2) {
    proto_str = pstrcat(p, proto_str, *proto_str ? ", " : "",
      "TLSv1.2", NULL);
    nproto++;
  }

  *count = nproto;
  return proto_str;
}

int proxy_tls_sess_init(pool *p) {
#ifdef PR_USE_OPENSSL
  config_rec *c;
  unsigned int enabled_proto_count = 0, proxy_tls_protocol = PROXY_TLS_PROTO_DEFAULT;
  int disabled_proto;
  const char *enabled_proto_str = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSEngine", FALSE);
  if (c != NULL) {
    proxy_tls_engine = *((int *) c->argv[0]);
  }

  if (proxy_tls_engine == PROXY_TLS_ENGINE_OFF) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSProtocol", FALSE);
  if (c != NULL) {
    proxy_tls_protocol = *((unsigned int *) c->argv[0]);
  }

  disabled_proto = get_disabled_protocols(proxy_tls_protocol);

  /* Per the comments in <ssl/ssl.h>, SSL_CTX_set_options() uses |= on
   * the previous value.  This means we can easily OR in our new option
   * values with any previously set values.
   */
  enabled_proto_str = get_enabled_protocols_str(main_server->pool,
    proxy_tls_protocol, &enabled_proto_count);

  pr_log_debug(DEBUG8, MOD_PROXY_VERSION ": supporting %s %s",
    enabled_proto_str,
    enabled_proto_count != 1 ? "protocols" : "protocol only");
  SSL_CTX_set_options(proxy_ssl_ctx, disabled_proto);

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCipherSuite", FALSE);
  if (c != NULL) {
    proxy_tls_cipher_suite = c->argv[0];

  } else {
    proxy_tls_cipher_suite = PROXY_TLS_DEFAULT_CIPHER_SUITE;
  }

  SSL_CTX_set_cipher_list(proxy_ssl_ctx, proxy_tls_cipher_suite);

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSTimeoutHandshake",
    FALSE);
  if (c != NULL) {
    handshake_timeout = *((unsigned int *) c->argv[0]);
  }

/* TODO (in this order):
 *  ProxyTLSCACertificate{File,Path}
 *  ProxyTLSVerifyServer
 *  ProxyTLSCertificate{File,Key}
 *
 *  Need to figure out where to do:
 *  AUTH TLS
 *   (SSL_connect)
 *  PBSZ 0
 *  PROT P
 *  ...
 *
 * AND do SSL_connect() for data connections (even when we accept), too.  Be
 * like lftp, and wait to receive 150 response code from backend server
 * BEFORE doing SSL_connect(), with timeout (5 sec, like lftp's default).
 *
 * session ID caching!
 */

/* On connect to backend, AFTER FEAT (and before HOST), do SSL_connect. */

#endif /* PR_USE_OPENSSL */

  return 0;
}

int proxy_tls_sess_free(pool *p) {
  return 0;
}
