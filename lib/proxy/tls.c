/*
 * ProFTPD - mod_proxy TLS implementation
 * Copyright (c) 2015-2025 TJ Saunders
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

#include "proxy/conn.h"
#include "proxy/netio.h"
#include "proxy/session.h"
#include "proxy/tls.h"
#include "proxy/tls/db.h"
#include "proxy/tls/redis.h"

/* Define if you have the LibreSSL library.  */
#if defined(LIBRESSL_VERSION_NUMBER)
# define HAVE_LIBRESSL  1
#endif

static const char *trace_channel = "proxy.tls";

#if defined(PR_USE_OPENSSL)
extern xaset_t *server_list;

static unsigned long tls_opts = 0UL;

static const char *tls_tables_path = NULL;
static struct proxy_tls_datastore tls_ds;
static int tls_engine = PROXY_TLS_ENGINE_AUTO;
static int tls_need_data_prot = TRUE;
static int tls_verify_server = TRUE;

#if defined(PSK_MAX_PSK_LEN)
static const char *tls_psk_name = NULL;
static BIGNUM *tls_psk_bn = NULL;
static int tls_psk_used = FALSE;
# define PROXY_TLS_MIN_PSK_LEN			20
#endif /* PSK support */

/* The SSL_set_session_ticket_ext() API was not fixed until OpenSSL-1.0.2e.
 * Thus mod_proxy's caching/reuse of session tickets will not work properly
 * before that version.
 */
#if defined(SSL_CTRL_SET_TLSEXT_TICKET_KEYS)
# define PROXY_TLS_USE_SESSION_TICKETS		1
#endif

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

#if defined(SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
static int tls_ssl_opts = (SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_SINGLE_DH_USE)^SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
#else
/* OpenSSL-0.9.6 and earlier (yes, it appears people still have these versions
 * installed) does not define the DONT_INSERT_EMPTY_FRAGMENTS option.
 */
static int tls_ssl_opts = SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_SINGLE_DH_USE;
#endif

static const char *tls_cipher_suite = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && \
    defined(TLS1_3_VERSION)
static const char *tlsv13_cipher_suite = NULL;
#endif /* TLS1_3_VERSION */

#define PROXY_TLS_VERIFY_DEPTH		9

/* ProxyTLSTimeoutHandshake */
static unsigned int handshake_timeout = 30;
static int handshake_timer_id = -1;
static int handshake_timed_out = FALSE;

#define PROXY_TLS_SHUTDOWN_BIDIRECTIONAL	0x001

/* Stream notes */
#define PROXY_TLS_NETIO_NOTE			"mod_proxy.SSL"
#define PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY	"mod_proxy.SSL.adaptive.bytes"
#define PROXY_TLS_ADAPTIVE_BYTES_MS_KEY		"mod_proxy.SSL.adaptive.ms"

/* Session caching */
#define PROXY_TLS_MAX_SESSION_AGE		86400
#define PROXY_TLS_MAX_SESSION_COUNT		1000

static SSL_CTX *ssl_ctx = NULL;
static pr_netio_t *tls_ctrl_netio = NULL;
static pr_netio_t *tls_data_netio = NULL;
static SSL *tls_ctrl_ssl = NULL;

static int netio_install_ctrl(void);
static int netio_install_data(void);

/* Indices for data stashed in SSL objects */
#define PROXY_TLS_IDX_TICKET_KEY		2
#define PROXY_TLS_IDX_HAD_TICKET		3

#if !defined(OPENSSL_NO_TLSEXT)
static void tls_tlsext_cb(SSL *, int, int, unsigned char *, int, void *);
#endif /* !OPENSSL_NO_TLSEXT */

static int handshake_timeout_cb(CALLBACK_FRAME) {
  handshake_timed_out = TRUE;
  return 0;
}

const char *proxy_tls_get_errors(void) {
  unsigned int count = 0;
  unsigned long error_code;
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *error_data = NULL, *str = "(unknown)";
  int error_flags = 0;

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  if (error_code) {
    bio = BIO_new(BIO_s_mem());
  }

  while (error_code) {
    pr_signals_handle();

    if (error_flags & ERR_TXT_STRING) {
      BIO_printf(bio, "\n  (%u) %s [%s]", ++count,
        ERR_error_string(error_code, NULL), error_data);

    } else {
      BIO_printf(bio, "\n  (%u) %s", ++count,
        ERR_error_string(error_code, NULL));
    }

    error_data = NULL;
    error_flags = 0;
    error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
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

static char *tls_x509_name_oneline(X509_NAME *x509_name) {
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

    if (data != NULL) {
      memset(&buf, '\0', sizeof(buf));

      if ((size_t) datalen >= sizeof(buf)) {
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

static char *tls_get_subj_name(SSL *ssl) {
  X509 *cert;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    char *subj_name;

    subj_name = tls_x509_name_oneline(X509_get_subject_name(cert));
    X509_free(cert);
    return subj_name;
  }

  errno = ENOENT;
  return NULL;
}

static int tls_get_block(conn_t *conn) {
  int flags;

  flags = fcntl(conn->rfd, F_GETFL);
  if (flags & O_NONBLOCK) {
    return FALSE;
  }

  return TRUE;
}

static void tls_fatal(long error, int lineno) {
  switch (error) {
    case SSL_ERROR_NONE:
      return;

    case SSL_ERROR_SSL:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "panic: SSL_ERROR_SSL, line %d: %s", lineno, proxy_tls_get_errors());
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
        pr_trace_msg(trace_channel, 17,
          "SSL_ERROR_SYSCALL error (errcode %ld) occurred on line %d; ignoring "
          "ECONNRESET (%s)", xerrcode, lineno, strerror(errno));
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
          "panic: SSL_ERROR_SYSCALL, line %d: %s", lineno,
          proxy_tls_get_errors());
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

static void tls_end_sess(SSL *ssl, int strms, int flags) {
  int lineno = 0, res = 0;
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
    pr_trace_msg(trace_channel, 17,
      "shutting down TLS session, 'close_notify' not already sent; "
      "sending now");
    lineno = __LINE__ + 1;
    res = SSL_shutdown(ssl);
  }

  if (res == 0) {
    /* Now call SSL_shutdown() again, but only if necessary. */
    if (flags & PROXY_TLS_SHUTDOWN_BIDIRECTIONAL) {
      shutdown_state = SSL_get_shutdown(ssl);

      res = 1;
      if (!(shutdown_state & SSL_RECEIVED_SHUTDOWN)) {
        errno = 0;

        pr_trace_msg(trace_channel, 17,
          "shutting down TLS session, 'close_notify' not received; try again");
        lineno = __LINE__ + 1;
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

          errors = proxy_tls_get_errors();
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
        if (lineno == 0) {
          lineno = __LINE__;
        }
        tls_fatal(err_code, lineno);
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

  if (res >= 0) {
    pr_trace_msg(trace_channel, 17, "TLS session cleanly shut down");
  }
}

static int tls_readmore(int rfd) {
  fd_set rfds;
  struct timeval tv;

  FD_ZERO(&rfds);
  FD_SET(rfd, &rfds);

  /* Use a timeout of 15 seconds */
  tv.tv_sec = 15;
  tv.tv_usec = 0;

  return select(rfd + 1, &rfds, NULL, NULL, &tv);
}

static int tls_writemore(int wfd) {
  fd_set wfds;
  struct timeval tv;

  FD_ZERO(&wfds);
  FD_SET(wfd, &wfds);

  /* Use a timeout of 15 seconds */
  tv.tv_sec = 15;
  tv.tv_usec = 0;

  return select(wfd + 1, NULL, &wfds, NULL, &tv);
}

static ssize_t tls_read(SSL *ssl, void *buf, size_t len,
    int nstrm_type, pr_table_t *notes) {
  int lineno;
  ssize_t count;

  read_retry:
  pr_signals_handle();
  lineno = __LINE__ + 1;
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
        err = tls_readmore(fd);
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
        err = tls_writemore(fd);
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
        tls_fatal(err, lineno);
        break;
    }
  }

  return count;
}

static ssize_t tls_write(SSL *ssl, const void *buf, size_t len,
    int nstrm_type, pr_table_t *notes) {
  ssize_t count;
  int lineno, xerrno = 0;

  /* Help ensure we have a clean/trustable errno value. */
  errno = 0;

  lineno = __LINE__ + 1;
  count = SSL_write(ssl, buf, len);
  xerrno = errno;

  if (count < 0) {
    long err = SSL_get_error(ssl, count);

    /* write(2) returns only the generic error number -1 */
    count = -1;

    switch (err) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        /* Simulate an EINTR in case OpenSSL wants to write more. */
        xerrno = EINTR;
        break;

      default:
        tls_fatal(err, lineno);
        break;
    }
  }

  if (nstrm_type == PR_NETIO_STRM_DATA) {
    BIO *wbio;
    uint64_t *adaptive_bytes_written_ms = NULL, now;
    off_t *adaptive_bytes_written_count = NULL;
    const void *v;

    v = pr_table_get(notes, PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY, NULL);
    if (v != NULL) {
      adaptive_bytes_written_count = (off_t *) v;
    }

    v = pr_table_get(notes, PROXY_TLS_ADAPTIVE_BYTES_MS_KEY, NULL);
    if (v != NULL) {
      adaptive_bytes_written_ms = (uint64_t *) v;
    }

    (void) pr_gettimeofday_millis(&now);

    wbio = SSL_get_wbio(ssl);

    if (adaptive_bytes_written_count != NULL) {
      (*adaptive_bytes_written_count) += count;

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
  }

  errno = xerrno;
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

static int cert_match_wildcard(pool *p, const char *host_name,
    const char *cert_name, size_t cert_namelen) {
  register unsigned int i;
  char *ptr, *ptr2;
  unsigned int host_label_count = 1, cert_label_count = 1;
  int res;
  size_t host_namelen;

  /* To be a valid wildcard pattern, we need a '*', a '.', and a top-level
   * domain.  Thus if the length is less than 4 characters, it CANNOT be
   * a wildcard match.
   */
  if (cert_namelen < 4) {
    return FALSE;
  }

  /* If no '.', FALSE. */
  ptr = strchr(cert_name, '.');
  if (ptr == NULL) {
    return FALSE;
  }

  /* If no '*', FALSE. */
  ptr2 = strchr(cert_name, '*');
  if (ptr2 == NULL) {
    return FALSE;
  }

  /* If more than one '*', FALSE. */
  if (strchr(ptr2 + 1, '*') != NULL) {
    pr_trace_msg(trace_channel, 17,
      "multiple '*' characters found in '%s', unable to use for wildcard "
      "matching", cert_name);
    return FALSE;
  }

  /* If not in leftmost label, FALSE. */
  if (ptr2 > ptr) {
    pr_trace_msg(trace_channel, 17,
      "wildcard character in '%s' is NOT in the leftmost label", cert_name);
    return FALSE;
  }

  /* If not the same number of labels, FALSE */
  host_namelen = strlen(host_name);
  for (i = 0; i < host_namelen; i++) {
    if (host_name[i] == '.') {
      host_label_count++;
    }
  }

  for (i = 0; i < cert_namelen; i++) {
    if (cert_name[i] == '.') {
      cert_label_count++;
    }
  }

  if (host_label_count != cert_label_count) {
    pr_trace_msg(trace_channel, 17,
      "cert name '%s' label count (%d) does not match host name '%s' "
      "label count (%d)", cert_name,
      cert_label_count, host_name, host_label_count);
    return FALSE;
  }

  res = pr_fnmatch(cert_name, host_name, PR_FNM_NOESCAPE);
  if (res == 0) {
    return TRUE;
  }

  pr_trace_msg(trace_channel, 17,
    "certificate name with wildcard '%s' did not match host name '%s'",
    cert_name, host_name);
  return FALSE;
}

static int cert_match_dns_san(pool *p, X509 *cert, const char *dns_name,
    int allow_wildcards) {
  int matched = FALSE;
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  STACK_OF(GENERAL_NAME) *sans;

  sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (sans != NULL) {
    register int i;
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

        if ((size_t) ASN1_STRING_length(alt_name->d.ia5) != dns_sanlen) {
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
          matched = TRUE;

        } else {
          if (allow_wildcards) {
            matched = cert_match_wildcard(p, dns_name, dns_san, dns_sanlen);
          }
        }

        if (matched == FALSE) {
          pr_trace_msg(trace_channel, 9,
            "cert dNSName SAN '%s' did not match '%s'", dns_san, dns_name);
        }
      }

      GENERAL_NAME_free(alt_name);

      if (matched == TRUE) {
        break;
      }
    }

    sk_GENERAL_NAME_free(sans);
  }
#endif /* OpenSSL-0.9.7 or later */

  return matched;
}

static int cert_match_ip_san(pool *p, X509 *cert, const char *ipstr) {
  int matched = FALSE;
  STACK_OF(GENERAL_NAME) *sans;

  sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (sans != NULL) {
    register int i;
    int nsans = sk_GENERAL_NAME_num(sans);

    for (i = 0; i < nsans; i++) {
      GENERAL_NAME *alt_name = sk_GENERAL_NAME_value(sans, i);

      if (alt_name->type == GEN_IPADD) {
        unsigned char *san_data = NULL;
        int have_ipstr = FALSE, san_datalen;
#if defined(PR_USE_IPV6)
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

#if defined(PR_USE_IPV6)
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
            matched = TRUE;

          } else {
            if (san_datalen == 16) {
              /* We need to handle the case where the iPAddress SAN might
               * have contained an IPv4-mapped IPv6 address, and we're
               * comparing against an IPv4 address.
               */
              if (san_ipstrlen > 7 &&
                  strncasecmp(san_ipstr, "::ffff:", 7) == 0) {
                if (strncmp(ipstr, san_ipstr + 7, san_ipstrlen - 6) == 0) {
                  pr_trace_msg(trace_channel, 8,
                    "found cert iPAddress SAN '%s' matching '%s'",
                    san_ipstr, ipstr);
                    matched = TRUE;
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

      if (matched == TRUE) {
        break;
      }
    }

    sk_GENERAL_NAME_free(sans);
  }

  return matched;
}

static int cert_match_cn(pool *p, X509 *cert, const char *name,
    int allow_wildcards) {
  int matched = FALSE, idx = -1;
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
      "no CommonName attribute found", name);
    return 0;
  }

  cn_entry = X509_NAME_get_entry(subj_name, idx);
  if (cn_entry == NULL) {
    pr_trace_msg(trace_channel, 12,
      "unable to check certificate CommonName against '%s': "
      "error obtaining CommonName attribute found: %s", name,
      proxy_tls_get_errors());
    return 0;
  }

  /* Convert the CN field to a string, by way of an ASN1 object. */
  cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
  if (cn_asn1 == NULL) {
    pr_trace_msg(trace_channel, 12,
      "unable to check certificate CommonName against '%s': "
      "error converting CommonName attribute to ASN.1: %s", name,
      proxy_tls_get_errors());
    return 0;
  }

  cn_str = (char *) ASN1_STRING_data(cn_asn1);

  /* Check for CommonName values which contain embedded NULs.  This can cause
   * verification problems (spoofing), e.g. if the string is
   * "www.goodguy.com\0www.badguy.com"; the use of strcmp() only checks
   * "www.goodguy.com".
   */

  cn_len = strlen(cn_str);

  if ((size_t) ASN1_STRING_length(cn_asn1) != cn_len) {
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
    pr_trace_msg(trace_channel, 12, "cert CommonName '%s' matches '%s'", cn_str,
      name);
    matched = TRUE;

  } else {
    if (allow_wildcards) {
       matched = cert_match_wildcard(p, name, cn_str, cn_len);
    }
  }

  if (matched == FALSE) {
    pr_trace_msg(trace_channel, 12, "cert CommonName '%s' does NOT match '%s'",
      cn_str, name);
  }

  return matched;
}

static int check_server_cert(SSL *ssl, conn_t *conn, const char *host_name) {
  X509 *cert = NULL;
  int ok = -1;
  long verify_result;

  /* Only perform these more stringent checks if asked to verify servers. */
  if (tls_verify_server == FALSE) {
    return 0;
  }

  /* Check SSL_get_verify_result. */
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

# if defined(PSK_MAX_PSK_LEN)
    if (tls_psk_used) {
      return 0;
    }
# endif /* PSK support */

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

  if (ok == 0) {
    ok = cert_match_dns_san(conn->pool, cert, host_name, TRUE);
    if (ok == 0) {
      ok = cert_match_cn(conn->pool, cert, host_name, TRUE);
    }
  }

  X509_free(cert);
  return ok;
}

static void stash_stream_ssl(pr_netio_stream_t *nstrm, SSL *ssl) {
  if (pr_table_add(nstrm->notes,
      pstrdup(nstrm->strm_pool, PROXY_TLS_NETIO_NOTE), ssl,
      sizeof(SSL *)) < 0) {
    if (errno != EEXIST) {
      pr_trace_msg(trace_channel, 4,
        "error stashing '%s' note on %s %s stream: %s",
        PROXY_TLS_NETIO_NOTE,
        nstrm->strm_type == PR_NETIO_STRM_CTRL ? "control" : "data",
        nstrm->strm_mode == PR_NETIO_IO_RD ? "read" : "write",
        strerror(errno));
    }
  }
}

static int tls_verify_cb(int ok, X509_STORE_CTX *ctx) {
  X509 *cert;

  cert = X509_STORE_CTX_get_current_cert(ctx);

  if (!ok) {
    int verify_depth, verify_error;

    verify_depth = X509_STORE_CTX_get_error_depth(ctx);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error: unable to verify server certificate at depth %d",
      verify_depth);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error: cert subject: %s",
      tls_x509_name_oneline(X509_get_subject_name(cert)));
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error: cert issuer: %s",
      tls_x509_name_oneline(X509_get_issuer_name(cert)));

    /* Catch a too long certificate chain here. */
    if (verify_depth > PROXY_TLS_VERIFY_DEPTH) {
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    verify_error = X509_STORE_CTX_get_error(ctx);
#else
    verify_error = ctx->error;
#endif /* OpenSSL-1.1.x and later */
    switch (verify_error) {
      case X509_V_ERR_CERT_CHAIN_TOO_LONG:
      case X509_V_ERR_CERT_NOT_YET_VALID:
      case X509_V_ERR_CERT_HAS_EXPIRED:
      case X509_V_ERR_CERT_REVOKED:
      case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
      case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
      case X509_V_ERR_APPLICATION_VERIFICATION:
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "server certificate failed verification: %s",
          X509_verify_cert_error_string(verify_error));
        ok = 0;
        break;

      case X509_V_ERR_INVALID_PURPOSE: {
        register int i;
        int count = X509_PURPOSE_get_count();

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "server certificate failed verification: %s",
          X509_verify_cert_error_string(verify_error));

        for (i = 0; i < count; i++) {
          X509_PURPOSE *purp = X509_PURPOSE_get0(i);
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "  purpose #%d: %s", i+1, X509_PURPOSE_get0_name(purp));
        }

        ok = 0;
        break;
      }

      default:
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error verifying server certificate: [%d] %s",
          verify_error, X509_verify_cert_error_string(verify_error));
        ok = 0;
        break;
    }

    if (tls_verify_server == FALSE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "ProxyTLSVerifyServer off, ignoring failed certificate verification");
      ok = 1;
    }
  } else {
    if (tls_opts & PROXY_TLS_OPT_ENABLE_DIAGS) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.verify]: cert subject: %s",
        tls_x509_name_oneline(X509_get_subject_name(cert)));
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.verify]: cert issuer: %s",
        tls_x509_name_oneline(X509_get_issuer_name(cert)));
    }
  }

  return ok;
}

static int tls_get_cached_sess(pool *p, SSL *ssl, const char *host, int port) {
  char port_str[32], *sess_key = NULL;
  SSL_SESSION *sess = NULL;

  if (tls_opts & PROXY_TLS_OPT_NO_SESSION_CACHE) {
    if (tls_opts & PROXY_TLS_OPT_NO_SESSION_TICKETS) {
      pr_trace_msg(trace_channel, 19,
        "NoSessionCache and NoSessionTickets ProxyTLSOptions in effect, "
        "not using cached SSL sessions");
      SSL_set_options(ssl, SSL_OP_NO_TICKET);
      return 0;
    }
  }

  memset(port_str, '\0', sizeof(port_str));
  snprintf(port_str, sizeof(port_str)-1, "%d", port);
  sess_key = pstrcat(p, "ftp://", host, ":", port_str, NULL);

  pr_trace_msg(trace_channel, 19,
    "looking for cached SSL session using key '%s'", sess_key);

  sess = (tls_ds.get_sess)(p, tls_ds.dsh, sess_key);
  if (sess != NULL) {
    long sess_age;
    time_t now;

    now = time(NULL);
    sess_age = now - SSL_SESSION_get_time(sess);

    if (sess_age >= PROXY_TLS_MAX_SESSION_AGE) {
      pr_trace_msg(trace_channel, 9, "cached SSL session expired, removing");
      (void) (tls_ds.remove_sess)(p, tls_ds.dsh, sess_key);

      SSL_SESSION_free(sess);
      errno = ENOENT;
      sess = NULL;
    }
  }

  if (sess == NULL) {
    if (errno == ENOENT) {
      pr_trace_msg(trace_channel, 19,
        "no cached sessions found for key '%s'", sess_key);

    } else {
      pr_trace_msg(trace_channel, 9,
        "error getting cached session using key '%s': %s", sess_key,
        strerror(errno));
    }

    return 0;
  }

  pr_trace_msg(trace_channel, 12,
    "found cached SSL session using key '%s'", sess_key);
  SSL_set_session(ssl, sess);
  SSL_SESSION_free(sess);

  return 0;
}

static int tls_add_cached_sess(pool *p, SSL *ssl, const char *host, int port) {
  char port_str[32], *sess_key = NULL;
  SSL_SESSION *sess = NULL;
  int res, sess_count, xerrno = 0;
  time_t now, sess_age;

  if (tls_opts & PROXY_TLS_OPT_NO_SESSION_CACHE) {
    if (tls_opts & PROXY_TLS_OPT_NO_SESSION_TICKETS) {
      pr_trace_msg(trace_channel, 19,
        "NoSessionCache and NoSessionTickets ProxyTLSOptions in effect, "
        "not caching SSL sessions");
      return 0;
    }
  }

  sess_count = (tls_ds.count_sess)(p, tls_ds.dsh);
  if (sess_count < 0) {
    return -1;
  }

  if (sess_count >= PROXY_TLS_MAX_SESSION_COUNT) {
    pr_trace_msg(trace_channel, 14,
      "Maximum number of cached sessions (%d) reached, not caching SSL session",
      PROXY_TLS_MAX_SESSION_COUNT);
    return 0;
  }

  sess = SSL_get1_session(ssl);

  /* If this session is already past our expiration policy, ignore it. */
  now = time(NULL);
  sess_age = now - SSL_SESSION_get_time(sess);
  if (sess_age >= PROXY_TLS_MAX_SESSION_AGE) {
    pr_trace_msg(trace_channel, 9,
      "SSL session has already expired, not caching");
    SSL_SESSION_free(sess);
    return 0;
  }

  memset(port_str, '\0', sizeof(port_str));
  snprintf(port_str, sizeof(port_str)-1, "%d", port);
  sess_key = pstrcat(p, "ftp://", host, ":", port_str, NULL);

  pr_trace_msg(trace_channel, 19,
    "caching SSL session using key '%s'", sess_key);

  res = (tls_ds.add_sess)(p, tls_ds.dsh, sess_key, sess);
  xerrno = errno;
  SSL_SESSION_free(sess);

  if (res < 0) {
    pr_trace_msg(trace_channel, 9,
      "error storing cached SSL session using key '%s': %s", sess_key,
      strerror(xerrno));

  } else {
    pr_trace_msg(trace_channel, 19,
      "successfully cached SSL session using key '%s'", sess_key);
  }

  return 0;
}

static int tls_connect(conn_t *conn, const char *host_name,
    pr_netio_stream_t *nstrm) {
  int blocking, res = 0, xerrno = 0;
  char *subj = NULL;
  SSL *ssl = NULL;
  BIO *rbio = NULL, *wbio = NULL;

  if (ssl_ctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to start session: null SSL_CTX");
    errno = EPERM;
    return -1;
  }

  ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error: unable to allocate SSL session: %s", proxy_tls_get_errors());
    return -2;
  }

  SSL_set_verify(ssl, SSL_VERIFY_PEER, tls_verify_cb);

  /* This works with either rfd or wfd (I hope). */
  rbio = BIO_new_socket(conn->rfd, FALSE);
  wbio = BIO_new_socket(conn->rfd, FALSE);
  SSL_set_bio(ssl, rbio, wbio);

#if !defined(OPENSSL_NO_TLSEXT)
  SSL_set_tlsext_debug_callback(ssl, tls_tlsext_cb);

  /* We should be a well-behaved TLS client, and NOT send an SNI value
   * that is an IP address.  Per RFC 6066, literal IPv4/IPv6 addresses are NOT
   * permitted in the SNI.
   */
  if (pr_netaddr_is_v4(host_name) != TRUE &&
      pr_netaddr_is_v6(host_name) != TRUE) {
    pr_trace_msg(trace_channel, 9, "sending SNI '%s'", host_name);
    SSL_set_tlsext_host_name(ssl, host_name);

  } else {
    pr_trace_msg(trace_channel, 9, "skipping sending of IP address SNI '%s'",
      host_name);
  }

# if defined(TLSEXT_STATUSTYPE_ocsp)
  pr_trace_msg(trace_channel, 9, "requesting stapled OCSP response");
  SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
# endif /* OCSP support */
#endif /* OPENSSL_NO_TLSEXT */

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {

    /* If we're opening a data connection, reuse the SSL data from the
     * session on the control connection (including any session IDs and/or
     * tickets).
     */
    SSL_copy_session_id(ssl, tls_ctrl_ssl);

  } else if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
    tls_get_cached_sess(nstrm->strm_pool, ssl, host_name, conn->remote_port);

# if !defined(PROXY_TLS_USE_SESSION_TICKETS)
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
# endif /* Session ticket support */
  }

  /* If configured, set a timer for the handshake. */
  if (handshake_timeout) {
    handshake_timer_id = pr_timer_add(handshake_timeout, -1,
      &proxy_module, handshake_timeout_cb, "SSL/TLS handshake");
  }

  /* Make sure that TCP_NODELAY is enabled for the handshake. */
  (void) pr_inet_set_proto_nodelay(conn->pool, conn, 1);

  /* Make sure that TCP_CORK (aka TCP_NOPUSH) is DISABLED for the handshake. */
  if (pr_inet_set_proto_cork(conn->wfd, 0) < 0) {
    pr_trace_msg(trace_channel, 9,
      "error disabling TCP_CORK on %s conn: %s",
       nstrm->strm_type == PR_NETIO_STRM_CTRL ? "control" : "data",
       strerror(errno));
  }

  connect_retry:

  blocking = tls_get_block(conn);
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
    const char *msg = "unable to connect using TLS";
    int errcode, shutdown_ssl;

    errcode = SSL_get_error(ssl, res);
    shutdown_ssl = TRUE;

    pr_signals_handle();

    if (handshake_timed_out) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "TLS negotiation timed out (%u seconds)", handshake_timeout);
      tls_end_sess(ssl, nstrm->strm_type, 0);
      return -4;
    }

    switch (errcode) {
      case SSL_ERROR_WANT_READ:
        pr_trace_msg(trace_channel, 17,
          "WANT_READ encountered while connecting on fd %d, "
          "waiting to read data", conn->rfd);
        tls_readmore(conn->rfd);
        goto connect_retry;

      case SSL_ERROR_WANT_WRITE:
        pr_trace_msg(trace_channel, 17,
          "WANT_WRITE encountered while connecting on fd %d, "
          "waiting to read data", conn->rfd);
        tls_writemore(conn->rfd);
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
            "%s: system call error: %s", msg, proxy_tls_get_errors());
        }

        shutdown_ssl = FALSE;
        break;
      }

      case SSL_ERROR_SSL:
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "%s: protocol error: %s", msg, proxy_tls_get_errors());
        shutdown_ssl = FALSE;
        break;
    }

    if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
      pr_event_generate("mod_proxy.tls-ctrl-handshake-failed", &errcode);

    } else if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
      pr_event_generate("mod_proxy.tls-data-handshake-failed", &errcode);
    }

    if (shutdown_ssl == TRUE) {
      tls_end_sess(ssl, nstrm->strm_type, 0);
    }

    return -3;
  }

  /* Disable the handshake timer. */
  pr_timer_remove(handshake_timer_id, &proxy_module);

  /* Disable TCP_NODELAY, now that the handshake is done. */
  (void) pr_inet_set_proto_nodelay(conn->pool, conn, 0);

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    /* Re-enable TCP_CORK (aka TCP_NOPUSH), now that the handshake is done. */
    if (pr_inet_set_proto_cork(conn->wfd, 1) < 0) {
      pr_trace_msg(trace_channel, 9,
        "error re-enabling TCP_CORK on data conn: %s", strerror(errno));
    }

  } else if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
    int reused;

    /* Only try to cache the new SSL session if we actually did create a
     * new session.  Otherwise, leave the previously cached session as is.
     */
    reused = SSL_session_reused(ssl);
    if (reused == 0) {
      tls_add_cached_sess(nstrm->strm_pool, ssl, host_name, conn->remote_port);
    }
  }

  /* Manually update the raw bytes counters with the network IO from the
   * SSL handshake.
   */
  session.total_raw_in += (BIO_number_read(rbio) +
    BIO_number_read(wbio));
  session.total_raw_out += (BIO_number_written(rbio) +
    BIO_number_written(wbio));

  /* Stash the SSL pointer in BOTH input and output streams for this
   * connection.
   */
  stash_stream_ssl(conn->instrm, ssl);
  stash_stream_ssl(conn->outstrm, ssl);

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
    tls_ctrl_ssl = ssl;
  }

  subj = tls_get_subj_name(ssl);
  if (subj != NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "Server: %s", subj);
  }

  if (check_server_cert(ssl, conn, host_name) < 0) {
    tls_end_sess(ssl, nstrm->strm_type, 0);
    return -1;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "%s connection created, using cipher %s (%d bits)",
    SSL_get_version(ssl), SSL_get_cipher_name(ssl),
    SSL_get_cipher_bits(ssl, NULL));

  return 0;
}

static int tls_seed_prng(void) {
  char *heapdata, stackdata[1024];
  FILE *fp = NULL;
  pid_t pid;
  struct timeval tv;

#if OPENSSL_VERSION_NUMBER >= 0x00905100L
  if (RAND_status() == 1) {
    /* PRNG already well-seeded. */
    return 0;
  }
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

  ssl = (SSL *) pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
  if (ssl != NULL) {
    if (nstrm->strm_type == PR_NETIO_STRM_CTRL &&
        nstrm->strm_mode == PR_NETIO_IO_WR) {
      const struct proxy_session *proxy_sess;
      const char *host_name;
      int remote_port;

      proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
      if (proxy_sess == NULL) {
        /* Unlikely to occur. */
        pr_trace_msg(trace_channel, 1, "missing proxy session unexpectedly");
        errno = EINVAL;
        return -1;
      }

      host_name = proxy_conn_get_host(proxy_sess->dst_pconn);
      remote_port = proxy_conn_get_port(proxy_sess->dst_pconn);

      /* Cache the SSL session here, as it may have changed (e.g. due to
       * renegotiations) during the lifetime of the control connection.
       */
      tls_add_cached_sess(nstrm->strm_pool, ssl, host_name, remote_port);

      pr_table_remove(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
      tls_end_sess(ssl, nstrm->strm_type, 0);
      proxy_sess_state &= ~PROXY_SESS_STATE_BACKEND_HAS_CTRL_TLS;
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

  /* If this stream is for writing, and TLS is wanted/required, then perform
   * a TLS handshake.
   */

  if (tls_engine == PROXY_TLS_ENGINE_OFF) {
    return 0;
  }

  if (nstrm->strm_mode == PR_NETIO_IO_WR) {
    const struct proxy_session *proxy_sess;
    uint64_t *adaptive_ms = NULL, start_ms;
    off_t *adaptive_bytes = NULL;
    conn_t *conn = NULL;
    const char *host_name;

    if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
      if (tls_need_data_prot == FALSE) {
        pr_trace_msg(trace_channel, 17,
          "data connection does not require SSL/TLS, skipping handshake");
        return 0;
      }

      /* This callback may be invoked by `pr_netio_postopen` for a frontend
       * data conn, as when we already have a backend data conn using TLS
       * already established.
       *
       * This happens when the frontend is NOT using TLS, and is using passive
       * data transfers, but the backed IS using TLS, and is using active
       * data transfers.
       *
       * NOTE: This is still a bug; mod_proxy is calling pr_netio_postopen(),
       * which should not be invoking this callback.
       */
      if (proxy_sess_state & PROXY_SESS_STATE_BACKEND_HAS_DATA_TLS) {
        pr_trace_msg(trace_channel, 27,
          "data connection already using SSL/TLS, skipping handshake");
        return 0;
      }
    }

    proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
    if (proxy_sess == NULL) {
      /* Unlikely to occur. */
      pr_trace_msg(trace_channel, 1, "missing proxy session unexpectedly");
      errno = EINVAL;
      return -1;
    }

    /* TODO: Handle SSCN_MODE CLIENT (connect), SERVER (accept) */

    pr_gettimeofday_millis(&start_ms);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "starting TLS negotiation on %s connection",
      nstrm->strm_type == PR_NETIO_STRM_CTRL ? "control" : "data");

    if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
      conn = proxy_sess->backend_ctrl_conn;

    } else {
      conn = proxy_sess->backend_data_conn;
    }

    host_name = proxy_conn_get_host(proxy_sess->dst_pconn);
    if (tls_connect(conn, host_name, nstrm) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to open %s connection to %s: TLS negotiation failed",
        nstrm->strm_type == PR_NETIO_STRM_CTRL ? "control" : "data", host_name);
      errno = EPERM;
      return -1;
    }

    if (pr_trace_get_level(timing_channel) >= 4) {
      unsigned long elapsed_ms;
      uint64_t finish_ms;

      pr_gettimeofday_millis(&finish_ms);
      elapsed_ms = (unsigned long) (finish_ms - start_ms);

      pr_trace_msg(timing_channel, 4,
        "TLS %s handshake duration: %lu ms",
        nstrm->strm_type == PR_NETIO_STRM_CTRL ? "control" : "data",
        elapsed_ms);
    }

    adaptive_ms = pcalloc(nstrm->strm_pool, sizeof(uint64_t));
    if (pr_table_add(nstrm->notes, PROXY_TLS_ADAPTIVE_BYTES_MS_KEY,
        adaptive_ms, sizeof(uint64_t)) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error stashing '%s' stream note: %s", PROXY_TLS_ADAPTIVE_BYTES_MS_KEY,
        strerror(errno));
    }

    adaptive_bytes = pcalloc(nstrm->strm_pool, sizeof(off_t));
    if (pr_table_add(nstrm->notes, PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY,
        adaptive_bytes, sizeof(off_t)) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error stashing '%s' stream note: %s",
        PROXY_TLS_ADAPTIVE_BYTES_COUNT_KEY, strerror(errno));
    }

    if (netio_install_data() < 0) {
      pr_trace_msg(trace_channel, 1,
        "error installing data connection NetIO: %s", strerror(errno));
    }

    if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
      proxy_sess_state |= PROXY_SESS_STATE_BACKEND_HAS_CTRL_TLS;

    } else if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
      proxy_sess_state |= PROXY_SESS_STATE_BACKEND_HAS_DATA_TLS;
    }
  }

  return 0;
}

static int netio_read_cb(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  SSL *ssl = NULL;

  ssl = (SSL *) pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
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

    res = tls_read(ssl, buf, buflen, nstrm->strm_type, nstrm->notes);

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

      /* If we do not have TLS on this connection, then don't try to do
       * a TLS shutdown.
       */
      if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
        if (!(proxy_sess_state & PROXY_SESS_STATE_BACKEND_HAS_CTRL_TLS)) {
          return shutdown(nstrm->strm_fd, how);
        }

      } else if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
        if (!(proxy_sess_state & PROXY_SESS_STATE_BACKEND_HAS_DATA_TLS)) {
          return shutdown(nstrm->strm_fd, how);
        }
      }

      ssl = (SSL *) pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
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

        if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
          proxy_sess_state &= ~PROXY_SESS_STATE_BACKEND_HAS_DATA_TLS;
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

  ssl = (SSL *) pr_table_get(nstrm->notes, PROXY_TLS_NETIO_NOTE, NULL);
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

    res = tls_write(ssl, buf, buflen, nstrm->strm_type, nstrm->notes);

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
     * in order to have %O be accurately represented for the raw traffic.
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

  if (tls_ctrl_netio != NULL) {
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

  if (proxy_netio_use(PR_NETIO_STRM_CTRL, netio) < 0) {
    return -1;
  }

  tls_ctrl_netio = netio;
  return 0;
}

static int netio_install_data(void) {
  pr_netio_t *netio;

  if (tls_data_netio != NULL) {
    pr_netio_t *using_netio = NULL;

    if (proxy_netio_using(PR_NETIO_STRM_DATA, &using_netio) == 0) {
      if (using_netio == NULL) {
        if (proxy_netio_use(PR_NETIO_STRM_DATA, tls_data_netio) < 0) {
          return -1;
        }
      }
    }

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

  if (proxy_netio_use(PR_NETIO_STRM_DATA, netio) < 0) {
    return -1;
  }

  tls_data_netio = netio;
  return 0;
}

/* Initialization routines */

#if defined(PSK_MAX_PSK_LEN)
static unsigned int tls_psk_cb(SSL *ssl, const char *psk_hint, char *identity,
    unsigned int max_identity_len,
    unsigned char *psk, unsigned int max_psklen) {
  int res, bn_len;
  unsigned int psklen;

  if (psk_hint != NULL) {
    pr_trace_msg(trace_channel, 7, "received PSK identity hint: '%s'",
      psk_hint);

  } else {
    pr_trace_msg(trace_channel, 17, "received no PSK identity hint");
  }

  res = snprintf(identity, max_identity_len, "%s", tls_psk_name);
  if (res < 0 ||
      res > (int) max_identity_len) {
    pr_trace_msg(trace_channel, 6,
      "error setting PSK identity to '%s'", tls_psk_name);
    return 0;
  }

  bn_len = BN_num_bytes(tls_psk_bn);
  if (bn_len > (int) max_psklen) {
    pr_trace_msg(trace_channel, 6,
      "warning: unable to use '%s' PSK: max buffer size (%u bytes) "
      "too small for key (%d bytes)", tls_psk_name, max_psklen,
      bn_len);
    return 0;
  }

  psklen = BN_bn2bin(tls_psk_bn, psk);
  if (psklen == 0) {
    pr_trace_msg(trace_channel, 6,
      "error converting '%s' PSK to binary: %s", tls_psk_name,
      proxy_tls_get_errors());
    return 0;
  }

  if (tls_opts & PROXY_TLS_OPT_ENABLE_DIAGS) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.psk] used PSK identity '%s'", tls_psk_name);
  }

  tls_psk_used = TRUE;
  return psklen;
}
#endif /* PSK support */

#if !defined(OPENSSL_NO_TLSEXT) && defined(TLSEXT_STATUSTYPE_ocsp)
/* TODO: Do more than just log the received stapled OCSP response. */
static int tls_ocsp_response_cb(SSL *ssl, void *user_data) {
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const unsigned char *ptr;
  int len, res = 1;

  bio = BIO_new(BIO_s_mem());

  len = SSL_get_tlsext_status_ocsp_resp(ssl, &ptr);
  BIO_puts(bio, "OCSP response: ");
  if (ptr == NULL) {
    BIO_puts(bio, "no response sent\n");

  } else {
    OCSP_RESPONSE *resp;

    resp = d2i_OCSP_RESPONSE(NULL, &ptr, len);
    if (resp == NULL) {
      BIO_puts(bio, "response parse error\n");
      BIO_dump_indent(bio, (char *) ptr, len, 4);
      res = 0;

    } else {
      BIO_puts(bio, "\n======================================\n");
      OCSP_RESPONSE_print(bio, resp, 0);
      BIO_puts(bio, "======================================\n");
      OCSP_RESPONSE_free(resp);
    }
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
  }

  pr_trace_msg(trace_channel, 1, "%s", "stapled OCSP response:");
  pr_trace_msg(trace_channel, 1, "%s", data);

  BIO_free(bio);
  return res;
}
#endif /* OCSP support */

#if !defined(OPENSSL_NO_TLSEXT)
struct proxy_tls_next_proto {
  const char *proto;
  unsigned char *encoded_proto;
  unsigned int encoded_protolen;
};

#if defined(PR_USE_OPENSSL_NPN)
static int tls_npn_cb(SSL *ssl,
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
        " %.*s", (int) npn_in[i], (char *) &(npn_in[i+1]));
      i += npn_in[i];
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
#endif /* PR_USE_OPENSSL_NPN */

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
  SSL_CTX_set_next_proto_select_cb(ctx, tls_npn_cb, next_proto);
# endif /* NPN */

# if defined(PR_USE_OPENSSL_ALPN)
  SSL_CTX_set_alpn_protos(ctx, next_proto->encoded_proto,
    next_proto->encoded_protolen);
# endif /* ALPN */

  return 0;
}
#endif /* OPENSSL_NO_TLSEXT */

static int init_ssl_ctx(void) {
  long ssl_mode = 0;
  int ssl_opts = tls_ssl_opts;

  if (ssl_ctx != NULL) {
    SSL_CTX_free(ssl_ctx);
    ssl_ctx = NULL;
  }

  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (ssl_ctx == NULL) {
    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error creating SSL_CTX: %s", proxy_tls_get_errors());
    errno = EPERM;
    return -1;
  }

  /* Note that we explicitly do NOT use OpenSSL's internal cache for
   * client session caching; we'll use our own.
   */
  SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);

#if OPENSSL_VERSION_NUMBER > 0x000906000L
  /* The SSL_MODE_AUTO_RETRY mode was added in 0.9.6. */
  ssl_mode |= SSL_MODE_AUTO_RETRY;
#endif

#if OPENSSL_VERSION_NUMBER >= 0x1000001fL
  /* The SSL_MODE_RELEASE_BUFFERS mode was added in 1.0.0a. */
  ssl_mode |= SSL_MODE_RELEASE_BUFFERS;
#endif

  if (ssl_mode != 0) {
    SSL_CTX_set_mode(ssl_ctx, ssl_mode);
  }

  /* If using OpenSSL-0.9.7 or greater, prevent session resumptions on
   * renegotiations (more secure).
   */
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  ssl_opts |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#endif

  /* Disable SSL compression. */
#if defined(SSL_OP_NO_COMPRESSION)
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

  SSL_CTX_set_options(ssl_ctx, ssl_opts);

#if !defined(OPENSSL_NO_TLSEXT)
  if (set_next_protocol(ssl_ctx) < 0) {
    pr_trace_msg(trace_channel, 4,
      "error setting TLS next protocol: %s", strerror(errno));
  }
#endif /* OPENSSL_NO_TLSEXT */

  if (tls_seed_prng() < 0) {
    pr_log_debug(DEBUG1, MOD_PROXY_VERSION ": unable to properly seed PRNG");
  }

  return 0;
}

/* Event listeners */

static void proxy_tls_shutdown_ev(const void *event_data, void *user_data) {
  RAND_cleanup();
}
#endif /* PR_USE_OPENSSL */

int proxy_tls_set_data_prot(int data_prot) {
  int old_data_prot;

#if defined(PR_USE_OPENSSL)
  old_data_prot = tls_need_data_prot;
  tls_need_data_prot = data_prot;
#else
  old_data_prot = FALSE;
#endif /* PR_USE_OPENSSL */

  return old_data_prot;
}

int proxy_tls_set_tls(int engine) {
#if defined(PR_USE_OPENSSL)
  if (engine != PROXY_TLS_ENGINE_ON &&
      engine != PROXY_TLS_ENGINE_OFF &&
      engine != PROXY_TLS_ENGINE_AUTO &&
      engine != PROXY_TLS_ENGINE_IMPLICIT) {
    errno = EINVAL;
    return -1;
  }

  tls_engine = engine;
#endif /* PR_USE_OPENSSL */

  return 0;
}

int proxy_tls_using_tls(void) {
#if defined(PR_USE_OPENSSL)
  return tls_engine;
#else
  return PROXY_TLS_ENGINE_OFF;
#endif /* PR_USE_OPENSSL */
}

int proxy_tls_match_client_tls(void) {
  int client_using_tls = FALSE, res = 0;

  /* Is the client using TLS right now? */
  if (session.rfc2228_mech != NULL &&
      strcasecmp(session.rfc2228_mech, "TLS") == 0) {
    client_using_tls = TRUE;
  }

  if (client_using_tls == TRUE) {
    int client_using_implicit_ftps = FALSE;
    config_rec *c;
    unsigned long mod_tls_opts = 0UL;

    /* Is the client using implicit FTPS? */
    c = find_config(main_server->conf, CONF_PARAM, "TLSOptions", FALSE);
    while (c != NULL) {
      unsigned long opts;

      pr_signals_handle();

      opts = *((unsigned long *) c->argv[0]);
      mod_tls_opts |= opts;

      c = find_config_next(c, c->next, CONF_PARAM, "TLSOptions", FALSE);
    }

    /* We cheat, and duplicate/check for the UseImplicitTLS TLSOption
     * (TLS_OPT_USE_IMPLICIT_SSL) from the mod_tls.c implementation.
     */
    if (mod_tls_opts & 0x0200) {
      client_using_implicit_ftps = TRUE;
    }

    if (client_using_implicit_ftps == TRUE) {
      pr_trace_msg(trace_channel, 17,
        "setting implicit FTPS due to ProxyTLSEngine MatchClient");
      res = proxy_tls_set_tls(PROXY_TLS_ENGINE_IMPLICIT);

    } else {
      /* Using explicit FTPS. */
      pr_trace_msg(trace_channel, 17,
        "setting explicit FTPS due to ProxyTLSEngine MatchClient");
      res = proxy_tls_set_tls(PROXY_TLS_ENGINE_ON);
    }

  } else {
    pr_trace_msg(trace_channel, 17,
      "disabling FTPS due to ProxyTLSEngine MatchClient");
    res = proxy_tls_set_tls(PROXY_TLS_ENGINE_OFF);
  }

  return res;
}

int proxy_tls_init(pool *p, const char *tables_path, int flags) {
#if defined(PR_USE_OPENSSL)
  int res;

  memset(&tls_ds, 0, sizeof(tls_ds));

  switch (proxy_datastore) {
    case PROXY_DATASTORE_SQLITE:
      res = proxy_tls_db_as_datastore(&tls_ds, proxy_datastore_data,
        proxy_datastore_datasz);
      break;

    case PROXY_DATASTORE_REDIS:
      res = proxy_tls_redis_as_datastore(&tls_ds, proxy_datastore_data,
        proxy_datastore_datasz);
      break;

    default:
      res = -1;
      errno = EINVAL;
      break;
  }

  if (res < 0) {
    return -1;
  }

  res = (tls_ds.init)(p, tables_path, flags);
  if (res < 0) {
    return -1;
  }

  if (pr_module_exists("mod_sftp.c") == FALSE &&
      pr_module_exists("mod_tls.c") == FALSE) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OPENSSL_config(NULL);
#endif /* prior to OpenSSL-1.1.x */
    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
  }

  res = init_ssl_ctx();
  if (res < 0) {
    return -1;
  }

  tls_tables_path = pstrdup(proxy_pool, tables_path);

  pr_event_register(&proxy_module, "core.shutdown", proxy_tls_shutdown_ev,
    NULL);
#endif /* PR_USE_OPENSSL */

  return 0;
}

int proxy_tls_free(pool *p) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(PR_USE_OPENSSL)
  if (ssl_ctx != NULL) {
    SSL_CTX_free(ssl_ctx);
    ssl_ctx = NULL;
  }

  if (tls_ds.dsh != NULL) {
    int res;

    res = (tls_ds.close)(p, tls_ds.dsh);
    if (res < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error closing datastore: %s", strerror(errno));
    }

    tls_ds.dsh = NULL;
  }
#endif /* PR_USE_OPENSSL */

  return 0;
}

#if defined(PR_USE_OPENSSL)
/* Construct the options value that disables all unsupported protocols. */
static int get_disabled_protocols(unsigned int supported_protocols) {
  int disabled_protocols;

  /* First, create an options value where ALL protocols are disabled. */
  disabled_protocols = (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);

# if defined(SSL_OP_NO_TLSv1_1)
  disabled_protocols |= SSL_OP_NO_TLSv1_1;
# endif
# if defined(SSL_OP_NO_TLSv1_2)
  disabled_protocols |= SSL_OP_NO_TLSv1_2;
# endif
# if defined(SSL_OP_NO_TLSv1_3)
  disabled_protocols |= SSL_OP_NO_TLSv1_3;
# endif

  /* Now, based on the given bitset of supported protocols, clear the
   * necessary bits.
   */

  if (supported_protocols & PROXY_TLS_PROTO_SSL_V3) {
    disabled_protocols &= ~SSL_OP_NO_SSLv3;
  }

  if (supported_protocols & PROXY_TLS_PROTO_TLS_V1) {
    disabled_protocols &= ~SSL_OP_NO_TLSv1;
  }

# if OPENSSL_VERSION_NUMBER >= 0x10001000L
  if (supported_protocols & PROXY_TLS_PROTO_TLS_V1_1) {
    disabled_protocols &= ~SSL_OP_NO_TLSv1_1;
  }

  if (supported_protocols & PROXY_TLS_PROTO_TLS_V1_2) {
    disabled_protocols &= ~SSL_OP_NO_TLSv1_2;
  }
# endif /* OpenSSL-1.0.1 or later */

#if defined(SSL_OP_NO_TLSv1_3)
  if (supported_protocols & PROXY_TLS_PROTO_TLS_V1_3) {
    disabled_protocols &= ~SSL_OP_NO_TLSv1_3;
  }
#endif /* OpenSSL 1.1.1 or later */

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

# if defined(PSK_MAX_PSK_LEN)
static int tls_load_psk(const char *identity, const char *path) {
  register int i;
  char key_buf[PR_TUNABLE_BUFFER_SIZE];
  int fd, key_len, valid_hex = TRUE, res, xerrno;
  struct stat st;
  BIGNUM *bn = NULL;

  PRIVS_ROOT
  fd = open(path, O_RDONLY);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fd < 0) {
    pr_trace_msg(trace_channel, 6,
      "error opening ProxyTLSPreSharedKey file '%s': %s", path,
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  if (fstat(fd, &st) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 6,
      "error checking ProxyTLSPreSharedKey file '%s': %s", path,
      strerror(xerrno));
    (void) close(fd);
    errno = xerrno;
    return -1;
  }

  /* Check on the permissions of the file; skip it if the permissions
   * are too permissive, e.g. file is world-read/writable.
   */
  if (st.st_mode & S_IROTH) {
    pr_trace_msg(trace_channel, 6,
      "unable to use ProxyTLSPreSharedKey file '%s': "
      "file is world-readable", path);
    (void) close(fd);
    errno = EPERM;
    return -1;
  }

  if (st.st_mode & S_IWOTH) {
    pr_trace_msg(trace_channel, 6,
      "unable to use ProxyTLSPreSharedKey file '%s': "
      "file is world-writable", path);
    (void) close(fd);
    errno = EPERM;
    return -1;
  }

  if (st.st_size == 0) {
    pr_trace_msg(trace_channel, 6,
      "unable to use ProxyTLSPreSharedKey file '%s': "
      "file is zero length", path);
    (void) close(fd);
    errno = ENOENT;
    return -1;
  }

  /* Read the entire key into memory. */
  memset(key_buf, '\0', sizeof(key_buf));
  key_len = read(fd, key_buf, sizeof(key_buf)-1);
  xerrno = errno;
  (void) close(fd);

  if (key_len < 0) {
    pr_trace_msg(trace_channel, 6,
      ": error reading ProxyTLSPreSharedKey file '%s': %s", path,
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  if (key_len < PROXY_TLS_MIN_PSK_LEN) {
    pr_trace_msg(trace_channel, 6,
      "read %d bytes from ProxyTLSPreSharedKey file '%s', need at least %d "
      "bytes of key data, ignoring", key_len, path, PROXY_TLS_MIN_PSK_LEN);
    errno = ENOENT;
    return -1;
  }

  key_buf[key_len] = '\0';
  key_buf[sizeof(key_buf)-1] = '\0';

  /* Ignore any trailing newlines. */
  if (key_buf[key_len-1] == '\n') {
    key_buf[key_len-1] = '\0';
    key_len--;
  }

  if (key_buf[key_len-1] == '\r') {
    key_buf[key_len-1] = '\0';
    key_len--;
  }

  /* Ensure that it is all hex encoded data */
  for (i = 0; i < key_len; i++) {
    if (isxdigit((int) key_buf[i]) == 0) {
      valid_hex = FALSE;
      break;
    }
  }

  if (valid_hex == FALSE) {
    pr_trace_msg(trace_channel, 6,
      "unable to use '%s' data from ProxyTLSPreSharedKey file '%s': "
      "not a hex number", key_buf, path);
    errno = EINVAL;
    return -1;
  }

  res = BN_hex2bn(&bn, key_buf);
  if (res == 0) {
    pr_trace_msg(trace_channel, 6,
      "failed to convert '%s' data from ProxyTLSPreSharedKey file '%s' "
      "to BIGNUM: %s", key_buf, path, proxy_tls_get_errors());

    if (bn != NULL) {
      BN_free(bn);
    }

    errno = EINVAL;
    return -1;
  }

  tls_psk_name = identity;
  tls_psk_bn = bn;
  return 0;
}
# endif /* PSK support */

static void tls_info_cb(const SSL *ssl, int where, int ret) {
  const char *str = "(unknown)";
  int w;

  pr_signals_handle();

  w = where & ~SSL_ST_MASK;

  if (w & SSL_ST_CONNECT) {
    str = "connecting";

  } else if (w & SSL_ST_ACCEPT) {
    str = "accepting";

  } else {
    int ssl_state;

    ssl_state = SSL_get_state(ssl);
    switch (ssl_state) {
# if defined(SSL_ST_BEFORE)
      case SSL_ST_BEFORE:
        str = "before";
        break;
# endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
      case TLS_ST_OK:
#else
      case SSL_ST_OK:
#endif /* OpenSSL-1.1.x and later */
        str = "ok";
        break;

# if defined(SSL_ST_RENEGOTIATE)
      case SSL_ST_RENEGOTIATE:
        str = "renegotiating";
        break;
# endif

      default:
        break;
    }
  }

  if (where & SSL_CB_CONNECT_LOOP) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.info] %s: %s", str, SSL_state_string_long(ssl));

  } else if (where & SSL_CB_HANDSHAKE_START) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.info] %s: %s", str, SSL_state_string_long(ssl));

  } else if (where & SSL_CB_HANDSHAKE_DONE) {
    if (pr_trace_get_level(trace_channel) >= 9) {
      int reused;

      reused = SSL_session_reused((SSL *) ssl);
      if (reused > 0) {
        pr_trace_msg(trace_channel, 9,
          "RESUMED SSL/TLS session: %s using cipher %s (%d bits)",
          SSL_get_version(ssl), SSL_get_cipher_name(ssl),
          SSL_get_cipher_bits(ssl, NULL));

      } else {
        pr_trace_msg(trace_channel, 9,
          "negotiated NEW SSL/TLS session");
      }
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.info] %s: %s", str, SSL_state_string_long(ssl));

  } else if (where & SSL_CB_LOOP) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.info] %s: %s", str, SSL_state_string_long(ssl));

  } else if (where & SSL_CB_ALERT) {
    str = (where & SSL_CB_READ) ? "reading" : "writing";
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.info] %s: SSL/TLS alert %s: %s", str,
      SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));

  } else if (where & SSL_CB_EXIT) {
    if (ret == 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.info] %s: failed in %s: %s", str, SSL_state_string_long(ssl),
        proxy_tls_get_errors());

    } else if (ret < 0 &&
               errno != 0 &&
               errno != EAGAIN) {
      /* Ignore EAGAIN errors */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.info] %s: error in %s (errno %d: %s)", str,
        SSL_state_string_long(ssl), errno, strerror(errno));
    }
  }
}

# if OPENSSL_VERSION_NUMBER > 0x000907000L

/* Borrowed from mod_tls.  Would be nice to share this code somehow. */

struct tls_label {
  int labelno;
  const char *label_name;
};

/* SSL record types */
static struct tls_label tls_record_type_labels[] = {
  { 20, "ChangeCipherSpec" },
  { 21, "Alert" },
  { 22, "Handshake" },
  { 23, "ApplicationData" },
  { 0, NULL }
};

/* SSL versions */
static struct tls_label tls_version_labels[] = {
  { 0x0002, "SSL 2.0" },
  { 0x0300, "SSL 3.0" },
  { 0x0301, "TLS 1.0" },
  { 0x0302, "TLS 1.1" },
  { 0x0303, "TLS 1.2" },
  { 0x0304, "TLS 1.3" },

  { 0, NULL }
};

/* Cipher suites.  These values come from:
 *   http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 */
static struct tls_label tls_ciphersuite_labels[] = {
  { 0x0000, "SSL_NULL_WITH_NULL_NULL" },
  { 0x0001, "SSL_RSA_WITH_NULL_MD5" },
  { 0x0002, "SSL_RSA_WITH_NULL_SHA" },
  { 0x0003, "SSL_RSA_EXPORT_WITH_RC4_40_MD5" },
  { 0x0004, "SSL_RSA_WITH_RC4_128_MD5" },
  { 0x0005, "SSL_RSA_WITH_RC4_128_SHA" },
  { 0x0006, "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
  { 0x0007, "SSL_RSA_WITH_IDEA_CBC_SHA" },
  { 0x0008, "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x0009, "SSL_RSA_WITH_DES_CBC_SHA" },
  { 0x000A, "SSL_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0x000B, "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x000C, "SSL_DH_DSS_WITH_DES_CBC_SHA" },
  { 0x000D, "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
  { 0x000E, "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x000F, "SSL_DH_RSA_WITH_DES_CBC_SHA" },
  { 0x0010, "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0x0011, "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x0012, "SSL_DHE_DSS_WITH_DES_CBC_SHA" },
  { 0x0013, "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
  { 0x0014, "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x0015, "SSL_DHE_RSA_WITH_DES_CBC_SHA" },
  { 0x0016, "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0x0017, "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5" },
  { 0x0018, "SSL_DH_anon_WITH_RC4_128_MD5" },
  { 0x0019, "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
  { 0x001A, "SSL_DH_anon_WITH_DES_CBC_SHA" },
  { 0x001B, "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA" },
  { 0x001D, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
  { 0x001E, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
  { 0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
  { 0x0020, "TLS_KRB5_WITH_RC4_128_SHA" },
  { 0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
  { 0x0022, "TLS_KRB5_WITH_DES_CBC_MD5" },
  { 0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
  { 0x0024, "TLS_KRB5_WITH_RC4_128_MD5" },
  { 0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
  { 0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
  { 0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
  { 0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
  { 0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
  { 0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
  { 0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
  { 0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA" },
  { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
  { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
  { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
  { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
  { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
  { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
  { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
  { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
  { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
  { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
  { 0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
  { 0x003B, "TLS_RSA_WITH_NULL_SHA256" },
  { 0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
  { 0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
  { 0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
  { 0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
  { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
  { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
  { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
  { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
  { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
  { 0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
  { 0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
  { 0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
  { 0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
  { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
  { 0x008A, "TLS_PSK_WITH_RC4_128_SHA" },
  { 0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
  { 0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
  { 0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
  { 0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
  { 0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
  { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
  { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
  { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
  { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
  { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
  { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
  { 0x0096, "TLS_RSA_WITH_SEED_CBC_SHA" },
  { 0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
  { 0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
  { 0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
  { 0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
  { 0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
  { 0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
  { 0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
  { 0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
  { 0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
  { 0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
  { 0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
  { 0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
  { 0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
  { 0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
  { 0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
  { 0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
  { 0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
  { 0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
  { 0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
  { 0x00B0, "TLS_PSK_WITH_NULL_SHA256" },
  { 0x00B1, "TLS_PSK_WITH_NULL_SHA384" },
  { 0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
  { 0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"},
  { 0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
  { 0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
  { 0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
  { 0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
  { 0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
  { 0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
  { 0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
  { 0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
  { 0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
  { 0x1301, "TLS_AES_128_GCM_SHA256" },
  { 0x1302, "TLS_AES_256_GCM_SHA384" },
  { 0x1303, "TLS_CHACHA20_POLY1305_SHA256" },
  { 0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
  { 0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
  { 0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
  { 0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
  { 0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
  { 0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
  { 0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
  { 0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
  { 0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA" },
  { 0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
  { 0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
  { 0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
  { 0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
  { 0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
  { 0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
  { 0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
  { 0xC015, "TLS_ECDH_anon_WITH_NULL_SHA" },
  { 0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
  { 0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
  { 0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
  { 0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
  { 0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
  { 0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
  { 0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
  { 0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
  { 0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
  { 0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
  { 0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
  { 0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
  { 0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
  { 0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
  { 0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
  { 0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
  { 0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
  { 0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
  { 0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
  { 0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
  { 0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
  { 0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
  { 0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
  { 0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
  { 0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
  { 0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
  { 0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
  { 0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
  { 0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
  { 0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
  { 0xC09C, "TLS_RSA_WITH_AES_128_CCM" },
  { 0xC09D, "TLS_RSA_WITH_AES_256_CCM" },
  { 0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" },
  { 0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM" },
  { 0xC0AE, "TLS_DHE_RSA_WITH_AES_128_CCM" },
  { 0xC0AF, "TLS_DHE_RSA_WITH_AES_256_CCM" },
  { 0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xFEFE, "SSL_RSA_FIPS_WITH_DES_CBC_SHA" },
  { 0xFEFF, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },

  { 0, NULL }
};

/* Compressions */
static struct tls_label tls_compression_labels[] = {
  { 0x0000, "None" },
  { 0x0001, "Zlib" },

  { 0, NULL }
};

/* Extensions */
static struct tls_label tls_extension_labels[] = {
  { 0, "server_name" },
  { 1, "max_fragment_length" },
  { 2, "client_certificate_url" },
  { 3, "trusted_ca_keys" },
  { 4, "truncated_hmac" },
  { 5, "status_request" },
  { 6, "user_mapping" },
  { 7, "client_authz" },
  { 8, "server_authz" },
  { 9, "cert_type" },
  { 10, "elliptic_curves" },
  { 11, "ec_point_formats" },
  { 12, "srp" },
  { 13, "signature_algorithms" },
  { 14, "use_srtp" },
  { 15, "heartbeat" },
  { 16, "application_layer_protocol_negotiation" },
  { 18, "signed_certificate_timestamp" },
  { 21, "padding" },
  { 22, "encrypt_then_mac" },
  { 23, "extended_master_secret" },
  { 35, "session_ticket" },
  { 41, "psk" },
  { 42, "early_data" },
  { 43, "supported_versions" },
  { 44, "cookie" },
  { 45, "psk_kex_modes" },
  { 47, "certificate_authorities" },
  { 49, "post_handshake_auth" },
  { 50, "signature_algorithms_cert" },
  { 51, "key_share" },
  { 0xFF01, "renegotiate" },
  { 13172, "next_proto_neg" },

  { 0, NULL }
};

# if defined(TLSEXT_TYPE_signature_algorithms)
/* Signature Algorithms.  These values come from:
 *   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
 */
static struct tls_label tls_sigalgo_labels[] = {
  { 0x0201, "rsa_pkcs1_sha1" },
  { 0x0202, "dsa_sha1" },
  { 0x0203, "ecdsa_sha1" },
  { 0x0301, "rsa_pkcs1_sha224" },
  { 0x0302, "dsa_sha224" },
  { 0x0303, "ecdsa_sha224" },
  { 0x0401, "rsa_pkcs1_sha256" },
  { 0x0402, "dsa_sha256" },
  { 0x0403, "ecdsa_secp256r1_sha256" },
  { 0x0501, "rsa_pkcs1_sha384" },
  { 0x0502, "dsa_sha384" },
  { 0x0503, "ecdsa_secp384r1_sha384" },
  { 0x0601, "rsa_pkcs1_sha512" },
  { 0x0602, "dsa_sha512" },
  { 0x0603, "ecdsa_secp521r1_sha512" },
  { 0x0804, "rsa_pss_rsae_sha256" },
  { 0x0805, "rsa_pss_rsae_sha384" },
  { 0x0806, "rsa_pss_rsae_sha512" },
  { 0x0807, "ed25519" },
  { 0x0808, "ed448" },
  { 0x0809, "rsa_pss_pss_sha256" },
  { 0x080A, "rsa_pss_pss_sha384" },
  { 0x080B, "rsa_pss_pss_sha512" },

  { 0, NULL }
};
# endif /* TLSEXT_TYPE_signature_algorithms */

# if defined(TLSEXT_TYPE_psk_kex_modes)
/* PSK KEX modes.  These values come from:
 *   https://tools.ietf.org/html/rfc8446#section-4.2.9
 */
static struct tls_label tls_psk_kex_labels[] = {
  { 0, "psk_ke" },
  { 1, "psk_dhe_key" },

  { 0, NULL }
};
# endif /* TLSEXT_TYPE_psk_kex_modes */

static const char *tls_get_label(int labelno, struct tls_label *labels) {
  register unsigned int i;

  for (i = 0; labels[i].label_name != NULL; i++) {
    if (labels[i].labelno == labelno) {
      return labels[i].label_name;
    }
  }

  return "[unknown/unsupported]";
}

static void tls_print_ssl_version(BIO *bio, const char *name,
    const unsigned char **msg, size_t *msglen, int *pversion) {
  int version;

  if (*msglen < 2) {
    return;
  }

  version = ((*msg)[0] << 8) | (*msg)[1];
  BIO_printf(bio, "  %s = %s\n", name,
    tls_get_label(version, tls_version_labels));
  *msg += 2;
  *msglen -= 2;

  if (pversion != NULL) {
    *pversion = version;
  }
}

static void tls_print_hex(BIO *bio, const char *indent, const char *name,
    const unsigned char *msg, size_t msglen) {

  BIO_printf(bio, "%s (%lu %s)\n", name, (unsigned long) msglen,
    msglen != 1 ? "bytes" : "byte");

  if (msglen > 0) {
    register unsigned int i;

    BIO_puts(bio, indent);
    for (i = 0; i < msglen; i++) {
      BIO_printf(bio, "%02x", msg[i]);
    }
    BIO_puts(bio, "\n");
  }
}

static void tls_print_hexbuf(BIO *bio, const char *indent, const char *name,
    size_t namelen, const unsigned char **msg, size_t *msglen) {
  size_t buflen;
  const unsigned char *ptr;

  if (*msglen < namelen) {
    return;
  }

  ptr = *msg;
  buflen = ptr[0];

  if (namelen > 1) {
    buflen = (buflen << 8) | ptr[1];
  }

  if (*msglen < namelen + buflen) {
    return;
  }

  ptr += namelen;
  tls_print_hex(bio, indent, name, ptr, buflen);
  *msg += (buflen + namelen);
  *msglen -= (buflen + namelen);
}

static void tls_print_random(BIO *bio, const unsigned char **msg,
    size_t *msglen) {
  time_t ts;
  const unsigned char *ptr;

  if (*msglen < 32) {
    return;
  }

  ptr = *msg;

  ts = ((ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3]);
  ptr += 4;

  BIO_puts(bio, "  random:\n");
  BIO_printf(bio, "    gmt_unix_time = %s (not guaranteed to be accurate)\n",
    pr_strtime2(ts, TRUE));
  tls_print_hex(bio, "      ", "    random_bytes", ptr, 28);
  *msg += 32;
  *msglen -= 32;
}

static void tls_print_session_id(BIO *bio, const unsigned char **msg,
    size_t *msglen) {
  tls_print_hexbuf(bio, "    ", "  session_id", 1, msg, msglen);
}

static void tls_print_ciphersuites(BIO *bio, const char *name,
    const unsigned char **msg, size_t *msglen) {
  size_t len;

  len = ((*msg[0]) << 8) | (*msg)[1];
  *msg += 2;
  *msglen -= 2;
  BIO_printf(bio, "  %s (%lu %s)\n", name, (unsigned long) len,
    len != 1 ? "bytes" : "byte");
  if (*msglen < len ||
      (len & 1)) {
    return;
  }

  while (len > 0) {
    unsigned int suiteno;

    pr_signals_handle();

    suiteno = ((*msg[0]) << 8) | (*msg)[1];
    BIO_printf(bio, "    %s (0x%x)\n",
      tls_get_label(suiteno, tls_ciphersuite_labels), suiteno);

    *msg += 2;
    *msglen -= 2;
    len -= 2;
  }
}

static void tls_print_compressions(BIO *bio, const char *name,
    const unsigned char **msg, size_t *msglen) {
  size_t len;

  len = (*msg)[0];
  *msg += 1;
  *msglen -= 1;

  if (*msglen < len) {
    return;
  }

  BIO_printf(bio, "  %s (%lu %s)\n", name, (unsigned long) len,
    len != 1 ? "bytes" : "byte");
  while (len > 0) {
    int comp_type;

    pr_signals_handle();

    comp_type = (*msg)[0];
    BIO_printf(bio, "    %s\n",
      tls_get_label(comp_type, tls_compression_labels));

    *msg += 1;
    *msglen -= 1;
    len -= 1;
  }
}

static void tls_print_extension(BIO *bio, const char *indent, int server,
    int ext_type, const unsigned char *ext, size_t extlen) {

  BIO_printf(bio, "%sextension_type = %s (%lu %s)\n", indent,
    tls_get_label(ext_type, tls_extension_labels), (unsigned long) extlen,
    extlen != 1 ? "bytes" : "byte");
}

static void tls_print_extensions(BIO *bio, const char *name, int server,
    const unsigned char **msg, size_t *msglen) {
  size_t len;

  if (*msglen == 0) {
    BIO_printf(bio, "%s: None\n", name);
    return;
  }

  len = ((*msg)[0] << 8) | (*msg)[1];
  if (len != (*msglen - 2)) {
    return;
  }

  *msg += 2;
  *msglen -= 2;

  BIO_printf(bio, "  %s (%lu %s)\n", name, (unsigned long) len,
    len != 1 ? "bytes" : "byte");
  while (len > 0) {
    int ext_type;
    size_t ext_len;

    pr_signals_handle();

    if (*msglen < 4) {
      break;
    }

    ext_type = ((*msg)[0] << 8) | (*msg)[1];
    ext_len = ((*msg)[2] << 8) | (*msg)[3];

    if (*msglen < (ext_len + 4)) {
      break;
    }

    *msg += 4;
    tls_print_extension(bio, "    ", server, ext_type, *msg, ext_len);
    *msg += ext_len;
    *msglen -= (ext_len + 4);
  }
}

static void tls_print_client_hello(int io_flag, int version, int content_type,
    const unsigned char *buf, size_t buflen, SSL *ssl, void *arg) {
  BIO *bio;
  char *data = NULL;
  long datalen;

  bio = BIO_new(BIO_s_mem());

  BIO_puts(bio, "\nClientHello:\n");
  tls_print_ssl_version(bio, "client_version", &buf, &buflen, NULL);
  tls_print_random(bio, &buf, &buflen);
  tls_print_session_id(bio, &buf, &buflen);
  if (buflen < 2) {
    BIO_free(bio);
    return;
  }
  tls_print_ciphersuites(bio, "cipher_suites", &buf, &buflen);
  if (buflen < 1) {
    BIO_free(bio);
    return;
  }
  tls_print_compressions(bio, "compression_methods", &buf, &buflen);
  tls_print_extensions(bio, "extensions", FALSE, &buf, &buflen);

  datalen = BIO_get_mem_data(bio, &data);
  if (data != NULL) {
    data[datalen] = '\0';
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION, "[tls.msg] %.*s",
      (int) datalen, data);
  }

  BIO_free(bio);
}

static void tls_print_server_hello(int io_flag, int version, int content_type,
    const unsigned char *buf, size_t buflen, SSL *ssl, void *arg) {
  BIO *bio;
  char *data = NULL;
  long datalen;
  int print_session_id = TRUE, print_compressions = TRUE, server_version;
  unsigned int suiteno;

  bio = BIO_new(BIO_s_mem());

  BIO_puts(bio, "\nServerHello:\n");
  tls_print_ssl_version(bio, "server_version", &buf, &buflen, &server_version);

#if defined(TLS1_3_VERSION)
  if (server_version == TLS1_3_VERSION) {
    print_session_id = FALSE;
    print_compressions = FALSE;
  }
#endif /* TLS1_3_VERSION */

  tls_print_random(bio, &buf, &buflen);
  if (print_session_id == TRUE) {
    tls_print_session_id(bio, &buf, &buflen);
  }
  if (buflen < 2) {
    BIO_free(bio);
    return;
  }

  /* Print the selected ciphersuite. */
  BIO_printf(bio, "  cipher_suites (2 bytes)\n");
  suiteno = (buf[0] << 8) | buf[1];
  BIO_printf(bio, "    %s (0x%x)\n",
    tls_get_label(suiteno, tls_ciphersuite_labels), suiteno);
  buf += 2;
  buflen -= 2;

  if (print_compressions == TRUE) {
    int comp_type;

    if (buflen < 1) {
      BIO_free(bio);
      return;
    }

    /* Print the selected compression. */
    BIO_printf(bio, "  compression_methods (1 byte)\n");
    comp_type = *buf;
    BIO_printf(bio, "    %s\n",
      tls_get_label(comp_type, tls_compression_labels));
    buf += 1;
    buflen -= 1;
  }
  tls_print_extensions(bio, "extensions", TRUE, &buf, &buflen);

  datalen = BIO_get_mem_data(bio, &data);
  if (data != NULL) {
    data[datalen] = '\0';
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION, "[tls.msg] %.*s",
      (int) datalen, data);
  }

  BIO_free(bio);
}

# if defined(SSL3_MT_NEWSESSION_TICKET)
static void tls_print_ticket(int io_flag, int version, int content_type,
    const unsigned char *buf, size_t buflen, SSL *ssl, void *arg) {
  BIO *bio;
  char *data = NULL;
  long datalen;

  bio = BIO_new(BIO_s_mem());

  BIO_puts(bio, "\nNewSessionTicket:\n");
  if (buflen != 0) {
    unsigned int ticket_lifetime;
    int print_ticket_age = FALSE, print_extensions = FALSE;

    ticket_lifetime = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    buf += 4;
    buflen -= 4;
    BIO_printf(bio, "  ticket_lifetime_hint\n    %u (sec)\n", ticket_lifetime);

#  if defined(TLS1_3_VERSION)
    if (SSL_version(ssl) == TLS1_3_VERSION) {
      print_ticket_age = TRUE;
      print_extensions = TRUE;
    }
#  endif /* TLS1_3_VERSION */

    if (print_ticket_age == TRUE) {
      unsigned int ticket_age_add;

      ticket_age_add = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
      buf += 4;
      buflen -= 4;
      BIO_printf(bio, "  ticket_age_add\n    %u (sec)\n", ticket_age_add);
      tls_print_hexbuf(bio, "    ", "  ticket_nonce", 1, &buf, &buflen);
    }

    tls_print_hexbuf(bio, "    ", "  ticket", 2, &buf, &buflen);

    if (print_extensions == TRUE) {
      tls_print_extensions(bio, "extensions", TRUE, &buf, &buflen);
    }

  } else {
    BIO_puts(bio, "  <no ticket>\n");
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data != NULL) {
    data[datalen] = '\0';
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION, "[tls.msg] %.*s",
      (int) datalen, data);
  }

  BIO_free(bio);
}
# endif /* SSL3_MT_NEWSESSION_TICKET */

#if !defined(OPENSSL_NO_TLSEXT)
static void tls_tlsext_cb(SSL *ssl, int server, int type,
    unsigned char *tlsext_data, int tlsext_datalen, void *user_data) {
  char *extension_name = "(unknown)";
  int print_basic_info = TRUE;

  /* Note: OpenSSL does not implement all possible extensions.  For the
   * "(unknown)" extensions, see:
   *
   *  http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
   */
  switch (type) {
# if defined(TLSEXT_TYPE_server_name)
    case TLSEXT_TYPE_server_name: {
      BIO *bio = NULL;
      char *ext_info = "";
      long ext_infolen = 0;

      extension_name = "server name";

      if (pr_trace_get_level(trace_channel) >= 21 &&
          tlsext_datalen >= 2) {

        /* We read 2 bytes for the extension length, 1 byte for the
         * name type, and 2 bytes for the name length.  For the SNI
         * format specification, see:
         *   https://tools.ietf.org/html/rfc6066#section-3
         */
        int ext_len;

        ext_len = (tlsext_data[0] << 8) | tlsext_data[1];
        if (tlsext_datalen == ext_len + 2 &&
            (ext_len & 1) == 0) {
          int name_type;
          tlsext_data += 2;

          name_type = tlsext_data[0];
          tlsext_data += 1;

          if (name_type == TLSEXT_NAMETYPE_host_name) {
            size_t name_len;

            name_len = (tlsext_data[0] << 8) | tlsext_data[1];
            tlsext_data += 2;

            bio = BIO_new(BIO_s_mem());
            BIO_printf(bio, "\n  %.*s (%lu)", (int) name_len, tlsext_data,
              (unsigned long) name_len);
            ext_infolen = BIO_get_mem_data(bio, &ext_info);
            if (ext_info != NULL) {
              ext_info[ext_infolen] = '\0';
            }
          }
        }
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.tlsext] TLS %s extension \"%s\" (ID %d, %d %s)%.*s",
        server ? "server" : "client", extension_name, type, tlsext_datalen,
        tlsext_datalen != 1 ? "bytes" : "byte", (int) ext_infolen,
        ext_info != NULL ? ext_info : "");

      if (bio != NULL) {
        BIO_free(bio);
      }

      print_basic_info = FALSE;
      break;
    }
# endif /* TLSEXT_TYPE_server_name */

# if defined(TLSEXT_TYPE_max_fragment_length)
    case TLSEXT_TYPE_max_fragment_length:
      extension_name = "max fragment length";
      break;
# endif /* TLSEXT_TYPE_max_fragment_length */

# if defined(TLSEXT_TYPE_client_certificate_url)
    case TLSEXT_TYPE_client_certificate_url:
      extension_name = "client certificate URL";
      break;
# endif /* TLSEXT_TYPE_client_certificate_url */

# if defined(TLSEXT_TYPE_trusted_ca_keys)
    case TLSEXT_TYPE_trusted_ca_keys:
      extension_name = "trusted CA keys";
      break;
# endif /* TLSEXT_TYPE_trusted_ca_keys */

# if defined(TLSEXT_TYPE_truncated_hmac)
    case TLSEXT_TYPE_truncated_hmac:
      extension_name = "truncated HMAC";
      break;
# endif /* TLSEXT_TYPE_truncated_hmac */

# if defined(TLSEXT_TYPE_status_request)
    case TLSEXT_TYPE_status_request:
      extension_name = "status request";
      break;
# endif /* TLSEXT_TYPE_status_request */

# if defined(TLSEXT_TYPE_user_mapping)
    case TLSEXT_TYPE_user_mapping:
      extension_name = "user mapping";
      break;
# endif /* TLSEXT_TYPE_user_mapping */

# if defined(TLSEXT_TYPE_client_authz)
    case TLSEXT_TYPE_client_authz:
      extension_name = "client authz";
      break;
# endif /* TLSEXT_TYPE_client_authz */

# if defined(TLSEXT_TYPE_server_authz)
    case TLSEXT_TYPE_server_authz:
      extension_name = "server authz";
      break;
# endif /* TLSEXT_TYPE_server_authz */

# if defined(TLSEXT_TYPE_cert_type)
    case TLSEXT_TYPE_cert_type:
      extension_name = "cert type";
      break;
# endif /* TLSEXT_TYPE_cert_type */

# if defined(TLSEXT_TYPE_elliptic_curves)
    case TLSEXT_TYPE_elliptic_curves:
      extension_name = "elliptic curves";
      break;
# endif /* TLSEXT_TYPE_elliptic_curves */

# if defined(TLSEXT_TYPE_ec_point_formats)
    case TLSEXT_TYPE_ec_point_formats:
      extension_name = "EC point formats";
      break;
# endif /* TLSEXT_TYPE_ec_point_formats */

# if defined(TLSEXT_TYPE_srp)
    case TLSEXT_TYPE_srp:
      extension_name = "SRP";
      break;
# endif /* TLSEXT_TYPE_srp */

# if defined(TLSEXT_TYPE_signature_algorithms)
    case TLSEXT_TYPE_signature_algorithms: {
      BIO *bio = NULL;
      char *ext_info = "";
      long ext_infolen = 0;

      extension_name = "signature algorithms";

      if (pr_trace_get_level(trace_channel) >= 21 &&
          tlsext_datalen >= 2) {
        int len;

        len = (tlsext_data[0] << 8) | tlsext_data[1];
        if (tlsext_datalen == len + 2 &&
            (len & 1) == 0) {
          tlsext_data += 2;

          bio = BIO_new(BIO_s_mem());
          BIO_puts(bio, "\n");

          while (len > 0) {
            unsigned int sig_algo;

            pr_signals_handle();

            sig_algo = (tlsext_data[0] << 8) | tlsext_data[1];
            BIO_printf(bio, "  %s (0x%x)\n",
              tls_get_label(sig_algo, tls_sigalgo_labels), sig_algo);
            len -= 2;
            tlsext_data += 2;
          }

          ext_infolen = BIO_get_mem_data(bio, &ext_info);
          if (ext_info != NULL) {
            ext_info[ext_infolen] = '\0';
          }
        }
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.tlsext] TLS %s extension \"%s\" (ID %d, %d %s)%.*s",
        server ? "server" : "client", extension_name, type, tlsext_datalen,
        tlsext_datalen != 1 ? "bytes" : "byte", (int) ext_infolen,
        ext_info != NULL ? ext_info : "");

      if (bio != NULL) {
        BIO_free(bio);
      }

      print_basic_info = FALSE;
      break;
    }
# endif /* TLSEXT_TYPE_signature_algorithms */

# if defined(TLSEXT_TYPE_use_srtp)
    case TLSEXT_TYPE_use_srtp:
      extension_name = "use SRTP";
      break;
# endif /* TLSEXT_TYPE_use_srtp */

# if defined(TLSEXT_TYPE_heartbeat)
    case TLSEXT_TYPE_heartbeat:
      extension_name = "heartbeat";
      break;
# endif /* TLSEXT_TYPE_heartbeat */

# if defined(TLSEXT_TYPE_signed_certificate_timestamp)
    case TLSEXT_TYPE_signed_certificate_timestamp:
      extension_name = "signed certificate timestamp";
      break;
# endif /* TLSEXT_TYPE_signed_certificate_timestamp */

# if defined(TLSEXT_TYPE_encrypt_then_mac)
    case TLSEXT_TYPE_encrypt_then_mac:
      extension_name = "encrypt then mac";
      break;
# endif /* TLSEXT_TYPE_encrypt_then_mac */

# if defined(TLSEXT_TYPE_extended_master_secret)
    case TLSEXT_TYPE_extended_master_secret:
      extension_name = "extended master secret";
      break;
# endif /* TLSEXT_TYPE_extended_master_secret */

# if defined(TLSEXT_TYPE_session_ticket)
    case TLSEXT_TYPE_session_ticket:
      extension_name = "session ticket";
      break;
# endif /* TLSEXT_TYPE_session_ticket */

# if defined(TLSEXT_TYPE_psk)
    case TLSEXT_TYPE_psk:
      extension_name = "PSK";
      break;
# endif /* TLSEXT_TYPE_psk */

# if defined(TLSEXT_TYPE_supported_versions)
    case TLSEXT_TYPE_supported_versions: {
      BIO *bio = NULL;
      char *ext_info = NULL;
      long ext_infolen = 0;

      /* If we are the server responding, we only indicate the selected
       * protocol version.  Otherwise, we are a client indicating the range
       * of versions supported.
       */

      extension_name = "supported versions";

      if (pr_trace_get_level(trace_channel) >= 21) {
        bio = BIO_new(BIO_s_mem());

        if (server) {
          if (tlsext_datalen == 2) {
            int version;

            version = (tlsext_data[0] << 8) | tlsext_data[1];
            BIO_printf(bio, "\n  %s (0x%x)\n",
              tls_get_label(version, tls_version_labels), version);
          }

        } else {
          if (tlsext_datalen >= 1) {
            int len;

            len = tlsext_data[0];
            if (tlsext_datalen == len + 1) {
              tlsext_data += 1;

              BIO_puts(bio, "\n");

              while (len > 0) {
                int version;

                pr_signals_handle();

                version = (tlsext_data[0] << 8) | tlsext_data[1];
                BIO_printf(bio, "  %s (0x%x)\n",
                  tls_get_label(version, tls_version_labels), version);
                len -= 2;
                tlsext_data += 2;
              }
            }
          }
        }

        ext_infolen = BIO_get_mem_data(bio, &ext_info);
        if (ext_info != NULL) {
          ext_info[ext_infolen] = '\0';
        }
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.tlsext] TLS %s extension \"%s\" (ID %d, %d %s)%.*s",
        server ? "server" : "client", extension_name, type, tlsext_datalen,
        tlsext_datalen != 1 ? "bytes" : "byte", (int) ext_infolen,
        ext_info != NULL ? ext_info : "");

      if (bio != NULL) {
        BIO_free(bio);
      }

      print_basic_info = FALSE;
      break;
    }
# endif /* TLSEXT_TYPE_supported_versions */

# if defined(TLSEXT_TYPE_psk_kex_modes)
    case TLSEXT_TYPE_psk_kex_modes: {
      BIO *bio = NULL;
      char *ext_info = NULL;
      long ext_infolen = 0;

      extension_name = "PSK KEX modes";

      if (pr_trace_get_level(trace_channel) >= 19) {
        if (tlsext_datalen >= 1) {
          int len;

          bio = BIO_new(BIO_s_mem());
          len = tlsext_data[0];

          if (tlsext_datalen == len + 1) {
            tlsext_data += 1;

            BIO_puts(bio, "\n");

            while (len > 0) {
              int kex_mode;

              pr_signals_handle();

              kex_mode = tlsext_data[0];
              BIO_printf(bio, "  %s (%d)\n",
                tls_get_label(kex_mode, tls_psk_kex_labels), kex_mode);
              len -= 1;
              tlsext_data += 1;
            }
          }
        }

        ext_infolen = BIO_get_mem_data(bio, &ext_info);
        if (ext_info != NULL) {
          ext_info[ext_infolen] = '\0';
        }
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.tlsext] TLS %s extension \"%s\" (ID %d, %d %s)%.*s",
        server ? "server" : "client", extension_name, type, tlsext_datalen,
        tlsext_datalen != 1 ? "bytes" : "byte", (int) ext_infolen,
        ext_info != NULL ? ext_info : "");

      if (bio != NULL) {
        BIO_free(bio);
      }

      print_basic_info = FALSE;
      break;
    }
# endif /* TLSEXT_TYPE_psk_kex_modes */

# if defined(TLSEXT_TYPE_renegotiate)
    case TLSEXT_TYPE_renegotiate:
      extension_name = "renegotiation info";
      break;
# endif /* TLSEXT_TYPE_renegotiate */

# if defined(TLSEXT_TYPE_opaque_prf_input)
    case TLSEXT_TYPE_opaque_prf_input:
      extension_name = "opaque PRF input";
      break;
# endif /* TLSEXT_TYPE_opaque_prf_input */

# if defined(TLSEXT_TYPE_next_proto_neg)
    case TLSEXT_TYPE_next_proto_neg:
      extension_name = "next protocol";
      break;
# endif /* TLSEXT_TYPE_next_proto_neg */

# if defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
    case TLSEXT_TYPE_application_layer_protocol_negotiation:
      extension_name = "application layer protocol";
      break;
# endif /* TLSEXT_TYPE_application_layer_protocol_negotiation */

# if defined(TLSEXT_TYPE_padding)
    case TLSEXT_TYPE_padding:
      extension_name = "TLS padding";
      break;
# endif /* TLSEXT_TYPE_padding */

# if defined(TLSEXT_TYPE_early_data)
    case TLSEXT_TYPE_early_data:
      extension_name = "early data";
      break;
# endif /* TLSEXT_TYPE_early_data */

# if defined(TLSEXT_TYPE_post_handshake_auth)
    case TLSEXT_TYPE_post_handshake_auth:
      extension_name = "post handshake auth";
      break;
# endif /* TLSEXT_TYPE_post_handshake_auth */

    default:
      print_basic_info = TRUE;
      break;
  }

  if (print_basic_info == TRUE) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.tlsext] TLS %s extension \"%s\" (ID %d, %d %s)",
      server ? "server" : "client", extension_name, type, tlsext_datalen,
      tlsext_datalen != 1 ? "bytes" : "byte");
  }
}
#endif /* OPENSSL_NO_TLSEXT */

static void tls_msg_cb(int io_flag, int version, int content_type,
    const void *buf, size_t buflen, SSL *ssl, void *arg) {
  char *action_str = NULL;
  char *version_str = NULL;
  char *bytes_str = buflen != 1 ? "bytes" : "byte";

  if (io_flag == 0) {
    action_str = "received";

  } else if (io_flag == 1) {
    action_str = "sent";
  }

  switch (version) {
    case SSL2_VERSION:
      version_str = "SSLv2";
      break;

    case SSL3_VERSION:
      version_str = "SSLv3";
      break;

    case TLS1_VERSION:
      version_str = "TLSv1";
      break;

#  if defined(TLS1_1_VERSION)
    case TLS1_1_VERSION:
      version_str = "TLSv1.1";
      break;
#  endif /* TLS1_1_VERSION */

#  if defined(TLS1_2_VERSION)
    case TLS1_2_VERSION:
      version_str = "TLSv1.2";
      break;
#  endif /* TLS1_2_VERSION */

#  if defined(TLS1_3_VERSION)
    case TLS1_3_VERSION:
      version_str = "TLSv1.3";
      break;
#  endif /* TLS1_3_VERSION */

    default:
#  if defined(SSL3_RT_HEADER)
      /* OpenSSL calls this callback for SSL records received; filter those
       * from true "unknowns".
       */
      if (version == 0 &&
          (content_type != SSL3_RT_HEADER ||
           buflen != SSL3_RT_HEADER_LENGTH)) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "[tls.msg] unknown/unsupported version: %d", version);
      }
#  else
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "[tls.msg] unknown/unsupported version: %d", version);
#  endif
      break;
  }

  if (version == SSL3_VERSION ||
#  if defined(TLS1_1_VERSION)
      version == TLS1_1_VERSION ||
#  endif /* TLS1_1_VERSION */
#  if defined(TLS1_2_VERSION)
      version == TLS1_2_VERSION ||
#  endif /* TLS1_2_VERSION */
#  if defined(TLS1_3_VERSION)
      version == TLS1_3_VERSION ||
#  endif /* TLS1_3_VERSION */
      version == TLS1_VERSION) {

    switch (content_type) {
      case SSL3_RT_CHANGE_CIPHER_SPEC:
        /* ChangeCipherSpec message */
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "[tls.msg] %s %s ChangeCipherSpec message (%u %s)",
          action_str, version_str, (unsigned int) buflen, bytes_str);
        break;

      case SSL3_RT_ALERT: {
        /* Alert messages */
        pr_trace_msg(trace_channel, 27,
          "%s %s Alert (%u %s)", action_str, version_str,
          (unsigned int) buflen, bytes_str);
        if (buflen == 2) {
          char *severity_str = NULL;

          /* Peek naughtily into the buffer. */
          switch (((const unsigned char *) buf)[0]) {
            case SSL3_AL_WARNING:
              severity_str = "warning";
              break;

            case SSL3_AL_FATAL:
              severity_str = "fatal";
              break;
          }

          switch (((const unsigned char *) buf)[1]) {
            case SSL3_AD_CLOSE_NOTIFY:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'close_notify' Alert message (%u %s)",
                action_str, version_str, severity_str, (unsigned int) buflen,
                bytes_str);
              break;

            case SSL3_AD_UNEXPECTED_MESSAGE:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'unexpected_message' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;

            case SSL3_AD_BAD_RECORD_MAC:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'bad_record_mac' Alert message (%u %s)",
                action_str, version_str, severity_str, (unsigned int) buflen,
                bytes_str);
              break;

            case 21:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'decryption_failed' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;

            case 22:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'record_overflow' Alert message (%u %s)",
                action_str, version_str, severity_str, (unsigned int) buflen,
                bytes_str);
              break;

            case 30:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'decompression_failure' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;

            case SSL3_AD_HANDSHAKE_FAILURE:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'handshake_failure' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;

#  if defined(SSL3_AD_BAD_CERTIFICATE)
            case SSL3_AD_BAD_CERTIFICATE:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'bad_certificate' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;
#  endif /* SSL3_AD_BAD_CERTIFICATE */

#  if defined(SSL3_AD_CERTIFICATE_REVOKED)
            case SSL3_AD_CERTIFICATE_REVOKED:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'certificate_revoked' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;
#  endif /* SSL3_AD_CERTIFICATE_REVOKED */

#  if defined(SSL3_AD_CERTIFICATE_EXPIRED)
            case SSL3_AD_CERTIFICATE_EXPIRED:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'certificate_expired' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;
#  endif /* SSL3_AD_CERTIFICATE_EXPIRED */

#  if defined(SSL3_AD_CERTIFICATE_UNKNOWN)
            case SSL3_AD_CERTIFICATE_UNKNOWN:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'certificate_unknown' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;
#  endif /* SSL3_AD_CERTIFICATE_UNKNOWN */

#  if defined(SSL3_AD_ILLEGAL_PARAMETER)
            case SSL3_AD_ILLEGAL_PARAMETER:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s %s 'illegal_parameter' Alert message "
                "(%u %s)", action_str, version_str, severity_str,
                (unsigned int) buflen, bytes_str);
              break;
#  endif /* SSL3_AD_ILLEGAL_PARAMETER */
          }

        } else {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "[tls.msg] %s %s Alert message, unknown type (%u %s)", action_str,
            version_str, (unsigned int) buflen, bytes_str);
        }

        break;
      }

      case SSL3_RT_HANDSHAKE: {
        /* Handshake messages */
        pr_trace_msg(trace_channel, 27,
          "%s %s Handshake (%u %s)", action_str, version_str,
          (unsigned int) buflen, bytes_str);
        if (buflen > 0) {
          /* Peek naughtily into the buffer. */
          switch (((const unsigned char *) buf)[0]) {
            case SSL3_MT_HELLO_REQUEST:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'HelloRequest' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              break;

            case SSL3_MT_CLIENT_HELLO: {
              const unsigned char *msg;
              size_t msglen;

              msg = buf;
              msglen = buflen;

              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'ClientHello' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              tls_print_client_hello(io_flag, version, content_type, msg + 4,
                msglen - 4, ssl, arg);

              break;
            }

            case SSL3_MT_SERVER_HELLO: {
              const unsigned char *msg;
              size_t msglen;

              msg = buf;
              msglen = buflen;

              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'ServerHello' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              tls_print_server_hello(io_flag, version, content_type, msg + 4,
                msglen - 4, ssl, arg);

              break;
            }

#  if defined(SSL3_MT_NEWSESSION_TICKET)
            case SSL3_MT_NEWSESSION_TICKET: {
              const unsigned char *msg;
              size_t msglen;

              msg = buf;
              msglen = buflen;

              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'NewSessionTicket' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              tls_print_ticket(io_flag, version, content_type, msg + 4,
                msglen - 4, ssl, arg);

              break;
            }
#  endif /* SSL3_MT_NEWSESSION_TICKET */

            case SSL3_MT_CERTIFICATE:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'Certificate' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              break;

            case SSL3_MT_SERVER_KEY_EXCHANGE:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'ServerKeyExchange' Handshake message "
                "(%u %s)", action_str, version_str, (unsigned int) buflen,
                bytes_str);
              break;

            case SSL3_MT_CERTIFICATE_REQUEST:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'CertificateRequest' Handshake message "
                "(%u %s)", action_str, version_str, (unsigned int) buflen,
                bytes_str);
              break;

            case SSL3_MT_SERVER_DONE:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'ServerHelloDone' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              break;

            case SSL3_MT_CERTIFICATE_VERIFY:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'CertificateVerify' Handshake message "
                "(%u %s)", action_str, version_str, (unsigned int) buflen,
                bytes_str);
              break;

            case SSL3_MT_CLIENT_KEY_EXCHANGE:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'ClientKeyExchange' Handshake message "
                "(%u %s)", action_str, version_str, (unsigned int) buflen,
                bytes_str);
              break;

            case SSL3_MT_FINISHED:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'Finished' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              break;

#  if defined(SSL3_MT_CERTIFICATE_STATUS)
            case SSL3_MT_CERTIFICATE_STATUS:
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'CertificateStatus' Handshake message (%u %s)",
                action_str, version_str, (unsigned int) buflen, bytes_str);
              break;
#  endif /* SSL3_MT_CERTIFICATE_STATUS */

#  if defined(SSL3_MT_ENCRYPTED_EXTENSIONS)
            case SSL3_MT_ENCRYPTED_EXTENSIONS: {
              const unsigned char *msg;
              size_t msglen;
              BIO *bio;
              char *data = NULL;
              long datalen;

              msg = buf;
              msglen = buflen;

              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "[tls.msg] %s %s 'EncryptedExtensions' Handshake message "
                "(%u %s)", action_str, version_str, (unsigned int) buflen,
                bytes_str);

              bio = BIO_new(BIO_s_mem());

              msg += 4;
              msglen -= 4;

              BIO_puts(bio, "\nEncryptedExtensions:\n");
              tls_print_extensions(bio, "extensions", TRUE, &msg, &msglen);
              datalen = BIO_get_mem_data(bio, &data);
              if (data != NULL) {
                data[datalen] = '\0';
                (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                  "[tls.msg] %.*s", (int) datalen, data);
              }

              BIO_free(bio);
              break;
            }
#  endif /* SSL3_MT_ENCRYPTED_EXTENSIONS */
          }

        } else {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "[tls.msg] %s %s Handshake message, unknown type %d (%u %s)",
            action_str, version_str, content_type, (unsigned int) buflen,
            bytes_str);
        }

        break;
      }
    }

#  if defined(SSL3_RT_HEADER)
  } else if (version == 0 &&
             content_type == SSL3_RT_HEADER &&
             buflen == SSL3_RT_HEADER_LENGTH) {
    const unsigned char *msg;
    const char *record_type;
    unsigned int msg_len;

    msg = buf;
    record_type = tls_get_label(msg[0], tls_record_type_labels);
    msg_len = msg[buflen - 2] << 8 | msg[buflen - 1];

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.msg] %s protocol record message (content_type = %s, len = %u)",
      action_str, record_type, msg_len);
#  endif

  } else {
    /* This case might indicate an issue with OpenSSL itself; the version
     * given to the msg_callback function was not initialized, or not set to
     * one of the recognized SSL/TLS versions.  Weird.
     */

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "[tls.msg] %s message of unknown version %d, type %d (%u %s)",
      action_str, version, content_type, (unsigned int) buflen, bytes_str);
  }
}
# endif /* OpenSSL-0.9.7 or later */
#endif /* PR_USE_OPENSSL */

int proxy_tls_sess_init(pool *p, struct proxy_session *proxy_sess, int flags) {
#if defined(PR_USE_OPENSSL)
  config_rec *c;
  unsigned int enabled_proto_count = 0, tls_protocol = PROXY_TLS_PROTO_DEFAULT;
  int disabled_proto, res, xerrno = 0;
  const char *enabled_proto_str = NULL;
  char *ca_file = NULL, *ca_path = NULL, *cert_file = NULL, *key_file = NULL,
    *crl_file = NULL, *crl_path = NULL;

  if (proxy_sess == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (proxy_sess->use_ftp == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSEngine", FALSE);
  if (c != NULL) {
    tls_engine = *((int *) c->argv[0]);
  }

  if (tls_engine == PROXY_TLS_ENGINE_OFF) {
    return 0;
  }

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (ssl_ctx == NULL) {
    /* We haven't been initialized properly! */
    pr_trace_msg(trace_channel, 2, "%s",
      "missing required SSL_CTX initialization!");
    errno = EPERM;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    tls_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyTLSOptions", FALSE);
  }

  PRIVS_ROOT
  tls_ds.dsh = (tls_ds.open)(proxy_pool, tls_tables_path, tls_opts);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (tls_ds.dsh == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error opening TLS datastore: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSProtocol", FALSE);
  if (c != NULL) {
    tls_protocol = *((unsigned int *) c->argv[0]);
  }

  disabled_proto = get_disabled_protocols(tls_protocol);

  /* Per the comments in <ssl/ssl.h>, SSL_CTX_set_options() uses |= on
   * the previous value.  This means we can easily OR in our new option
   * values with any previously set values.
   */
  enabled_proto_str = get_enabled_protocols_str(main_server->pool,
    tls_protocol, &enabled_proto_count);

  pr_log_debug(DEBUG8, MOD_PROXY_VERSION ": supporting %s %s",
    enabled_proto_str,
    enabled_proto_count != 1 ? "protocols" : "protocol only");
  SSL_CTX_set_options(ssl_ctx, disabled_proto);

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCipherSuite", FALSE);
  while (c != NULL) {
    int protocol;

    pr_signals_handle();

    protocol = *((int *) c->argv[1]);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && \
    defined(TLS1_3_VERSION)
    if (protocol == PROXY_TLS_PROTO_TLS_V1_3) {
      tlsv13_cipher_suite = c->argv[0];

    } else {
      tls_cipher_suite = c->argv[0];
    }
#else
    tls_cipher_suite = c->argv[0];
#endif /* TLS1_3_VERSION */

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyTLSCipherSuite", FALSE);
  }

  if (tls_cipher_suite == NULL) {
    tls_cipher_suite = PROXY_TLS_DEFAULT_CIPHER_SUITE;
  }

  SSL_CTX_set_cipher_list(ssl_ctx, tls_cipher_suite);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && \
    defined(TLS1_3_VERSION)
  if (tlsv13_cipher_suite != NULL) {
    SSL_CTX_set_ciphersuites(ssl_ctx, tlsv13_cipher_suite);
  }
#endif /* TLS1_3_VERSION */

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSTimeoutHandshake",
    FALSE);
  if (c != NULL) {
    handshake_timeout = *((unsigned int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCACertificateFile",
    FALSE);
  if (c != NULL) {
    ca_file = c->argv[0];

  } else {
    ca_file = PR_CONFIG_DIR "/cacerts.pem";
    if (!file_exists2(p, ca_file)) {
      pr_trace_msg(trace_channel, 9,
        "warning: no default ProxyTLSCACertificateFile found at '%s'", ca_file);
      ca_file = NULL;
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCACertificatePath",
    FALSE);
  if (c != NULL) {
    ca_path = c->argv[0];
  }

  if (ca_file != NULL ||
      ca_path != NULL) {
    long verify_flags = 0;
    X509_VERIFY_PARAM *verify_param;

    /* Set the locations used for verifying certificates. */
    PRIVS_ROOT
    if (SSL_CTX_load_verify_locations(ssl_ctx, ca_file, ca_path) != 1) {
      PRIVS_RELINQUISH
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to set CA verification using file '%s' or "
        "directory '%s': %s", ca_file ? ca_file : "(none)",
        ca_path ? ca_path : "(none)", proxy_tls_get_errors());
      errno = EPERM;
      return -1;
    }
    PRIVS_RELINQUISH

    verify_param = X509_VERIFY_PARAM_new();

#if 0
/* NOTE: Many server certs may not have a CRL provider configured; such certs
 * would be deemed invalid/unusable by these CRL_CHECK flags.  So they are
 * disabled, for now.
 */
# if defined(X509_V_FLAG_CRL_CHECK)
    verify_flags |= X509_V_FLAG_CRL_CHECK;
# endif
# if defined(X509_V_FLAG_CRL_CHECK_ALL)
    verify_flags |= X509_V_FLAG_CRL_CHECK_ALL;
# endif
#endif

# if defined(X509_V_FLAG_TRUSTED_FIRST)
    verify_flags |= X509_V_FLAG_TRUSTED_FIRST;
# endif
# if defined(X509_V_FLAG_PARTIAL_CHAIN)
    verify_flags |= X509_V_FLAG_PARTIAL_CHAIN;
# endif

    if (X509_VERIFY_PARAM_set_flags(verify_param, verify_flags) != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error preparing X509 verification parameters: %s",
        proxy_tls_get_errors());

    } else {
      if (SSL_CTX_set1_param(ssl_ctx, verify_param) != 1) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error setting X509 verification parameters: %s",
          proxy_tls_get_errors());
      }
    }

  } else {
    /* Default to using locations set in the OpenSSL config file. */
    pr_trace_msg(trace_channel, 9,
      "using default OpenSSL CA verification locations (see $SSL_CERT_DIR "
      "environment variable)");

    if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error setting default CA verification locations: %s",
        proxy_tls_get_errors());
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCARevocationFile",
    FALSE);
  if (c != NULL) {
    crl_file = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCARevocationPath",
    FALSE);
  if (c != NULL) {
    crl_path = c->argv[0];
  }

  if (crl_file != NULL ||
      crl_path != NULL) {
    X509_STORE *crl_store;

    crl_store = X509_STORE_new();
    if (crl_store == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error allocating CRL store: %s", proxy_tls_get_errors());
      errno = EPERM;
      return -1;
    }

    if (X509_STORE_load_locations(crl_store, crl_file, crl_path) != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error loading ProxyTLSCARevocation files: %s", proxy_tls_get_errors());

    } else {
      SSL_CTX_set_cert_store(ssl_ctx, crl_store);
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSVerifyServer", FALSE);
  if (c != NULL) {
    tls_verify_server = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCertificateFile",
    FALSE);
  if (c != NULL) {
    cert_file = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSCertificateKeyFile",
    FALSE);
  if (c != NULL) {
    key_file = c->argv[0];

  } else {
    key_file = cert_file;
  }

  if (cert_file != NULL) {
    int ok = TRUE;

    PRIVS_ROOT
    res = SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM);
    PRIVS_RELINQUISH

    if (res != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error loading certificate from ProxyTLSCertificateFile '%s': %s",
        cert_file, proxy_tls_get_errors());
      ok = FALSE;
    }

    if (ok) {
      PRIVS_ROOT
      res = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM);
      PRIVS_RELINQUISH

      if (res != 1) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error loading private key from ProxyTLSCertificateKeyFile '%s': %s",
          key_file, proxy_tls_get_errors());
        ok = FALSE;
      }
    }

    if (ok) {
      res = SSL_CTX_check_private_key(ssl_ctx);
      if (res != 1) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "warning: ProxyTLSCertificateKeyFile '%s' private key does not "
          "match ProxyTLSCertificateFile '%s' certificate", key_file,
          cert_file);
      }
    }
  }

# if defined(PSK_MAX_PSK_LEN)
  c = find_config(main_server->conf, CONF_PARAM, "ProxyTLSPreSharedKey", FALSE);
  if (c != NULL) {
    const char *identity, *path;

    pr_signals_handle();

    identity = c->argv[0];
    path = c->argv[1];

    /* Advance past the "hex:" format prefix. */
    path += 4;

    res = tls_load_psk(identity, path);
    if (res < 0) {
      pr_log_debug(DEBUG2, MOD_PROXY_VERSION
        ": error loading ProxyTLSPreSharedKey file '%s': %s", path,
        strerror(errno));
    }
  }

  if (tls_psk_name != NULL) {
    pr_trace_msg(trace_channel, 9,
      "enabling support for PSK identities");
    SSL_CTX_set_psk_client_callback(ssl_ctx, tls_psk_cb);
  }
# endif /* PSK support */

# if !defined(OPENSSL_NO_TLSEXT) && defined(TLSEXT_STATUSTYPE_ocsp)
  SSL_CTX_set_tlsext_status_cb(ssl_ctx, tls_ocsp_response_cb);
# endif /* OCSP support */

  if (tls_opts & PROXY_TLS_OPT_ALLOW_WEAK_SECURITY) {
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_security_level(ssl_ctx, 0);
# endif /* OpenSSL-1.1.0 and later */
  }

  if (tls_opts & PROXY_TLS_OPT_ENABLE_DIAGS) {
    SSL_CTX_set_info_callback(ssl_ctx, tls_info_cb);
# if OPENSSL_VERSION_NUMBER > 0x000907000L
    SSL_CTX_set_msg_callback(ssl_ctx, tls_msg_cb);
# endif
  }

  if (netio_install_ctrl() < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error installing control connection proxy NetIO: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }
#endif /* PR_USE_OPENSSL */

  return 0;
}

int proxy_tls_sess_free(pool *p) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(PR_USE_OPENSSL)
  /* Reset any state, but only if we have not already negotiated an SSL
   * session.
   */

  if (session.rfc2228_mech == NULL) {
    handshake_timeout = 30;

    tls_opts = 0UL;
    tls_engine = PROXY_TLS_ENGINE_AUTO;
    tls_verify_server = TRUE;
    tls_cipher_suite = NULL;
# if OPENSSL_VERSION_NUMBER >= 0x10101000L && \
     defined(TLS1_3_VERSION)
    tlsv13_cipher_suite = NULL;
# endif /* TLS1_3_VERSION */

# if defined(PSK_MAX_PSK_LEN)
    tls_psk_name = NULL;
    tls_psk_bn = NULL;
    tls_psk_used = FALSE;
# endif /* PSK support */

    if (tls_ds.dsh != NULL) {
      (void) (tls_ds.close)(p, tls_ds.dsh);
      tls_ds.dsh = NULL;
    }

    if (ssl_ctx != NULL) {
      if (init_ssl_ctx() < 0) {
        return -1;
      }
    }

    if (tls_ctrl_netio != NULL) {
      pr_netio_t *using_netio = NULL;

      if (proxy_netio_using(PR_NETIO_STRM_CTRL, &using_netio) == 0) {
        if (using_netio == tls_ctrl_netio) {
          proxy_netio_use(PR_NETIO_STRM_CTRL, NULL);
        }
      }

      destroy_pool(tls_ctrl_netio->pool);
      tls_ctrl_netio = NULL;
    }
  }
#endif /* PR_USE_OPENSSL */

  return 0;
}
