/*
 * ProFTPD - mod_proxy RFC 4716 parsing
 * Copyright (c) 2026 TJ Saunders
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_proxy.h"
#include "proxy/session.h"
#include "proxy/ssh/crypto.h"
#include "proxy/ssh/certs.h"
#include "proxy/ssh/keys.h"
#include "proxy/ssh/rfc4716.h"

extern int ServerUseReverseDNS;

static const char *trace_channel = "proxy.ssh.rfc4716";

/* File-based key store implementation */

struct filestore_key {
  const char *subject;

  /* Optional headers */
  pr_table_t *headers;

  /* Key data */
  unsigned char *key_data;
  uint32_t key_datalen;
};

struct filestore_data {
  pr_fh_t *fh;
  const char *path;
  unsigned int lineno;
};

/* This getline() function is quite similar to pr_fsio_getline(), except
 * that it a) enforces the 72-byte max line length from RFC4716, and b)
 * properly handles lines ending with CR, LF, or CRLF.
 *
 * Technically it allows one more byte than necessary, since the worst case
 * is 74 bytes (72 + CRLF); this also means 73 + CR or 73 + LF.  The extra
 * byte is for the terminating NUL.
 */
static char *filestore_getline(struct filestore_data *store_data, pool *p) {
  char linebuf[75], *line = "", *res;

  while (TRUE) {
    size_t linelen;

    pr_signals_handle();

    memset(&linebuf, '\0', sizeof(linebuf));
    res = pr_fsio_gets(linebuf, sizeof(linebuf) - 1, store_data->fh);

    if (res == NULL) {
      if (errno == EINTR) {
        continue;
      }

      pr_trace_msg(trace_channel, 10, "reached end of '%s', no matching "
        "key found", store_data->path);
      errno = EOF;
      return NULL;
    }

    linelen = strlen(linebuf);
    if (linelen >= 1) {

      /* Check for the CRLF case first.  If those are not present, then we
       * check for either CR or LF.  Doing the "CR or LF" check first prevents
       * us from properly handling CRLFs, and thus lead to Issue #1904.
       */

      if (linelen >= 2 &&
          linebuf[linelen - 2] == '\r' &&
          linebuf[linelen - 1] == '\n') {
        char *tmp;
        unsigned int header_taglen, header_valuelen;
        int have_line_continuation = FALSE;

        store_data->lineno++;

        linebuf[linelen - 2] = '\0';
        linebuf[linelen - 1] = '\0';
        line = pstrcat(p, line, linebuf, NULL);

        if (line[0] != '\0' &&
            line[strlen(line) - 1] == '\\') {
          have_line_continuation = TRUE;
          line[strlen(line) - 1] = '\0';
        }

        tmp = strchr(line, ':');
        if (tmp == NULL) {
          return line;
        }

        /* We have a header.  Make sure the header tag is not longer than
         * the specified length of 64 bytes, and that the header value is
         * not longer than 1024 bytes.
         */
        header_taglen = tmp - line;
        if (header_taglen > 64) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "header tag too long (%u) on line %u of '%s'", header_taglen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        /* Header value starts at 2 after the ':' (one for the mandatory
         * space character.
         */
        header_valuelen = strlen(line) - (header_taglen + 2);
        if (header_valuelen > 1024) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "header value too long (%u) on line %u of '%s'", header_valuelen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        if (have_line_continuation == FALSE) {
          return line;
        }

        continue;

      } else if (linebuf[linelen - 1] == '\r' ||
                 linebuf[linelen - 1] == '\n') {
        char *tmp;
        unsigned int header_taglen, header_valuelen;
        int have_line_continuation = FALSE;

        store_data->lineno++;

        linebuf[linelen - 1] = '\0';
        line = pstrcat(p, line, linebuf, NULL);

        if (line[0] != '\0' &&
            line[strlen(line) - 1] == '\\') {
          have_line_continuation = TRUE;
          line[strlen(line) - 1] = '\0';
        }

        tmp = strchr(line, ':');
        if (tmp == NULL) {
          return line;
        }

        /* We have a header.  Make sure the header tag is not longer than
         * the specified length of 64 bytes, and that the header value is
         * not longer than 1024 bytes.
         */
        header_taglen = tmp - line;
        if (header_taglen > 64) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "header tag too long (%u) on line %u of '%s'", header_taglen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        /* Header value starts at 2 after the ':' (one for the mandatory
         * space character.
         */
        header_valuelen = strlen(line) - (header_taglen + 2);
        if (header_valuelen > 1024) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "header value too long (%u) on line %u of '%s'", header_valuelen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        if (have_line_continuation == FALSE) {
          return line;
        }

        continue;

      } else if (linelen < sizeof(linebuf)) {
        /* No CR or LF terminator; maybe a badly formatted file?  Try to
         * work with the data, if we can.
         */
        line = pstrcat(p, line, linebuf, NULL);
        return line;

      } else {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "line too long (%lu) on line %u of '%s'", (unsigned long) linelen,
          store_data->lineno, store_data->path);
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "Make sure that '%s' is a RFC4716 formatted key", store_data->path);
        errno = EINVAL;
        break;
      }
    }
  }

  return NULL;
}

static struct filestore_key *filestore_alloc_key(pool *p) {
  struct filestore_key *key = NULL;

  key = pcalloc(p, sizeof(struct filestore_key));
  key->headers = pr_table_nalloc(p, 0, 1);

  return key;
}

static struct filestore_key *filestore_get_key(
    struct filestore_data *store_data, pool *p) {
  char *line;
  BIO *bio = NULL;
  struct filestore_key *key = NULL;
  size_t begin_markerlen = 0, end_markerlen = 0;

  line = filestore_getline(store_data, p);
  while (line == NULL &&
         errno == EINVAL) {
    pr_signals_handle();

    line = filestore_getline(store_data, p);
  }

  if (line == NULL) {
    return NULL;
  }

  begin_markerlen = strlen(PROXY_SSH_SSH2_PUBKEY_BEGIN_MARKER);
  end_markerlen = strlen(PROXY_SSH_SSH2_PUBKEY_END_MARKER);

  while (line != NULL) {
    pr_signals_handle();

    if (key == NULL &&
        strncmp(line, PROXY_SSH_SSH2_PUBKEY_BEGIN_MARKER,
        begin_markerlen + 1) == 0) {
      key = filestore_alloc_key(p);
      bio = BIO_new(BIO_s_mem());

    } else if (key != NULL &&
               strncmp(line, PROXY_SSH_SSH2_PUBKEY_END_MARKER,
                 end_markerlen + 1) == 0) {
      if (bio != NULL) {
        BIO *b64 = NULL, *bmem = NULL;
        char chunk[1024], *data = NULL;
        int chunklen;
        long datalen = 0;

        /* Add a base64 filter BIO, and read the data out, thus base64-decoding
         * the key.  Write the decoded data into another memory BIO.
         */
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        bmem = BIO_new(BIO_s_mem());

        memset(chunk, '\0', sizeof(chunk));
        chunklen = BIO_read(bio, chunk, sizeof(chunk));

        if (chunklen < 0 &&
            !BIO_should_retry(bio)) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "unable to base64-decode data in '%s': %s",
            store_data->path, proxy_ssh_crypto_get_errors());
          BIO_free_all(bio);
          BIO_free_all(bmem);

          errno = EPERM;
          return NULL;
        }

        while (chunklen > 0) {
          pr_signals_handle();

          if (BIO_write(bmem, chunk, chunklen) < 0) {
            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "error writing to memory BIO: %s", proxy_ssh_crypto_get_errors());
            BIO_free_all(bio);
            BIO_free_all(bmem);

            errno = EPERM;
            return NULL;
          }

          memset(chunk, '\0', sizeof(chunk));
          chunklen = BIO_read(bio, chunk, sizeof(chunk));
        }

        datalen = BIO_get_mem_data(bmem, &data);

        if (data != NULL &&
            datalen > 0) {
          key->key_data = palloc(p, datalen);
          key->key_datalen = datalen;
          memcpy(key->key_data, data, datalen);

        } else {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error base64-decoding key data in '%s'", store_data->path);
        }

        BIO_free_all(bio);
        bio = NULL;

        BIO_free_all(bmem);
      }

      break;

    } else {
      if (key != NULL) {
        char *ptr;

        ptr = strstr(line, ": ");
        if (ptr != NULL) {
          /* We have a header. */
          char *tag, *text;

          tag = pstrndup(p, line, ptr - line);
          text = pstrdup(p, ptr + 2);
          if (pr_table_add(key->headers, tag, text, 0) < 0) {
            pr_trace_msg(trace_channel, 4,
             "failed to add header '%s' to notes: %s", tag, strerror(errno));

          } else {
            pr_trace_msg(trace_channel, 22, "added header '%s: %s' to notes",
              tag, text);
          }

        } else {
          if (BIO_write(bio, line, strlen(line)) < 0) {
            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "error buffering base64 data");
          }
        }

      } else {
        /* We have a line of unexpected format.  Log it, at least, for
         * debugging/diagnosis.
         */
        pr_trace_msg(trace_channel, 20, "unexpected text at line %u: '%s'",
          store_data->lineno, line);
      }
    }

    line = filestore_getline(store_data, p);
    while (line == NULL &&
           errno == EINVAL) {
      pr_signals_handle();

      line = filestore_getline(store_data, p);
    }
  }

  if (bio != NULL) {
    BIO_free_all(bio);
    bio = NULL;
  }

  return key;
}

int proxy_ssh_rfc4716_is_revoked_key(const struct proxy_session *proxy_sess,
    pool *p, const char *path, unsigned char *public_key,
    uint32_t public_keylen) {
  int res, xerrno;
  pool *tmp_pool;
  struct filestore_data *store_data;
  struct filestore_key *key = NULL;
  pr_fh_t *fh;
  struct stat st;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Proxy SSH File-based Keystore Pool");

  PRIVS_ROOT
  fh = pr_fsio_open(path, O_RDONLY|O_NONBLOCK);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fh == NULL) {
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (pr_fsio_set_block(fh) < 0) {
    xerrno = errno;

    destroy_pool(tmp_pool);
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return -1;
  }

  /* Stat the opened file to determine the optimal buffer size for IO. */
  memset(&st, 0, sizeof(st));
  if (pr_fsio_fstat(fh, &st) < 0) {
    xerrno = errno;

    destroy_pool(tmp_pool);
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    destroy_pool(tmp_pool);
    (void) pr_fsio_close(fh);

    errno = EISDIR;
    return -1;
  }

  fh->fh_iosz = st.st_blksize;

  store_data = pcalloc(tmp_pool, sizeof(struct filestore_data));
  store_data->path = path;
  store_data->fh = fh;
  store_data->lineno = 0;

  res = -1;

  /* XXX Note that this will scan the file from the beginning, each time.
   * There's room for improvement; perhaps mmap() the file into memory?
   */

  key = filestore_get_key(store_data, tmp_pool);
  while (key != NULL) {
    int ok;

    pr_signals_handle();

    ok = proxy_ssh_keys_compare_keys(tmp_pool, public_key, public_keylen,
      key->key_data, key->key_datalen);
    if (ok == TRUE) {
      res = TRUE;
      break;
    }

    key = filestore_get_key(store_data, tmp_pool);
  }

  if (res == TRUE) {
    pr_trace_msg(trace_channel, 10, "found matching revoked public key in '%s'",
      store_data->path);
  }

  if (pr_fsio_lseek(store_data->fh, 0, SEEK_SET) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error seeking to start of '%s': %s", store_data->path, strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  store_data->lineno = 0;
  pr_fsio_close(fh);
  destroy_pool(tmp_pool);

  return res;
}

int proxy_ssh_rfc4716_verify_host_cert(const struct proxy_session *proxy_sess,
    pool *p, const char *path, struct proxy_ssh_cert *cert,
    unsigned long cert_opts) {
  int matched_principal = FALSE, res, xerrno;
  pool *tmp_pool;
  struct filestore_data *store_data;
  struct filestore_key *key = NULL;
  pr_fh_t *fh;
  struct stat st;
  const char *host_ip, *host_fqdn = NULL;

  host_ip = host_fqdn = pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr);

  if (ServerUseReverseDNS) {
    host_fqdn = pr_netaddr_get_dnsstr(proxy_sess->backend_ctrl_conn->remote_addr);
  }

  /* Verify the principals list contains the given name/IP of the host. */
  if (cert->principals == NULL &&
      (cert_opts & PROXY_SSH_CERT_OPT_ALLOW_EMPTY_PRINCIPALS)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "%s host certificate has empty principals, using AllowEmptyPrincipals "
      "to authenticate host '%s' (%s)", cert->cert_algo, host_fqdn, host_ip);
    matched_principal = TRUE;

  } else {
    register unsigned int i;

    for (i = 0; i < cert->principals->nelts; i++) {
      const char *principal;

      principal = ((char **) cert->principals->elts)[i];

      pr_trace_msg(trace_channel, 25,
        "comparing host certificate principal '%s' against host '%s' (%s)",
        principal, host_fqdn, host_ip);

      if (cert_opts & PROXY_SSH_CERT_OPT_ALLOW_MATCH_PRINCIPALS) {
        if (pr_fnmatch(principal, host_fqdn, 0) == 0) {
          matched_principal = TRUE;

        } else if (pr_fnmatch(principal, host_ip, 0) == 0) {
          matched_principal = TRUE;
        }

      } else {
        if (strcasecmp(principal, host_fqdn) == 0) {
          matched_principal = TRUE;

        } else if (strcmp(principal, host_ip) == 0) {
          matched_principal = TRUE;
        }
      }

      if (matched_principal == TRUE) {
        break;
      }
    }
  }

  if (matched_principal == FALSE) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "%s certificate is invalid, for host '%s' (%s) is not a listed principal",
      cert->cert_algo, host_fqdn, host_ip);
    destroy_pool(cert->cert_pool);
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Proxy SSH File-based Keystore Pool");

  PRIVS_ROOT
  fh = pr_fsio_open(path, O_RDONLY|O_NONBLOCK);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fh == NULL) {
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (pr_fsio_set_block(fh) < 0) {
    xerrno = errno;

    destroy_pool(tmp_pool);
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return -1;
  }

  /* Stat the opened file to determine the optimal buffer size for IO. */
  memset(&st, 0, sizeof(st));
  if (pr_fsio_fstat(fh, &st) < 0) {
    xerrno = errno;

    destroy_pool(tmp_pool);
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    destroy_pool(tmp_pool);
    (void) pr_fsio_close(fh);

    errno = EISDIR;
    return -1;
  }

  fh->fh_iosz = st.st_blksize;

  store_data = pcalloc(tmp_pool, sizeof(struct filestore_data));
  store_data->path = path;
  store_data->fh = fh;
  store_data->lineno = 0;

  res = -1;

  /* XXX Note that this will scan the file from the beginning, each time.
   * There's room for improvement; perhaps mmap() the file into memory?
   */

  res = -1;
  key = filestore_get_key(store_data, tmp_pool);
  while (key != NULL) {
    int ok;

    pr_signals_handle();

    ok = proxy_ssh_keys_compare_keys(p, cert->signature_pubkey_data,
      cert->signature_pubkey_datalen, key->key_data, key->key_datalen);
    if (ok != TRUE) {
      if (ok == -1) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error comparing keys from '%s': %s", store_data->path,
          strerror(errno));
      }

    } else {
      /* XXX Verify that the user and the host_user match?? */
      res = 0;
      break;
    }

    key = filestore_get_key(store_data, tmp_pool);
  }

  if (res == 0) {
    pr_trace_msg(trace_channel, 10, "found matching public key for in '%s'",
      store_data->path);
  }

  if (pr_fsio_lseek(store_data->fh, 0, SEEK_SET) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error seeking to start of '%s': %s", store_data->path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  store_data->lineno = 0;
  pr_fsio_close(fh);
  destroy_pool(tmp_pool);

  return res;
}
