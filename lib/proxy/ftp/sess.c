/*
 * ProFTPD - mod_proxy FTP session routines
 * Copyright (c) 2013-2016 TJ Saunders
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
#include "proxy/tls.h"
#include "proxy/ftp/sess.h"
#include "proxy/ftp/ctrl.h"

static const char *feat_crlf = "\r\n";

static const char *trace_channel = "proxy.ftp.sess";

/* Many FTP servers (e.g. IIS) use the semicolon delimiter syntax, as used
 * for listing the MLSD/MLST facts, for other FEAT values (e.g. AUTH, PROT,
 * etc).
 *
 * NOTE: Should this return a table rather than an array, for easier lookup
 * of parsed values by callers?
 */
static int parse_feat(pool *p, const char *feat, array_header **res) {
  char *ptr, *ptr2 = NULL;
  array_header *vals;
  size_t len;

  if (feat == NULL) {
    return 0;
  }

  vals = make_array(p, 1, sizeof(char *));

  /* No semicolons in this value?  No work to do...*/
  ptr = strchr(feat, ';');
  if (ptr == NULL) {
    *((char **) push_array(vals)) = pstrdup(p, feat);
    *res = vals;
    return vals->nelts;
  }

  len = ptr - feat;
  if (len > 0) {
    *((char **) push_array(vals)) = pstrndup(p, feat, len);
  }

  /* Watch for any sequences of just semicolons. */
  while (*ptr == ';') {
    pr_signals_handle();
    ptr++;
  }

  ptr2 = strchr(ptr, ';');
  while (ptr2 != NULL) {
    pr_signals_handle();

    len = ptr2 - ptr;
    if (len > 0) {
      *((char **) push_array(vals)) = pstrndup(p, ptr, len);
    }
 
    ptr = ptr2;
    while (*ptr == ';') {
      pr_signals_handle();
      ptr++;
    }

    ptr2 = strchr(ptr, ';');
  }

  /* Since the semicolon delimiter syntax uses a trailing semicolon,
   * we shouldn't need to worry about something like "...;FOO".  Right?
   */

  *res = vals;
  return vals->nelts;
}

int proxy_ftp_sess_get_feat(pool *p, struct proxy_session *proxy_sess) {
  pool *tmp_pool;
  int res, xerrno = 0;
  cmd_rec *cmd;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  char *feats, *token;
  size_t token_len = 0;

  tmp_pool = make_sub_pool(p);

  cmd = pr_cmd_alloc(tmp_pool, 1, C_FEAT);
  res = proxy_ftp_ctrl_send_cmd(tmp_pool, proxy_sess->backend_ctrl_conn, cmd);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error sending %s to backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  if (resp->num[0] != '2') {
    pr_trace_msg(trace_channel, 4,
      "received unexpected %s response code %s from backend",
      (char *) cmd->argv[0], resp->num);

    /* Note: If the UseProxyProtocol ProxyOption is enabled, AND if the
     * response message mentions a "PROXY" command, we might read an
     * error response here that is NOT actually for the FEAT command we just
     * sent.
     *
     * A backend FTP server which does not understand the PROXY protocol
     * will treat it as a normal FTP command, and respond.  And that will
     * put us, the client, out of lockstep with the server, for how do we know
     * that we need to read that error response FIRST, then send another
     * command?
     */

    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  proxy_sess->backend_features = pr_table_nalloc(p, 0, 4);

  feats = resp->msg;
  token = pr_str_get_token2(&feats, (char *) feat_crlf, &token_len);
  while (token != NULL) {
    pr_signals_handle();

    if (token_len > 0) {
      /* The FEAT response lines in which we are interested all start with
       * a single space, per RFC spec.  Ignore any other lines.
       */
      if (token[0] == ' ') {
        char *key, *val, *ptr;

        /* Find the next space in the string, to delimit our key/value pairs. */
        ptr = strchr(token + 1, ' ');
        if (ptr != NULL) {
          key = pstrndup(p, token + 1, ptr - token - 1);
          val = pstrdup(p, ptr + 1);

        } else {
          key = pstrdup(p, token + 1);
          val = pstrdup(p, "");
        }

        pr_table_add(proxy_sess->backend_features, key, val, 0);
      }
    }

    feats = token + token_len + 1;
    token = pr_str_get_token2(&feats, (char *) feat_crlf, &token_len);
  }

  destroy_pool(tmp_pool);
  return 0;
}

static pr_response_t *send_recv(pool *p, conn_t *conn, cmd_rec *cmd,
    unsigned int *resp_nlines) {
  int res, xerrno;
  pr_response_t *resp;

  res = proxy_ftp_ctrl_send_cmd(p, conn, cmd);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error sending '%s %s' to backend: %s", (char *) cmd->argv[0], cmd->arg,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  resp = proxy_ftp_ctrl_recv_resp(p, conn, resp_nlines);
  if (resp == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  return resp;
}

int proxy_ftp_sess_send_host(pool *p, struct proxy_session *proxy_sess) {
  pool *tmp_pool;
  int xerrno = 0;
  cmd_rec *cmd;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  const char *host;

  if (pr_table_get(proxy_sess->backend_features, C_HOST, NULL) == NULL) {
    pr_trace_msg(trace_channel, 9,
      "HOST not supported by backend server, ignoring");
    return 0;
  }

  tmp_pool = make_sub_pool(p);

  host = proxy_conn_get_host(proxy_sess->dst_pconn);
  cmd = pr_cmd_alloc(tmp_pool, 2, C_HOST, host);
  cmd->arg = pstrdup(tmp_pool, host);

  resp = send_recv(tmp_pool, proxy_sess->backend_ctrl_conn, cmd, &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (resp->num[0] != '2') {
    pr_trace_msg(trace_channel, 4,
      "received unexpected %s response code %s from backend",
      (char *) cmd->argv[0], resp->num);
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  destroy_pool(tmp_pool);
  return 0;
}

int proxy_ftp_sess_send_auth_tls(pool *p, struct proxy_session *proxy_sess) {
  int uri_tls, use_tls, xerrno;
  char *auth_feat;
  array_header *auth_feats = NULL;
  pool *tmp_pool;
  cmd_rec *cmd;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  use_tls = proxy_tls_using_tls();
  if (use_tls == PROXY_TLS_ENGINE_OFF) {
    pr_trace_msg(trace_channel, 19,
      "TLS support not enabled/desired, skipping");
    return 0;
  }

  /* Check for any per-URI scheme-based TLS requirements. */
  uri_tls = proxy_conn_get_tls(proxy_sess->dst_pconn);

  auth_feat = pr_table_get(proxy_sess->backend_features, C_AUTH, NULL);
  if (auth_feat == NULL) {
    /* Backend server does not indicate that it supports AUTH via FEAT.
     *
     * Even though this is the case, we will still try to send the AUTH
     * command.  A malicious attacker could be modifying the plaintext
     * FEAT listing, to make us think that TLS is not supported, and thus
     * prevent us from encrypting the session (a la "SSL stripping").
     */

    /* If TLS is required, then complain loudly.  */
    if (uri_tls == PROXY_TLS_ENGINE_ON ||
        use_tls == PROXY_TLS_ENGINE_ON) {
      const char *ip_str;

      ip_str = pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr);

      if (uri_tls == PROXY_TLS_ENGINE_ON) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "backend server %s does not support AUTH TLS (see FEAT response) but "
          "URI '%.100s' requires TLS, attempting anyway", ip_str,
          proxy_conn_get_uri(proxy_sess->dst_pconn));

      } else if (use_tls == PROXY_TLS_ENGINE_ON) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "backend server %s does not support AUTH TLS (see FEAT response) but "
          "ProxyTLSEngine requires TLS, attempting anyway", ip_str);
      }
    }

    pr_trace_msg(trace_channel, 9,
      "backend server does not support AUTH TLS (via FEAT)");
  }

  tmp_pool = make_sub_pool(p);

  /* Note: the FEAT response against IIS servers shows e.g.:
   *
   * 211-Extended features supported:
   *  LANG EN*
   *  UTF8
   *  AUTH TLS;TLS-C;SSL;TLS-P;
   *  PBSZ
   *  PROT C;P;
   *  CCC
   *  HOST
   *  SIZE
   *  MDTM
   *  REST STREAM
   * 211 END
   *
   * Note how the AUTH and PROT values are not exactly as specified
   * in RFC 4217.  This means we'll need to deal with it as is.  There will
   * be other servers with other FEAT response formats, too.
   */
  if (parse_feat(tmp_pool, auth_feat, &auth_feats) > 0) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 9, "parsed FEAT value '%s' into %d values",
      auth_feat, auth_feats->nelts);
    for (i = 0; i < auth_feats->nelts; i++) {
      char *val;

      val = ((char **) auth_feats->elts)[i];
      pr_trace_msg(trace_channel, 9, " %s", val);
    }
  }

  /* XXX How should we interoperate with servers that support/want the
   * older formats, e.g.:
   *
   *  AUTH SSL (which automatically assumes PBSZ 0, PROT P)
   *  AUTH TLS-P (synonym for AUTH SSL)
   *  AUTH TLS-C (synonym for AUTH TLS)
   */

  cmd = pr_cmd_alloc(tmp_pool, 2, C_AUTH, "TLS");
  cmd->arg = pstrdup(tmp_pool, "TLS");

  resp = send_recv(tmp_pool, proxy_sess->backend_ctrl_conn, cmd, &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;

    proxy_netio_use(PR_NETIO_STRM_CTRL, NULL);
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (resp->num[0] != '2') {
    if (uri_tls != PROXY_TLS_ENGINE_ON &&
        use_tls != PROXY_TLS_ENGINE_ON) {
      proxy_tls_set_tls(PROXY_TLS_ENGINE_OFF);
      errno = ENOSYS;
      return -1;
    }

    /* XXX Some older servers might respond with a 334 response code, per
     * RFC 2228.  See, for example:
     *   http://serverfault.com/questions/640978/ftp-alter-server-response-in-transit
     */
    pr_trace_msg(trace_channel, 4,
      "received unexpected %s response code %s from backend",
      (char *) cmd->argv[0], resp->num);

    proxy_netio_use(PR_NETIO_STRM_CTRL, NULL);
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  destroy_pool(tmp_pool);
  return 0;
}

int proxy_ftp_sess_send_pbsz_prot(pool *p, struct proxy_session *proxy_sess) {
  int use_tls;

  use_tls = proxy_tls_using_tls();
  if (use_tls == PROXY_TLS_ENGINE_OFF) {
    pr_trace_msg(trace_channel, 19,
      "TLS support not enabled/desired, skipping");
    return 0;
  }

  if (pr_table_get(proxy_sess->backend_features, C_PBSZ, NULL) != NULL) {
    int xerrno;
    pool *tmp_pool;
    cmd_rec *cmd;
    pr_response_t *resp;
    unsigned int resp_nlines = 0;

    tmp_pool = make_sub_pool(p);

    cmd = pr_cmd_alloc(tmp_pool, 2, C_PBSZ, "0");
    cmd->arg = pstrdup(tmp_pool, "0");

    resp = send_recv(tmp_pool, proxy_sess->backend_ctrl_conn, cmd,
      &resp_nlines);
    if (resp == NULL) {
      xerrno = errno;
      destroy_pool(tmp_pool);
      errno = xerrno;
      return -1;
    }

    if (resp->num[0] != '2') {
      pr_trace_msg(trace_channel, 4,
        "received unexpected %s response code %s from backend",
        (char *) cmd->argv[0], resp->num);
      destroy_pool(tmp_pool);
      errno = EPERM;
      return -1;
    }

    destroy_pool(tmp_pool);
  }

  if (pr_table_get(proxy_sess->backend_features, C_PROT, NULL) != NULL) {
    int xerrno;
    pool *tmp_pool;
    cmd_rec *cmd;
    pr_response_t *resp;
    unsigned int resp_nlines = 0;

    tmp_pool = make_sub_pool(p);

    cmd = pr_cmd_alloc(tmp_pool, 2, C_PROT, "P");
    cmd->arg = pstrdup(tmp_pool, "P");

    resp = send_recv(tmp_pool, proxy_sess->backend_ctrl_conn, cmd,
      &resp_nlines);
    if (resp == NULL) {
      xerrno = errno;
      destroy_pool(tmp_pool);
      errno = xerrno;
      return -1;
    }

    if (resp->num[0] != '2') {
      pr_trace_msg(trace_channel, 4,
        "received unexpected %s response code %s from backend",
        (char *) cmd->argv[0], resp->num);
      destroy_pool(tmp_pool);
      errno = EPERM;
      return -1;
    }

    destroy_pool(tmp_pool);
  }

  return 0;
}
