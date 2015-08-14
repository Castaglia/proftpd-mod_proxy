/*
 * ProFTPD - mod_proxy FTP session routines
 * Copyright (c) 2013-2015 TJ Saunders
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
     * response message mentions a "PROXY" command, we will optimistically
     * try this FEAT command again.  Why?  It could be that the backend
     * server in question does not support the PROXY protocol, but the
     * configuration is telling mod_proxy to use it.  The FEAT command
     * would be the first command/response to read the backend control
     * connection's response to that "PROXY" command, and thus would appear
     * to fail like this.
     */
    if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
      if (strstr(resp->msg, "PROXY") != NULL) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "UseProxyProtocol ProxyOption in effect, but backend server %s does "
          "not support PROXY protocol ('%s %s'), retrying FEAT",
          pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
          resp->num, resp->msg);
        destroy_pool(tmp_pool);
        return proxy_ftp_sess_get_feat(p, proxy_sess);
      }
    }

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
  pool *tmp_pool;
  cmd_rec *cmd;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  use_tls = proxy_tls_use_tls();
  if (use_tls == PROXY_TLS_ENGINE_OFF) {
    pr_trace_msg(trace_channel, 19,
      "TLS support not enabled/desired, skipping");
    return 0;
  }

  /* Check for any per-URI scheme-based TLS requirements. */
  uri_tls = proxy_conn_get_tls(proxy_sess->dst_pconn);

  auth_feat = pr_table_get(proxy_sess->backend_features, C_AUTH, NULL);
  if (auth_feat == NULL) {
    /* Backend server does not indicate that it supports AUTH via FEAT. */

    /* If TLS is required, then fail now. */
    if (uri_tls == PROXY_TLS_ENGINE_ON ||
        use_tls == PROXY_TLS_ENGINE_ON) {
      const char *ip_str;

      ip_str = pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr);

      if (uri_tls == PROXY_TLS_ENGINE_ON) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "backend server %s does not support AUTH TLS (see FEAT response) but "
          "URI '%.100s' requires TLS, failing connection", ip_str,
          proxy_conn_get_uri(proxy_sess->dst_pconn));

      } else if (use_tls == PROXY_TLS_ENGINE_ON) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "backend server %s does not support AUTH TLS (see FEAT response) but "
          "ProxyTLSEngine requires TLS, failing connection", ip_str);
      }

      errno = EPERM;
      return -1;
    }

    /* Tell the Proxy NetIO API to NOT try to use our TLS NetIO. */
    proxy_netio_use(PR_NETIO_STRM_CTRL, NULL);

    pr_trace_msg(trace_channel, 9,
      "backend server does not support AUTH TLS (via FEAT), skipping");
    return 0;
  }

  if (strcasecmp(auth_feat, "AUTH SSL") == 0) {
    /* Legacy FTPS server; log and ignore this for now. */
    pr_trace_msg(trace_channel, 9,
      "backend server %s provides legacy FTPS support via '%s', ignoring",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      auth_feat);
  }

  tmp_pool = make_sub_pool(p);
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

  use_tls = proxy_tls_use_tls();
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
