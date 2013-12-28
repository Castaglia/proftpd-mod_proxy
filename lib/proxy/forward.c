/*
 * ProFTPD - mod_proxy forward-proxy implementation
 * Copyright (c) 2012-2013 TJ Saunders
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
#include "proxy/forward.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/feat.h"

static int proxy_method = PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH;

static const char *trace_channel = "proxy.forward";

int proxy_forward_init(pool *p) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyForwardMethod", FALSE);
  if (c != NULL) {
    proxy_method = *((int *) c->argv[0]);
  }

  return 0;
}

int proxy_forward_have_authenticated(cmd_rec *cmd) {
  int authd = FALSE;

  /* XXX Use a state variable here, which returns true when we have seen
   * a successful response to the PASS command...but only if we do NOT connect
   * to the backend at connect time (for then we are handling all FTP
   * commands, until the client sends USER).
   *
   * And does this mean authenticated *to the proxy*, or to the
   * backend/destination server?  As far as the command dispatching code
   * goes, I think this means "authenticated locally", i.e. should we allow
   * more commands, or reject them because the client hasn't authenticated
   * yet.
   */

  switch (proxy_method) {
    case PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH:
      authd = TRUE;
      break;

    case PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH:
    default:
      /* XXX Remove this once we're better implemented */
      authd = TRUE;
  }

  return authd;
}

static int forward_connect(pool *p, struct proxy_session *proxy_sess,
    pr_netaddr_t *remote_addr,
    pr_response_t **resp, unsigned int *resp_nlines) {
  conn_t *server_conn = NULL;
  int banner_ok = TRUE;

  server_conn = proxy_conn_get_server_conn(p, proxy_sess, remote_addr);
  if (server_conn == NULL) {
    return -1;
  }

  /* XXX Support/send a CLNT command of our own?  Configurable via e.g.
   * "UserAgent" string?
   */

  proxy_sess->frontend_ctrl_conn = session.c;
  proxy_sess->backend_ctrl_conn = server_conn;

  /* Read the response from the backend server. */
  *resp = proxy_ftp_ctrl_recv_resp(p, proxy_sess->backend_ctrl_conn,
    resp_nlines);
  if (*resp == NULL) {
    int xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if ((*resp)->num[0] != '2') {
    banner_ok = FALSE;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "received banner from backend %s:%u%s: %s %s",
    pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
    ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
    banner_ok ? "" : ", DISCONNECTING", (*resp)->num, (*resp)->msg);

  if (banner_ok == FALSE) {
    pr_inet_close(p, proxy_sess->backend_ctrl_conn);
    proxy_sess->backend_ctrl_conn = NULL;
    return -1;
  }

  /* Get the features supported by the backend server */
  if (proxy_ftp_feat_get(p, proxy_sess) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to determine features of backend server: %s", strerror(errno));
  }

  proxy_sess_state |= PROXY_SESS_STATE_CONNECTED;
  return 0;
}

static int forward_user_noproxyauth_parse(pool *p, const char *arg,
    char **name, struct proxy_conn **pconn) {
  const char *default_proto = NULL, *default_port = NULL, *proto = NULL,
    *port, *uri = NULL;
  char *host = NULL, *host_ptr = NULL, *port_ptr = NULL;

  /* TODO: Revisit theses default once we start supporting other protocols. */
  default_proto = "ftp";
  default_port = "21";

  /* First, look for the optional port. */
  port_ptr = strrchr(arg, ':');
  if (port_ptr == NULL) {
    port = default_port;

  } else {
    char *tmp2 = NULL;
    long num;

    num = strtol(port_ptr+1, &tmp2, 10);

    if (tmp2 && *tmp2) {
      /* Trailing garbage found in port number. */
      pr_trace_msg(trace_channel, 1,
        "malformed port number '%s' found in USER '%s', rejecting",
        port_ptr+1, arg);
      errno = EINVAL;
      return -1;
    }

    if (num < 0 ||
        num > 65535) {
      pr_trace_msg(trace_channel, 1,
        "invalid port number %ld found in USER '%s', rejecting", num, arg);
      errno = EINVAL;
      return -1;
    }

    port = pstrdup(p, port_ptr + 1);
  }

  /* Find the required '@' delimiter. */
  host_ptr = strrchr(arg, '@');
  if (host_ptr == NULL) {
    pr_trace_msg(trace_channel, 1,
      "missing required '@' delimiter in USER '%s', rejecting", arg);
    errno = EINVAL;
    return -1;
  }

  if (port_ptr == NULL) {
    host = pstrdup(p, host_ptr + 1);

  } else {
    host = pstrndup(p, host_ptr + 1, (port_ptr - host_ptr - 1));
  }

  *name = pstrndup(p, arg, (host_ptr - arg));
  proto = default_proto;

  uri = pstrcat(p, proto, "://", host, ":", port, NULL);

  /* Note: We deliberately use proxy_pool, rather than the given pool, here
   * so that the created structure (especially the pr_netaddr_t) are
   * longer-lived.
   */
  *pconn = proxy_conn_create(proxy_pool, uri);
  if (*pconn == NULL) {
    return -1;
  }

  return 0;
}

static int forward_handle_user_noproxyauth(cmd_rec *cmd,
    struct proxy_session *proxy_sess, int *ok) {
  int res, xerrno;
  char *user = NULL;
  cmd_rec *user_cmd = NULL;
  struct proxy_conn *pconn = NULL;
  pr_netaddr_t *remote_addr = NULL;
  pr_response_t *banner = NULL, *resp = NULL;
  unsigned int banner_nlines = 0, resp_nlines = 0;

  res = forward_user_noproxyauth_parse(cmd->tmp_pool, cmd->arg, &user, &pconn);
  if (res < 0) {
    return -1;
  }

  remote_addr = proxy_conn_get_addr(pconn);

  res = forward_connect(proxy_pool, proxy_sess, remote_addr, &banner,
    &banner_nlines);
  if (res < 0) {
    *ok = FALSE;

    /* Send a failed USER response to our waiting frontend client, but do
     * not necessarily close the frontend connection.
     */
    resp = pcalloc(cmd->tmp_pool, sizeof(pr_response_t));
    resp->num = R_530;

    if (banner != NULL) {
      resp->msg = banner->msg;
      resp_nlines = banner_nlines;

    } else {
      char *host_ptr = NULL;

      host_ptr = strrchr(cmd->arg, '@');

      resp->msg = pstrcat(cmd->tmp_pool, "Unable to connect to ",
        host_ptr + 1, NULL);
      resp_nlines = 1;
    }

    res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
      proxy_sess->frontend_ctrl_conn, resp, resp_nlines);
    if (res < 0) {
      xerrno = errno;

      pr_response_block(TRUE);
      errno = xerrno;
      return -1;
    }

    return 0;
  }

  /* Change the command so that it no longer includes the proxy info. */
  user_cmd = pr_cmd_alloc(cmd->pool, 2, C_USER, user);
  user_cmd->arg = user;
  pr_cmd_clear_cache(user_cmd);

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    user_cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", user_cmd->argv[0], strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (resp->num[0] == '2' ||
      resp->num[0] == '3') {
    *ok = TRUE;
  }

  /* XXX TODO: Concatenate the banner from the connect with the USER response
   * message here, and send the entire kit to the frontend client, e.g.:
   * 
   *  Name (gatekeeper:you): anonymous@ftp.uu.net
   *  331-(----GATEWAY CONNECTED TO ftp.uu.net----)
   *  331-(220 ftp.uu.net FTP server (SunOS 4.1) ready. 
   *  331 Guest login ok, send ident as password.
   *  Password: ######
   *  230 Guest login ok, access restrictions apply.
   *  ftp> dir
   */

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return -1;
  }

  return 0; 
}

int proxy_forward_handle_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *ok) {
  int res = -1;

  /* Look at our proxy method to see what we should do here. */
  switch (proxy_method) {
    case PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH:
      res = forward_handle_user_noproxyauth(cmd, proxy_sess, ok);
      break;

    default:
      errno = ENOSYS;
      res = -1;
  }

  return res;
}

int proxy_forward_get_method(const char *method) {
  if (method == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (strncasecmp(method, "proxyAuth", 10) == 0) {
    return PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH;

  } else if (strncasecmp(method, "user@host", 10) == 0) {
    return PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH;
  }

  errno = ENOENT;
  return -1;
}
