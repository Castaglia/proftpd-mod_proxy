/*
 * ProFTPD - mod_proxy forward proxy implementation
 * Copyright (c) 2012-2020 TJ Saunders
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
#include "proxy/inet.h"
#include "proxy/forward.h"
#include "proxy/tls.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/sess.h"

static int proxy_method = PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH;
static int forward_retry_count = PROXY_DEFAULT_RETRY_COUNT;

/* handle_user_passthru flags */
#define PROXY_FORWARD_USER_PASSTHRU_FL_PARSE_DSTADDR	0x001
#define PROXY_FORWARD_USER_PASSTHRU_FL_CONNECT_DSTADDR	0x002

static const char *trace_channel = "proxy.forward";

int proxy_forward_use_proxy_auth(void) {
  if (proxy_method == PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH) {
    return FALSE;
  }

  return TRUE;
}

int proxy_forward_init(pool *p, const char *tables_dir) {
  return 0;
}

int proxy_forward_free(pool *p) {
  /* TODO: Implement any necessary cleanup */
  return 0;
}

int proxy_forward_sess_free(pool *p, struct proxy_session *proxy_sess) {
  /* Reset any state. */

  proxy_method = PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH;
  forward_retry_count = PROXY_DEFAULT_RETRY_COUNT;

  return 0;
}

int proxy_forward_sess_init(pool *p, const char *tables_dir,
    struct proxy_session *proxy_sess) {
  config_rec *c;
  int allowed = FALSE;
  const void *enabled = NULL;

  /* By default, only allow connections from RFC1918 addresses to use
   * forward proxying.  Otherwise, it must be from an explicitly allowed
   * connection class, via the class notes.
   */
  if (session.conn_class != NULL) {
    enabled = pr_table_get(session.conn_class->cls_notes,
      PROXY_FORWARD_ENABLED_NOTE, NULL);
  }

  if (enabled != NULL) {
    allowed = *((int *) enabled);
    if (allowed == FALSE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "forward proxying not allowed from client address %s in <Class %s> "
        "(see ProxyForwardEnabled)",
        pr_netaddr_get_ipstr(session.c->remote_addr),
        session.conn_class->cls_name);
    }

  } else {
    if (pr_netaddr_is_rfc1918(session.c->remote_addr) == TRUE) {
      allowed = TRUE;

    } else {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "forward proxying not allowed from non-RFC1918 client address %s",
        pr_netaddr_get_ipstr(session.c->remote_addr));
    }
  }

  if (allowed == FALSE) {
    errno = EPERM;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyForwardMethod", FALSE);
  if (c != NULL) {
    proxy_method = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyRetryCount", FALSE);
  if (c != NULL) {
    forward_retry_count = *((int *) c->argv[0]);
  }

  return 0;
}

int proxy_forward_have_authenticated(cmd_rec *cmd) {
  int authd = FALSE;

  /* Authenticated here means authenticated *to the proxy*, i.e. should we
   * allow more commands, or reject them because the client hasn't authenticated
   * yet.
   */

  switch (proxy_method) {
    case PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH:
      authd = TRUE;
      break;

    case PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH:
    case PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH:
      if (proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED) {
        authd = TRUE;
      }
      break;

    default:
      authd = FALSE;
  }

  if (authd == FALSE) {
    pr_response_send(R_530, _("Please login with USER and PASS"));
  }

  return authd;
}

static int forward_tls_postopen(pool *p, struct proxy_session *proxy_sess,
    conn_t *server_conn, pr_response_t **resp) {
  int xerrno;

  if (proxy_netio_postopen(server_conn->instrm) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "postopen error for backend control connection input stream: %s",
      strerror(xerrno));
    proxy_inet_close(session.pool, server_conn);
    proxy_sess->backend_ctrl_conn = NULL;

    *resp = NULL;
    errno = xerrno;
    return -1;
  }

  if (proxy_netio_postopen(server_conn->outstrm) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "postopen error for backend control connection output stream: %s",
      strerror(xerrno));
    proxy_inet_close(session.pool, server_conn);
    proxy_sess->backend_ctrl_conn = NULL;

    *resp = NULL;
    errno = xerrno;
    return -1;
  }

  return 0;
}

static int forward_connect(pool *p, struct proxy_session *proxy_sess,
    pr_response_t **resp, unsigned int *resp_nlines) {
  conn_t *server_conn = NULL;
  int banner_ok = TRUE, use_tls, xerrno = 0;
  const pr_netaddr_t *dst_addr;
  array_header *other_addrs = NULL;
  char port_text[32];

  dst_addr = proxy_sess->dst_addr;
  other_addrs = proxy_sess->other_addrs;

  /* If the destination port is 990, assume implicit FTPS. */
  if (ntohs(pr_netaddr_get_port(dst_addr)) == PROXY_TLS_IMPLICIT_FTPS_PORT) {
    pr_trace_msg(trace_channel, 9, "%s#%u requesting, using implicit FTPS",
      pr_netaddr_get_ipstr(dst_addr),
      (unsigned int) ntohs(pr_netaddr_get_port(dst_addr)));
    proxy_tls_set_tls(PROXY_TLS_ENGINE_IMPLICIT);
  }

  server_conn = proxy_conn_get_server_conn(p, proxy_sess, dst_addr);
  if (server_conn == NULL) {
    xerrno = errno;

    if (other_addrs != NULL) {
      register unsigned int i;

      /* Try the other IP addresses for the requested name (if any) as well. */
      for (i = 0; i < other_addrs->nelts; i++) {
        dst_addr = ((pr_netaddr_t **) other_addrs->elts)[i];

        pr_trace_msg(trace_channel, 8,
          "attempting to connect to other address #%u (%s) for requested "
          "URI '%.100s'", i+1, pr_netaddr_get_ipstr(dst_addr),
          proxy_conn_get_uri(proxy_sess->dst_pconn));
        server_conn = proxy_conn_get_server_conn(p, proxy_sess, dst_addr);
        if (server_conn != NULL) {
          proxy_sess->dst_addr = dst_addr;
          break;
        }
      }
    }

    if (server_conn == NULL) {
      xerrno = errno;

      /* EINVALs lead to strange-looking error responses; change them to
       * EPERM.
       */
      if (xerrno == EINVAL) {
        xerrno = EPERM;
      }
    }

    errno = xerrno;
    return -1;
  }

  proxy_sess->frontend_ctrl_conn = session.c;
  proxy_sess->backend_ctrl_conn = server_conn;

  use_tls = proxy_tls_using_tls();

  /* Handle implicit FTPS connects. */
  if (use_tls == PROXY_TLS_ENGINE_IMPLICIT) {
    if (forward_tls_postopen(p, proxy_sess, server_conn, resp) < 0) {
      return -1;
    }
  }

  /* XXX Support/send a CLNT command of our own?  Configurable via e.g.
   * "UserAgent" string?
   */

  /* Read the response from the backend server. */
  *resp = proxy_ftp_ctrl_recv_resp(p, proxy_sess->backend_ctrl_conn,
    resp_nlines, 0);
  if (*resp == NULL) {
    xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
      strerror(xerrno));

    errno = EPERM;
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

    errno = EPERM;
    return -1;
  }

  /* Get the features supported by the backend server */
  if (proxy_ftp_sess_get_feat(p, proxy_sess) < 0) {
    if (errno != EPERM) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to determine features of backend server: %s", strerror(errno));
    }
  }

  use_tls = proxy_tls_using_tls();
  if (use_tls != PROXY_TLS_ENGINE_OFF &&
      use_tls != PROXY_TLS_ENGINE_IMPLICIT) {
    if (proxy_ftp_sess_send_auth_tls(p, proxy_sess) < 0 &&
        errno != ENOSYS) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error enabling TLS on control connection to backend server: %s",
        strerror(xerrno));
      pr_inet_close(p, proxy_sess->backend_ctrl_conn);
      proxy_sess->backend_ctrl_conn = NULL;

      *resp = NULL;
      errno = xerrno;
      return -1;
    }

    use_tls = proxy_tls_using_tls();
  }

  if (use_tls != PROXY_TLS_ENGINE_OFF &&
      use_tls != PROXY_TLS_ENGINE_IMPLICIT) {
    if (forward_tls_postopen(p, proxy_sess, server_conn, resp) < 0) {
      return -1;
    }
  }

  if (use_tls != PROXY_TLS_ENGINE_OFF) {
    if (proxy_sess_state & PROXY_SESS_STATE_BACKEND_HAS_CTRL_TLS) {
      /* NOTE: should this be a fatal error? */
      (void) proxy_ftp_sess_send_pbsz_prot(p, proxy_sess);
    }
  }

  (void) proxy_ftp_sess_send_host(p, proxy_sess);

  /* Populate the session notes about this connection. */
  memset(port_text, '\0', sizeof(port_text));
  pr_snprintf(port_text, sizeof(port_text)-1, "%d",
    proxy_conn_get_port(proxy_sess->dst_pconn));
  (void) pr_table_add_dup(session.notes, "mod_proxy.backend-ip",
    pr_netaddr_get_ipstr(dst_addr), 0);
  (void) pr_table_remove(session.notes, "mod_proxy.backend-port", NULL);
  (void) pr_table_add_dup(session.notes, "mod_proxy.backend-port",
    port_text, 0);
  (void) pr_table_add_dup(session.notes, "mod_proxy.backend-url",
    proxy_conn_get_uri(proxy_sess->dst_pconn), 0);

  proxy_sess_state |= PROXY_SESS_STATE_CONNECTED;
  return 0;
}

static int forward_dst_filter(pool *p, const char *hostport) {
#ifdef PR_USE_REGEX
  config_rec *c;
  pr_regex_t *pre;
  int negated = FALSE, res;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyForwardTo", FALSE);
  if (c == NULL) {
    return 0;
  }

  pre = c->argv[0];
  negated = *((int *) c->argv[1]);

  res = pr_regexp_exec(pre, hostport, 0, NULL, 0, 0, 0);
  if (res == 0) {
    /* Pattern matched */
    if (negated == TRUE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "host/port '%.100s' matched ProxyForwardTo !%s, rejecting",
        hostport, pr_regexp_get_pattern(pre));

      errno = EPERM;
      return -1;
    }

  } else {
    /* Pattern NOT matched */
    if (negated == FALSE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "host/port '%.100s' did not match ProxyForwardTo %s, rejecting",
        hostport, pr_regexp_get_pattern(pre));
      errno = EPERM;
      return -1;
    }
  }
#endif /* PR_USE_REGEX */
  return 0;
}

static int forward_cmd_parse_dst(pool *p, const char *arg, char **name,
    const struct proxy_conn **pconn) {
  const char *default_proto = NULL, *default_port = NULL, *proto = NULL,
    *port, *uri = NULL;
  char *host = NULL, *hostport = NULL, *host_ptr = NULL, *port_ptr = NULL;

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
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "malformed port number '%s' found in USER '%s', rejecting",
        port_ptr+1, arg);
      errno = EINVAL;
      return -1;
    }

    if (num < 0 ||
        num > 65535) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "invalid port number %ld found in USER '%s', rejecting", num, arg);
      errno = EINVAL;
      return -1;
    }

    port = pstrdup(p, port_ptr + 1);
  }

  /* Find the required '@' delimiter. */
  host_ptr = strrchr(arg, '@');
  if (host_ptr == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
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

  hostport = pstrcat(p, host, ":", port, NULL);
  if (forward_dst_filter(p, hostport) < 0) {
    return -1;
  }

  uri = pstrcat(p, proto, "://", hostport, NULL);

  /* Note: We deliberately use proxy_pool, rather than the given pool, here
   * so that the created structure (especially the pr_netaddr_t) are
   * longer-lived.
   */
  *pconn = proxy_conn_create(proxy_pool, uri, 0);
  if (*pconn == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error handling URI '%.100s': %s", uri, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int forward_handle_user_passthru(cmd_rec *cmd,
    struct proxy_session *proxy_sess, int *successful, int flags) {
  int res, xerrno;
  char *user = NULL;
  cmd_rec *user_cmd = NULL;
  pr_response_t *resp = NULL;
  unsigned int resp_nlines = 0;

  if (flags & PROXY_FORWARD_USER_PASSTHRU_FL_PARSE_DSTADDR) {
    const struct proxy_conn *pconn = NULL;
    const pr_netaddr_t *remote_addr = NULL;
    array_header *other_addrs = NULL;

    res = forward_cmd_parse_dst(cmd->tmp_pool, cmd->arg, &user, &pconn);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }

    remote_addr = proxy_conn_get_addr(pconn, &other_addrs);

    /* Ensure that the requested remote address is NOT (blatantly) ourselves,
     * i.e. the proxy itself.  This prevents easy-to-detect proxy loops.
     */
    if (pr_netaddr_cmp(remote_addr, session.c->local_addr) == 0 &&
        pr_netaddr_get_port(remote_addr) == pr_netaddr_get_port(session.c->local_addr)) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "requested destination %s#%u is local address %s#%u, rejecting",
        pr_netaddr_get_ipstr(remote_addr),
        ntohs(pr_netaddr_get_port(remote_addr)),
        pr_netaddr_get_ipstr(session.c->local_addr),
        ntohs(pr_netaddr_get_port(session.c->local_addr)));
      pr_response_send(R_530, _("Unable to connect to %s: %s"),
        proxy_conn_get_host(pconn), strerror(EPERM));
      return 1;
    }

    proxy_sess->dst_addr = remote_addr;
    proxy_sess->other_addrs = other_addrs;
    proxy_sess->dst_pconn = pconn;

    /* Change the command so that it no longer includes the proxy info. */
    user_cmd = pr_cmd_alloc(cmd->pool, 2, C_USER, user);
    user_cmd->arg = user;

  } else {
    user_cmd = cmd;
  }

  if (flags & PROXY_FORWARD_USER_PASSTHRU_FL_CONNECT_DSTADDR) {
    pr_response_t *banner = NULL;
    unsigned int banner_nlines = 0;

    res = forward_connect(proxy_pool, proxy_sess, &banner, &banner_nlines);
    if (res < 0) {
      xerrno = errno;

      *successful = FALSE;

      /* Send a failed USER response to our waiting frontend client, but do
       * not necessarily close the frontend connection.
       */
      resp = pcalloc(cmd->tmp_pool, sizeof(pr_response_t));
      resp->num = R_530;

      if (banner != NULL) {
        resp->msg = banner->msg;
        resp_nlines = banner_nlines;

      } else {
        resp->msg = pstrcat(cmd->tmp_pool, "Unable to connect to ",
          proxy_conn_get_host(proxy_sess->dst_pconn), ": ",
          strerror(xerrno), NULL);
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

      errno = EINVAL;
      return 1;
    }
  }

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    user_cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) user_cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines, 0);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (resp->num[0] == '2' ||
      resp->num[0] == '3') {
    *successful = TRUE;

    if (strcmp(resp->num, R_232) == 0) {
      proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
      pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
    }
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

  return 1; 
}

static int forward_handle_user_proxyuserwithproxyauth(cmd_rec *cmd,
    struct proxy_session *proxy_sess, int *successful, int *block_responses) {
  int flags = 0, res;

  if (!(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED)) {
    char *user = NULL;
    const struct proxy_conn *pconn = NULL;
    const pr_netaddr_t *remote_addr = NULL;
    array_header *other_addrs = NULL;

    res = forward_cmd_parse_dst(cmd->pool, cmd->arg, &user, &pconn);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }

    remote_addr = proxy_conn_get_addr(pconn, &other_addrs);
    proxy_sess->dst_addr = remote_addr;
    proxy_sess->other_addrs = other_addrs;
    proxy_sess->dst_pconn = pconn;

    /* Rewrite the USER command here with the trimmed/truncated name. */
    pr_cmd_clear_cache(cmd);
    cmd->arg = cmd->argv[1] = pstrdup(cmd->pool, user);

    /* By returning zero here, we let the rest of the proftpd internals
     * deal with the USER command locally, leading to proxy auth.
     */
    *block_responses = FALSE;
    return 0;
  }

  flags = PROXY_FORWARD_USER_PASSTHRU_FL_CONNECT_DSTADDR;
  res = forward_handle_user_passthru(cmd, proxy_sess, successful, flags);
  return res;
}

static int forward_handle_user_userwithproxyauth(cmd_rec *cmd,
    struct proxy_session *proxy_sess, int *successful, int *block_responses) {
  int flags = 0, res;

  if (!(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED)) {
    /* By returning zero here, we let the rest of the proftpd internals
     * deal with the USER command locally, leading to proxy auth.
     */
    *block_responses = FALSE;
    return 0;
  }

  flags = PROXY_FORWARD_USER_PASSTHRU_FL_PARSE_DSTADDR|PROXY_FORWARD_USER_PASSTHRU_FL_CONNECT_DSTADDR;
  res = forward_handle_user_passthru(cmd, proxy_sess, successful, flags);
  return res;
}

int proxy_forward_handle_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful, int *block_responses) {
  int res = -1;

  /* Look at our proxy method to see what we should do here. */
  switch (proxy_method) {
    case PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH: {
      int flags = PROXY_FORWARD_USER_PASSTHRU_FL_PARSE_DSTADDR|PROXY_FORWARD_USER_PASSTHRU_FL_CONNECT_DSTADDR;
      res = forward_handle_user_passthru(cmd, proxy_sess, successful, flags);
      break;
    }

    case PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH:
      res = forward_handle_user_userwithproxyauth(cmd, proxy_sess,
        successful, block_responses);
      break;

    case PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH:
      res = forward_handle_user_proxyuserwithproxyauth(cmd, proxy_sess,
        successful, block_responses);
      break;

    default:
      errno = ENOSYS;
      res = -1;
  }

  return res;
}

static int forward_handle_pass_passthru(cmd_rec *cmd,
    struct proxy_session *proxy_sess, int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines, 0);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    /* If we receive an EPERM here, it is probably because the backend
     * closed its control connection, yielding an EOF.  To better indicate
     * this situation, propagate the error using EPIPE.
     */
    if (xerrno == EPERM) {
      xerrno = EPIPE;
    }

    errno = xerrno;
    return -1;
  }

  /* XXX What about other response codes for PASS? */
  if (resp->num[0] == '2') {
    *successful = TRUE;

    proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return -1;
  }

  return 1;
}

static int forward_handle_pass_userwithproxyauth(cmd_rec *cmd,
    struct proxy_session *proxy_sess, int *successful, int *block_responses) {

  if (!(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED)) {
    int res;
    const char *user;

    user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);

    res = proxy_session_check_password(cmd->pool, user, cmd->arg);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }

    res = proxy_session_setup_env(proxy_pool, user,
      PROXY_SESSION_FL_CHECK_LOGIN_ACL);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }

    if (session.auth_mech) {
      pr_log_debug(DEBUG2, "user '%s' authenticated by %s", user,
        session.auth_mech);
    }

    pr_response_send(R_230, _("User %s logged in"), user);
    return 1;
  }

  return forward_handle_pass_passthru(cmd, proxy_sess, successful);
}

static int forward_handle_pass_proxyuserwithproxyauth(cmd_rec *cmd,
    struct proxy_session *proxy_sess, int *successful, int *block_responses) {

  /* The functionality is identical to that of handle_pass_userwithproxyauth. */
  return forward_handle_pass_userwithproxyauth(cmd, proxy_sess, successful,
    block_responses);
}

int proxy_forward_handle_pass(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful, int *block_responses) {
  int res = -1, xerrno = 0;

  /* Look at our proxy method to see what we should do here. */
  switch (proxy_method) {
    case PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH:
      res = forward_handle_pass_passthru(cmd, proxy_sess, successful);
      xerrno = errno;
      if (res == 1) {
        pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
      }
      break;

    case PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH:
      res = forward_handle_pass_userwithproxyauth(cmd, proxy_sess,
        successful, block_responses);
      xerrno = errno;
      if (res == 1) {
        pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
      }
      break;

    case PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH:
      res = forward_handle_pass_proxyuserwithproxyauth(cmd, proxy_sess,
        successful, block_responses);
      xerrno = errno;
      if (res == 1) {
        pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
      }
      break;

    default:
      xerrno = ENOSYS;
      res = -1;
  }

  errno = xerrno;
  return res;
}

int proxy_forward_get_method(const char *method) {
  if (method == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (strcasecmp(method, "proxyuser,user@host") == 0) {
    return PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH;

  } else if (strcasecmp(method, "user@host") == 0) {
    return PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH;

  } else if (strcasecmp(method, "proxyuser@host,user") == 0) {
    return PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH;
  }

  errno = ENOENT;
  return -1;
}
