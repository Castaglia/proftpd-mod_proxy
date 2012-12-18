/*
 * ProFTPD - mod_proxy
 * Copyright (c) 2012 TJ Saunders
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
 *
 * ---DO NOT EDIT BELOW THIS LINE---
 * $Archive: mod_proxy.a $
 */

#include "mod_proxy.h"
#include "proxy/session.h"
#include "proxy/conn.h"
#include "proxy/forward.h"
#include "proxy/reverse.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/data.h"

/* Proxy mode/type */
#define PROXY_MODE_GATEWAY		1
#define PROXY_MODE_PROXY		2

/* How long (in secs) to wait to connect to real server? */
#define PROXY_CONNECT_DEFAULT_TIMEOUT	60

/* From response.c */
extern pr_response_t *resp_list, *resp_err_list;
extern xaset_t *server_list;

module proxy_module;

int proxy_logfd = -1;
pool *proxy_pool = NULL;

static int proxy_engine = FALSE;
static int proxy_mode = PROXY_MODE_GATEWAY;

static const char *trace_channel = "proxy";

static int proxy_connect_timeout_cb(CALLBACK_FRAME) {
  struct proxy_session *proxy_sess;
  pr_netaddr_t *server_addr;

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  server_addr = proxy_sess->server_ctrl_conn->remote_addr;

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "timed out connecting to %s:%d after %d %s",
    pr_netaddr_get_ipstr(server_addr), ntohs(pr_netaddr_get_port(server_addr)),
    proxy_sess->connect_timeout,
    proxy_sess->connect_timeout != 1 ? "seconds" : "second");

  pr_event_generate("mod_proxy.timeout-connect", NULL);

  pr_log_pri(PR_LOG_NOTICE, "%s", "Connect timed out, disconnected");
  pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_TIMEOUT,
    "ProxyTimeoutConnect");

  /* Do not restart the timer (should never be reached). */
  return 0;
}

static pr_netaddr_t *proxy_gateway_get_server(struct proxy_session *proxy_sess) {
  config_rec *c;
  array_header *backend_servers;
  struct proxy_conn **conns;
  pr_netaddr_t *addr;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyGatewayServers", FALSE);
  if (c == NULL) {
    /* XXX This shouldn't happen; should be checked by proxy_reverse_init(). */
    errno = ENOENT;
    return NULL;
  }

  backend_servers = c->argv[0];
  conns = backend_servers->elts;

  /* XXX Insert selection criteria here */

  addr = proxy_conn_get_addr(conns[0]);
  return addr;
}

static conn_t *proxy_gateway_get_server_conn(struct proxy_session *proxy_sess) {
  pr_netaddr_t *server_addr;
  unsigned int server_port;
  const char *server_ipstr;
  conn_t *server_conn, *server_ctrl_conn;
  int res;

  server_addr = proxy_gateway_get_server(proxy_sess);
  if (server_addr == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to find suitable backend server: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  if (proxy_sess->connect_timeout > 0) {
    proxy_sess->connect_timerno = pr_timer_add(proxy_sess->connect_timeout,
      -1, &proxy_module, proxy_connect_timeout_cb, "ProxyTimeoutConnect");
  }

  server_ipstr = pr_netaddr_get_ipstr(server_addr);
  server_port = ntohs(pr_netaddr_get_port(server_addr));

  /* Instead of passing the local_addr here for the bind address, this is where
   * one could configure the source interface/address for the client/connect
   * side of the proxy connection.
   */
  server_conn = pr_inet_create_conn(proxy_pool, -1, session.c->local_addr,
    INPORT_ANY, FALSE);  

  res = pr_inet_connect_nowait(proxy_pool, server_conn, server_addr,
    ntohs(pr_netaddr_get_port(server_addr)));
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error starting connect to %s:%u: %s", server_ipstr, server_port,
      strerror(xerrno));

    pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
    errno = xerrno;
    return NULL;
  }  

  if (res == 0) {
    pr_netio_stream_t *nstrm;

    /* Not yet connected. */
    nstrm = pr_netio_open(proxy_pool, PR_NETIO_STRM_OTHR,
      server_conn->listen_fd, PR_NETIO_IO_RD);
    if (nstrm == NULL) {
      int xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error opening stream to %s:%u: %s", server_ipstr, server_port,
        strerror(xerrno));

      pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
      pr_inet_close(proxy_pool, server_conn);

      errno = xerrno;
      return NULL;
    }

    pr_netio_set_poll_interval(nstrm, 1);

    switch (pr_netio_poll(nstrm)) {
      case 1: {
        /* Aborted, timed out.  Note that we shouldn't reach here. */
        pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
        pr_netio_close(nstrm);
        pr_inet_close(proxy_pool, server_conn);
        errno = ETIMEDOUT;
        return NULL;
      }

      case -1: {
        /* Error */
        int xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error connecting to %s:%u: %s", server_ipstr, server_port,
          strerror(xerrno));

        pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
        pr_netio_close(nstrm);
        pr_inet_close(proxy_pool, server_conn);

        errno = xerrno;
        return NULL;
      }

      default: {
        /* Connected */
        server_conn->mode = CM_OPEN;
        pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);

        res = pr_inet_get_conn_info(server_conn, server_conn->listen_fd);
        if (res < 0) {
          int xerrno = errno;

          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error obtaining local socket info on fd %d: %s\n",
            server_conn->listen_fd, strerror(xerrno));

          pr_netio_close(nstrm);
          pr_inet_close(proxy_pool, server_conn);
          errno = xerrno;
          return NULL;
        }

        break;
      }
    }
  }

  pr_trace_msg(trace_channel, 5,
    "successfully connected to %s:%u from %s:%d", server_ipstr, server_port,
    pr_netaddr_get_ipstr(server_conn->local_addr),
    ntohs(pr_netaddr_get_port(server_conn->local_addr)));

  server_ctrl_conn = pr_inet_openrw(proxy_pool, server_conn, NULL,
    PR_NETIO_STRM_CTRL, -1, -1, -1, FALSE);
  if (server_ctrl_conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to open control connection to %s:%u: %s", server_ipstr,
      server_port, strerror(xerrno));

    pr_inet_close(proxy_pool, server_conn);

    errno = xerrno;
    return NULL;
  }

  return server_ctrl_conn;
}

static int proxy_have_authenticated(cmd_rec *cmd) {
  /* XXX Use a state variable here, which returns true when we have seen
   * a successful response to the PASS command...but only if we do NOT connect
   * to the backend at connect time (for then we are handling all FTP
   * commands, until the client sends USER).
   */
  return TRUE;
}

static int proxy_mkdir(const char *dir, uid_t uid, gid_t gid, mode_t mode) {
  mode_t prev_mask;
  struct stat st;
  int res = -1;

  pr_fs_clear_cache();
  res = pr_fsio_stat(dir, &st);

  if (res == -1 &&
      errno != ENOENT) {
    return -1;
  }

  /* The directory already exists. */
  if (res == 0) {
    return 0;
  }

  /* The given mode is absolute, not subject to any Umask setting. */
  prev_mask = umask(0);

  if (pr_fsio_mkdir(dir, mode) < 0) {
    int xerrno = errno;

    (void) umask(prev_mask);
    errno = xerrno;
    return -1;
  }

  umask(prev_mask);

  if (pr_fsio_chown(dir, uid, gid) < 0) {
    return -1;
  }

  return 0;
}

/* Configuration handlers
 */

/* usage: ProxyEngine on|off */
MODRET set_proxyengine(cmd_rec *cmd) {
  int bool = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: ProxyGatewayServers server1 ... server N
 *                            file://path/to/server/list.txt
 *                            sql://SQLNamedQuery
 */
MODRET set_proxygatewayservers(cmd_rec *cmd) {
  config_rec *c;
  array_header *backend_servers;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  backend_servers = make_array(c->pool, 1, sizeof(struct proxy_conn *));

  if (cmd->argc-1 == 1) {

    /* We are dealing with one of the following possibilities:
     *
     *  file:/path/to/file.txt
     *  sql://SQLNamedQuery/...
     *  <server>
     */

    if (strncmp(cmd->argv[1], "file:", 5) == 0) {
      char *path;

      path = cmd->argv[1] + 5;
    
      /* Make sure the path is an absolute path.
       *
       * XXX For now, load the list of servers at sess init time.  In
       * the future, we will want to load it at postparse time, mapped
       * to the appropriate server_rec, and clear/reload on 'core.restart'.
       */

    } else if (strncmp(cmd->argv[1], "sql:/", 5) == 0) {
      /* XXX Implement */

      CONF_ERROR(cmd, "not yet implemented");

    } else {
      /* Treat it as a server-spec (i.e. a URI) */
      struct proxy_conn *pconn;

      pconn = proxy_conn_create(c->pool, cmd->argv[1]);
      if (pconn == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing '", cmd->argv[1],
          "': ", strerror(errno), NULL));
      }

      *((struct proxy_conn **) push_array(backend_servers)) = pconn;
    }

  } else {
    register unsigned int i;

    /* More than one parameter, which means they are all URIs. */

    for (i = 1; i < cmd->argc; i++) {
      struct proxy_conn *pconn;

      pconn = proxy_conn_create(c->pool, cmd->argv[i]);
      if (pconn == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing '", cmd->argv[i],
          "': ", strerror(errno), NULL));
      }

      *((struct proxy_conn **) push_array(backend_servers)) = pconn;
    }
  }

  c->argv[0] = backend_servers;

  return PR_HANDLED(cmd);
}

/* usage: ProxyGatewayStrategy [strategy] */
MODRET set_proxygatewaystrategy(cmd_rec *cmd) {

  /* CHECK_ARGS(cmd, 1) */
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  return PR_HANDLED(cmd);
}

/* usage: ProxyLog path|"none" */
MODRET set_proxylog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: ProxyMode "forward" (proxy) |"reverse" (gateway) */
MODRET set_proxymode(cmd_rec *cmd) {
  int mode = 0;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "forward") == 0 ||
      strcasecmp(cmd->argv[1], "proxy") == 0) {
    mode = PROXY_MODE_PROXY;

  } else if (strcasecmp(cmd->argv[1], "reverse") == 0 ||
             strcasecmp(cmd->argv[1], "gateway") == 0) {
    mode = PROXY_MODE_GATEWAY;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown proxy mode '", cmd->argv[1],
      "'", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = mode;

  return PR_HANDLED(cmd);
}

/* usage: ProxyOptions opt1 ... optN */
MODRET set_proxyoptions(cmd_rec *cmd) {
  return PR_HANDLED(cmd);
}

/* usage: ProxyTimeoutConnect secs */
MODRET set_proxytimeoutconnect(cmd_rec *cmd) {
  int timeout = -1;
  char *tmp = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  timeout = (int) strtol(cmd->argv[1], &tmp, 10);

  if ((tmp && *tmp) ||
      timeout < 0 ||
      timeout > 65535) {
    CONF_ERROR(cmd, "timeout values must be between 0 and 65535");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET proxy_eprt(cmd_rec *cmd) {
  int res;
  struct proxy_session *proxy_sess;
  pr_response_t *resp;

  if (proxy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  return PR_HANDLED(cmd);
}

MODRET proxy_epsv(cmd_rec *cmd) {
  int res;
  struct proxy_session *proxy_sess;
  pr_response_t *resp;

  if (proxy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  return PR_HANDLED(cmd);
}

MODRET proxy_pasv(cmd_rec *cmd) {
  int res;
  struct proxy_session *proxy_sess;
  pr_response_t *resp;

  if (proxy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  return PR_HANDLED(cmd);
}

MODRET proxy_port(cmd_rec *cmd) {
  int res;
  struct proxy_session *proxy_sess;
  pr_response_t *resp;

  if (proxy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  return PR_HANDLED(cmd);
}

MODRET proxy_any(cmd_rec *cmd) {
  int res, xerrno;
  struct proxy_session *proxy_sess;
  pr_response_t *resp;
  modret_t *mr = NULL;

  if (proxy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  pr_response_block(FALSE);

  /* Commands related to data transfers are handled separately */
  switch (cmd->cmd_id) {
    case PR_CMD_EPRT_ID:
      mr = proxy_eprt(cmd);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_EPSV_ID:
      mr = proxy_epsv(cmd);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_PASV_ID:
      mr = proxy_pasv(cmd);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_PORT_ID:
      mr = proxy_port(cmd);
      pr_response_block(TRUE);
      return mr;
  }

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->server_ctrl_conn,
    cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", cmd->argv[0], strerror(xerrno));

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->server_ctrl_conn);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", cmd->argv[0],
      strerror(xerrno));

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->client_ctrl_conn,
    resp, PROXY_FTP_SEND_RESP_FL_SEND_NOW);
  xerrno = errno;

  if (res < 0) {
    pr_response_block(TRUE);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_block(TRUE);
  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void proxy_exit_ev(const void *event_data, void *user_data) {
  struct proxy_session *proxy_sess;

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  if (proxy_sess != NULL) {
    if (proxy_sess->client_ctrl_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->client_ctrl_conn);
      proxy_sess->client_ctrl_conn = NULL;
    }

    if (proxy_sess->client_data_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->client_data_conn);
      proxy_sess->client_data_conn = NULL;
    }

    if (proxy_sess->server_ctrl_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->server_ctrl_conn);
      proxy_sess->server_ctrl_conn = NULL;
    }

    if (proxy_sess->server_data_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->server_data_conn);
      proxy_sess->server_data_conn = NULL;
    }

    pr_table_remove(session.notes, "mod_proxy.proxy-session", NULL);
  }

  if (proxy_logfd >= 0) {
    (void) close(proxy_logfd);
    proxy_logfd = -1;
  }
}

#if defined(PR_SHARED_MODULE)
static void proxy_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp((const char *) event_data, "mod_proxy.c", 12) == 0) {
    register unsigned int i;

    /* Unregister ourselves from all events. */
    pr_event_unregister(&proxy_module, NULL, NULL);

    destroy_pool(proxy_pool);
    proxy_pool = NULL;

    (void) close(proxy_logfd);
    proxy_logfd = -1;
  }
}
#endif

static void proxy_restart_ev(const void *event_data, void *user_data) {
}

static void proxy_shutdown_ev(const void *event_data, void *user_data) {
  destroy_pool(proxy_pool);
  proxy_pool = NULL;

  if (proxy_logfd >= 0) {
    (void) close(proxy_logfd);
    proxy_logfd = -1;
  }
}

/* XXX Do we want to support any Controls/ftpctl actions? */

/* Initialization routines
 */

static int proxy_init(void) {

  proxy_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(proxy_pool, MOD_PROXY_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&proxy_module, "core.module-unload", proxy_mod_unload_ev,
    NULL);
#endif
  pr_event_register(&proxy_module, "core.restart", proxy_restart_ev, NULL);
  pr_event_register(&proxy_module, "core.shutdown", proxy_shutdown_ev, NULL);

  return 0;
}

static int proxy_sess_init(void) {
  config_rec *c;
  int res;
  conn_t *server_conn;
  struct proxy_session *proxy_sess;
  pr_response_t *resp;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyEngine", FALSE);
  if (c != NULL) {
    proxy_engine = *((int *) c->argv[0]);
  }

  if (proxy_engine == FALSE) {
    return 0;
  }

  /* XXX Install event handlers for timeouts, so that we can properly close
   * the connections on either side.
   */

  pr_event_register(&proxy_module, "core.exit", proxy_exit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "ProxyLog", FALSE);
  if (c != NULL) {
    char *logname;

    logname = c->argv[0];

    if (strncasecmp(logname, "none", 5) != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(logname, &proxy_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
            ": notice: unable to open ProxyLog '%s': %s", logname,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
            ": notice: unable to open ProxyLog '%s': parent directory is "
            "world-writable", logname);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
            ": notice: unable to open ProxyLog '%s': cannot log to a symlink",
            logname);
        }
      }
    }
  }

  proxy_pool = make_sub_pool(session.pool);
  pr_pool_tag(proxy_pool, MOD_PROXY_VERSION);

  c = find_config(main_server->conf, CONF_PARAM, "ProxyMode", FALSE);
  if (c != NULL) {
    proxy_mode = *((int *) c->argv[0]);
  }

  /* XXX All proxied connections are automatically chrooted (after auth,
   * or immediately upon connect?  Depends on the backend selection
   * mechanism...)
   *
   * All proxied connections immediately have root privs dropped.  (Act as
   * if the RootRevoke option was programmatically set?)
   */

  switch (proxy_mode) {
    case PROXY_MODE_GATEWAY:
      if (proxy_reverse_init(proxy_pool) < 0) {
        proxy_engine = FALSE;
        return -1;
      }
      break;

    case PROXY_MODE_PROXY:
      if (proxy_forward_init(proxy_pool) < 0) {
        proxy_engine = FALSE;
        return -1; 
      }
      break;
  }

  /* XXX DisplayLogin? Only if we do the gateway selection at USER time... */

  /* XXX block responses?
   *
   * If we are to connect to the backend right now, then yes, block responses:
   * we will proxy the connect banner back to the client.  Otherwise, no, do
   * not block responses.  By using:
   *
   *  pr_response_block(TRUE);
   *
   * here, as mod_sftp does, we can prevent the client from receiving
   * the normal FTP banner later.
   */

  /* XXX set protocol?  What about ssh2 proxying?  How to interact
   * with mod_sftp, which doesn't have the same pipeline of request
   * handling? (Need to add PRE_REQ handling in mod_sftp, to support proxying.)
   *
   * pr_session_set_protocol("proxy"); ?
   *
   * If we do this, we should also add separate "proxy" rows to the DelayTable.
   */

  /* Use our own "authenticated yet?" check. */
  set_auth_check(proxy_have_authenticated);

  /* Allocate our own session structure, for tracking proxy-specific
   * fields.  Use the session.notes table for stashing/retrieving it as
   * needed.
   */
  proxy_sess = pcalloc(proxy_pool, sizeof(struct proxy_session));
  if (pr_table_add(session.notes, "mod_proxy.proxy-session", proxy_sess,
      sizeof(struct proxy_session)) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error stashing proxy session note: %s", strerror(errno));
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTimeoutConnect", FALSE);
  if (c != NULL) {
    proxy_sess->connect_timeout = *((int *) c->argv[0]);

  } else {
    proxy_sess->connect_timeout = PROXY_CONNECT_DEFAULT_TIMEOUT;
  }

  /* XXX For now, assume we're acting as a gateway.  That being the case,
   * we need to look at our gateway backend server selection strategy.
   *
   * For now, we assume there's only one backend server configured, so
   * we connect to it.
   */

  server_conn = proxy_gateway_get_server_conn(proxy_sess);
  if (server_conn == NULL) {
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  proxy_sess->server_ctrl_conn = server_conn;

  /* XXX Read the response from the backend server and send it to the
   * connected client as if it were our own banner.
   */
  resp = proxy_ftp_ctrl_recv_resp(proxy_pool, proxy_sess->server_ctrl_conn);
  if (resp == NULL) {
    int xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(proxy_sess->server_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->server_ctrl_conn->remote_addr)),
      strerror(xerrno));

  } else {
    int flags = PROXY_FTP_SEND_RESP_FL_SEND_NOW;

    if (proxy_ftp_ctrl_send_resp(proxy_pool, session.c, resp, flags) < 0) {
      pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to send banner to client: %s", strerror(errno));
    }
  }

  pr_response_block(TRUE);
  return 0;
}

/* Module API tables
 */

static conftable proxy_conftab[] = {
  { "ProxyEngine",		set_proxyengine,	NULL },
  { "ProxyMode",		set_proxymode,		NULL },
  { "ProxyLog",			set_proxylog,		NULL },
  { "ProxyOptions",		set_proxyoptions,	NULL },
  { "ProxyTimeoutConnect",	set_proxytimeoutconnect,NULL },

  /* Forward proxy directives */

  /* Reverse proxy directives */
  { "ProxyGatewayServers",	set_proxygatewayservers,	NULL },
  { "ProxyGatewayStrategy",	set_proxygatewaystrategy,	NULL },

  { NULL }
};

static cmdtable proxy_cmdtab[] = {
  /* XXX Should this be marked with a CL_ value, for logging? */
  { CMD,	C_ANY,	G_NONE,	proxy_any,	FALSE, FALSE },

  { 0, NULL }
};

module proxy_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "proxy",

  /* Module configuration handler table */
  proxy_conftab,

  /* Module command handler table */
  proxy_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  proxy_init,

  /* Session initialization */
  proxy_sess_init,

  /* Module version */
  MOD_PROXY_VERSION
};

