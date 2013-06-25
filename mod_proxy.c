/*
 * ProFTPD - mod_proxy
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
 *
 * ---DO NOT EDIT BELOW THIS LINE---
 * $Archive: mod_proxy.a $
 */

#include "mod_proxy.h"
#include "proxy/session.h"
#include "proxy/conn.h"
#include "proxy/forward.h"
#include "proxy/reverse.h"
#include "proxy/ftp/conn.h"
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
  server_addr = proxy_sess->backend_ctrl_conn->remote_addr;

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
  conn_t *server_conn, *backend_ctrl_conn;
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

  backend_ctrl_conn = pr_inet_openrw(proxy_pool, server_conn, NULL,
    PR_NETIO_STRM_CTRL, -1, -1, -1, FALSE);
  if (backend_ctrl_conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to open control connection to %s:%u: %s", server_ipstr,
      server_port, strerror(xerrno));

    pr_inet_close(proxy_pool, server_conn);

    errno = xerrno;
    return NULL;
  }

  return backend_ctrl_conn;
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

/* mod_proxy event/dispatch loop. */
static void proxy_cmd_loop(server_rec *s, conn_t *conn) {

  /* XXX Note: when reading/writing data from data connections, do NOT
   * perform any sort of ASCII translation; we leave the data as is.
   * (Or maybe we SHOULD perform the ASCII translation here, in case of
   * ASCII translation error; the backend server can then be told that
   * the data are binary, and thus relieve the backend of the translation
   * burden.  Configurable?)
   */

  while (TRUE) {
    int res = 0;
    cmd_rec *cmd = NULL;

    pr_signals_handle();

    /* XXX Insert select(2) call here, where we wait for readability on:
     *
     *  client control connection
     *  client data connection (if uploading)
     *  server data connection (if downloading/directory listing)
     *
     * Bonus points for handling aborts on either control connection,
     * broken data connections, blocked/slow writes to client (how much
     * can/should we buffer?  what about short writes to the client?),
     * timeouts, etc.
     */
 
    res = pr_cmd_read(&cmd);
    if (res < 0) {
      if (PR_NETIO_ERRNO(session.c->instrm) == EINTR) {
        /* Simple interrupted syscall */
        continue;
      }

#ifndef PR_DEVEL_NO_DAEMON
      /* Otherwise, EOF */
      pr_session_disconnect(NULL, PR_SESS_DISCONNECT_CLIENT_EOF, NULL);
#else
      return;
#endif /* PR_DEVEL_NO_DAEMON */
    }

    /* Data received, reset idle timer */
    if (pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE) > 0) {
      pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
    }

    if (cmd) {
      pr_cmd_dispatch(cmd);
      destroy_pool(cmd->pool);

    } else {
      pr_event_generate("core.invalid-command", NULL);
      pr_response_send(R_500, _("Invalid command: try being more creative"));
    }

    /* Release any working memory allocated in inet */
    pr_inet_clear();
  }
}

/* Command handlers
 */

MODRET proxy_data(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  pr_response_t *resp;
  conn_t *frontend_conn = NULL, *backend_conn = NULL;

  /* We are handling a data transfer command (e.g. LIST, RETR, etc).
   *
   * Thus we need to check the session.sf_flags, and determine whether
   * we are to connect to the backend server, or open a listening socket
   * to which the backend will connect.  Then we send the given command
   * to the backend.
   *
   * At the same time, we will need to be managing the data connection
   * from the frontend client separately; we will need to multiplex
   * across the four connections: frontend control, frontend data,
   * backend control, backend data.
   */

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
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

  /* XXX Should handle PASSIVE_ALL here, too. */
  if (session.sf_flags & SF_PASSIVE) {

    /* Connect to the backend server now. */
    /* XXX We won't receive the initial response until we connect to the
     * backend data address/port.
     */
    /* XXX Note: This is where we would specify the specific address/interface
     * to use as the source address for connections to the backend server,
     * rather than using session.c->local_addr as the bind address.
     */

    backend_conn = proxy_ftp_conn_connect(cmd->tmp_pool, session.c->local_addr,
      proxy_sess->data_addr);
    if (backend_conn == NULL) {
      xerrno = errno;

      pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
      pr_response_flush(&resp_err_list);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    proxy_sess->backend_data_conn = backend_conn;

  } else if (session.sf_flags & SF_PORT) {
    backend_conn = proxy_ftp_conn_accept(cmd->tmp_pool,
      proxy_sess->backend_data_conn, proxy_sess->backend_ctrl_conn);
    if (backend_conn == NULL) {
      xerrno = errno;

      if (proxy_sess->backend_data_conn != NULL) {
        pr_inet_close(session.pool, proxy_sess->backend_data_conn);
        proxy_sess->backend_data_conn = NULL;
      }

      pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
      pr_response_flush(&resp_err_list);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    /* We can close our listening socket now. */
    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = backend_conn; 

    pr_inet_set_nonblock(session.pool, backend_conn);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "active data connection opened - local  : %s:%d",
      pr_netaddr_get_ipstr(backend_conn->local_addr),
      backend_conn->local_port);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "active data connection opened - remote : %s:%d",
      pr_netaddr_get_ipstr(backend_conn->remote_addr),
      backend_conn->remote_port);

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "ERROR: not in SF_PASSIVE or SF_PORT session state/flag");
  }

  /* Now we should receive the initial response from the backend server. */
  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", cmd->argv[0],
      strerror(xerrno));

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    if (proxy_sess->backend_data_conn != NULL) {
      pr_inet_close(session.pool, proxy_sess->backend_data_conn);
      proxy_sess->backend_data_conn = NULL;
    }

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* If the backend server responds with 4xx/5xx here, close the frontend
   * data connection.
   */
  if (resp->num[0] == '4' || resp->num[0] == '5') {
    res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
      proxy_sess->frontend_ctrl_conn, resp);

    if (proxy_sess->frontend_data_conn) {
      pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
      proxy_sess->frontend_data_conn = NULL;
    }

    if (proxy_sess->backend_data_conn) {
      pr_inet_close(session.pool, proxy_sess->backend_data_conn);
      proxy_sess->backend_data_conn = NULL;
    }

    errno = EPERM;
    return PR_HANDLED(cmd);
  }

  if (session.sf_flags & SF_PASSIVE) {
    frontend_conn = proxy_ftp_conn_accept(cmd->tmp_pool,
      proxy_sess->frontend_data_conn, proxy_sess->frontend_ctrl_conn);
    if (frontend_conn == NULL) {
      xerrno = errno;

      if (proxy_sess->frontend_data_conn != NULL) {
        pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
        proxy_sess->frontend_data_conn = NULL;
      }

      pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
      pr_response_flush(&resp_err_list);
    
      errno = xerrno;
      return PR_ERROR(cmd);
    } 

    /* We can close our listening socket now. */
    pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
    proxy_sess->frontend_data_conn = frontend_conn; 

    pr_inet_set_nonblock(session.pool, frontend_conn);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "passive data connection opened - local  : %s:%d",
      pr_netaddr_get_ipstr(frontend_conn->local_addr),
      frontend_conn->local_port);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "passive data connection opened - remote : %s:%d",
      pr_netaddr_get_ipstr(frontend_conn->remote_addr),
      frontend_conn->remote_port);

  } else if (session.sf_flags & SF_PORT) {
    /* Connect to the frontend server now. */
    frontend_conn = proxy_ftp_conn_connect(cmd->tmp_pool, session.c->local_addr,
      proxy_sess->data_addr);
    if (frontend_conn == NULL) {
      xerrno = errno;

      pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
      pr_response_flush(&resp_err_list);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    proxy_sess->frontend_data_conn = frontend_conn;

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "ERROR: not in SF_PASSIVE or SF_PORT session state/flag");
  }

  /* Now that we have our frontend connection, we can send the response from
   * the backend to the frontend.
   */
  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
    proxy_sess->frontend_ctrl_conn, resp);
  if (res < 0) {
    xerrno = errno;

    if (proxy_sess->frontend_data_conn != NULL) {
      pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
      proxy_sess->frontend_data_conn = NULL;
    }

    if (proxy_sess->backend_data_conn != NULL) {
      pr_inet_close(session.pool, proxy_sess->backend_data_conn);
      proxy_sess->backend_data_conn = NULL;
    }

    pr_response_block(TRUE);

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* If we don't have our frontend/backend connections by now, it's a
   * problem.
   */
  if (frontend_conn == NULL ||
      backend_conn == NULL) {
    xerrno = EPERM;
    pr_response_block(TRUE);

    pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  session.sf_flags |= SF_XFER;

  /* XXX Reset/clear TimeoutNoTransfer; is there a frontend/backend specific
   * version of that timer?
   */

  while (TRUE) {
    fd_set rfds, wfds;
    struct timeval tv;
    int maxfd = -1, timeout = 15;

    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    res = -1;

    pr_signals_handle();

    /* XXX Whether we set the write or the read fds depends on the direction
     * of the data transfer.
     */

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm), &rfds);
    if (PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm) > maxfd) {
      maxfd = PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm);
    }

    if (proxy_sess->backend_data_conn != NULL) {
      FD_SET(PR_NETIO_FD(proxy_sess->backend_data_conn->instrm), &rfds);
      if (PR_NETIO_FD(proxy_sess->backend_data_conn->instrm) > maxfd) {
        maxfd = PR_NETIO_FD(proxy_sess->backend_data_conn->instrm);
      }
    }

    res = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (res < 0) {
      xerrno = errno;

      if (xerrno == EINTR) {
        pr_signals_handle();
        continue;
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error calling select(2) while transferring data: %s",
        strerror(xerrno));

      errno = xerrno;
      break;
    }

    if (res == 0) {
      /* XXX Have MAX_RETRIES logic here. */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "timed out waiting for readability on backend ctrl/data conns, "
        "trying again");
      continue;
    }

    if (proxy_sess->backend_data_conn != NULL) {
      if (FD_ISSET(PR_NETIO_FD(proxy_sess->backend_data_conn->instrm), &rfds)) {
        /* Some data arrived on the data connection... */
        pr_buffer_t *pbuf = NULL;

        pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
 
        pbuf = proxy_ftp_data_recv(cmd->tmp_pool,
          proxy_sess->backend_data_conn);
        if (pbuf == NULL) {
          xerrno = errno;

          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error receiving from backend server data conn: %s",
            strerror(xerrno));

        } else {
          if (pbuf->remaining == 0) {
            /* EOF on the data connection; close it. */
            pr_inet_close(session.pool, proxy_sess->backend_data_conn);
            proxy_sess->backend_data_conn = NULL;

          } else {
            size_t remaining = pbuf->remaining;

            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "received %lu bytes of data from backend server",
              (unsigned long) remaining);

            res = proxy_ftp_data_send(cmd->tmp_pool,
              proxy_sess->frontend_data_conn, pbuf);
            if (res < 0) {
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "error writng %lu bytes of data to frontend server: %s",
                (unsigned long) remaining, strerror(errno));
            }
          }
        }
      }
    }

    if (FD_ISSET(PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm), &rfds)) {
      /* Some data arrived on the ctrl connection... */
      pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);

      resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool,
        proxy_sess->backend_ctrl_conn);
      if (resp == NULL) {
        xerrno = errno;
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error receiving response from backend server: %s", strerror(xerrno));

      } else {

        /* If not a 1xxx response, close the frontend data connection,
         * BEFORE we send the response from the backend to the connected client.
         */
        if (resp->num[0] != '1') {
          pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
          proxy_sess->frontend_data_conn = NULL;
        }

        res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
          proxy_sess->frontend_ctrl_conn, resp);
        xerrno = errno;

        if (res < 0) {
          pr_response_block(TRUE);

          pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
          pr_response_flush(&resp_err_list);

          errno = xerrno;
          return PR_ERROR(cmd);
        }

        /* If we get a 1xx response here, keep going.  Otherwise, we're
         * done with this data transfer.
         */
        if (proxy_sess->backend_data_conn == NULL ||
            (resp->num)[0] != '1') {
          session.sf_flags &= (SF_ALL^SF_PASSIVE);
          session.sf_flags &= (SF_ALL^(SF_ABORT|SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));
          break;
        }
      }
    }
  }

  pr_response_clear(&resp_list);
  return PR_HANDLED(cmd);
}

MODRET proxy_eprt(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res;
  pr_response_t *resp;

  return PR_HANDLED(cmd);
}

MODRET proxy_epsv(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res;
  pr_response_t *resp;

  return PR_HANDLED(cmd);
}

MODRET proxy_pasv(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, valid_response = FALSE, xerrno;
  conn_t *data_conn;
  char *addr_str, *data_addr, *ptr, resp_msg[PR_RESPONSE_BUFFER_SIZE];
  size_t data_addrlen;
  pr_netaddr_t *bind_addr, *remote_addr;
  pr_response_t *resp;
  unsigned int addr_vals[4];
  unsigned short port_vals[2];
  unsigned short local_port, remote_port;

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
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

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn);
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

  /* Have to scan the response message for the encoded address/port to
   * which we are to connect.  Note that we may see some strange formats
   * for PASV responses from FTP servers here.
   *
   * We can't predict where the expected address/port numbers start in the
   * string, so start from the beginning.
   */
  for (ptr = resp->msg; *ptr; ptr++) {
    if (sscanf(ptr, "%u,%u,%u,%u,%hu,%hu",
        &addr_vals[0], &addr_vals[1], &addr_vals[2], &addr_vals[3],
        &port_vals[0], &port_vals[1]) == 6) {
      valid_response = TRUE;
      break;
    }
  }

  if (valid_response == FALSE) {
    pr_trace_msg("proxy", 2, "unknown PASV response format '%s'", resp->msg);
    xerrno = EPERM;

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (addr_vals[0] > 255 ||
      addr_vals[1] > 255 ||
      addr_vals[2] > 255 ||
      addr_vals[3] > 255 ||
      port_vals[0] > 255 ||
      port_vals[1] > 255 ||
      (addr_vals[0]|addr_vals[1]|addr_vals[2]|addr_vals[3]) == 0 ||
      (port_vals[0]|port_vals[1]) == 0) {
    pr_trace_msg("proxy", 1, "PASV response '%s' has invalid value(s)",
      resp->msg);
    xerrno = EPERM;

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  data_addrlen = (4 * 3) + (3 * 1) + 1;
  data_addr = pcalloc(cmd->tmp_pool, data_addrlen);
  snprintf(data_addr, data_addrlen-1, "%u.%u.%u.%u", addr_vals[0], addr_vals[1],
    addr_vals[2], addr_vals[3]);
  remote_addr = pr_netaddr_get_addr(cmd->tmp_pool, data_addr, NULL);
  if (remote_addr == NULL) {
    pr_trace_msg("proxy", 2, "unable to resolve '%s': %s", data_addr,
      strerror(errno));
    xerrno = EINVAL;

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  remote_port = ((port_vals[0] << 8) + port_vals[1]);
  pr_netaddr_set_port2(remote_addr, remote_port);

  /* Make sure that the given address matches the address to which we
   * originally connected.
   */

#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    /* XXX Add appropriate check here */
  }
#endif /* PR_USE_IPV6 */

  if (pr_netaddr_cmp(remote_addr,
      proxy_sess->backend_ctrl_conn->remote_addr) != 0) {
    pr_trace_msg("proxy", 1,
      "Refused PASV address %s (address mismatch with %s)",
      pr_netaddr_get_ipstr(remote_addr),
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr));
    xerrno = EPERM;

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (remote_port < 1024) {
    pr_trace_msg("proxy", 1, "Refused PASV port %hu (below 1024)",
      remote_port);
    xerrno = EPERM;

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* We do NOT want to connect here, but would rather wait until the
   * ensuing data transfer-initiating command.  Otherwise, a client could
   * spew PASV commands at us, and we would flood the backend server with
   * data transfer connections needlessly.
   *
   * We DO, however, need to create our own listening connection, so that
   * we can inform the client of the address/port to which IT is to
   * connect for its part of the data transfer.
   */

  proxy_sess->data_addr = remote_addr;
  bind_addr = session.c->local_addr;

  data_conn = pr_inet_create_conn(session.pool, -1, bind_addr, INPORT_ANY,
    FALSE);
  if (data_conn == NULL) {
    pr_response_add_err(R_425, _("Unable to build data connection: "
      "Internal error"));
    pr_response_flush(&resp_err_list);

    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  /* Make sure that necessary socket options are set on the socket prior
   * to the call to listen(2).
   */
  pr_inet_set_proto_opts(session.pool, data_conn, main_server->tcp_mss_len, 0,
    IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("proxy.data-listen", main_server,
    data_conn->local_addr, data_conn->listen_fd);

  pr_inet_set_block(session.pool, data_conn);
  if (pr_inet_listen(session.pool, data_conn, 1, 0) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to listen on %s#%u: %s", pr_netaddr_get_ipstr(bind_addr),
      ntohs(pr_netaddr_get_port(bind_addr)), strerror(xerrno));

    pr_inet_close(session.pool, data_conn);
    pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* XXX Do we need to open the outstrm here, too? */
  data_conn->instrm = pr_netio_open(session.pool, PR_NETIO_STRM_DATA,
    data_conn->listen_fd, PR_NETIO_IO_RD);

  if (proxy_sess->frontend_data_conn != NULL) {
    /* Make sure that we only have one frontend data connection. */
    pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
    proxy_sess->frontend_data_conn = NULL;
  }

  proxy_sess->frontend_data_conn = data_conn;

  local_port = data_conn->local_port;
  session.sf_flags |= SF_PASSIVE;

  addr_str = pstrdup(cmd->tmp_pool,
    pr_netaddr_get_ipstr(data_conn->local_addr));

  /* Fixup the address string for the PASV response. */
  ptr = strrchr(addr_str, ':');
  if (ptr != NULL) {
    addr_str = ptr + 1;
  }

  for (ptr = addr_str; *ptr; ptr++) {
    if (*ptr == '.') {
      *ptr = ',';
    }
  }

  pr_log_debug(DEBUG1, MOD_PROXY_VERSION ": Entering Passive Mode (%s,%u,%u).",
    addr_str, (local_port >> 8) & 255, local_port & 255);

  /* Change the response to send back to the connecting client, telling it
   * to use OUR address/port.
   */
  resp->next = NULL;
  resp->num = R_227;
  memset(resp_msg, '\0', sizeof(resp_msg));
  snprintf(resp_msg, sizeof(resp_msg)-1, "Entering Passive Mode (%s,%u,%u).",
    addr_str, (local_port >> 8) & 255, local_port & 255);
  resp->msg = resp_msg;

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp);
  xerrno = errno;

  if (res < 0) {
    pr_inet_close(session.pool, data_conn);
    pr_response_block(TRUE);

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_block(TRUE);
  return PR_HANDLED(cmd);
}

MODRET proxy_port(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  pr_netaddr_t *bind_addr = NULL, *remote_addr = NULL;
  pr_response_t *resp;
  conn_t *data_conn;
#ifdef PR_USE_IPV6
  char buf[INET6_ADDRSTRLEN] = {'\0'};
#else
  char buf[INET_ADDRSTRLEN] = {'\0'};
#endif /* PR_USE_IPV6 */
  unsigned int h1, h2, h3, h4, p1, p2;
  unsigned short local_port = 0, remote_port;
  char *addr_str, *data_addr, *ptr;
  size_t data_addrlen;

  CHECK_CMD_ARGS(cmd, 2);

  /* XXX Can't just send the frontend's PORT, as is, to the backend.
   * We need to connect to the frontend's PORT; we need to open a listening
   * socket and send its address to the backend in our PORT command.
   */

  /* XXX How to handle this if we are chrooted, without root privs, for
   * e.g. source ports below 1024?
   */

  /* Format is h1,h2,h3,h4,p1,p2 (ASCII in network order) */
  if (sscanf(cmd->argv[1], "%u,%u,%u,%u,%u,%u", &h1, &h2, &h3, &h4, &p1,
      &p2) != 6) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "PORT '%s' is not syntactically valid", cmd->argv[1]);

    pr_response_add_err(R_501, _("Illegal PORT command"));
    pr_response_flush(&resp_err_list);

    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (h1 > 255 || h2 > 255 || h3 > 255 || h4 > 255 || p1 > 255 || p2 > 255 ||
      (h1|h2|h3|h4) == 0 || (p1|p2) == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "PORT '%s' has invalid value(s)", cmd->arg);

    pr_response_add_err(R_501, _("Illegal PORT command"));
    pr_response_flush(&resp_err_list);

    errno = EPERM;
    return PR_ERROR(cmd);
  }
  remote_port = ((p1 << 8) | p2);

#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET6) {
      snprintf(buf, sizeof(buf), "::ffff:%u.%u.%u.%u", h1, h2, h3, h4);

    } else {
      snprintf(buf, sizeof(buf), "%u.%u.%u.%u", h1, h2, h3, h4);
    }

  } else
#endif /* PR_USE_IPV6 */
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u", h1, h2, h3, h4);
  buf[sizeof(buf)-1] = '\0';

  remote_addr = pr_netaddr_get_addr(session.pool, buf, NULL);
  if (remote_addr == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting sockaddr for '%s': %s", buf, strerror(errno));

    pr_response_add_err(R_501, _("Illegal PORT command"));
    pr_response_flush(&resp_err_list);

    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* If we are NOT listening on an RFC1918 address, BUT the client HAS
   * sent us an RFC1918 address in its PORT command (which we know to not be
   * routable), then ignore that address, and use the client's remote address.
   */
  if (pr_netaddr_is_rfc1918(session.c->local_addr) != TRUE &&
      pr_netaddr_is_rfc1918(session.c->remote_addr) != TRUE &&
      pr_netaddr_is_rfc1918(remote_addr) == TRUE) {
    const char *rfc1918_ipstr;

    rfc1918_ipstr = pr_netaddr_get_ipstr(remote_addr);
    remote_addr = pr_netaddr_dup(cmd->tmp_pool, session.c->remote_addr);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "client sent RFC1918 address '%s' in PORT command, ignoring it and "
      "using '%s'", rfc1918_ipstr, pr_netaddr_get_ipstr(remote_addr));
  }

  /* XXX Make sure that the address specified matches the address from which
   * the control connection is coming (AllowForeignAddress check)
   */

  /* Additionally, make sure that the port number used is a "high numbered"
   * port, to avoid bounce attacks.  For remote Windows machines, the
   * port numbers mean little.  However, there are also quite a few Unix
   * machines out there for whom the port number matters...
   */
  if (remote_port < 1024) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "Refused PORT %s (port %d below 1024, possible bounce attack)", cmd->arg,
      remote_port);

    pr_response_add_err(R_500, _("Illegal PORT command"));
    pr_response_flush(&resp_err_list);

    errno = EPERM;
    return PR_ERROR(cmd);
  }

  pr_netaddr_set_port(remote_addr, htons(remote_port));
  proxy_sess->data_addr = remote_addr;

  /* XXX Now that we recorded the address to which we'll connect, we need
   * to open a new listening socket for the backend to which connect,
   * and sent that address to the backend in our PORT command.
   */

  /* XXX This is where we would configure a different source address/interface
   * for the backend to connect to.
   */
  bind_addr = session.c->local_addr;

  data_conn = pr_inet_create_conn(session.pool, -1, bind_addr, INPORT_ANY,
    FALSE);
  if (data_conn == NULL) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to create socket: %s", strerror(xerrno));

    pr_response_add_err(R_425, _("Unable to build data connection: "
      "Internal error"));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Make sure that necessary socket options are set on the socket prior
   * to the call to listen(2).
   */
  pr_inet_set_proto_opts(session.pool, data_conn, main_server->tcp_mss_len, 0,
    IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("proxy.data-listen", main_server,
    data_conn->local_addr, data_conn->listen_fd);

  pr_inet_set_block(session.pool, data_conn);
  if (pr_inet_listen(session.pool, data_conn, 1, 0) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to listen on %s#%u: %s", pr_netaddr_get_ipstr(bind_addr),
      ntohs(pr_netaddr_get_port(bind_addr)), strerror(xerrno));

    pr_inet_close(session.pool, data_conn);
    pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* XXX Do we need to open the outstrm here, too? */
  data_conn->instrm = pr_netio_open(session.pool, PR_NETIO_STRM_DATA,
    data_conn->listen_fd, PR_NETIO_IO_RD);

  if (proxy_sess->backend_data_conn != NULL) {
    /* Make sure that we only have one backend data connection. */
    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;
  }

  proxy_sess->backend_data_conn = data_conn;
  local_port = data_conn->local_port;

  addr_str = pstrdup(cmd->tmp_pool,
    pr_netaddr_get_ipstr(data_conn->local_addr));

  /* Fixup the address string for the PORT command. */
  ptr = strrchr(addr_str, ':');
  if (ptr != NULL) {
    addr_str = ptr + 1;
  }

  for (ptr = addr_str; *ptr; ptr++) {
    if (*ptr == '.') {
      *ptr = ',';
    }
  }

  /* Allocate enough room for 6 numbers (3 digits max each), 5 separators,
   * and a trailing NUL.
   */
  data_addrlen = (6 * 3) + (5 * 1) + 1;
  data_addr = pcalloc(cmd->pool, data_addrlen);
  snprintf(data_addr, data_addrlen-1, "%s,%u,%u", addr_str,
    (local_port >> 8) & 255, local_port & 255);

  cmd->arg = data_addr;

  /* XXX Need to fix logging; why does the trace logging show
   * "proxied <old-port>" rather than showing the new address from data_addr?
   */
  pr_cmd_clear_cache(cmd);

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", cmd->argv[0], strerror(xerrno));

    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", cmd->argv[0],
      strerror(xerrno));

    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (resp->num[0] == '2') {
    /* If the command was successful, mark it in the session state/flags. */
    session.sf_flags |= SF_PORT;
  }

  return PR_HANDLED(cmd);
}

MODRET proxy_user(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  pr_response_t *resp;

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
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

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn);
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

  if (resp->num[0] == '2') {
    char *user;

    /* For 2xx responses (others?), stash the user name appropriately. */
    user = cmd->arg;

    (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);

    if (pr_table_add_dup(session.notes, "mod_auth.orig-user", user, 0) < 0) {
      pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
        "session.notes: %s", strerror(errno));
    }
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

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
  pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
 
  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);

  /* Commands related to logins and data transfers are handled separately */
  switch (cmd->cmd_id) {
    case PR_CMD_USER_ID:
      mr = proxy_user(cmd, proxy_sess);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_EPRT_ID:
      mr = proxy_eprt(cmd, proxy_sess);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_EPSV_ID:
      mr = proxy_epsv(cmd, proxy_sess);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_PASV_ID:
      mr = proxy_pasv(cmd, proxy_sess);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_PORT_ID:
      mr = proxy_port(cmd, proxy_sess);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_APPE_ID:
    case PR_CMD_LIST_ID:
    case PR_CMD_MLSD_ID:
    case PR_CMD_NLST_ID:
    case PR_CMD_RETR_ID:
    case PR_CMD_STOR_ID:
    case PR_CMD_STOU_ID:
      mr = proxy_data(cmd, proxy_sess);
      pr_response_block(TRUE);
      return mr;
  }

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
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

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn);
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

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp);
  if (res < 0) {
    xerrno = errno;

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
    if (proxy_sess->frontend_ctrl_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->frontend_ctrl_conn);
      proxy_sess->frontend_ctrl_conn = NULL;
    }

    if (proxy_sess->frontend_data_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->frontend_data_conn);
      proxy_sess->frontend_data_conn = NULL;
    }

    if (proxy_sess->backend_ctrl_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->backend_ctrl_conn);
      proxy_sess->backend_ctrl_conn = NULL;
    }

    if (proxy_sess->backend_data_conn != NULL) {
      pr_inet_close(proxy_sess->pool, proxy_sess->backend_data_conn);
      proxy_sess->backend_data_conn = NULL;
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

  /* XXX Support/send a CLNT command of our own?  Configurable via e.g.
   * "UserAgent" string?
   */

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

  proxy_sess->frontend_ctrl_conn = session.c;
  proxy_sess->backend_ctrl_conn = server_conn;

  /* XXX Read the response from the backend server and send it to the
   * connected client as if it were our own banner.
   */
  resp = proxy_ftp_ctrl_recv_resp(proxy_pool, proxy_sess->backend_ctrl_conn);
  if (resp == NULL) {
    int xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
      strerror(xerrno));

  } else {
    if (proxy_ftp_ctrl_send_resp(proxy_pool, session.c, resp) < 0) {
      pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to send banner to client: %s", strerror(errno));
    }
  }

  pr_response_block(TRUE);

  /* We have to use our own command event loop, since we will also need to
   * watch any data transfer connections with the backend server, in addition
   * to the client control connection.
   */
  pr_cmd_set_handler(proxy_cmd_loop);

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

