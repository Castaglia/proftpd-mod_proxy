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
#include "proxy/random.h"
#include "proxy/session.h"
#include "proxy/conn.h"
#include "proxy/forward.h"
#include "proxy/reverse.h"
#include "proxy/ftp/conn.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/data.h"
#include "proxy/ftp/msg.h"
#include "proxy/ftp/feat.h"
#include "proxy/ftp/xfer.h"

/* Proxy role */
#define PROXY_ROLE_REVERSE		1
#define PROXY_ROLE_FORWARD		2

/* How long (in secs) to wait to connect to real server? */
#define PROXY_CONNECT_DEFAULT_TIMEOUT	2

extern module xfer_module;

/* From response.c */
extern pr_response_t *resp_list, *resp_err_list;

module proxy_module;

int proxy_logfd = -1;
pool *proxy_pool = NULL;
unsigned long proxy_opts = 0UL;
unsigned int proxy_sess_state = 0U;

static int proxy_engine = FALSE;
static int proxy_role = PROXY_ROLE_REVERSE;
static const char *proxy_tables_dir = NULL;

static const char *trace_channel = "proxy";

static int proxy_stalled_timeout_cb(CALLBACK_FRAME) {
  int timeout_stalled;

  timeout_stalled = pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED);

  pr_event_generate("core.timeout-stalled", NULL);
  pr_log_pri(PR_LOG_NOTICE, "Data transfer stall timeout: %d %s",
    timeout_stalled, timeout_stalled != 1 ? "seconds" : "second");
  pr_session_disconnect(NULL, PR_SESS_DISCONNECT_TIMEOUT,
    "TimeoutStalled during data transfer");

  /* Do not restart the timer (should never be reached). */
  return 0;
}

static void proxy_log_xfer(cmd_rec *cmd, char abort_flag) {
  struct timeval end_time;
  char direction, *path = NULL;

  switch (cmd->cmd_id) {
    case PR_CMD_APPE_ID:
    case PR_CMD_STOR_ID:
    case PR_CMD_STOU_ID:
      direction = 'i';
      break;

    case PR_CMD_RETR_ID:
      direction = 'o';
      break;
  }

  memset(&end_time, '\0', sizeof(end_time));

  if (session.xfer.start_time.tv_sec != 0) {
    gettimeofday(&end_time, NULL);
    end_time.tv_sec -= session.xfer.start_time.tv_sec;

    if (end_time.tv_usec >= session.xfer.start_time.tv_usec) {
      end_time.tv_usec -= session.xfer.start_time.tv_usec;

    } else {
      end_time.tv_usec = 1000000L - (session.xfer.start_time.tv_usec -
        end_time.tv_usec);
      end_time.tv_sec--;
    }
  }

  path = cmd->arg;

  xferlog_write(end_time.tv_sec, pr_netaddr_get_sess_remote_name(),
    session.xfer.total_bytes, path,
    (session.sf_flags & SF_ASCII ? 'a' : 'b'), direction,
    'r', session.user, abort_flag, "_");

  pr_log_debug(DEBUG1, "Transfer %s %" PR_LU " bytes in %ld.%02lu seconds",
    abort_flag == 'c' ? "completed:" : "aborted after",
    (pr_off_t) session.xfer.total_bytes, (long) end_time.tv_sec,
    (unsigned long)(end_time.tv_usec / 10000));
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

static int proxy_mkpath(pool *p, const char *path, uid_t uid, gid_t gid,
    mode_t mode) {
  char *currpath = NULL, *tmppath = NULL;
  struct stat st;

  pr_fs_clear_cache();
  if (pr_fsio_stat(path, &st) == 0) {
    /* Path already exists, nothing to be done. */
    errno = EEXIST;
    return -1;
  }

  tmppath = pstrdup(p, path);

  currpath = "/";
  while (tmppath && *tmppath) {
    char *currdir = strsep(&tmppath, "/");
    currpath = pdircat(p, currpath, currdir, NULL);

    if (proxy_mkdir(currpath, uid, gid, mode) < 0) {
      return -1;
    }

    pr_signals_handle();
  }

  return 0;
}

/* Configuration handlers
 */

/* usage: ProxyDataTransferPolicy "active"|"passive"|"pasv"|"epsv"|"port"|
 *          "eprt"|"client"
 */
MODRET set_proxydatatransferpolicy(cmd_rec *cmd) {
  config_rec *c;
  int cmd_id = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  cmd_id = pr_cmd_get_id(cmd->argv[1]);
  if (cmd_id < 0) {
    if (strncasecmp(cmd->argv[1], "active", 7) == 0) {
      cmd_id = PR_CMD_PORT_ID;

    } else if (strncasecmp(cmd->argv[1], "passive", 8) == 0) {
      cmd_id = PR_CMD_PASV_ID;

    } else if (strncasecmp(cmd->argv[1], "client", 7) == 0) {
      cmd_id = 0;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported DataTransferPolicy: ",
        cmd->argv[1], NULL));
    }
  }

  if (cmd_id != PR_CMD_PASV_ID &&
      cmd_id != PR_CMD_EPSV_ID &&
      cmd_id != PR_CMD_PORT_ID &&
      cmd_id != PR_CMD_EPRT_ID &&
      cmd_id != 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported DataTransferPolicy: ",
      cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = cmd_id;

  return PR_HANDLED(cmd);
}

/* usage: ProxyEngine on|off */
MODRET set_proxyengine(cmd_rec *cmd) {
  int engine = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: ProxyForwardMethod method */
MODRET set_proxyforwardmethod(cmd_rec *cmd) {
  config_rec *c;
  int forward_method = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  forward_method = proxy_forward_get_method(cmd->argv[1]);
  if (forward_method < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unknown/unsupported forward method: ", cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = forward_method;

  return PR_HANDLED(cmd);
}

/* usage: ProxyLog path|"none" */
MODRET set_proxylog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: ProxyOptions opt1 ... optN */
MODRET set_proxyoptions(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strncmp(cmd->argv[i], "UseProxyProtocol", 17) == 0) {
      opts |= PROXY_OPT_USE_PROXY_PROTOCOL;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown ProxyOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: ProxyReverseSelection [policy] */
MODRET set_proxyreverseselection(cmd_rec *cmd) {
  config_rec *c;
  int select_policy = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  select_policy = proxy_reverse_select_get_policy(cmd->argv[1]);
  if (select_policy < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unknown/unsupported selection policy: ", cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = select_policy;

  return PR_HANDLED(cmd);
}

/* usage: ProxyReverseServers server1 ... server N
 *                            file://path/to/server/list.txt
 *                            sql://SQLNamedQuery
 */
MODRET set_proxyreverseservers(cmd_rec *cmd) {
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

      CONF_ERROR(cmd, "not yet implemented");

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

/* usage: ProxyRole "forward"|"reverse" */
MODRET set_proxyrole(cmd_rec *cmd) {
  int role = 0;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "forward") == 0) {
    role = PROXY_ROLE_FORWARD;

  } else if (strcasecmp(cmd->argv[1], "reverse") == 0) {
    role = PROXY_ROLE_REVERSE;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown proxy type '", cmd->argv[1],
      "'", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = role;

  return PR_HANDLED(cmd);
}

/* usage: ProxySourceAddress address */
MODRET set_proxysourceaddress(cmd_rec *cmd) {
  config_rec *c = NULL;
  pr_netaddr_t *src_addr = NULL;
  unsigned int addr_flags = PR_NETADDR_GET_ADDR_FL_INCL_DEVICE;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  src_addr = pr_netaddr_get_addr2(cmd->server->pool, cmd->argv[1], NULL,
    addr_flags);
  if (src_addr == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to resolve '", cmd->argv[1],
      "'", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = src_addr;

  return PR_HANDLED(cmd);
}

/* usage: ProxyTables path */
MODRET set_proxytables(cmd_rec *cmd) {
  int res;
  struct stat st;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (*cmd->argv[1] != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '",
      cmd->argv[1], "'", NULL));
  }

  res = stat(cmd->argv[1], &st);
  if (res < 0) {
    char *proxy_chroot;

    if (errno != ENOENT) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to stat '", cmd->argv[1],
        "': ", strerror(errno), NULL));
    }

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": ProxyTables directory '%s' does not exist, creating it", cmd->argv[1]);

    /* Create the directory. */
    res = proxy_mkpath(cmd->tmp_pool, cmd->argv[1], geteuid(), getegid(), 0755);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
        cmd->argv[1], "': ", strerror(errno), NULL));
    }

    /* Also create the empty/ directory underneath, for the chroot. */
    proxy_chroot = pdircat(cmd->tmp_pool, cmd->argv[1], "empty", NULL);

    res = proxy_mkpath(cmd->tmp_pool, proxy_chroot, geteuid(), getegid(), 0111);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
        proxy_chroot, "': ", strerror(errno), NULL));
    }

    pr_log_debug(DEBUG2, MOD_PROXY_VERSION
      ": created ProxyTables directory '%s'", cmd->argv[1]);

  } else {
    char *proxy_chroot;

    if (!S_ISDIR(st.st_mode)) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use '", cmd->argv[1],
        ": Not a directory", NULL));
    }

    /* See if the chroot directory empty/ already exists as well.  And enforce
     * the permissions on that directory.
     */
    proxy_chroot = pdircat(cmd->tmp_pool, cmd->argv[1], "empty", NULL);

    res = stat(proxy_chroot, &st);
    if (res < 0) {
      if (errno != ENOENT) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to stat '", proxy_chroot,
          "': ", strerror(errno), NULL));
      }

      res = proxy_mkpath(cmd->tmp_pool, proxy_chroot, geteuid(), getegid(),
        0111);
      if (res < 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
          proxy_chroot, "': ", strerror(errno), NULL));
      }

    } else {
      mode_t dir_mode, expected_mode;

      if (!S_ISDIR(st.st_mode)) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "path '", proxy_chroot,
          "' is not a directory as expected", NULL));
      }

      dir_mode = st.st_mode;
      dir_mode &= ~S_IFMT;
      expected_mode = (S_IXUSR|S_IXGRP|S_IXOTH);

      if (dir_mode != expected_mode) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "directory '", proxy_chroot,
          "' has incorrect permissions (not 0111 as required)", NULL));
      }
    }
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: ProxyTimeoutConnect secs */
MODRET set_proxytimeoutconnect(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

/* mod_proxy event/dispatch loop. */
static void proxy_cmd_loop(server_rec *s, conn_t *conn) {

  while (TRUE) {
    int res = 0;
    cmd_rec *cmd = NULL;

    pr_signals_handle();

    /* XXX Insert select(2) call here, where we wait for readability on
     * the client control connection.
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

    pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);

    if (cmd) {
      /* We unblock responses here so that if any PRE_CMD handlers generate
       * responses (usually errors), those responses are sent to the
       * connecting client.
       */
      pr_response_block(FALSE);

      /* XXX If we need to, we can exert finer-grained control over
       * command dispatching/routing here.  For example, this is where we
       * could block responses for PRE_CMD handlers, or skip certain
       * modules' handlers.
       */
      pr_cmd_dispatch(cmd);
      destroy_pool(cmd->pool);

      pr_response_block(TRUE);

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
  int res, xerrno, xfer_direction, xfer_ok = TRUE;
  unsigned int resp_nlines = 0;
  pr_response_t *resp;
  conn_t *frontend_conn = NULL, *backend_conn = NULL;

  /* We are handling a data transfer command (e.g. LIST, RETR, etc).
   *
   * Thus we need to check the proxy_session->backend_sess_flags, and
   * determine whether we are to connect to the backend server, or open a
   * listening socket to which the backend will connect.  Then we send the
   * given command to the backend.
   *
   * At the same time, we will need to be managing the data connection
   * from the frontend client separately; we will need to multiplex
   * across the four connections: frontend control, frontend data,
   * backend control, backend data.
   */

  if (pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOU_ID) == 0) {
    /* Uploading, i.e. writing to backend data conn. */
    xfer_direction = PR_NETIO_IO_WR;

    session.xfer.path = pr_table_get(cmd->notes, "mod_xfer.store-path", NULL);

  } else {
    /* Downloading, i.e. reading from backend data conn.*/
    xfer_direction = PR_NETIO_IO_RD;

    session.xfer.path = pr_table_get(cmd->notes, "mod_xfer.retr-path", NULL);
  }

  /* XXX Move all this connection setup into a function, separate from the
   * transfer loop, if possible.
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

  /* XXX Should handle EPSV_ALL here, too. */
  if (proxy_sess->backend_sess_flags & SF_PASSIVE) {
    pr_netaddr_t *bind_addr = NULL;

    /* Connect to the backend server now. We won't receive the initial
     * response until we connect to the backend data address/port.
     */

    /* Specify the specific address/interface to use as the source address for
     * connections to the destination server.
     */
    bind_addr = proxy_sess->src_addr;
    if (bind_addr == NULL) {
      bind_addr = session.c->local_addr;
    }

    backend_conn = proxy_ftp_conn_connect(cmd->tmp_pool, bind_addr,
      proxy_sess->backend_data_addr);
    if (backend_conn == NULL) {
      xerrno = errno;

      pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
      pr_response_flush(&resp_err_list);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (pr_netio_postopen(backend_conn->instrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for backend data connection input stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, backend_conn);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (pr_netio_postopen(backend_conn->outstrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for backend data connection output stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, backend_conn);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    proxy_sess->backend_data_conn = backend_conn;

  } else if (proxy_sess->backend_sess_flags & SF_PORT) {
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

    if (pr_netio_postopen(backend_conn->instrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for backend data connection input stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, backend_conn);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (pr_netio_postopen(backend_conn->outstrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for backend data connection output stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, backend_conn);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    pr_inet_set_nonblock(session.pool, backend_conn);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "active data connection opened - local  : %s:%d",
      pr_netaddr_get_ipstr(backend_conn->local_addr),
      backend_conn->local_port);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "active data connection opened - remote : %s:%d",
      pr_netaddr_get_ipstr(backend_conn->remote_addr),
      backend_conn->remote_port);
  }

  /* Now we should receive the initial response from the backend server. */
  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
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
      proxy_sess->frontend_ctrl_conn, resp, resp_nlines);

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

  if (proxy_sess->frontend_sess_flags & SF_PASSIVE) {
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

    if (pr_netio_postopen(frontend_conn->instrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for frontend data connection input stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, frontend_conn);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (pr_netio_postopen(frontend_conn->outstrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for frontend data connection output stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, frontend_conn);

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

  } else if (proxy_sess->frontend_sess_flags & SF_PORT) {
    /* Connect to the frontend server now. */
    frontend_conn = proxy_ftp_conn_connect(cmd->tmp_pool, session.c->local_addr,
      proxy_sess->frontend_data_addr);
    if (frontend_conn == NULL) {
      xerrno = errno;

      pr_response_add_err(R_425, _("%s: %s"), cmd->argv[0], strerror(xerrno));
      pr_response_flush(&resp_err_list);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (pr_netio_postopen(frontend_conn->instrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for frontend data connection input stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, frontend_conn);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (pr_netio_postopen(frontend_conn->outstrm) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "postopen error for frontend data connection output stream: %s",
        strerror(xerrno));
      pr_inet_close(session.pool, frontend_conn);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    proxy_sess->frontend_data_conn = frontend_conn;
    pr_inet_set_nonblock(session.pool, frontend_conn);
  }

  /* Now that we have our frontend connection, we can send the response from
   * the backend to the frontend.
   */
  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
    proxy_sess->frontend_ctrl_conn, resp, resp_nlines);
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

  /* Allow aborts -- set the current NetIO stream to allow interrupted
   * syscalls, so our SIGURG handler can interrupt it
   */
  switch (xfer_direction) {
    case PR_NETIO_IO_RD:
      pr_netio_set_poll_interval(backend_conn->instrm, 1);
      pr_netio_set_poll_interval(frontend_conn->outstrm, 1);
      break;

    case PR_NETIO_IO_WR:
      pr_netio_set_poll_interval(frontend_conn->instrm, 1);
      pr_netio_set_poll_interval(backend_conn->outstrm, 1);
      break;
  }

  proxy_sess->frontend_sess_flags |= SF_XFER;
  proxy_sess->backend_sess_flags |= SF_XFER;

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER) > 0) {
    pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  }

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED) > 0) {
    pr_timer_add(pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED),
      PR_TIMER_STALLED, &proxy_module, proxy_stalled_timeout_cb,
      "TimeoutStalled");
  }

  /* XXX Note: when reading/writing data from data connections, do NOT
   * perform any sort of ASCII translation; we leave the data as is.
   * (Or maybe we SHOULD perform the ASCII translation here, in case of
   * ASCII translation error; the backend server can then be told that
   * the data are binary, and thus relieve the backend of the translation
   * burden.  Configurable?)
   */

  while (TRUE) {
    fd_set rfds;
    struct timeval tv;
    int maxfd = -1, timeout = 15;
    conn_t *src_data_conn = NULL, *dst_data_conn = NULL;

    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    res = -1;

    pr_signals_handle();

    FD_ZERO(&rfds);

    /* XXX If we wanted to allow/support commands during transfers, we would
     * also need to add the frontend_ctrl_conn instrm fd here for reading.
     * And possibly for ABOR commands, SIGURG.
     */

    /* The source/origin data connection depends on our direction:
     * downloads (IO_RD) from the backend, uploads (IO_WR) to the frontend.
     */
    switch (xfer_direction) {
      case PR_NETIO_IO_RD:
        src_data_conn = proxy_sess->backend_data_conn;
        dst_data_conn = proxy_sess->frontend_data_conn;
        break;

      case PR_NETIO_IO_WR:
        src_data_conn = proxy_sess->frontend_data_conn;
        dst_data_conn = proxy_sess->backend_data_conn;

        break;
    }

    FD_SET(PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm), &rfds);
    if (PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm) > maxfd) {
      maxfd = PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm);
    }

    if (src_data_conn != NULL) {
      FD_SET(PR_NETIO_FD(src_data_conn->instrm), &rfds);
      if (PR_NETIO_FD(src_data_conn->instrm) > maxfd) {
        maxfd = PR_NETIO_FD(src_data_conn->instrm);
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

      if (proxy_sess->frontend_data_conn != NULL) {
        pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
        proxy_sess->frontend_data_conn = NULL;
      }

      if (proxy_sess->backend_data_conn != NULL) {
        pr_inet_close(session.pool, proxy_sess->backend_data_conn);
        proxy_sess->backend_data_conn = NULL;
      }

      pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);
      pr_response_block(TRUE);

      pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
      pr_response_flush(&resp_err_list);

      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (res == 0) {
      /* XXX Have MAX_RETRIES logic here. */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "timed out waiting for readability on ctrl/data connections, "
        "trying again");
      continue;
    }

    if (src_data_conn != NULL) {
      if (FD_ISSET(PR_NETIO_FD(src_data_conn->instrm), &rfds)) {
        /* Some data arrived on the data connection... */
        pr_buffer_t *pbuf = NULL;

        pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
 
        pbuf = proxy_ftp_data_recv(cmd->tmp_pool, src_data_conn);
        if (pbuf == NULL) {
          xerrno = errno;

          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error receiving from source data connection: %s",
            strerror(xerrno));

        } else {
          pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
          pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);

          if (pbuf->remaining == 0) {
            /* EOF on the data connection; close BOTH of them. */

            pr_inet_close(session.pool, proxy_sess->backend_data_conn);
            proxy_sess->backend_data_conn = NULL;

            pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
            proxy_sess->frontend_data_conn = NULL;

          } else {
            size_t remaining = pbuf->remaining;

            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "received %lu bytes of data from source data connection",
              (unsigned long) remaining);
            session.xfer.total_bytes += remaining;

            res = proxy_ftp_data_send(cmd->tmp_pool, dst_data_conn, pbuf);
            if (res < 0) {
              xerrno = errno;

              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "error writing %lu bytes of data to sink data connection: %s",
                (unsigned long) remaining, strerror(xerrno));

              /* If this happens, close our connection prematurely.
               * XXX Should we try to send an ABOR here, too?  Or SIGURG?
               * XXX Should we only do this for e.g. Broken pipe?
               */
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "unable to proxy data between frontend/backend, "
                "closing data connections");

              pr_inet_close(session.pool, proxy_sess->backend_data_conn);
              proxy_sess->backend_data_conn = NULL;

              pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
              proxy_sess->frontend_data_conn = NULL;
            }
          }
        }
      }
    }

    if (FD_ISSET(PR_NETIO_FD(proxy_sess->backend_ctrl_conn->instrm), &rfds)) {
      /* Some data arrived on the ctrl connection... */
      pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);

      resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool,
        proxy_sess->backend_ctrl_conn, &resp_nlines);
      if (resp == NULL) {
        xerrno = errno;
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error receiving response from control connection: %s",
          strerror(xerrno));

        if (proxy_sess->frontend_data_conn != NULL) {
          pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
          proxy_sess->frontend_data_conn = NULL;
        }

        if (proxy_sess->backend_data_conn != NULL) {
          pr_inet_close(session.pool, proxy_sess->backend_data_conn);
          proxy_sess->backend_data_conn = NULL;
        }

        /* For a certain number of conditions, if we cannot read the response
         * from the backend, then we should just close the frontend, otherwise
         * we might "leak" to the client the fact that we are fronting some
         * backend server rather than being the server.
         */
        if (xerrno == ECONNRESET ||
            xerrno == ECONNABORTED ||
            xerrno == ENOENT ||
            xerrno == EPIPE) {
          pr_session_disconnect(&proxy_module,
            PR_SESS_DISCONNECT_BY_APPLICATION,
            "Backend control connection lost");
        }

        xfer_ok = FALSE;
        break;

      } else {

        /* If not a 1xx response, close the destination data connection,
         * BEFORE we send the response from the backend to the connected client.
         */
        if (resp->num[0] != '1') {
          switch (xfer_direction) {
            case PR_NETIO_IO_RD:
              if (proxy_sess->frontend_data_conn != NULL) {
                pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
                proxy_sess->frontend_data_conn = NULL;
              }
              break;

            case PR_NETIO_IO_WR:
              if (proxy_sess->backend_data_conn != NULL) {
                pr_inet_close(session.pool, proxy_sess->backend_data_conn);
                proxy_sess->backend_data_conn = NULL;
              }
              break;
          }

          /* If the response was a 4xx or 5xx, then we need to note that as
           * a failed transfer.
           */
          /* XXX What about ABOR/aborted transfers? */
          if (resp->num[0] == '4' || resp->num[0] == '5') {
            xfer_ok = FALSE;
          }
        }

        res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
          proxy_sess->frontend_ctrl_conn, resp, resp_nlines);
        if (res < 0) {
          xerrno = errno;

          pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0],
            strerror(xerrno));
          pr_response_flush(&resp_err_list);

          pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);
          errno = xerrno;
          return PR_ERROR(cmd);
        }

        /* If we get a 1xx response here, keep going.  Otherwise, we're
         * done with this data transfer.
         */
        if (src_data_conn == NULL ||
            (resp->num)[0] != '1') {
          proxy_sess->frontend_sess_flags &= (SF_ALL^SF_PASSIVE);
          proxy_sess->frontend_sess_flags &= (SF_ALL^(SF_ABORT|SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));

          proxy_sess->backend_sess_flags &= (SF_ALL^SF_PASSIVE);
          proxy_sess->backend_sess_flags &= (SF_ALL^(SF_ABORT|SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));
          break;
        }
      }
    }
  }

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED) > 0) {
    pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);
  }

  pr_response_clear(&resp_list);
  pr_response_clear(&resp_err_list);

  return (xfer_ok ? PR_HANDLED(cmd) : PR_ERROR(cmd));
}

MODRET proxy_eprt(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  pr_netaddr_t *remote_addr = NULL;
  unsigned short remote_port;
  unsigned char *allow_foreign_addr = NULL;

  CHECK_CMD_ARGS(cmd, 2);

  /* We can't just send the frontend's EPRT, as is, to the backend.
   * We need to connect to the frontend's EPRT; we need to open a listening
   * socket and send its address to the backend in our EPRT command.
   */

  /* XXX How to handle this if we are chrooted, without root privs, for
   * e.g. source ports below 1024?
   */

  remote_addr = proxy_ftp_msg_parse_ext_addr(cmd->tmp_pool, cmd->argv[1],
    session.c->remote_addr, cmd->cmd_id, NULL);
  if (remote_addr == NULL) {
    xerrno = errno;

    pr_trace_msg("proxy", 2, "error parsing EPRT command '%s': %s",
      cmd->argv[1], strerror(xerrno));

    if (xerrno == EPROTOTYPE) {
#ifdef PR_USE_IPV6
      if (pr_netaddr_use_ipv6()) {
        pr_response_add_err(R_522,
          _("Network protocol not supported, use (1,2)"));

      } else {
        pr_response_add_err(R_522,
          _("Network protocol not supported, use (1)"));
      }
#else
      pr_response_add_err(R_522, _("Network protocol not supported, use (1)"));
#endif /* PR_USE_IPV6 */

    } else {
      pr_response_add_err(R_501, _("Illegal EPRT command"));
    }

    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  remote_port = ntohs(pr_netaddr_get_port(remote_addr));

  /* If we are NOT listening on an RFC1918 address, BUT the client HAS
   * sent us an RFC1918 address in its EPRT command (which we know to not be
   * routable), then ignore that address, and use the client's remote address.
   */
  if (pr_netaddr_is_rfc1918(session.c->local_addr) != TRUE &&
      pr_netaddr_is_rfc1918(session.c->remote_addr) != TRUE &&
      pr_netaddr_is_rfc1918(remote_addr) == TRUE) {
    const char *rfc1918_ipstr;

    rfc1918_ipstr = pr_netaddr_get_ipstr(remote_addr);
    remote_addr = pr_netaddr_dup(cmd->tmp_pool, session.c->remote_addr);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "client sent RFC1918 address '%s' in EPRT command, ignoring it and "
      "using '%s'", rfc1918_ipstr, pr_netaddr_get_ipstr(remote_addr));
  }

  /* Make sure that the address specified matches the address from which
   * the control connection is coming.
   */
  allow_foreign_addr = get_param_ptr(main_server->conf, "AllowForeignAddress",
    FALSE);

  if (allow_foreign_addr == NULL ||
      *allow_foreign_addr == FALSE) {
    if (pr_netaddr_cmp(remote_addr, session.c->remote_addr) != 0 ||
        !remote_port) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
       "Refused EPRT %s (address mismatch)", cmd->arg);
      pr_response_add_err(R_500, _("Illegal EPRT command"));
      pr_response_flush(&resp_err_list);

      errno = EPERM;
      return PR_ERROR(cmd);
    }
  }

  /* Additionally, make sure that the port number used is a "high numbered"
   * port, to avoid bounce attacks.  For remote Windows machines, the
   * port numbers mean little.  However, there are also quite a few Unix
   * machines out there for whom the port number matters...
   */
  if (remote_port < 1024) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "Refused EPRT %s (port %d below 1024, possible bounce attack)", cmd->arg,
      remote_port);

    pr_response_add_err(R_500, _("Illegal EPRT command"));
    pr_response_flush(&resp_err_list);

    errno = EPERM;
    return PR_ERROR(cmd);
  }

  proxy_sess->frontend_data_addr = remote_addr;

  switch (proxy_sess->dataxfer_policy) {
    case PR_CMD_PASV_ID:
    case PR_CMD_EPSV_ID: {
      pr_netaddr_t *addr;
      pr_response_t *resp;
      unsigned int resp_nlines = 0;

      addr = proxy_ftp_xfer_prepare_passive(proxy_sess->dataxfer_policy, cmd,
        R_500, proxy_sess);
      if (addr == NULL) {
        return PR_ERROR(cmd);
      }

      resp = palloc(cmd->tmp_pool, sizeof(pr_response_t));
      resp->num = R_200;
      resp->msg = _("EPRT command successful");
      resp_nlines = 1;

      res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
        proxy_sess->frontend_ctrl_conn, resp, resp_nlines);
      if (res < 0) {
        xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error sending '%s %s' response to frontend: %s", resp->num,
          resp->msg, strerror(xerrno));

        errno = xerrno;
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_data_addr = addr;
      proxy_sess->backend_sess_flags |= SF_PASSIVE;
      break;
    }

    case PR_CMD_PORT_ID:
    case PR_CMD_EPRT_ID: 
    default: {
      pr_response_t *resp;
      unsigned int resp_nlines = 0;

      res = proxy_ftp_xfer_prepare_active(proxy_sess->dataxfer_policy, cmd,
        R_425, proxy_sess);
      if (res < 0) {
        return PR_ERROR(cmd);
      }

      resp = palloc(cmd->tmp_pool, sizeof(pr_response_t));
      resp->num = R_200;
      resp->msg = _("EPRT command successful");
      resp_nlines = 1;

      res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
        proxy_sess->frontend_ctrl_conn, resp, resp_nlines);
      if (res < 0) {
        xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error sending '%s %s' response to frontend: %s", resp->num,
          resp->msg, strerror(xerrno));

        errno = xerrno;
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_sess_flags |= SF_PORT;
      break;
    }
  }

  /* If the command was successful, mark it in the session state/flags. */
  proxy_sess->frontend_sess_flags |= SF_PORT;

  return PR_HANDLED(cmd);
}

MODRET proxy_epsv(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  conn_t *data_conn;
  const char *epsv_msg;
  char resp_msg[PR_RESPONSE_BUFFER_SIZE];
  pr_netaddr_t *bind_addr, *remote_addr;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  /* TODO: Handle any possible EPSV params, e.g. "EPSV ALL", properly. */

  switch (proxy_sess->dataxfer_policy) {
    case PR_CMD_PORT_ID:
    case PR_CMD_EPRT_ID:
      res = proxy_ftp_xfer_prepare_active(proxy_sess->dataxfer_policy, cmd,
        R_425, proxy_sess);
      if (res < 0) {
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_sess_flags |= SF_PORT;
      break;

    case PR_CMD_PASV_ID:
    case PR_CMD_EPSV_ID:
    default:
      remote_addr = proxy_ftp_xfer_prepare_passive(proxy_sess->dataxfer_policy,
        cmd, R_500, proxy_sess);
      if (remote_addr == NULL) {
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_data_addr = remote_addr;
      proxy_sess->backend_sess_flags |= SF_PASSIVE;
      break;
  }

  /* We do NOT want to connect here, but would rather wait until the
   * ensuing data transfer-initiating command.  Otherwise, a client could
   * spew PASV commands at us, and we would flood the backend server with
   * data transfer connections needlessly.
   *
   * We DO, however, need to create our own listening connection, so that
   * we can inform the client of the address/port to which IT is to
   * connect for its part of the data transfer.
   *
   * Note that we do NOT use the ProxySourceAddress here, since this listening
   * connection is for the frontend client.
   */

  if (pr_netaddr_get_family(session.c->local_addr) == pr_netaddr_get_family(session.c->remote_addr)) {
    bind_addr = session.c->local_addr;

  } else {
    /* In this scenario, the server has an IPv6 socket, but the remote client
     * is an IPv4 (or IPv4-mapped IPv6) peer.
     */
    bind_addr = pr_netaddr_v6tov4(cmd->pool, session.c->local_addr);
  }

  /* PassivePorts is handled by proxy_ftp_conn_listen(). */
  data_conn = proxy_ftp_conn_listen(cmd->tmp_pool, bind_addr);
  if (data_conn == NULL) {
    xerrno = errno;

    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_response_add_err(R_425, _("Unable to build data connection: "
      "Internal error"));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (proxy_sess->frontend_data_conn != NULL) {
    /* Make sure that we only have one frontend data connection. */
    pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
    proxy_sess->frontend_data_conn = NULL;
  }

  proxy_sess->frontend_data_conn = data_conn;

  epsv_msg = proxy_ftp_msg_fmt_ext_addr(cmd->tmp_pool, data_conn->local_addr,
    data_conn->local_port, cmd->cmd_id, TRUE);

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "Entering Extended Passive Mode (%s)", epsv_msg);

  /* Change the response to send back to the connecting client, telling it
   * to use OUR address/port.
   */
  resp = palloc(cmd->tmp_pool, sizeof(pr_response_t));
  resp->num = R_229;
  memset(resp_msg, '\0', sizeof(resp_msg));
  snprintf(resp_msg, sizeof(resp_msg)-1, "Entering Extended Passive Mode (%s)",
    epsv_msg);
  resp->msg = resp_msg;

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_inet_close(session.pool, data_conn);
    pr_response_block(TRUE);

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  proxy_sess->frontend_sess_flags |= SF_PASSIVE;
  return PR_HANDLED(cmd);
}

MODRET proxy_pasv(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  conn_t *data_conn;
  const char *pasv_msg;
  char resp_msg[PR_RESPONSE_BUFFER_SIZE];
  pr_netaddr_t *bind_addr, *remote_addr;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  switch (proxy_sess->dataxfer_policy) {
    case PR_CMD_PORT_ID:
    case PR_CMD_EPRT_ID:
      res = proxy_ftp_xfer_prepare_active(proxy_sess->dataxfer_policy, cmd,
        R_425, proxy_sess);
      if (res < 0) {
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_sess_flags |= SF_PORT;
      break;

    case PR_CMD_PASV_ID:
    case PR_CMD_EPSV_ID:
    default:
      remote_addr = proxy_ftp_xfer_prepare_passive(proxy_sess->dataxfer_policy,
        cmd, R_500, proxy_sess);
      if (remote_addr == NULL) {
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_data_addr = remote_addr;
      proxy_sess->backend_sess_flags |= SF_PASSIVE;
      break;
  }

  /* We do NOT want to connect here, but would rather wait until the
   * ensuing data transfer-initiating command.  Otherwise, a client could
   * spew PASV commands at us, and we would flood the backend server with
   * data transfer connections needlessly.
   *
   * We DO, however, need to create our own listening connection, so that
   * we can inform the client of the address/port to which IT is to
   * connect for its part of the data transfer.
   *
   * Note that we do NOT use the ProxySourceAddress here, since this listening
   * connection is for the frontend client.
   */

  bind_addr = session.c->local_addr;

  /* PassivePorts is handled by proxy_ftp_conn_listen(). */
  data_conn = proxy_ftp_conn_listen(cmd->tmp_pool, bind_addr);
  if (data_conn == NULL) {
    xerrno = errno;

    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_response_add_err(R_425, _("Unable to build data connection: "
      "Internal error"));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (proxy_sess->frontend_data_conn != NULL) {
    /* Make sure that we only have one frontend data connection. */
    pr_inet_close(session.pool, proxy_sess->frontend_data_conn);
    proxy_sess->frontend_data_conn = NULL;
  }

  proxy_sess->frontend_data_conn = data_conn;

  pasv_msg = proxy_ftp_msg_fmt_addr(cmd->tmp_pool, data_conn->local_addr,
    data_conn->local_port, TRUE);

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "Entering Passive Mode (%s).", pasv_msg);

  /* Change the response to send back to the connecting client, telling it
   * to use OUR address/port.
   */
  resp = palloc(cmd->tmp_pool, sizeof(pr_response_t));
  resp->num = R_227;
  memset(resp_msg, '\0', sizeof(resp_msg));
  snprintf(resp_msg, sizeof(resp_msg)-1, "Entering Passive Mode (%s).",
    pasv_msg);
  resp->msg = resp_msg;

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_inet_close(session.pool, data_conn);
    pr_response_block(TRUE);

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  proxy_sess->frontend_sess_flags |= SF_PASSIVE;
  return PR_HANDLED(cmd);
}

MODRET proxy_port(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  pr_netaddr_t *remote_addr = NULL;
  unsigned short remote_port;
  unsigned char *allow_foreign_addr = NULL;

  CHECK_CMD_ARGS(cmd, 2);

  /* We can't just send the frontend's PORT, as is, to the backend.
   * We need to connect to the frontend's PORT; we need to open a listening
   * socket and send its address to the backend in our PORT command.
   */

  /* XXX How to handle this if we are chrooted, without root privs, for
   * e.g. source ports below 1024?
   */

  remote_addr = proxy_ftp_msg_parse_addr(cmd->tmp_pool, cmd->argv[1],
    pr_netaddr_get_family(session.c->remote_addr));
  if (remote_addr == NULL) {
    xerrno = errno;

    pr_trace_msg("proxy", 2, "error parsing PORT command '%s': %s",
      cmd->argv[1], strerror(xerrno));

    pr_response_add_err(R_501, _("Illegal PORT command"));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  remote_port = ntohs(pr_netaddr_get_port(remote_addr));

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

  /* Make sure that the address specified matches the address from which
   * the control connection is coming.
   */

  allow_foreign_addr = get_param_ptr(TOPLEVEL_CONF, "AllowForeignAddress",
    FALSE);

  if (allow_foreign_addr == NULL ||
      *allow_foreign_addr == FALSE) {
#ifdef PR_USE_IPV6
    if (pr_netaddr_use_ipv6()) {
      /* We can only compare the PORT-given address against the remote client
       * address if the remote client address is an IPv4-mapped IPv6 address.
       */
      if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET6 &&
          pr_netaddr_is_v4mappedv6(session.c->remote_addr) != TRUE) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "Refused PORT %s (IPv4/IPv6 address mismatch)", cmd->arg);

        pr_response_add_err(R_500, _("Illegal PORT command"));
        pr_response_flush(&resp_err_list);

        errno = EPERM;
        return PR_ERROR(cmd);
      }
    }
#endif /* PR_USE_IPV6 */

    if (pr_netaddr_cmp(remote_addr, session.c->remote_addr) != 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "Refused PORT %s (address mismatch)", cmd->arg);

      pr_response_add_err(R_500, _("Illegal PORT command"));
      pr_response_flush(&resp_err_list);

      errno = EPERM;
      return PR_ERROR(cmd);
    }
  }

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

  proxy_sess->frontend_data_addr = remote_addr;

  switch (proxy_sess->dataxfer_policy) {
    case PR_CMD_PASV_ID:
    case PR_CMD_EPSV_ID: {
      pr_netaddr_t *addr;
      pr_response_t *resp;
      unsigned int resp_nlines = 0;

      addr = proxy_ftp_xfer_prepare_passive(proxy_sess->dataxfer_policy, cmd,
        R_500, proxy_sess);
      if (addr == NULL) {
        return PR_ERROR(cmd);
      }

      resp = palloc(cmd->tmp_pool, sizeof(pr_response_t));
      resp->num = R_200;
      resp->msg = _("PORT command successful");
      resp_nlines = 1;

      res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
        proxy_sess->frontend_ctrl_conn, resp, resp_nlines);
      if (res < 0) {
        xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error sending '%s %s' response to frontend: %s", resp->num,
          resp->msg, strerror(xerrno));

        errno = xerrno;
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_data_addr = addr;
      proxy_sess->backend_sess_flags |= SF_PASSIVE;
      break;
    }

    case PR_CMD_PORT_ID:
    case PR_CMD_EPRT_ID:
    default: {
      pr_response_t *resp;
      unsigned int resp_nlines = 0;

      res = proxy_ftp_xfer_prepare_active(proxy_sess->dataxfer_policy, cmd,
        R_425, proxy_sess);
      if (res < 0) {
        return PR_ERROR(cmd);
      }

      resp = palloc(cmd->tmp_pool, sizeof(pr_response_t));
      resp->num = R_200;
      resp->msg = _("PORT command successful");
      resp_nlines = 1;

      res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
        proxy_sess->frontend_ctrl_conn, resp, resp_nlines);
      if (res < 0) {
        xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error sending '%s %s' response to frontend: %s", resp->num,
          resp->msg, strerror(xerrno));

        errno = xerrno;
        return PR_ERROR(cmd);
      }

      proxy_sess->backend_sess_flags |= SF_PORT;
      break;
    }
  }

  /* If the command was successful, mark it in the session state/flags. */
  proxy_sess->frontend_sess_flags |= SF_PORT;

  return PR_HANDLED(cmd);
}

MODRET proxy_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *block_responses) {
  int successful = FALSE, res;

  switch (proxy_role) {
    case PROXY_ROLE_REVERSE:
      res = proxy_reverse_handle_user(cmd, proxy_sess, &successful);
      break;

    case PROXY_ROLE_FORWARD:
      res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
        block_responses);
      break;
  }

  if (res < 0) {
    int xerrno = errno;

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (successful) {
    config_rec *c;
    const char *notes_key = "mod_auth.orig-user";
    char *user, *xferlog = PR_XFERLOG_PATH;

    /* For 2xx/3xx responses (others?), stash the user name appropriately. */
    user = cmd->arg;

    (void) pr_table_remove(session.notes, notes_key, NULL);

    if (pr_table_add_dup(session.notes, notes_key, user, 0) < 0) {
      pr_log_debug(DEBUG3, "error stashing '%s' in session.notes: %s",
        notes_key, strerror(errno));
    }

    /* Open the TransferLog here. */
    c = find_config(main_server->conf, CONF_PARAM, "TransferLog", FALSE);
    if (c != NULL) {
      xferlog = c->argv[0];
    }

    if (strncasecmp(xferlog, "none", 5) == 0) {
      xferlog_open(NULL);

    } else {
      xferlog_open(xferlog);
    }

    /* Handle DefaultTransferMode here. */
    c = find_config(main_server->conf, CONF_PARAM, "DefaultTransferMode",
      FALSE);
    if (c != NULL) {
      if (strncasecmp(c->argv[0], "binary", 7) == 0) {
        session.sf_flags &= (SF_ALL^SF_ASCII);

      } else {
        session.sf_flags |= SF_ASCII;
      }

    } else {
      /* ASCII by default. */
      session.sf_flags |= SF_ASCII;
    }
  }

  return (res == 0 ? PR_DECLINED(cmd) : PR_HANDLED(cmd));
}

MODRET proxy_pass(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *block_responses) {
  int successful = FALSE, res;

  switch (proxy_role) {
    case PROXY_ROLE_REVERSE:
      res = proxy_reverse_handle_pass(cmd, proxy_sess, &successful);
      break;

    case PROXY_ROLE_FORWARD:
      res = proxy_forward_handle_pass(cmd, proxy_sess, &successful,
        block_responses);
      break;
  }

  if (res < 0) {
    int xerrno = errno;

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (successful) {
    char *user;

    user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    session.user = user;

    /* XXX Do we need to set other login-related fields here?  E.g.
     * session.uid, session.gid, etc?
     */

    fixup_dirs(main_server, CF_DEFER);
  }

  /* Remove any exit handlers installed by mod_xfer.  We do this here,
   * rather than in sess_init, since our sess_init is called BEFORE the
   * sess_init of mod_xfer.
   *
   * XXX What if no PASS command is sent/needed by the client?  Can we
   * remove the mod_xfer exit headers in the proxy_user() function?
   */
  pr_event_unregister(&xfer_module, "core.exit", NULL);

  return PR_HANDLED(cmd);
}

MODRET proxy_type(cmd_rec *cmd, struct proxy_session *proxy_sess) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

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

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
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
    char *type;

    /* This code is duplicated from mod_xfer.c:xfer_type().  Would be nice
     * to factor it out somewhere reusable, i.e. some pr_str_ function.
     */

    type = pstrdup(cmd->tmp_pool, cmd->argv[1]);
    type[0] = toupper(type[0]);

    if (strncmp(type, "A", 2) == 0 ||
        (cmd->argc == 3 &&
         strncmp(type, "L", 2) == 0 &&
         strncmp(cmd->argv[2], "7", 2) == 0)) {

      /* TYPE A(SCII) or TYPE L 7. */
      session.sf_flags |= SF_ASCII;

    } else if (strncmp(type, "I", 2) == 0 ||
        (cmd->argc == 3 &&
         strncmp(type, "L", 2) == 0 &&
         strncmp(cmd->argv[2], "8", 2) == 0)) {

      /* TYPE I(MAGE) or TYPE L 8. */
      session.sf_flags &= (SF_ALL^(SF_ASCII|SF_ASCII_OVERRIDE));
    }
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  return PR_HANDLED(cmd);
}

MODRET proxy_any(cmd_rec *cmd) {
  int block_responses = TRUE, res, xerrno;
  struct proxy_session *proxy_sess;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  modret_t *mr = NULL;

  if (proxy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* XXX TODO: the response blocking is role-specific...? */
  pr_response_block(FALSE);
  pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
 
  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);

  /* Commands related to logins and data transfers are handled separately.
   *
   * RFC 2228 commands are not to be proxied (since we cannot necessarily
   * provide end-to-end protection, just hop-by-hop).
   *
   * FEAT should not necessarily be proxied to the backend, but should be
   * handled locally.
   */

  switch (cmd->cmd_id) {
    case PR_CMD_USER_ID:
      mr = proxy_user(cmd, proxy_sess, &block_responses);
      if (block_responses) {
        pr_response_block(TRUE);
      }
      return mr;

    case PR_CMD_PASS_ID:
      mr = proxy_pass(cmd, proxy_sess, &block_responses);
      if (block_responses) {
        pr_response_block(TRUE);
      }
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

    case PR_CMD_TYPE_ID:
      /* Used for setting the ASCII/binary session flag properly, e.g. for
       * TransferLogs.
       */
      mr = proxy_type(cmd, proxy_sess);
      pr_response_block(TRUE);
      return mr;

    case PR_CMD_LIST_ID:
    case PR_CMD_MLSD_ID:
    case PR_CMD_NLST_ID:
      session.xfer.p = make_sub_pool(session.pool);
      mr = proxy_data(cmd, proxy_sess);
      destroy_pool(session.xfer.p);
      memset(&session.xfer, 0, sizeof(session.xfer));

      pr_response_block(TRUE);
      return mr;

    case PR_CMD_APPE_ID:
    case PR_CMD_RETR_ID:
    case PR_CMD_STOR_ID:
    case PR_CMD_STOU_ID:
      /* In addition to the same setup as for directory listings, we also
       * track more things, for supporting e.g. TransferLog.
       */
      memset(&session.xfer, 0, sizeof(session.xfer));
      session.xfer.p = make_sub_pool(session.pool);
      gettimeofday(&session.xfer.start_time, NULL);

      mr = proxy_data(cmd, proxy_sess);

      proxy_log_xfer(cmd, 'c');
      destroy_pool(session.xfer.p);
      memset(&session.xfer, 0, sizeof(session.xfer));

      pr_response_block(TRUE);
      return mr;

    case PR_CMD_FEAT_ID:
      return PR_DECLINED(cmd);

    /* RFC 2228 commands */
    case PR_CMD_ADAT_ID:
    case PR_CMD_AUTH_ID:
    case PR_CMD_CCC_ID:
    case PR_CMD_CONF_ID:
    case PR_CMD_ENC_ID:
    case PR_CMD_MIC_ID:
    case PR_CMD_PBSZ_ID:
    case PR_CMD_PROT_ID:
      return PR_DECLINED(cmd);
  }

  /* If we are not connected to a backend server, then don't try to proxy
   * the command.
   */
  if (!(proxy_sess_state & PROXY_SESS_STATE_CONNECTED)) {
    return PR_DECLINED(cmd);
  }

  if (pr_cmd_cmp(cmd, PR_CMD_QUIT_ID) != 0) {
    /* If we have connected to a backend server, but we have NOT authenticated
     * to that backend server, then reject all commands as "out of sequence"
     * errors (i.e. malicious or misinformed clients).
     *
     * Note that we use 500 rather than 503 here since 503 is not specifically
     * mentioned in RFC 959 as being allowed for all commands, unfortunately.
     */
    if (!(proxy_sess_state & PROXY_SESS_STATE_BACKEND_AUTHENTICATED)) {
      pr_response_add_err(R_500, _("Bad sequence of commands"));
      return PR_ERROR(cmd);
    }
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

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;

    /* For a certain number of conditions, if we cannot read the response
     * from the backend, then we should just close the frontend, otherwise
     * we might "leak" to the client the fact that we are fronting some
     * backend server rather than being the server.
     */
    if (xerrno == ECONNRESET ||
        xerrno == ECONNABORTED ||
        xerrno == ENOENT ||
        xerrno == EPIPE) {
      pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
        "Backend control connection lost");
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", cmd->argv[0],
      strerror(xerrno));

    pr_response_add_err(R_500, _("%s: %s"), cmd->argv[0], strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
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

static void restrict_session(void) {
  const char *proxy_chroot = NULL;
  rlim_t curr_nproc, max_nproc;

  /* XXX TODO: If we are a forward proxy, AND we require proxy auth, THEN
   * this chroot/privdrop should not happen until AFTER successful
   * authentication.  Right?
   */

  PRIVS_ROOT

  if (getuid() == PR_ROOT_UID) {
    int res;

    /* Chroot to the ProxyTables/empty/ directory before dropping root privs. */
    proxy_chroot = pdircat(proxy_pool, proxy_tables_dir, "empty", NULL);
    res = chroot(proxy_chroot);
    if (res < 0) {
      int xerrno = errno;

      PRIVS_RELINQUISH

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to chroot to ProxyTables/empty/ directory '%s': %s",
        proxy_chroot, strerror(xerrno));
      pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_MODULE_ACL,
       "Unable to chroot proxy session");
    }

    if (chdir("/") < 0) {
      int xerrno = errno;

      PRIVS_RELINQUISH

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to chdir to root directory within chroot: %s",
        strerror(xerrno));
      pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_MODULE_ACL,
       "Unable to chroot proxy session");
    }
  }

  /* Make the proxy session process have the identity of the configured daemon
   * User/Group.
   */
  PRIVS_REVOKE

  if (proxy_chroot != NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "proxy session running as UID %lu, GID %lu, restricted to '%s'",
      (unsigned long) getuid(), (unsigned long) getgid(), proxy_chroot);

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "proxy session running as UID %lu, GID %lu, located in '%s'",
      (unsigned long) getuid(), (unsigned long) getgid(), getcwd(NULL, 0));
  }

  /* Once we have chrooted, and dropped root privs completely, we can now
   * lower our nproc resource limit, so that we cannot fork any new
   * processed.  We should not be doing so, and we want to mitigate any
   * possible exploitation.
   */
  if (pr_rlimit_get_nproc(&curr_nproc, NULL) == 0) {
    max_nproc = curr_nproc;

    if (pr_rlimit_set_nproc(curr_nproc, max_nproc) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error setting nproc resource limits to %lu: %s",
        (unsigned long) max_nproc, strerror(errno));

    } else {
      pr_trace_msg(trace_channel, 13,
        "set nproc resource limits to %lu", (unsigned long) max_nproc);
    }

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting nproc limits: %s", strerror(errno));
  }
}

static void proxy_ctrl_read_ev(const void *event_data, void *user_data) {
  if (proxy_sess_state & PROXY_SESS_STATE_CONNECTED) {
    restrict_session();

    /* Our work here is done; we no longer need to listen for future reads. */
    pr_event_unregister(&proxy_module, "mod_proxy.ctrl-read",
      proxy_ctrl_read_ev);
  }
}

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

    /* TODO: Remove/clean up state files (e.g. roundrobin.dat). */

    destroy_pool(proxy_pool);
    proxy_pool = NULL;

    (void) close(proxy_logfd);
    proxy_logfd = -1;
  }
}
#endif

static void proxy_postparse_ev(const void *event_data, void *user_data) {
  int engine = FALSE;
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyEngine", FALSE);
  if (c) {
    engine = *((int *) c->argv[0]);
  }

  if (engine == FALSE) {
    return;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTables", FALSE);
  if (c == NULL) {
    /* No ProxyTables configured, mod_proxy cannot run. */
    pr_log_pri(PR_LOG_WARNING, MOD_PROXY_VERSION
      ": missing required ProxyTables directive, failing to start up");

    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "Missing required config");
  }

  proxy_tables_dir = c->argv[0];

  if (proxy_forward_init(proxy_pool, proxy_tables_dir) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_PROXY_VERSION
      ": unable to initialize forward-proxy, failing to start up");

    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "Failed forward-proxy initialization");
  }

  if (proxy_reverse_init(proxy_pool, proxy_tables_dir) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_PROXY_VERSION
      ": unable to initialize reverse-proxy, failing to start up");

    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "Failed reverse-proxy initialization");
  }
}

static void proxy_restart_ev(const void *event_data, void *user_data) {

  /* TODO: Remove/clean up state files (e.g. roundrobin.dat). */
}

static void proxy_shutdown_ev(const void *event_data, void *user_data) {
  proxy_forward_free(proxy_pool, proxy_tables_dir);
  proxy_reverse_free(proxy_pool, proxy_tables_dir);

  /* TODO: Delete ProxyTables dir, recursively. */

  destroy_pool(proxy_pool);
  proxy_pool = NULL;

  if (proxy_logfd >= 0) {
    (void) close(proxy_logfd);
    proxy_logfd = -1;
  }
}

static void proxy_timeoutidle_ev(const void *event_data, void *user_data) {
  /* Unblock responses here, so that mod_core's response will be flushed
   * out to the frontend client.
   */
  pr_response_block(FALSE);
}

static void proxy_timeoutnoxfer_ev(const void *event_data, void *user_data) {
  /* Unblock responses here, so that mod_xfer's response will be flushed
   * out to the frontend client.
   */
  pr_response_block(FALSE);
}

static void proxy_timeoutstalled_ev(const void *event_data, void *user_data) {
  /* Unblock responses here, so that mod_xfer's response will be flushed
   * out to the frontend client.
   */
  pr_response_block(FALSE);
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
  pr_event_register(&proxy_module, "core.postparse", proxy_postparse_ev, NULL);
  pr_event_register(&proxy_module, "core.restart", proxy_restart_ev, NULL);
  pr_event_register(&proxy_module, "core.shutdown", proxy_shutdown_ev, NULL);

  return 0;
}

/* Set defaults for directives that mod_proxy should allow (but whose
 * values are checked e.g. by PRE_CMD handlers):
 *
 *  AllowOverwrite
 *  AllowStoreRestart
 *
 * Unless these directives have already been set, of course.
 */
static void proxy_set_sess_defaults(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "AllowOverwrite", FALSE);
  if (c == NULL) {
    c = add_config_param_set(&main_server->conf, "AllowOverwrite", 1, NULL);
    c->argv[0] = palloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = TRUE;
    c->flags |= CF_MERGEDOWN;
  }

  c = find_config(main_server->conf, CONF_PARAM, "AllowStoreRestart", FALSE);
  if (c == NULL) {
    c = add_config_param_set(&main_server->conf, "AllowStoreRestart", 1, NULL);
    c->argv[0] = palloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = TRUE;
    c->flags |= CF_MERGEDOWN;
  }
}

static int proxy_sess_init(void) {
  config_rec *c;
  int res;
  struct proxy_session *proxy_sess;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyEngine", FALSE);
  if (c != NULL) {
    proxy_engine = *((int *) c->argv[0]);
  }

  if (proxy_engine == FALSE) {
    return 0;
  }

  pr_event_register(&proxy_module, "core.exit", proxy_exit_ev, NULL);
  pr_event_register(&proxy_module, "mod_proxy.ctrl-read", proxy_ctrl_read_ev,
    NULL);

  /* Install event handlers for timeouts, so that we can properly close
   * the connections on either side.
   */
  pr_event_register(&proxy_module, "core.timeout-idle",
    proxy_timeoutidle_ev, NULL);
  pr_event_register(&proxy_module, "core.timeout-no-transfer",
    proxy_timeoutnoxfer_ev, NULL);
  pr_event_register(&proxy_module, "core.timeout-stalled",
    proxy_timeoutstalled_ev, NULL);

  /* XXX What do we do about TimeoutLogin?  That timeout doesn't really mean
   * much to mod_proxy; how can we ensure that it won't be enforced e.g.
   * by mod_core?
   *
   * Well, it MIGHT mean something for a forward ProxyRole, since we
   * need to at least get the USER command from the client before knowing
   * the destination server.
   */

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

  c = find_config(main_server->conf, CONF_PARAM, "ProxyOptions", FALSE);
  while (c != NULL) {
    unsigned long opts;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    proxy_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyOptions", FALSE);
  }

  proxy_random_init();

  c = find_config(main_server->conf, CONF_PARAM, "ProxyRole", FALSE);
  if (c != NULL) {
    proxy_role = *((int *) c->argv[0]);
  }

  /* Set defaults for directives that mod_proxy should allow. */
  proxy_set_sess_defaults();

  /* Allocate our own session structure, for tracking proxy-specific
   * fields.  Use the session.notes table for stashing/retrieving it as
   * needed.
   */
  proxy_sess = pcalloc(proxy_pool, sizeof(struct proxy_session));
  if (pr_table_add(session.notes, "mod_proxy.proxy-session", proxy_sess,
      sizeof(struct proxy_session)) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error stashing proxy session note: %s", strerror(errno));

    /* This is a fatal error; mod_proxy won't function without this note. */
    errno = EPERM;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxySourceAddress", FALSE);
  if (c != NULL) {
    proxy_sess->src_addr = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyDataTransferPolicy",
    FALSE);
  if (c != NULL) {
    proxy_sess->dataxfer_policy = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyTimeoutConnect", FALSE);
  if (c != NULL) {
    proxy_sess->connect_timeout = *((int *) c->argv[0]);

  } else {
    proxy_sess->connect_timeout = PROXY_CONNECT_DEFAULT_TIMEOUT;
  }

  /* XXX All proxied connections are automatically chrooted (after auth,
   * or immediately upon connect?  Depends on the backend selection
   * mechanism...)
   *
   * All proxied connections immediately have root privs dropped.  (Act as
   * if the RootRevoke option was programmatically set?)
   */

  switch (proxy_role) {
    case PROXY_ROLE_REVERSE:
      if (proxy_reverse_sess_init(proxy_pool, proxy_tables_dir) < 0) {
        proxy_engine = FALSE;

        /* XXX TODO: Return 530 to connecting client? */
        return -1;
      }

      /* XXX TODO: Move this reverse_connect() call into the reverse module,
       * so that e.g. we can do user-based selection.
       */
      if (proxy_reverse_connect(proxy_pool, proxy_sess) < 0) {
        /* XXX TODO: Return 530 to connecting client? */
        pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
          "Unable to connect to backend server");
      }

      set_auth_check(proxy_reverse_have_authenticated);
      break;

    case PROXY_ROLE_FORWARD:
      if (proxy_forward_sess_init(proxy_pool, proxy_tables_dir) < 0) {
        proxy_engine = FALSE;

        /* XXX TODO: Return 530 to connecting client? */
        return -1; 
      }

      /* XXX TODO:
       *   DisplayConnect
       */

      set_auth_check(proxy_forward_have_authenticated);
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
  { "ProxyDataTransferPolicy",	set_proxydatatransferpolicy,	NULL },
  { "ProxyEngine",		set_proxyengine,		NULL },
  { "ProxyForwardMethod",	set_proxyforwardmethod,		NULL },
  { "ProxyLog",			set_proxylog,			NULL },
  { "ProxyOptions",		set_proxyoptions,		NULL },
  { "ProxyReverseSelection",	set_proxyreverseselection,	NULL },
  { "ProxyReverseServers",	set_proxyreverseservers,	NULL },
  { "ProxyRole",		set_proxyrole,			NULL },
  { "ProxySourceAddress",	set_proxysourceaddress,		NULL },
  { "ProxyTables",		set_proxytables,		NULL },
  { "ProxyTimeoutConnect",	set_proxytimeoutconnect,	NULL },

  /* Support TransferPriority for proxied connections? */
  /* Deliberately ignore/disable HiddenStores in mod_proxy configs */
  /* Two timeouts, one for frontend and one for backend? */

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

