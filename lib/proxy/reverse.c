/*
 * ProFTPD - mod_proxy reverse-proxy implementation
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
#include "proxy/reverse.h"
#include "proxy/random.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/feat.h"

/* From response.c */
extern xaset_t *server_list;

static int reverse_select_policy = PROXY_REVERSE_SELECT_POLICY_RANDOM;

static const char *trace_channel = "proxy.reverse";

int proxy_reverse_init(pool *p, const char *tables_dir) {
  server_rec *s;
  unsigned int vhost_count = 0;

  /* Iterate through the server_list, and count up the number of vhosts. */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    vhost_count++;
  }

  /* XXX Create our roundrobin.dat file:
   *
   *  size = (sizeof(unsigned int) * 3) * vhost_count
   *
   * Do we do this if any of the vhosts are configured as reverse proxies,
   * or do we do it all of the time, regardless of whether any reverse proxies
   * are configured?
   */

  return 0;
}

int proxy_reverse_free(pool *p, const char *tables_dir) {
  /* TODO: Implement any necessary cleanup */
  return 0;
}

int proxy_reverse_sess_init(pool *p, const char *tables_dir) {
  config_rec *c;
  array_header *backend_servers;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers",
    FALSE);
  if (c == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": gateway mode enabled, but no ProxyReverseServers configured");
    return -1;
  }

  backend_servers = c->argv[0];

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseSelection",
    FALSE);
  if (c != NULL) {
    reverse_select_policy = *((int *) c->argv[0]);

    /* XXX For a 'roundRobin' selection, use a slot allocated in the
     * ProxyReverseServers config_rec, one that will contain the index
     * (into the backend_servers list, if present) of the last-used
     * backend server. 
     */
  }

  /* XXX Need to be given/set the ProxyTables directory, for opening fds
   * and mmapping the necessary selection state tables.  Need to determine
   * curr/max indexes, set up the three lists of backend server:
   *
   *  configured
   *  live
   *  dead (initially empty)
   */

  /* XXX On mod_proxy 'core.postparse', need additional code which writes
   * out the state tables, so that each vhost gets a SID entry.  Make sure
   * each SID row's curr_idx == max_idx, so that incrementing it goes to the
   * "first" configured backend server.
   */

  return 0;
}

int proxy_reverse_have_authenticated(cmd_rec *cmd) {
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

#if 0
   /* This state check will become more complex when implementing per-user
    * reverse proxy lookups.
    */
   if (authd == FALSE) {
     pr_response_send(R_530, _("Please login with USER and PASS"));
   }
#endif

  return TRUE;
}

static int check_parent_dir_perms(pool *p, const char *path) {
  struct stat st;
  int res;
  char *dir_path, *ptr = NULL;

  ptr = strrchr(path, '/');
  if (ptr != path) {
    dir_path = pstrndup(p, path, ptr - path);

  } else {
    dir_path = "/";
  }

  res = stat(dir_path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to stat ProxyReverseServers %s directory '%s': %s",
      path, dir_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (st.st_mode & S_IWOTH) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use ProxyReverseServers %s from world-writable "
      "directory '%s' (perms %04o): %s", path, dir_path,
      st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int check_file_perms(pool *p, const char *path) {
  struct stat st;
  int res;
  const char *orig_path;

  orig_path = path;

  res = lstat(path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to lstat ProxyReverseServers '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (S_ISLNK(st.st_mode)) {
    char buf[PR_TUNABLE_PATH_MAX+1];

    /* Check the permissions on the parent directory; if they're world-writable,
     * then this symlink can be deleted/pointed somewhere else.
     */
    res = check_parent_dir_perms(p, path);
    if (res < 0) {
      return -1;
    }

    /* Follow the link to the target path; that path will then have its
     * parent directory checked.
     */
    memset(buf, '\0', sizeof(buf));
    res = readlink(path, buf, sizeof(buf)-1);
    if (res > 0) {
      path = pstrdup(p, buf);
    }

    res = stat(orig_path, &st);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": unable to stat ProxyReverseServers '%s': %s", orig_path,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  if (S_ISDIR(st.st_mode)) {
    int xerrno = EISDIR;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use ProxyReverseServers '%s': %s", orig_path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* World-writable files are insecure, and are thus not usable/trusted. */
  if (st.st_mode & S_IWOTH) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use world-writable ProxyReverseServers '%s' "
      "(perms %04o): %s", orig_path, st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* TODO: This will warn about files such as FIFOs, BUT will leave them
   * usable.  Good idea, or bad idea?
   */
  if (!S_ISREG(st.st_mode)) {
    pr_log_pri(PR_LOG_WARNING, MOD_PROXY_VERSION
      ": ProxyReverseServers '%s' is not a regular file", orig_path);
  }

  /* Check the parent directory of this file.  If the parent directory
   * is world-writable, that too is insecure.
   */
  res = check_parent_dir_perms(p, path);
  if (res < 0) {
    return -1;
  }

  return 0;
}

array_header *proxy_reverse_file_parse_uris(pool *p, const char *path) {
  int res;
  pool *tmp_pool;
  char buf[PR_TUNABLE_BUFFER_SIZE+1];
  pr_fh_t *fh;
  unsigned int lineno = 0;
  array_header *uris = NULL;
  struct stat st;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*path != '/') {
    /* A relative path?  Unacceptable. */
    errno = EINVAL;
    return NULL;
  }

  res = check_file_perms(p, path);
  if (res < 0) {
    return NULL;
  }

  /* Use a nonblocking open() for the path; it could be a FIFO, and we don't
   * want to block forever if the other end of the FIFO is not running.
   */
  fh = pr_fsio_open(path, O_RDONLY|O_NONBLOCK);
  if (fh == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7,
      "error opening ProxyReverseServers file '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  pr_fsio_set_block(fh);

  /* Stat the file to find the optimal buffer size for reading. */
  res = pr_fsio_fstat(fh, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "unable to fstat '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  fh->fh_iosz = st.st_blksize;

  memset(buf, '\0', sizeof(buf));
  uris = make_array(p, 1, sizeof(struct proxy_conn *));

  while ((pr_fsio_getline(buf, sizeof(buf)-1, fh, &lineno) != NULL)) {
    int have_eol = FALSE;
    char *bufp = NULL;
    size_t buflen;
    struct proxy_conn *pconn;

    pr_signals_handle();

    buflen = strlen(buf);

    /* Trim off the trailing newline, if present. */
    if (buflen &&
        buf[buflen - 1] == '\n') {
      have_eol = TRUE;
      buf[buflen-1] = '\0';
      buflen--;
    }

    while (buflen &&
           buf[buflen - 1] == '\r') {
      pr_signals_handle();
      buf[buflen-1] = '\0';
      buflen--;
    }

    if (!have_eol) {
      pr_trace_msg(trace_channel, 3,
        "warning: skipping possibly truncated ProxyReverseServers data (%s:%u)",
        path, lineno);
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    /* Advance past any leading whitespace. */
    for (bufp = buf; *bufp && PR_ISSPACE(*bufp); bufp++);

    /* Check for commented or blank lines at this point, and just continue on
     * to the next configuration line if found.
     */
    if (*bufp == '#' || !*bufp) {
      pr_trace_msg(trace_channel, 9,
        "skipping commented/empty line (%s:%u)", path, lineno);
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    pconn = proxy_conn_create(p, bufp);
    if (pconn == NULL) {
      pr_trace_msg(trace_channel, 9,
        "skipping malformed URL '%s' (%s:%u)", bufp, path, lineno);
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    *((struct proxy_conn **) push_array(uris)) = pconn; 
    memset(buf, '\0', sizeof(buf));
  }

  (void) pr_fsio_close(fh);
  return uris;
}

int proxy_reverse_select_get_policy(const char *policy) {
  if (policy == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (strncmp(policy, "random", 7) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_RANDOM;

  } else if (strncmp(policy, "roundRobin", 11) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_ROUND_ROBIN;

  } else if (strncmp(policy, "leastConns", 11) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_LEAST_CONNS;

  } else if (strncmp(policy, "equalConns", 11) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_EQUAL_CONNS;

  } else if (strncmp(policy, "lowestResponseTime", 19) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_LOWEST_RESPONSE_TIME;

  } else if (strncmp(policy, "shuffle", 8) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_SHUFFLE;

  } else if (strncmp(policy, "perUser", 8) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_PER_USER;
  }

  errno = ENOENT;
  return -1;
}

static int reverse_select_next_index(unsigned int sid,
    unsigned int backend_count, void *policy_data) {
  int next_idx = -1;

  if (backend_count == 1) {
    return 0;
  }

  switch (reverse_select_policy) {
    case PROXY_REVERSE_SELECT_POLICY_RANDOM:
      next_idx = (int) proxy_random_next(0, backend_count-1);      
      pr_trace_msg(trace_channel, 11,
        "RANDOM selection: selected index %d of %u", next_idx, backend_count-1);
      break;

    case PROXY_REVERSE_SELECT_POLICY_ROUND_ROBIN:
      /* Find current index for SID, increment by one, lock row, write data,
       * unlock row, return incremented idx.
       */

    default:
      errno = ENOSYS;
      return -1;
  }

  return next_idx;
}

static int reverse_select_used_index(unsigned int sid, unsigned int idx,
    unsigned long response_ms) {
  errno = ENOSYS;
  return -1;
}

static pr_netaddr_t *get_reverse_server_addr(pool *p,
    struct proxy_session *proxy_sess) {
  config_rec *c;
  array_header *backend_servers;
  struct proxy_conn **conns;
  pr_netaddr_t *addr;
  int idx;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
  backend_servers = c->argv[0];
  conns = backend_servers->elts;

  idx = reverse_select_next_index(main_server->sid,
    backend_servers->nelts, NULL);
  if (idx < 0) {
    return NULL;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "selected backend server '%s'", proxy_conn_get_uri(conns[idx]));

  addr = proxy_conn_get_addr(conns[idx]);
  return addr;
}

int proxy_reverse_connect(pool *p, struct proxy_session *proxy_sess) {
  conn_t *server_conn = NULL;
  pr_response_t *resp = NULL;
  unsigned int resp_nlines = 0;
  pr_netaddr_t *remote_addr;

  remote_addr = get_reverse_server_addr(p, proxy_sess);
  if (remote_addr == NULL) {
    return -1;
  }

  proxy_sess->dst_addr = remote_addr;

  server_conn = proxy_conn_get_server_conn(p, proxy_sess, proxy_sess->dst_addr);
  if (server_conn == NULL) {
    return -1;
  }

  if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
    if (proxy_conn_send_proxy(p, server_conn) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error sending PROXY message to %s#%u: %s",
        pr_netaddr_get_ipstr(server_conn->remote_addr),
        ntohs(pr_netaddr_get_port(server_conn->remote_addr)),
        strerror(errno));
    }
  }

  /* XXX Support/send a CLNT command of our own?  Configurable via e.g.
   * "UserAgent" string?
   */

  proxy_sess->frontend_ctrl_conn = session.c;
  proxy_sess->backend_ctrl_conn = server_conn;

  /* Read the response from the backend server and send it to the connected
   * client as if it were our own banner.
   */
  resp = proxy_ftp_ctrl_recv_resp(p, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    int xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
      strerror(xerrno));

    errno = xerrno;
    return -1;

  } else {
    int banner_ok = TRUE;

    if (resp->num[0] != '2') {
      banner_ok = FALSE;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "received banner from backend %s:%u%s: %s %s",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
      banner_ok ? "" : ", DISCONNECTING", resp->num, resp->msg);

    if (proxy_ftp_ctrl_send_resp(p, session.c, resp, resp_nlines) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to send banner to client: %s", strerror(errno));
    }

    if (banner_ok == FALSE) {
      pr_inet_close(p, proxy_sess->backend_ctrl_conn);
      proxy_sess->backend_ctrl_conn = NULL;
      return -1;
    }
  }

  /* Get the features supported by the backend server */
  if (proxy_ftp_feat_get(p, proxy_sess) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to determine features of backend server: %s", strerror(errno));
  }

  proxy_sess_state |= PROXY_SESS_STATE_CONNECTED;

  pr_response_block(TRUE);

  return 0;
}

int proxy_reverse_handle_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", cmd->argv[0], strerror(xerrno));

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
    *successful = TRUE;
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

int proxy_reverse_handle_pass(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", cmd->argv[0], strerror(xerrno));

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

  /* XXX What about other response codes for PASS? */
  if (resp->num[0] == '2') {
    *successful = TRUE;

    proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
    pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE); 
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
