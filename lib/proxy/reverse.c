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

static int reverse_select_policy = PROXY_REVERSE_SELECT_POLICY_RANDOM;

static const char *trace_channel = "proxy.reverse";

int proxy_reverse_init(pool *p) {
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
  return TRUE;
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

  server_conn = proxy_conn_get_server_conn(p, proxy_sess, remote_addr);
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
    int *ok) {
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
    *ok = TRUE;
  }

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
