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
#include "proxy/session.h"
#include "proxy/reverse.h"
#include "proxy/random.h"

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

int proxy_reverse_select_next_index(unsigned int sid,
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

int proxy_reverse_select_used_index(unsigned int sid, unsigned int idx,
    unsigned long response_ms) {
  errno = ENOSYS;
  return -1;
}

static pr_netaddr_t *get_reverse_server_addr(struct proxy_session *proxy_sess) {
  config_rec *c;
  array_header *backend_servers;
  struct proxy_conn **conns;
  pr_netaddr_t *addr;
  int idx;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
  backend_servers = c->argv[0];
  conns = backend_servers->elts;

  idx = proxy_reverse_select_next_index(main_server->sid,
    backend_servers->nelts, NULL);
  if (idx < 0) {
    return NULL;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "selected backend server '%s'", proxy_conn_get_uri(conns[idx]));

  addr = proxy_conn_get_addr(conns[idx]);
  return addr;
}

conn_t *proxy_reverse_server_get_conn(struct proxy_session *proxy_sess) {
  pr_netaddr_t *bind_addr, *local_addr, *remote_addr;
  unsigned int remote_port;
  const char *remote_ipstr;
  conn_t *server_conn, *backend_ctrl_conn;
  int res;

  remote_addr = get_reverse_server_addr(proxy_sess);
  if (remote_addr == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to find suitable backend server: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  if (proxy_sess->connect_timeout > 0) {
    proxy_sess->connect_timerno = pr_timer_add(proxy_sess->connect_timeout,
      -1, &proxy_module, proxy_conn_connect_timeout_cb, "ProxyTimeoutConnect");

    if (pr_table_add(session.notes, "mod_proxy.proxy-connect-address",
      remote_addr, sizeof(pr_netaddr_t)) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error stashing proxy connect address note: %s", strerror(errno));
    }
  }

  remote_ipstr = pr_netaddr_get_ipstr(remote_addr);
  remote_port = ntohs(pr_netaddr_get_port(remote_addr));

  /* Check the family of the retrieved address vs what we'll be using
   * to connect.  If there's a mismatch, we need to get an addr with the
   * matching family.
   */

  if (pr_netaddr_get_family(session.c->local_addr) == pr_netaddr_get_family(remote_addr)) {
    local_addr = session.c->local_addr;

  } else {
    /* In this scenario, the proxy has an IPv6 socket, but the remote/backend
     * server has an IPv4 (or IPv4-mapped IPv6) address.
     */
    local_addr = pr_netaddr_v6tov4(session.pool, session.c->local_addr);
  }

  bind_addr = proxy_sess->backend_addr;
  if (bind_addr == NULL) {
    bind_addr = local_addr;
  }

  server_conn = pr_inet_create_conn(proxy_pool, -1, bind_addr, INPORT_ANY,
    FALSE); 

  pr_trace_msg(trace_channel, 11, "connecting to backend address %s:%u from %s",
    remote_ipstr, remote_port, pr_netaddr_get_ipstr(bind_addr));

  res = pr_inet_connect_nowait(proxy_pool, server_conn, remote_addr,
    ntohs(pr_netaddr_get_port(remote_addr)));
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error starting connect to %s#%u: %s", remote_ipstr, remote_port,
      strerror(xerrno));

    pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
    errno = xerrno;
    return NULL;
  } 

  if (res == 0) {
    pr_netio_stream_t *nstrm;
    int nstrm_mode = PR_NETIO_IO_RD;

    if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
      /* Rather than waiting for the stream to be readable (because the
       * other end sent us something), wait for the stream to be writable
       * so that we can send something to the other end).
       */
      nstrm_mode = PR_NETIO_IO_WR;
    }

    /* Not yet connected. */
    nstrm = pr_netio_open(proxy_pool, PR_NETIO_STRM_OTHR,
      server_conn->listen_fd, nstrm_mode);
    if (nstrm == NULL) {
      int xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error opening stream to %s#%u: %s", remote_ipstr, remote_port,
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
          "error connecting to %s#%u: %s", remote_ipstr, remote_port,
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
        pr_table_remove(session.notes, "mod_proxy.proxy-connect-addr", NULL);

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
    "successfully connected to %s#%u from %s#%d", remote_ipstr, remote_port,
    pr_netaddr_get_ipstr(server_conn->local_addr),
    ntohs(pr_netaddr_get_port(server_conn->local_addr)));

  backend_ctrl_conn = pr_inet_openrw(proxy_pool, server_conn, NULL,
    PR_NETIO_STRM_CTRL, -1, -1, -1, FALSE);
  if (backend_ctrl_conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to open control connection to %s#%u: %s", remote_ipstr,
      remote_port, strerror(xerrno));

    pr_inet_close(proxy_pool, server_conn);

    errno = xerrno;
    return NULL;
  }

  if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
    if (proxy_conn_send_proxy(proxy_pool, backend_ctrl_conn) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error sending PROXY message to %s#%u: %s", remote_ipstr, remote_port,
        strerror(errno));
    }
  }

  return backend_ctrl_conn;
}

