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

static const char *trace_channel = "proxy.reverse";

int proxy_reverse_init(pool *p) {
  config_rec *c;
  array_header *backend_servers;
  struct proxy_conn *pconn, **pconns;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyBackendServers",
    FALSE);
  if (c == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": gateway mode enabled, but no ProxyBackendServers configured");
    return -1;
  }

  backend_servers = c->argv[0];

  /* XXX ProxyGatewayBalancing? */
  c = find_config(main_server->conf, CONF_PARAM, "ProxyBackendSelection",
    FALSE);
  if (c != NULL) {
    /* Handle the particular connect/balancing/selection method configured.
     *
     * XXX For a 'roundrobin' selection, use a slot allocated in the
     * ProxyReverseServers config_rec, one that will contain the index
     * (into the backend_servers list, if present) of the last-used
     * backend server. 
     */
  }

  /* XXX For now, only use the first backend server. */
  pconns = backend_servers->elts;
  pconn = pconns[0];

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "connecting to backend server '%s'", proxy_conn_get_uri(pconn));

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

  if (strncasecmp(policy, "random", 7) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_RANDOM;

  } else if (strncasecmp(policy, "roundRobin", 11) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_ROUND_ROBIN;

  } else if (strncasecmp(policy, "leastConns", 11) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_LEAST_CONNS;

  } else if (strncasecmp(policy, "equalConns", 11) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_EQUAL_CONNS;

  } else if (strncasecmp(policy, "lowestResponseTime", 19) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_LOWEST_RESPONSE_TIME;

  } else if (strncasecmp(policy, "perUser", 8) == 0) {
    return PROXY_REVERSE_SELECT_POLICY_PER_USER;
  }

  errno = ENOENT;
  return -1;
}

int proxy_reverse_select_next_index(unsigned int sid, unsigned int idx,
    int select_policy, void *policy_data) {

  switch (select_policy) {
    case PROXY_REVERSE_SELECT_POLICY_RANDOM:
      /* Find max index for SID, randomly choose between 0 and max (inclusive).
       */
      break;

    case PROXY_REVERSE_SELECT_POLICY_ROUND_ROBIN:
      /* Find current index for SID, increment by one, lock row, write data,
       * unlock row, return incremented idx.
       */
      break;

    default:
      break;
  }

  errno = ENOSYS;
  return -1;
}

int proxy_reverse_select_used_index(unsigned int sid, unsigned int idx,
    unsigned long response_ms) {
  errno = ENOSYS;
  return -1;
}
