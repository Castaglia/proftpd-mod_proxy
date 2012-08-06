/*
 * ProFTPD - mod_proxy reverse-proxy implementation
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
 */

#include "mod_proxy.h"
#include "conn.h"
#include "reverse.h"

static const char *trace_channel = "proxy.reverse";

int proxy_reverse_init(pool *p) {
  config_rec *c;
  array_header *backend_servers;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers",
    FALSE);
  if (c == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": reverse proxy mode enabled, but no ProxyReverseServers configured");
    return -1;
  }

  backend_servers = *(array_header **) c->argv[0]);

  /* XXX ProxyReverseBalancing? */
  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseConnect",
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

  return 0;
}
