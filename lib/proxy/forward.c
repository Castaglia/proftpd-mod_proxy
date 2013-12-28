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

