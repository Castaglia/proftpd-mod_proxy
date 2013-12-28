/*
 * ProFTPD - mod_proxy session routines
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
#include "proxy/session.h"

static const char *trace_channel = "proxy.session";

struct proxy_session *proxy_session_alloc(pool *p) {
  pool *sess_pool;
  struct proxy_session *proxy_sess;

  sess_pool = make_sub_pool(p);
  pr_pool_tag(sess_pool, "Proxy Session pool");

  proxy_sess = pcalloc(sess_pool, sizeof(struct proxy_session));
  proxy_sess->pool = sess_pool;

  /* This will be configured by the ProxyReverseAddress directive, if
   * present.
   */
  proxy_sess->backend_addr = NULL;

  /* This will be configured by the ProxyDataTransferPolicy directive, if
   * present.
   */
  proxy_sess->dataxfer_policy = PROXY_SESS_DATA_TRANSFER_POLICY_DEFAULT;

  /* Fill in the defaults for the session members. */
  proxy_sess->connect_timeout = -1;
  proxy_sess->connect_timerno = -1;

  return proxy_sess;
}
