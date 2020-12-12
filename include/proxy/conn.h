/*
 * ProFTPD - mod_proxy conn API
 * Copyright (c) 2012-2020 TJ Saunders
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

#ifndef MOD_PROXY_CONN_H
#define MOD_PROXY_CONN_H

#include "mod_proxy.h"
#include "proxy/session.h"

struct proxy_conn;

void proxy_conn_clear_username(const struct proxy_conn *pconn);
void proxy_conn_clear_password(const struct proxy_conn *pconn);
int proxy_conn_connect_timeout_cb(CALLBACK_FRAME);

const struct proxy_conn *proxy_conn_create(pool *p, const char *uri,
  unsigned int flags);
#define PROXY_CONN_CREATE_FL_USE_DNS_TTL	0x0001

const pr_netaddr_t *proxy_conn_get_addr(const struct proxy_conn *,
  array_header **);
int proxy_conn_get_dns_ttl(const struct proxy_conn *pconn);
const char *proxy_conn_get_host(const struct proxy_conn *pconn);
const char *proxy_conn_get_hostport(const struct proxy_conn *pconn);
int proxy_conn_get_port(const struct proxy_conn *pconn);
conn_t *proxy_conn_get_server_conn(pool *p, struct proxy_session *proxy_sess,
  const pr_netaddr_t *remote_addr);
const char *proxy_conn_get_uri(const struct proxy_conn *pconn);
const char *proxy_conn_get_username(const struct proxy_conn *pconn);
const char *proxy_conn_get_password(const struct proxy_conn *pconn);
int proxy_conn_get_tls(const struct proxy_conn *pconn);
int proxy_conn_use_dns_srv(const struct proxy_conn *pconn);
int proxy_conn_use_dns_txt(const struct proxy_conn *pconn);
int proxy_conn_send_proxy_v1(pool *p, conn_t *conn);
int proxy_conn_send_proxy_v2(pool *p, conn_t *conn);
void proxy_conn_free(const struct proxy_conn *pconn);

#endif /* MOD_PROXY_CONN_H */
