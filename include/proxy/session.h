/*
 * ProFTPD - mod_proxy sessions
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

#ifndef MOD_PROXY_SESSION_H
#define MOD_PROXY_SESSION_H

#include "mod_proxy.h"

struct proxy_conn;

struct proxy_session {
  struct pool_rec *pool;

  int connect_timeout;
  int connect_timerno;
  int linger_timeout;

  /* Frontend connection */
  conn_t *frontend_ctrl_conn;
  conn_t *frontend_data_conn;
  volatile int frontend_sess_flags;
  const pr_netaddr_t *frontend_data_addr;

  /* Backend connection */
  conn_t *backend_ctrl_conn;
  conn_t *backend_data_conn;
  volatile int backend_sess_flags;
  const pr_netaddr_t *backend_data_addr;

  /* Address for connections to/from destination server.  May be null. */
  const pr_netaddr_t *src_addr;

  const struct proxy_conn *dst_pconn;

  /* Address of the destination server.  May be null. */
  const pr_netaddr_t *dst_addr;
  array_header *other_addrs;

  /* Features supported by backend server */
  pr_table_t *backend_features;

  /* Data transfer policy: PASV, EPSV, PORT, EPRT, or client. */
  int dataxfer_policy;

  /* Directory list policy: LIST, or client. */
  int dirlist_policy;
  unsigned long dirlist_opts;
  void *dirlist_ctx;
};

/* Zero indicates "do what the client does". */

#define PROXY_SESS_DATA_TRANSFER_POLICY_DEFAULT		0

#define PROXY_SESS_DIRECTORY_LIST_POLICY_DEFAULT	0
#define PROXY_SESS_DIRECTORY_LIST_POLICY_LIST		1

/* Default MaxLoginAttempts */
#define PROXY_SESS_MAX_LOGIN_ATTEMPTS			3

const struct proxy_session *proxy_session_alloc(pool *p);
int proxy_session_free(pool *p, const struct proxy_session *proxy_sess);

int proxy_session_check_password(pool *p, const char *user, const char *passwd);
int proxy_session_setup_env(pool *p, const char *user, int flags);
#define PROXY_SESSION_FL_CHECK_LOGIN_ACL		0x00001

#endif /* MOD_PROXY_SESSION_H */
