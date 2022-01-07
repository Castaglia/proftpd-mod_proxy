/*
 * ProFTPD - mod_proxy SSH kex API
 * Copyright (c) 2021 TJ Saunders
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

#ifndef MOD_PROXY_SSH_KEX_H
#define MOD_PROXY_SSH_KEX_H

#include "mod_proxy.h"
#include "proxy/session.h"
#include "proxy/ssh.h"

#if defined(PR_USE_OPENSSL)

int proxy_ssh_kex_handle(struct proxy_ssh_packet *pkt,
  const struct proxy_session *proxy_sess);
int proxy_ssh_kex_init(pool *p, const char *client_version,
  const char *server_version);
int proxy_ssh_kex_free(void);

int proxy_ssh_kex_sess_init(pool *p, struct proxy_ssh_datastore *ds,
  int verify_hostkeys);
int proxy_ssh_kex_sess_free(void);

int proxy_ssh_kex_send_first_kexinit(pool *p,
  const struct proxy_session *proxy_sess);

#define PROXY_SSH_KEX_DH_GROUP_MIN	1024
#define PROXY_SSH_KEX_DH_GROUP_MAX	8192
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_KEX_H */
