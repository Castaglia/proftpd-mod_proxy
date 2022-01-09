/*
 * ProFTPD - mod_proxy SSH disconnect API
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

#ifndef MOD_PROXY_SSH_DISCONNECT_H
#define MOD_PROXY_SSH_DISCONNECT_H

#include "mod_proxy.h"

#if defined(PR_USE_OPENSSL)

void proxy_ssh_disconnect_conn(conn_t *, uint32_t, const char *, const char *,
  int, const char *);
void proxy_ssh_disconnect_send(pool *, conn_t *, uint32_t, const char *,
  const char *, int, const char *);

/* Given a disconnect reason code from a server, return a string explaining
 * that code.
 */
const char *proxy_ssh_disconnect_get_text(uint32_t);

/* Deal with the fact that __FUNCTION__ is a gcc extension.  Sun's compilers
 * (e.g. SunStudio) like __func__.
 */

# if defined(__FUNCTION__)
#define PROXY_SSH_DISCONNECT_CONN(c, n, m) \
  proxy_ssh_disconnect_conn((c), (n), (m), __FILE__, __LINE__, __FUNCTION__)

# elif defined(__func__)
#define PROXY_SSH_DISCONNECT_CONN(c, n, m) \
  proxy_ssh_disconnect_conn((c), (n), (m), __FILE__, __LINE__, __func__)

# else
#define PROXY_SSH_DISCONNECT_CONN(c, n, m) \
  proxy_ssh_disconnect_conn((c), (n), (m), __FILE__, __LINE__, "")

# endif
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_DISCONNECT_H */
