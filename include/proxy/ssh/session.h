/*
 * ProFTPD - mod_proxy SSH session API
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

#ifndef MOD_PROXY_SSH_SESSION_H
#define MOD_PROXY_SSH_SESSION_H

#include "mod_proxy.h"

#if defined(PR_USE_OPENSSL)
uint32_t proxy_ssh_session_get_id(const unsigned char **);

/* Note that the provided pool must have the same lifetime as that of the
 * entire SSH session, e.g. proxy_pool or similar.
 */
int proxy_ssh_session_set_id(pool *p, const unsigned char *, uint32_t);
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_SESSION_H */
