/*
 * ProFTPD - mod_proxy reverse-proxy API
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

#ifndef MOD_PROXY_REVERSE_H
#define MOD_PROXY_REVERSE_H

int proxy_reverse_init(pool *p);
int proxy_reverse_have_authenticated(cmd_rec *cmd);

/* Backend selection policy API */

#define PROXY_REVERSE_SELECT_POLICY_RANDOM			1
#define PROXY_REVERSE_SELECT_POLICY_ROUND_ROBIN			2
#define PROXY_REVERSE_SELECT_POLICY_LEAST_CONNS			3
#define PROXY_REVERSE_SELECT_POLICY_EQUAL_CONNS			4
#define PROXY_REVERSE_SELECT_POLICY_LOWEST_RESPONSE_TIME	5
#define PROXY_REVERSE_SELECT_POLICY_SHUFFLE			6
#define PROXY_REVERSE_SELECT_POLICY_PER_USER			7

/* Return the policy ID for the given string, or -1 if the given policy
 * is not recognized/supported.
 */
int proxy_reverse_select_get_policy(const char *policy);

int proxy_reverse_select_next_index(unsigned int sid,
  unsigned int backend_count, void *policy_data);

int proxy_reverse_select_used_index(unsigned int sid, unsigned int idx,
  unsigned long response_ms);

conn_t *proxy_reverse_server_get_conn(struct proxy_session *);

#endif /* MOD_PROXY_REVERSE_H */
