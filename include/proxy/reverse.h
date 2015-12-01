/*
 * ProFTPD - mod_proxy reverse-proxy API
 * Copyright (c) 2012-2015 TJ Saunders
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

#ifndef MOD_PROXY_REVERSE_H
#define MOD_PROXY_REVERSE_H

int proxy_reverse_init(pool *p, const char *tables_dir);
int proxy_reverse_free(pool *p);

int proxy_reverse_have_authenticated(cmd_rec *cmd);
int proxy_reverse_sess_init(pool *p, const char *tables_dir,
  struct proxy_session *proxy_sess);
int proxy_reverse_sess_free(pool *p, struct proxy_session *proxy_sess);
int proxy_reverse_sess_exit(pool *p);

int proxy_reverse_handle_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
  int *successful, int *block_responses);
int proxy_reverse_handle_pass(cmd_rec *cmd, struct proxy_session *proxy_sess,
  int *successful, int *block_responses);

array_header *proxy_reverse_json_parse_uris(pool *p, const char *path);

/* Connect policy API */
#define PROXY_REVERSE_CONNECT_POLICY_RANDOM			1
#define PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN		2
#define PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS		3
#define PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME	4
#define PROXY_REVERSE_CONNECT_POLICY_SHUFFLE			5
#define PROXY_REVERSE_CONNECT_POLICY_PER_USER			6
#define PROXY_REVERSE_CONNECT_POLICY_PER_GROUP			7
#define PROXY_REVERSE_CONNECT_POLICY_PER_HOST			8

/* Return the policy ID for the given string, or -1 if the given policy
 * is not recognized/supported.
 */
int proxy_reverse_connect_get_policy(const char *policy);

/* Returns TRUE if the Reverse API is using proxy auth, FALSE otherwise. */
int proxy_reverse_use_proxy_auth(void);

#endif /* MOD_PROXY_REVERSE_H */
