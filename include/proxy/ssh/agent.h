/*
 * ProFTPD - mod_proxy SSH agent API
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

#ifndef MOD_PROXY_SSH_AGENT_H
#define MOD_PROXY_SSH_AGENT_H

#include "mod_proxy.h"

#if defined(PR_USE_OPENSSL)

struct agent_key {
  unsigned char *key_data;
  uint32_t key_datalen;
  const char *agent_path;
};

int proxy_ssh_agent_get_keys(pool *p, const char *, array_header *);
const unsigned char *proxy_ssh_agent_sign_data(pool *, const char *,
  const unsigned char *, uint32_t, const unsigned char *, uint32_t, uint32_t *,
  int);

#define PROXY_SSH_AGENT_SIGN_FL_USE_RSA_SHA256	0x001
#define PROXY_SSH_AGENT_SIGN_FL_USE_RSA_SHA512	0x002

#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_AGENT_H */
