/*
 * ProFTPD - mod_proxy RFC 4716 format support
 * Copyright (c) 2026 TJ Saunders
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#ifndef MOD_PROXY_SSH_RFC4716_H
#define MOD_PROXY_SSH_RFC4716_H

#include "mod_proxy.h"
#include "proxy/session.h"
#include "proxy/ssh/certs.h"

/* These strings are part of any RFC4716 key; thus they will be needed by
 * any keystore backend modules.
 */
#define PROXY_SSH_SSH2_PUBKEY_BEGIN_MARKER	"---- BEGIN SSH2 PUBLIC KEY ----"
#define PROXY_SSH_SSH2_PUBKEY_END_MARKER	"---- END SSH2 PUBLIC KEY ----"

int proxy_ssh_rfc4716_is_revoked_key(const struct proxy_session *proxy_sess,
  pool *p, const char *path, unsigned char *public_key, uint32_t public_keylen);
int proxy_ssh_rfc4716_verify_host_cert(const struct proxy_session *proxy_sess,
  pool *p, const char *path, struct proxy_ssh_cert *cert,
  unsigned long cert_opts);

#endif /* MOD_PROXY_SSH_RFC4716_H */
