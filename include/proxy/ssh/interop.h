/*
 * ProFTPD - mod_proxy SSH interop API
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

#ifndef MOD_PROXY_SSH_INTEROP_H
#define MOD_PROXY_SSH_INTEROP_H

#include "mod_proxy.h"
#include "proxy/session.h"

#if defined(PR_USE_OPENSSL)

/* For servers which do not support IGNORE packets */
#define PROXY_SSH_FEAT_IGNORE_MSG			0x0001

/* For servers which always truncate the HMAC len to 16 bits, regardless
 * of the actual HMAC len.
 */
#define PROXY_SSH_FEAT_MAC_LEN				0x0002

/* For servers which do not include K when deriving cipher keys. */
#define PROXY_SSH_FEAT_CIPHER_USE_K			0x0004

/* For servers which do not support rekeying */
#define PROXY_SSH_FEAT_REKEYING				0x0008

/* For servers which do not support USERAUTH_BANNER packets */
#define PROXY_SSH_FEAT_USERAUTH_BANNER			0x0010

/* For servers which do not send a string indicating the public key
 * algorithm in their publickey authentication requests.  This also
 * includes servers which do not use the string "publickey", and the
 * string for the public key algorithm, in the public key signature
 * (as dictated by Section 7 of RFC4252).
 */
#define PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO			0x0020

/* For servers whose publickey signatures always use a service name of
 * "ssh-userauth", regardless of the actual service name included in the
 * USERAUTH_REQUEST packet.
 */
#define PROXY_SSH_FEAT_SERVICE_IN_PUBKEY_SIG		0x0040

/* For servers whose DSA publickey signatures do not include the string
 * "ssh-dss".
 */
#define PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG	0x0080

/* For servers whose hostbased signatures always use a service name of
 * "ssh-userauth", regardless of the actual service name included in the
 * USERAUTH_REQUEST packet.
 */
#define PROXY_SSH_FEAT_SERVICE_IN_HOST_SIG		0x0100

/* For servers that want the client to pessimistically send its NEWKEYS message
 * after they send their NEWKEYS message.
 */
#define PROXY_SSH_FEAT_PESSIMISTIC_NEWKEYS		0x0200

/* For servers which cannot/do not tolerate non-kex related packets after a
 * client has requested rekeying.
 */
#define PROXY_SSH_FEAT_NO_DATA_WHILE_REKEYING		0x0400

/* For servers which do not support/implement RFC 4419 DH group exchange. */
#define PROXY_SSH_FEAT_DH_NEW_GEX			0x0800

/* Compares the given server version string against a table of known server
 * versions and their interoperability/compatibility issues.
 */
int proxy_ssh_interop_handle_version(pool *, const struct proxy_session *,
  const char *);

/* Returns TRUE if the server supports the requested feature, FALSE
 * otherwise.
 */
int proxy_ssh_interop_supports_feature(int);

int proxy_ssh_interop_init(void);
int proxy_ssh_interop_free(void);
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_INTEROP_H */
