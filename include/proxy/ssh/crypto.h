/*
 * ProFTPD - mod_proxy SSH crypto API
 * Copyright (c) 2021-2026 TJ Saunders
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

#ifndef MOD_PROXY_SSH_CRYPTO_H
#define MOD_PROXY_SSH_CRYPTO_H

#include "mod_proxy.h"

#include <openssl/evp.h>

#if defined(EVP_PKEY_X25519)
# define HAVE_X25519_OPENSSL	1
#endif /* EVP_PKEY_X25519 */

void proxy_ssh_crypto_free(int flags);
const EVP_CIPHER *proxy_ssh_crypto_get_cipher(const char *algo, size_t *key_len,
  size_t *auth_len, size_t *discard_len);
const EVP_MD *proxy_ssh_crypto_get_digest(const char *algo, uint32_t *mac_len);
const char *proxy_ssh_crypto_get_kexinit_cipher_list(pool *p);
const char *proxy_ssh_crypto_get_kexinit_digest_list(pool *p);

const char *proxy_ssh_crypto_get_errors(void);
size_t proxy_ssh_crypto_get_size(size_t, size_t);

#endif /* MOD_PROXY_SSH_CRYPTO_H */
