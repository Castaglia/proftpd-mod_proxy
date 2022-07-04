/*
 * ProFTPD - mod_proxy SSH keys API
 * Copyright (c) 2021-2022 TJ Saunders
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

#ifndef MOD_PROXY_SSH_KEYS_H
#define MOD_PROXY_SSH_KEYS_H

#include "mod_proxy.h"

#if defined(PR_USE_OPENSSL)
#include <openssl/ec.h>

enum proxy_ssh_key_type_e {
  PROXY_SSH_KEY_UNKNOWN = 0,
  PROXY_SSH_KEY_DSA,
  PROXY_SSH_KEY_RSA,
  PROXY_SSH_KEY_RSA_SHA256,
  PROXY_SSH_KEY_RSA_SHA512,
  PROXY_SSH_KEY_ECDSA_256,
  PROXY_SSH_KEY_ECDSA_384,
  PROXY_SSH_KEY_ECDSA_521,
  PROXY_SSH_KEY_ED25519,
  PROXY_SSH_KEY_ED448
};

/* Returns a string of colon-separated lowercase hex characters, representing
 * the key "fingerprint" which has been run through the specified digest
 * algorithm.
 *
 * As per draft-ietf-secsh-fingerprint-00, only MD5 fingerprints are currently
 * supported.
 */
const char *proxy_ssh_keys_get_fingerprint(pool *, unsigned char *, uint32_t,
  int);
#define PROXY_SSH_KEYS_FP_DIGEST_MD5		1
#define PROXY_SSH_KEYS_FP_DIGEST_SHA1		2
#define PROXY_SSH_KEYS_FP_DIGEST_SHA256		3

enum proxy_ssh_key_type_e proxy_ssh_keys_get_key_type(const char *algo);
const char *proxy_ssh_keys_get_key_type_desc(enum proxy_ssh_key_type_e);

void proxy_ssh_keys_free(void);
int proxy_ssh_keys_have_hostkey(enum proxy_ssh_key_type_e);
int proxy_ssh_keys_get_hostkey(pool *p, const char *);
const unsigned char *proxy_ssh_keys_get_hostkey_data(pool *,
  enum proxy_ssh_key_type_e, uint32_t *);
void proxy_ssh_keys_get_passphrases(void);
int proxy_ssh_keys_set_passphrase_provider(const char *);
const unsigned char *proxy_ssh_keys_sign_data(pool *, enum proxy_ssh_key_type_e,
  const unsigned char *, size_t, size_t *);
#if defined(PR_USE_OPENSSL_ECC)
int proxy_ssh_keys_validate_ecdsa_params(const EC_GROUP *, const EC_POINT *);
#endif /* PR_USE_OPENSSL_ECC */
int proxy_ssh_keys_verify_pubkey_type(pool *, unsigned char *, uint32_t,
  enum proxy_ssh_key_type_e);
int proxy_ssh_keys_verify_signed_data(pool *p, const char *pubkey_algo,
  unsigned char *pubkey_data, uint32_t pubkey_datalen,
  unsigned char *signature, uint32_t signaturelen,
  unsigned char *sig_data, size_t sig_datalen);
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_KEYS_H */
