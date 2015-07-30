/*
 * ProFTPD - mod_proxy TLS API
 * Copyright (c) 2015 TJ Saunders
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

#ifndef MOD_PROXY_TLS_H
#define MOD_PROXY_TLS_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER > 0x000907000L
# include <openssl/engine.h>
# include <openssl/ocsp.h>
#endif
#ifdef PR_USE_OPENSSL_ECC
# include <openssl/ec.h>
# include <openssl/ecdh.h>
#endif /* PR_USE_OPENSSL_ECC */

/* ProxyTLSEngine values */
#define PROXY_TLS_ENGINE_ON		1
#define PROXY_TLS_ENGINE_OFF		2
#define PROXY_TLS_ENGINE_AUTO		3

/* ProxyTLSVerifyServer values */
#define PROXY_TLS_VERIFY_SERVER		0x0001
#define PROXY_TLS_VERIFY_SERVER_NO_DNS	0x0002

int proxy_tls_init(pool *p, const char *tables_dir);
int proxy_tls_free(pool *p);

int proxy_tls_sess_init(pool *p);
int proxy_tls_sess_free(pool *p);

/* Returns the ProxyTLSEngine value; see above. */
int proxy_tls_use_tls(void);

#endif /* MOD_PROXY_TLS_H */
