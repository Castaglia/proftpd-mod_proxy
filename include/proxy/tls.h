/*
 * ProFTPD - mod_proxy TLS API
 * Copyright (c) 2015-2016 TJ Saunders
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

#ifdef PR_USE_OPENSSL
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/conf.h>
# include <openssl/crypto.h>
# include <openssl/evp.h>
# include <openssl/ssl.h>
# include <openssl/ssl3.h>
# include <openssl/x509v3.h>
# include <openssl/rand.h>
# if OPENSSL_VERSION_NUMBER > 0x000907000L
#  include <openssl/engine.h>
#  include <openssl/ocsp.h>
# endif
# ifdef PR_USE_OPENSSL_ECC
#  include <openssl/ec.h>
#  include <openssl/ecdh.h>
# endif /* PR_USE_OPENSSL_ECC */
#endif

/* ProxyTLSEngine values */
#define PROXY_TLS_ENGINE_ON		1
#define PROXY_TLS_ENGINE_OFF		2
#define PROXY_TLS_ENGINE_AUTO		3

/* ProxyTLSOptions values */
#define PROXY_TLS_OPT_ENABLE_DIAGS		0x0001
#define PROXY_TLS_OPT_NO_SESSION_CACHE		0x0002
#define PROXY_TLS_OPT_NO_SESSION_TICKETS	0x0004

/* ProxyTLSProtocol handling */
#define PROXY_TLS_PROTO_SSL_V3		0x0001
#define PROXY_TLS_PROTO_TLS_V1		0x0002
#define PROXY_TLS_PROTO_TLS_V1_1	0x0004
#define PROXY_TLS_PROTO_TLS_V1_2	0x0008

#if defined(PR_USE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10001000L
# define PROXY_TLS_PROTO_DEFAULT	(PROXY_TLS_PROTO_TLS_V1|PROXY_TLS_PROTO_TLS_V1_1|PROXY_TLS_PROTO_TLS_V1_2)
#else
# define PROXY_TLS_PROTO_DEFAULT	(PROXY_TLS_PROTO_TLS_V1)
#endif /* OpenSSL 1.0.1 or later */

/* This is used for e.g. "ProxyTLSProtocol ALL -SSLv3 ...". */
#define PROXY_TLS_PROTO_ALL		(PROXY_TLS_PROTO_SSL_V3|PROXY_TLS_PROTO_TLS_V1|PROXY_TLS_PROTO_TLS_V1_1|PROXY_TLS_PROTO_TLS_V1_2)

int proxy_tls_init(pool *p, const char *tables_dir, int flags);
int proxy_tls_free(pool *p);

int proxy_tls_sess_init(pool *p, int flags);
int proxy_tls_sess_free(pool *p);

/* Programmatically set the ProxyTLSEngine value. */
int proxy_tls_set_tls(int);

/* Programmatically set the ProxyTLSVerifyServer value. */
int proxy_tls_set_verify_server(int);

/* Returns the ProxyTLSEngine value; see above. */
int proxy_tls_using_tls(void);

#endif /* MOD_PROXY_TLS_H */
