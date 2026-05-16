/*
 * ProFTPD - mod_proxy TLS PKCS11 API
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

#ifndef MOD_PROXY_TLS_PKCS11_H
#define MOD_PROXY_TLS_PKCS11_H

#include "mod_proxy.h"
#include "proxy/tls.h"

int proxy_tls_pkcs11_supported(void);
int proxy_tls_pkcs11_uri(const char *text);
EVP_PKEY *proxy_tls_pkcs11_get_private_key(const char *text);

#endif /* MOD_PROXY_TLS_PKCS11_H */
