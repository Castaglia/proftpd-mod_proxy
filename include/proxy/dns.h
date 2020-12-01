/*
 * ProFTPD - mod_proxy DNS API
 * Copyright (c) 2020 TJ Saunders
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

#ifndef MOD_PROXY_DNS_H
#define MOD_PROXY_DNS_H

#include "mod_proxy.h"

typedef enum {
  PROXY_DNS_UNKNOWN,
  PROXY_DNS_A,
  PROXY_DNS_AAAA,
  PROXY_DNS_SRV,
  PROXY_DNS_TXT
} proxy_dns_type_e;

/* Resolves a given `name` to a list of textual response lines, based on the
 * given DNS record type.
 *
 * For A records, the responses will be IPv4 addresses.
 * For AAAA records, the responses will be IPv6 addresses.
 * For SRV records, the responses will be the returned address/ports, in
 * priority order.
 * For TXT records, the responses will be the returned textual lines.
 *
 * If a `ttl` pointer is provided, the shortest TTL on retrieved records
 * retrieved is returned.
 */
int proxy_dns_resolve(pool *p, const char *name, proxy_dns_type_e dns_type,
  array_header **resp, uint32_t *ttl);

#endif /* MOD_PROXY_DNS_H */
