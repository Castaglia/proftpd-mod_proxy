/*
 * ProFTPD - mod_proxy SSH MAC API
 * Copyright (c) 2021-2025 TJ Saunders
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

#ifndef MOD_PROXY_SSH_MAC_H
#define MOD_PROXY_SSH_MAC_H

#include "mod_proxy.h"
#include "proxy/ssh/packet.h"

#if defined(PR_USE_OPENSSL)
#include <openssl/evp.h>

int proxy_ssh_mac_init(void);
int proxy_ssh_mac_free(void);

/* Returns the block size of the negotiated MAC algorithm, or 0 if no MAC
 * has been negotiated yet.
 */
size_t proxy_ssh_mac_get_block_size(void);
void proxy_ssh_mac_set_block_size(size_t blocksz);

const char *proxy_ssh_mac_get_read_algo(void);
int proxy_ssh_mac_is_read_etm(void);
int proxy_ssh_mac_set_read_algo(pool *p, const char *algo);
int proxy_ssh_mac_set_read_key(pool *p, const EVP_MD *md,
  const unsigned char *k, uint32_t klen, const char *h, uint32_t hlen,
  int role);
int proxy_ssh_mac_read_data(struct proxy_ssh_packet *pkt);

const char *proxy_ssh_mac_get_write_algo(void);
int proxy_ssh_mac_is_write_etm(void);
int proxy_ssh_mac_set_write_algo(pool *p, const char *algo);
int proxy_ssh_mac_set_write_key(pool *p, const EVP_MD *md,
  const unsigned char *k, uint32_t klen, const char *h, uint32_t hlen,
  int role);
int proxy_ssh_mac_write_data(struct proxy_ssh_packet *pkt);
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_MAC_H */
