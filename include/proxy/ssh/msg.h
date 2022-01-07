/*
 * ProFTPD - mod_proxy SSH message API
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

#ifndef MOD_PROXY_SSH_MSG_H
#define MOD_PROXY_SSH_MSG_H

#include "mod_proxy.h"

#if defined(PR_USE_OPENSSL)

#if defined(PR_USE_OPENSSL_ECC)
# include <openssl/ec.h>
# include <openssl/ecdh.h>
#endif /* PR_USE_OPENSSL_ECC */

uint32_t proxy_ssh_msg_read_byte(pool *p, unsigned char **buf,
  uint32_t *buflen, unsigned char *msg);
uint32_t proxy_ssh_msg_read_bool(pool *p, unsigned char **buf,
  uint32_t *buflen, int *msg);
uint32_t proxy_ssh_msg_read_data(pool *p, unsigned char **buf,
  uint32_t *buflen, size_t msglen, unsigned char **msg);
#if defined(PR_USE_OPENSSL_ECC)
uint32_t proxy_ssh_msg_read_ecpoint(pool *p, unsigned char **buf,
  uint32_t *buflen, const EC_GROUP *ec_group, EC_POINT **msg);
#endif /* PR_USE_OPENSSL_ECC */
uint32_t proxy_ssh_msg_read_int(pool *p, unsigned char **buf, uint32_t *buflen,
  uint32_t *msg);
uint32_t proxy_ssh_msg_read_long(pool *p, unsigned char **buf, uint32_t *buflen,
  uint64_t *msg);
uint32_t proxy_ssh_msg_read_mpint(pool *p, unsigned char **buf,
  uint32_t *buflen, const BIGNUM **msg);
uint32_t proxy_ssh_msg_read_string(pool *p, unsigned char **buf,
  uint32_t *buflen, char **msg);

uint32_t proxy_ssh_msg_write_byte(unsigned char **buf, uint32_t *buflen,
  unsigned char msg);
uint32_t proxy_ssh_msg_write_bool(unsigned char **buf, uint32_t *buflen,
  unsigned char msg);
uint32_t proxy_ssh_msg_write_data(unsigned char **buf, uint32_t *buflen,
  const unsigned char *msg, size_t msglen, int include_len);
#if defined(PR_USE_OPENSSL_ECC)
uint32_t proxy_ssh_msg_write_ecpoint(unsigned char **buf, uint32_t *buflen,
  const EC_GROUP *ec_group, const EC_POINT *ec_point);
#endif /* PR_USE_OPENSSL_ECC */
uint32_t proxy_ssh_msg_write_int(unsigned char **buf, uint32_t *buflen,
  uint32_t msg);
uint32_t proxy_ssh_msg_write_long(unsigned char **buf, uint32_t *buflen,
  uint64_t msg);
uint32_t proxy_ssh_msg_write_mpint(unsigned char **buf, uint32_t *buflen,
  const BIGNUM *msg);
uint32_t proxy_ssh_msg_write_string(unsigned char **buf, uint32_t *buflen,
  const char *msg);
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_MSG_H */
