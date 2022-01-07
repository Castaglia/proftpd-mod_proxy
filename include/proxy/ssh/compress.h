/*
 * ProFTPD - mod_proxy SSH compression API
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

#ifndef MOD_PROXY_SSH_COMPRESS_H
#define MOD_PROXY_SSH_COMPRESS_H

#include "mod_proxy.h"
#include "proxy/ssh/packet.h"

#if defined(PR_USE_OPENSSL)

#define PROXY_SSH_COMPRESS_FL_NEW_KEY		1
#define PROXY_SSH_COMPRESS_FL_AUTHENTICATED	2

int proxy_ssh_compress_init_read(int);
const char *proxy_ssh_compress_get_read_algo(void);
int proxy_ssh_compress_set_read_algo(pool *p, const char *algo);
int proxy_ssh_compress_read_data(struct proxy_ssh_packet *);

int proxy_ssh_compress_init_write(int);
const char *proxy_ssh_compress_get_write_algo(void);
int proxy_ssh_compress_set_write_algo(pool *p, const char *algo);
int proxy_ssh_compress_write_data(struct proxy_ssh_packet *);
#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_COMPRESS_H */
