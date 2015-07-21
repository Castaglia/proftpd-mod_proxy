/*
 * ProFTPD - mod_proxy NetIO API
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

#ifndef MOD_PROXY_NETIO_H
#define MOD_PROXY_NETIO_H

int proxy_netio_init(pool *p);
int proxy_netio_free(void);

/* Proxied versions of the core NetIO API functions; see include/netio.h.
 */

pr_netio_stream_t *proxy_netio_open(pool *p, int strm_type, int fd, int mode);

int proxy_netio_close(pr_netio_stream_t *nstrm);

int proxy_netio_postopen(pr_netio_stream_t *nstrm);

int proxy_netio_printf(pr_netio_stream_t *nstrm, const char *fmt, ...);

int proxy_netio_poll(pr_netio_stream_t *nstrm);

int proxy_netio_postopen(pr_netio_stream_t *nstrm);

int proxy_netio_read(pr_netio_stream_t *nstrm, char *buf, size_t bufsz,
  int bufmin);

void proxy_netio_set_poll_interval(pr_netio_stream_t *nstrm, unsigned int secs);

int proxy_netio_shutdown(pr_netio_stream_t *nstrm, int how);

int proxy_netio_write(pr_netio_stream_t *nstrm, char *buf, size_t bufsz);

#endif /* MOD_PROXY_NETIO_H */
