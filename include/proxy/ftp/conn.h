/*
 * ProFTPD - mod_proxy FTP connection API
 * Copyright (c) 2013-2016 TJ Saunders
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

#ifndef MOD_PROXY_FTP_CONN_H
#define MOD_PROXY_FTP_CONN_H

#include "mod_proxy.h"

conn_t *proxy_ftp_conn_accept(pool *p, conn_t *data_conn, conn_t *ctrl_conn,
  int frontend_data);
conn_t *proxy_ftp_conn_connect(pool *p, const pr_netaddr_t *local_addr,
  const pr_netaddr_t *remote_addr, int frontend_data);
conn_t *proxy_ftp_conn_listen(pool *p, const pr_netaddr_t *bind_addr,
  int frontend_data);

#endif /* MOD_PROXY_FTP_CONN_H */
