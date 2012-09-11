/*
 * ProFTPD - mod_proxy FTP client library
 * Copyright (c) 2012 TJ Saunders <tj@castaglia.org>
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

#ifndef MOD_PROXY_CLIENT_FTP_H
#define MOD_PROXY_CLIENT_FTP_H

#include "conf.h"
#include "privs.h"

#include "proxy.h"

/* Allocate a client used for communicating with an FTP server at the given
 * remote address and port.
 */
struct proxy_ftp_client *proxy_ftp_open(pool *p, pr_netaddr_t *remote_addr,
  unsigned int remote_port);

/* Connect to the given remote address/port via FTP.
 *
 * Returns zero upon successful connection AND receipt of 200 response
 * code/greeting from the remote FTP server. Otherwise, returns -1 if the
 * connection timed out, or the remote FTP server did not send a 200 response
 * code/greeting.
 */
int proxy_ftp_connect(struct proxy_ftp_client *ftp,
  unsigned int connect_timeout, char **banner);

/* Disconnect from the remote FTP server by sending the QUIT command. */
int proxy_ftp_disconnect(struct proxy_ftp_client *ftp);

void proxy_ftp_close(struct proxy_ftp_client **ftp);

#endif /* MOD_PROXY_CLIENT_FTP_H */
