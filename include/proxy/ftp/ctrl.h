/*
 * ProFTPD - mod_proxy FTP control conn API
 * Copyright (c) 2012 TJ Saunders
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

#ifndef MOD_PROXY_FTP_CTRL_H
#define MOD_PROXY_FTP_CTRL_H

cmd_rec *proxy_ftp_ctrl_recv_cmd(pool *, conn_t *);
pr_response_t *proxy_ftp_ctrl_recv_resp(pool *p, conn_t *);
int proxy_ftp_ctrl_send_cmd(pool *, conn_t *, cmd_rec *);
int proxy_ftp_ctrl_send_resp(pool *, conn_t *, pr_response_t *);

#endif /* MOD_PROXY_FTP_CTRL_H */
