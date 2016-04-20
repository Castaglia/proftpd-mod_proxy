/*
 * ProFTPD - mod_proxy FTP data transfer API
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

#include "mod_proxy.h"
#include "proxy/session.h"

#ifndef MOD_PROXY_FTP_XFER_H
#define MOD_PROXY_FTP_XFER_H

int proxy_ftp_xfer_prepare_active(int, cmd_rec *, const char *,
  struct proxy_session *);
const pr_netaddr_t *proxy_ftp_xfer_prepare_passive(int, cmd_rec *, const char *,
  struct proxy_session *);

#endif /* MOD_PROXY_FTP_XFER_H */
