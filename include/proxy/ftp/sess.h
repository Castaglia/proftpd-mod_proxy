/*
 * ProFTPD - mod_proxy FTP session API
 * Copyright (c) 2015-2021 TJ Saunders
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

#ifndef MOD_PROXY_FTP_SESS_H
#define MOD_PROXY_FTP_SESS_H

#include "mod_proxy.h"
#include "proxy/session.h"

/* ProxyTLSTransferProtectionPolicy values */
#define PROXY_FTP_SESS_TLS_XFER_PROTECTION_POLICY_REQUIRED	 1
#define PROXY_FTP_SESS_TLS_XFER_PROTECTION_POLICY_CLIENT	 0
#define PROXY_FTP_SESS_TLS_XFER_PROTECTION_POLICY_CLEAR		-1

int proxy_ftp_sess_get_feat(pool *, const struct proxy_session *proxy_sess);
int proxy_ftp_sess_send_auth_tls(pool *p,
  const struct proxy_session *proxy_sess);
int proxy_ftp_sess_send_host(pool *, const struct proxy_session *proxy_sess);
int proxy_ftp_sess_send_pbsz_prot(pool *p,
  const struct proxy_session *proxy_sess);

#endif /* MOD_PROXY_FTP_SESS_H */
