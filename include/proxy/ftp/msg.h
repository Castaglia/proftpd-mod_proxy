/*
 * ProFTPD - mod_proxy FTP message API
 * Copyright (c) 2013 TJ Saunders
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

#ifndef MOD_PROXY_FTP_MSG_H
#define MOD_PROXY_FTP_MSG_H

/* Format a string containg the address for use in a PORT command or a
 * PASV response.
 */
const char *proxy_ftp_msg_fmt_addr(pool *, pr_netaddr_t *, unsigned short);

/* Format a string containg the address for use in an EPRT command or an
 * EPSV response.
 */
const char *proxy_ftp_msg_fmt_ext_addr(pool *, pr_netaddr_t *, unsigned short,
  int);

/* Parse the address/port out of a string, e.g. from a PORT command or from
 * a PASV response.
 */
pr_netaddr_t *proxy_ftp_msg_parse_addr(pool *, const char *, int);

/* Parse the address/port out of a string, e.g. from an EPRT command or from
 * an EPSV response.
 */
pr_netaddr_t *proxy_ftp_msg_parse_ext_addr(pool *, const char *, pr_netaddr_t *,
  const char *);

#endif /* MOD_PROXY_FTP_MSG_H */
