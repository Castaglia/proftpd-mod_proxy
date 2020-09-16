/*
 * ProFTPD - mod_proxy FTP Facts API
 * Copyright (c) 2020 TJ Saunders
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

#ifndef MOD_PROXY_FTP_FACTS_H
#define MOD_PROXY_FTP_FACTS_H

#include "mod_proxy.h"

/* RFC 3659 Facts */
#define PROXY_FTP_FACTS_OPT_SHOW_MODIFY			0x00001
#define PROXY_FTP_FACTS_OPT_SHOW_PERM			0x00002
#define PROXY_FTP_FACTS_OPT_SHOW_SIZE			0x00004
#define PROXY_FTP_FACTS_OPT_SHOW_TYPE			0x00008
#define PROXY_FTP_FACTS_OPT_SHOW_UNIQUE			0x00010
#define PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP		0x00020
#define PROXY_FTP_FACTS_OPT_SHOW_UNIX_MODE		0x00040
#define PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER		0x00080
#define PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER_NAME	0x00100
#define PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP_NAME	0x00200

unsigned long proxy_ftp_facts_get_opts(void);
void proxy_ftp_facts_parse_opts(char *facts);

#endif /* MOD_PROXY_FTP_FACTS_H */
