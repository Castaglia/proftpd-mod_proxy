/*
 * ProFTPD - mod_proxy forward-proxy API
 * Copyright (c) 2012-2013 TJ Saunders
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

#ifndef MOD_PROXY_FORWARD_H
#define MOD_PROXY_FORWARD_H

int proxy_forward_init(pool *p);

/* Forward proxy method API */

#define PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH		1
#define PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH			2

/* Return the method ID for the given string, or -1 if the given method
 * is not recognized/supported.
 */
int proxy_forward_get_method(const char *);

#endif /* MOD_PROXY_FORWARD_H */
