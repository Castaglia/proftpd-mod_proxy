/*
 * ProFTPD - mod_proxy SSH UMAC
 * Copyright (c) 2022 TJ Saunders
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
#include "proxy/ssh/umac.h"

#define UMAC_OUTPUT_LEN	16

#define proxy_ssh_umac_alloc	proxy_ssh_umac128_alloc
#define proxy_ssh_umac_init	proxy_ssh_umac128_init
#define proxy_ssh_umac_new	proxy_ssh_umac128_new
#define proxy_ssh_umac_update	proxy_ssh_umac128_update
#define proxy_ssh_umac_reset	proxy_ssh_umac128_reset
#define proxy_ssh_umac_final	proxy_ssh_umac128_final
#define proxy_ssh_umac_delete	proxy_ssh_umac128_delete
#define proxy_ssh_umac_ctx	proxy_ssh_umac128_ctx

#include "umac.c"
