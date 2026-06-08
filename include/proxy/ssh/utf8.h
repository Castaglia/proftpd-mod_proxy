/*
 * ProFTPD - mod_proxy SSH UTF8 API
 * Copyright (c) 2021-2026 TJ Saunders
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#ifndef MOD_PROXY_SSH_UTF8_H
#define MOD_PROXY_SSH_UTF8_H

char *proxy_ssh_utf8_decode_text(pool *p, const char *text);
char *proxy_ssh_utf8_encode_text(pool *p, const char *text);

/* Set the local charset to use explicitly, rather than relying on
 * nl_langinfo(3).
 */
int proxy_ssh_utf8_set_charset(const char *charset);

int proxy_ssh_utf8_init(void);
int proxy_ssh_utf8_free(void);

#endif /* MOD_PROXY_SSH_UTF8_H */
