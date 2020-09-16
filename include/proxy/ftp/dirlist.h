/*
 * ProFTPD - mod_proxy FTP dirlist API
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

#ifndef MOD_PROXY_FTP_DIRLIST_H
#define MOD_PROXY_FTP_DIRLIST_H

#include "mod_proxy.h"
#include "proxy/session.h"

int proxy_ftp_dirlist_init(pool *p, struct proxy_session *proxy_sess);
int proxy_ftp_dirlist_finish(struct proxy_session *proxy_sess);

struct proxy_dirlist_fileinfo {
  pool *pool;
  struct stat *st;
  unsigned char have_uid, have_gid;
  struct tm *tm;
  const char *user;
  const char *group;
  const char *type;
  const char *perm;
  const char *path;
};

#define PROXY_FTP_DIRLIST_OPT_USE_SLINK		0x0001

struct proxy_dirlist_fileinfo *proxy_ftp_dirlist_fileinfo_from_dos(pool *p,
  const char *text, size_t textlen, unsigned long opts);
struct proxy_dirlist_fileinfo *proxy_ftp_dirlist_fileinfo_from_unix(pool *p,
  const char *text, size_t textlen, struct tm *tm, unsigned long opts);
struct proxy_dirlist_fileinfo *proxy_ftp_dirlist_fileinfo_from_text(pool *p,
  const char *text, size_t textlen, struct tm *tm, void *user_data,
  unsigned long opts);

const char *proxy_ftp_dirlist_fileinfo_to_facts(pool *p,
  const struct proxy_dirlist_fileinfo *pdf, size_t *textlen);

/* Given a buffer of (possibly incomplete) dirlist data, return the text
 * to give to the client.  Note that there may be enough data accumulated
 * yet to provide text to the client.
 */
int proxy_ftp_dirlist_to_text(pool *p, char *buf, size_t buflen,
  size_t max_textsz, char **text, size_t *textlen, void *user_data);

#endif /* MOD_PROXY_FTP_DIRLIST_H */
