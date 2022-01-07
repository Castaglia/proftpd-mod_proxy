/*
 * ProFTPD - mod_proxy SSH API
 * Copyright (c) 2021 TJ Saunders
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

#ifndef MOD_PROXY_SSH_H
#define MOD_PROXY_SSH_H

#include "mod_proxy.h"
#include "proxy/session.h"

/* ProxySFTPOptions values.  NOTE: Make sure these do NOT collide with existing
 * PROXY_OPT_ values defined in mod_proxy.h.
 */
#define PROXY_OPT_SSH_PESSIMISTIC_KEXINIT	0x0100
#define PROXY_OPT_SSH_OLD_PROTO_COMPAT		0x0200
#define PROXY_OPT_SSH_ALLOW_WEAK_DH		0x0400
#define PROXY_OPT_SSH_ALLOW_WEAK_SECURITY	0x0800
#define PROXY_OPT_SSH_NO_EXT_INFO		0x1000
#define PROXY_OPT_SSH_NO_HOSTKEY_ROTATION	0x2000

int proxy_ssh_init(pool *p, const char *tables_dir, int flags);
int proxy_ssh_free(pool *p);

int proxy_ssh_sess_init(pool *p, struct proxy_session *proxy_sess, int flags);
int proxy_ssh_sess_free(pool *p);

/* Defines the datastore interface. */
struct proxy_ssh_datastore {
  /* Keystore callbacks */
  int (*hostkey_add)(pool *p, void *dsh, unsigned int vhost_id,
    const char *backend_uri, const char *algo,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen);
  const unsigned char *(*hostkey_get)(pool *p, void *dsh,
    unsigned int vhost_id, const char *backend_uri, const char **algo,
    uint32_t *hostkey_datalen);
  int (*hostkey_update)(pool *p, void *dsh, unsigned int vhost_id,
    const char *backend_uri, const char *algo,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen);

  int (*init)(pool *p, const char *path, int flags);
  void *(*open)(pool *p, const char *path, unsigned long opts);
  int (*close)(pool *p, void *dsh);

  /* Datastore handle returned by the open callback. */
  void *dsh;
};

#endif /* MOD_PROXY_SSH_H */
