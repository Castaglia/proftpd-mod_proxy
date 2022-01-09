/*
 * ProFTPD - mod_proxy SSH miscellany
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

#include "mod_proxy.h"
#include "proxy/ssh/misc.h"

#if defined(PR_USE_OPENSSL)
int proxy_ssh_misc_namelist_contains(pool *p, const char *namelist,
    const char *name) {
  register unsigned int i;
  int res = FALSE;
  pool *tmp_pool;
  array_header *list;
  const char **elts;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Contains name pool");

  list = pr_str_text_to_array(tmp_pool, namelist, ',');
  elts = (const char **) list->elts;

  for (i = 0; i < list->nelts; i++) {
    if (strcmp(elts[i], name) == 0) {
      res = TRUE;
      break;
    }
  }

  destroy_pool(tmp_pool);
  return res;
}

const char *proxy_ssh_misc_namelist_shared(pool *p, const char *c2s_names,
    const char *s2c_names) {
  register unsigned int i;
  const char *name = NULL, **client_names, **server_names;
  pool *tmp_pool;
  array_header *client_list, *server_list;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Share name pool");

  client_list = pr_str_text_to_array(tmp_pool, c2s_names, ',');
  client_names = (const char **) client_list->elts;

  server_list = pr_str_text_to_array(tmp_pool, s2c_names, ',');
  server_names = (const char **) server_list->elts;

  for (i = 0; i < client_list->nelts; i++) {
    register unsigned int j;

    if (name != NULL) {
      break;
    }

    for (j = 0; j < server_list->nelts; j++) {
      if (strcmp(client_names[i], server_names[j]) == 0) {
        name = client_names[i];
        break;
      }
    }
  }

  name = pstrdup(p, name);
  destroy_pool(tmp_pool);

  return name;
}
#endif /* PR_USE_OPENSSL */
