/*
 * ProFTPD - mod_proxy SSH Redis implementation
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

#include "redis.h"
#include "proxy/ssh.h"
#include "proxy/ssh/crypto.h"
#include "proxy/ssh/redis.h"

#if defined(PR_USE_OPENSSL)
#include <openssl/evp.h>

extern xaset_t *server_list;

static const char *trace_channel = "proxy.ssh.redis";

static void *redis_prefix = NULL;
static size_t redis_prefixsz = 0;
static unsigned long redis_opts = 0UL;

static const char *redis_algo_field = "algo";
static const char *redis_blob_field = "blob";

static char *make_key(pool *p, const char *backend_uri) {
  char *key;
  size_t keysz;

  keysz = strlen(backend_uri) + 64;
  key = pcalloc(p, keysz + 1);
  snprintf(key, keysz, "proxy_ssh_hostkeys:%s", backend_uri);

  return key;
}

static int ssh_redis_update_hostkey(pool *p, void *dsh, unsigned int vhost_id,
    const char *backend_uri, const char *algo,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen) {
  int res, xerrno = 0;
  pool *tmp_pool;
  pr_redis_t *redis;
  char *key, *data = NULL;
  long datalen = 0;
  size_t field_len;

  redis = dsh;

  tmp_pool = make_sub_pool(p);
  data = palloc(tmp_pool, (2 * hostkey_datalen) + 1);
  datalen = EVP_EncodeBlock((unsigned char *) data, hostkey_data,
    (int) hostkey_datalen);

  if (datalen == 0) {
    pr_trace_msg(trace_channel, 3,
      "error base640-encoding hostkey data: %s", proxy_ssh_crypto_get_errors());
    destroy_pool(tmp_pool);
    return 0;
  }

  key = make_key(tmp_pool, backend_uri);

  field_len = strlen(algo);
  res = pr_redis_hash_set(redis, &proxy_module, key, redis_algo_field,
    (void *) algo, field_len);
  xerrno = errno;

  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error setting value for field '%s' in Redis hash '%s': %s",
      redis_algo_field, key, strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  field_len = datalen;
  res = pr_redis_hash_set(redis, &proxy_module, key, redis_blob_field,
    (void *) data, field_len);
  xerrno = errno;

  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error setting value for field '%s' in Redis hash '%s': %s",
      redis_blob_field, key, strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  destroy_pool(tmp_pool);
  return 0;
}

static const unsigned char *ssh_redis_get_hostkey(pool *p, void *dsh,
    unsigned int vhost_id, const char *backend_uri, const char **algo,
    uint32_t *hostkey_datalen) {
  int have_padding = FALSE, res, xerrno;
  pool *tmp_pool;
  pr_redis_t *redis;
  pr_table_t *hostkey_tab;
  char *key;
  void *data = NULL;
  const unsigned char *hostkey_data = NULL;
  size_t blocklen = 0, datalen = 0, rem;

  redis = dsh;

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, backend_uri);

  res = pr_redis_hash_getall(tmp_pool, redis, &proxy_module, key, &hostkey_tab);
  xerrno = errno;

  if (res < 0) {
    if (xerrno != ENOENT) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error getting hash from Redis '%s': %s", key, strerror(xerrno));
    }

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  if (hostkey_tab == NULL) {
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  data = (void *) pr_table_kget(hostkey_tab, redis_algo_field,
    strlen(redis_algo_field), &datalen);
  if (data != NULL) {
    *algo = pstrndup(p, data, datalen);
  }

  data = (void *) pr_table_kget(hostkey_tab, redis_blob_field,
    strlen(redis_blob_field), &datalen);
  if (data == NULL) {
    pr_trace_msg(trace_channel, 3, "%s",
      "missing base64-decoding hostkey data from Redis, skipping");
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  /* Due to Base64's padding, we need to detect if the last block was padded
   * with zeros; we do this by looking for '=' characters at the end of the
   * text being decoded.  If we see these characters, then we will "trim" off
   * any trailing zero values in the decoded data, on the ASSUMPTION that they
   * are the auto-added padding bytes.
   */
  if (((char *) data)[datalen-1] == '=') {
    have_padding = TRUE;
  }

  blocklen = datalen;

  /* Ensure that the output buffer is divisible by 4, per OpenSSL
   * requirements.
   */
  rem = blocklen % 4;
  if (rem != 0) {
    blocklen += rem;
  }

  hostkey_data = pcalloc(p, blocklen);
  res = EVP_DecodeBlock((unsigned char *) hostkey_data, (unsigned char *) data,
    (int) datalen);
  if (res <= 0) {
    pr_trace_msg(trace_channel, 3,
      "error base64-decoding hostkey data: %s", proxy_ssh_crypto_get_errors());
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  if (have_padding == TRUE) {
    /* Assume that only one or two zero bytes of padding were added. */
    if (hostkey_data[res-1] == '\0') {
      res -= 1;

      if (hostkey_data[res-1] == '\0') {
        res -= 1;
      }
    }
  }

  *hostkey_datalen = res;

  pr_trace_msg(trace_channel, 19,
    "retrieved hostkey (algo '%s', %lu bytes) for vhost ID %u, URI '%s'",
    *algo, (unsigned long) *hostkey_datalen, vhost_id, backend_uri);
  return hostkey_data;
}

/* Initialization routines */

static int ssh_redis_init(pool *p, const char *tables_path, int flags) {
  /* We currently don't need to do anything, at init time, to any existing
   * SSH Redis keys.
   */
  return 0;
}

static int ssh_redis_close(pool *p, void *redis) {
  if (redis != NULL) {
    if (pr_redis_conn_close(redis) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error closing Redis connection: %s", strerror(errno));
    }
  }

  return 0;
}

static void *ssh_redis_open(pool *p, const char *tables_dir,
    unsigned long opts) {
  int xerrno = 0;
  pr_redis_t *redis;

  redis = pr_redis_conn_new(p, &proxy_module, 0);
  xerrno = errno;

  if (redis == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error opening Redis connection: %s", strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  (void) pr_redis_conn_set_namespace(redis, &proxy_module, redis_prefix,
    redis_prefixsz);
  redis_opts = opts;

  return redis;
}

int proxy_ssh_redis_as_datastore(struct proxy_ssh_datastore *ds, void *ds_data,
    size_t ds_datasz) {
  if (ds == NULL) {
    errno = EINVAL;
    return -1;
  }

  redis_prefix = ds_data;
  redis_prefixsz = ds_datasz;

  ds->hostkey_add = ssh_redis_update_hostkey;
  ds->hostkey_get = ssh_redis_get_hostkey;
  ds->hostkey_update = ssh_redis_update_hostkey;

  ds->init = ssh_redis_init;
  ds->open = ssh_redis_open;
  ds->close = ssh_redis_close;

  return 0;
}
#endif /* PR_USE_OPENSSL */
