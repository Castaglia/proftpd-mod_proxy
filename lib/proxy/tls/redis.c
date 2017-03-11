/*
 * ProFTPD - mod_proxy TLS Redis implementation
 * Copyright (c) 2017 TJ Saunders
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
#include "proxy/tls.h"

#ifdef PR_USE_OPENSSL

extern xaset_t *server_list;

static const char *trace_channel = "proxy.tls.redis";

static void *redis_prefix = NULL;
static size_t redis_prefixsz = 0;
static unsigned long redis_opts = 0UL;

static char *make_key(pool *p, unsigned int vhost_id) {
  char *key;
  size_t keysz;

  keysz = 64;
  key = pcalloc(p, keysz + 1);
  snprintf(key, keysz, "proxy_tls_sessions:vhost#%u", vhost_id);

  return key;
}

static int tls_redis_add_sess(pool *p, void *redis, const char *sess_key,
    SSL_SESSION *sess) {
  int res, xerrno = 0;
  pool *tmp_pool;
  char *key;
  BIO *bio;
  char *data = NULL;
  long datalen = 0;

  bio = BIO_new(BIO_s_mem());
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  res = PEM_write_bio_SSL_SESSION(bio, sess);
  if (res != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error writing PEM-encoded SSL session data: %s", proxy_tls_get_errors());
  }
  (void) BIO_flush(bio);

  datalen = BIO_get_mem_data(bio, &data);
  if (data == NULL) {
    pr_trace_msg(trace_channel, 9,
      "no PEM data found for SSL session, not caching");
    BIO_free(bio);
    return 0;
  }

  data[datalen] = '\0';

  if (redis_opts & PROXY_TLS_OPT_ENABLE_DIAGS) {
    BIO *diags_bio;

    diags_bio = BIO_new(BIO_s_mem());
    if (diags_bio != NULL) {
      if (SSL_SESSION_print(diags_bio, sess) == 1) {
        char *diags_data = NULL;
        long diags_datalen = 0;

        diags_datalen = BIO_get_mem_data(diags_bio, &diags_data);
        if (diags_data != NULL) {
          diags_data[diags_datalen] = '\0';
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "[tls.redis] caching SSL session (%lu bytes):\n%s",
            (unsigned long) datalen, diags_data);
        }
      }
    }
  }

  tmp_pool = make_sub_pool(p);

  key = make_key(tmp_pool, main_server->sid);
  res = pr_redis_hash_set(redis, &proxy_module, key, sess_key, data, datalen);
  xerrno = errno;

  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error setting value for field '%s' in Redis hash '%s': %s", sess_key,
      key, strerror(xerrno));

    destroy_pool(tmp_pool);
    BIO_free(bio);
    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 17, "cached SSL session (%lu bytes) for key '%s'",
    (unsigned long) datalen, sess_key);

  destroy_pool(tmp_pool);
  BIO_free(bio);
  return 0;
}

static int tls_redis_remove_sess(pool *p, void *redis, const char *sess_key) {
  int res, xerrno;
  pool *tmp_pool;
  char *key;

  tmp_pool = make_sub_pool(p);

  key = make_key(tmp_pool, main_server->sid);
  res = pr_redis_hash_delete(redis, &proxy_module, key, sess_key);
  xerrno = errno;

  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error deleting field '%s' from Redis hash '%s': %s", sess_key, key,
      strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 17, "removed cached SSL session for key '%s'",
    sess_key);
  destroy_pool(tmp_pool);
  return 0;
}

static SSL_SESSION *tls_redis_get_sess(pool *p, void *redis,
    const char *sess_key) {
  int res, xerrno;
  pool *tmp_pool;
  BIO *bio;
  char *key;
  char *data = NULL;
  size_t datalen = 0;
  SSL_SESSION *sess = NULL;

  tmp_pool = make_sub_pool(p);

  key = make_key(tmp_pool, main_server->sid);
  res = pr_redis_hash_get(tmp_pool, redis, &proxy_module, key, sess_key,
    (void **) &data, &datalen);
  xerrno = errno;

  if (res < 0) {
    if (xerrno != ENOENT) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error getting value for field '%s' from Redis hash '%s': %s", sess_key,
        key, strerror(xerrno));
    }

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  pr_trace_msg(trace_channel, 19,
    "retrieved cached session (%lu bytes) for key '%s'",
    (unsigned long) datalen, sess_key);

  bio = BIO_new_mem_buf((char *) data, datalen);
  sess = PEM_read_bio_SSL_SESSION(bio, NULL, 0, NULL);
  destroy_pool(tmp_pool);

  if (sess == NULL) {
    pr_trace_msg(trace_channel, 3,
      "error converting database entry to SSL session: %s",
      proxy_tls_get_errors());
  }

  BIO_free(bio);

  if (sess == NULL) {
    errno = ENOENT;
    return NULL;
  }

  pr_trace_msg(trace_channel, 17, "retrieved cached SSL session for key '%s'",
    sess_key);
  return sess;
}

static int tls_redis_count_sess(pool *p, void *redis) {
  int res, xerrno;
  uint64_t count = 0;
  pool *tmp_pool;
  char *key;

  tmp_pool = make_sub_pool(p);

  key = make_key(tmp_pool, main_server->sid);
  res = pr_redis_hash_count(redis, &proxy_module, key, &count);
  xerrno = errno;

  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting size of Redis hash '%s': %s", key, strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  destroy_pool(tmp_pool);
  return (int) count;
}

/* Initialization routines */

static int tls_redis_truncate_tables(pool *p, pr_redis_t *redis,
    unsigned int vhost_id) {
  register unsigned int i;
  int res, xerrno;
  pool *tmp_pool;
  const char *key;
  array_header *fields = NULL;

  tmp_pool = make_sub_pool(p);

  key = make_key(tmp_pool, vhost_id);
  res = pr_redis_hash_keys(tmp_pool, redis, &proxy_module, key, &fields);
  xerrno = errno;

  if (res < 0) {
    if (xerrno == ENOENT) {
      /* Ignore. */
      res = 0;

    } else {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error obtaining fields from Redis hash '%s': %s", key,
        strerror(errno));
    }

    destroy_pool(tmp_pool);
    errno = xerrno;
    return res;
  }

  pr_trace_msg(trace_channel, 17, "deleting %u %s for hash '%s'",
    fields->nelts, fields->nelts != 1 ? "fields" : "field", key);

  for (i = 0; i < fields->nelts; i++) {
    char *field;

    field = ((char **) fields->elts)[i];
    pr_trace_msg(trace_channel, 17, "deleting field '%s' from Redis hash '%s'",
      field, key);
    res = pr_redis_hash_delete(redis, &proxy_module, key, field);
    if (res < 0) {
      pr_trace_msg(trace_channel, 4,
        "error deleting field '%s' from Redis hash '%s': %s", field, key,
        strerror(errno));
    }
  }

  destroy_pool(tmp_pool);
  return 0;
}

static int tls_redis_init(pool *p, const char *tables_path, int flags) {
  int res, xerrno = 0;
  server_rec *s;
  pr_redis_t *redis = NULL;

  (void) tables_path;
  (void) flags;

  redis = pr_redis_conn_new(p, &proxy_module, 0);
  xerrno = errno;

  if (redis == NULL) {
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening Redis connection: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  (void) pr_redis_conn_set_namespace(redis, &proxy_module, redis_prefix,
    redis_prefixsz);

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    res = tls_redis_truncate_tables(p, redis, s->sid);
    if (res < 0) {
      pr_trace_msg(trace_channel, 3,
        "error truncating Redis keys for server '%s': %s", s->ServerName,
        strerror(errno));
    } 
  }

  (void) pr_redis_conn_close(redis);
  return 0;
}

static int tls_redis_close(pool *p, void *redis) {
  if (redis != NULL) {
    if (pr_redis_conn_close(redis) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error closing Redis connection: %s", strerror(errno));
    }
  }

  return 0;
}

static void *tls_redis_open(pool *p, const char *tables_dir,
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
#endif /* PR_USE_OPENSSL */

int proxy_tls_redis_as_datastore(struct proxy_tls_datastore *ds, void *ds_data,
    size_t ds_datasz) {
  if (ds == NULL) {
    errno = EINVAL;
    return -1;
  }

  redis_prefix = ds_data;
  redis_prefixsz = ds_datasz;

#ifdef PR_USE_OPENSSL
  ds->add_sess = tls_redis_add_sess;
  ds->remove_sess = tls_redis_remove_sess;
  ds->get_sess = tls_redis_get_sess;
  ds->count_sess = tls_redis_count_sess;

  ds->init = tls_redis_init;
  ds->open = tls_redis_open;
  ds->close = tls_redis_close;
#endif /* PR_USE_OPENSSL */

  return 0;
}
