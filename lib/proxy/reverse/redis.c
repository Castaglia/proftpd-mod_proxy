/*
 * ProFTPD - mod_proxy reverse datastore implementation
 * Copyright (c) 2012-2020 TJ Saunders
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

#include "proxy/conn.h"
#include "proxy/reverse.h"
#include "proxy/reverse/redis.h"
#include "proxy/random.h"
#include "proxy/tls.h"
#include "proxy/ftp/ctrl.h"

/* PerHost/PerUser/PerGroup table limits */
#define PROXY_REVERSE_REDIS_PERHOST_MAX_ENTRIES		8192
#define PROXY_REVERSE_REDIS_PERUSER_MAX_ENTRIES		8192
#define PROXY_REVERSE_REDIS_PERGROUP_MAX_ENTRIES	8192

static array_header *redis_backends = NULL;

static const char *trace_channel = "proxy.reverse.redis";

static void *redis_prefix = NULL;
static size_t redis_prefixsz = 0;

static char *make_key(pool *p, const char *policy, unsigned int vhost_id,
    const char *name) {
  char *key;
  size_t keysz;

  /* It's 21 characters for "proxy_reverse:" and ":vhost#", and one for the
   * trailing NUL.  Allocate enough room for a large vhost ID, e.g.
   * optimistically in the thousands.
   */
  keysz = 22 + 6 + strlen(policy);
  if (name != NULL) {
    keysz += strlen(name) + 1;
  }

  key = pcalloc(p, keysz + 1);

  if (name == NULL) {
    snprintf(key, keysz, "proxy_reverse:%s:vhost#%u", policy, vhost_id);

  } else {
    snprintf(key, keysz, "proxy_reverse:%s:vhost#%u:%s", policy, vhost_id,
      name);
  }

  return key;
}

static unsigned int str2hash(const void *key, size_t keysz) {
  unsigned int i = 0;
  size_t sz = !keysz ? strlen((const char *) key) : keysz;

  while (sz--) {
    const char *k = key;
    unsigned int c;

    pr_signals_handle();

    c = k[sz];
    i = (i * 33) + c;
  }

  return i;
}

/* Given an index into the array_header of backend pconns, return the URI
 * for the indexed conn.
 */
static const char *backend_uri_by_idx(int idx) {
  const struct proxy_conn *pconn;

  if (redis_backends == NULL) {
    errno = EPERM;
    return NULL;
  }

  if (idx < 0) {
    errno = EPERM;
    return NULL;
  }

  pconn = ((struct proxy_conn **) redis_backends->elts)[idx];
  return proxy_conn_get_uri(pconn);
}

/* Redis List helpers */
static array_header *redis_get_list_backend_uris(pool *p,
    pr_redis_t *redis, const char *policy, unsigned int vhost_id,
    const char *name) {
  int res;
  pool *tmp_pool;
  char *key;
  array_header *backend_uris, *values = NULL, *valueszs = NULL;

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, policy, vhost_id, name);

  res = pr_redis_list_getall(tmp_pool, redis, &proxy_module, key, &values,
    &valueszs);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error retrieving %s Redis entries using key '%s': %s", policy, key,
      strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  backend_uris = copy_array_str(p, values);
  destroy_pool(tmp_pool);

  return backend_uris;
}

static int redis_set_list_backends(pool *p, pr_redis_t *redis,
    const char *policy, unsigned int vhost_id, const char *name,
    array_header *backends) {
  register unsigned int i;
  int res = 0, xerrno;
  pool *tmp_pool;
  char *key;
  array_header *backend_uris, *backend_uriszs;

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, policy, vhost_id, name);
  backend_uris = make_array(tmp_pool, 0, sizeof(char *));
  backend_uriszs = make_array(tmp_pool, 0, sizeof(size_t));

  for (i = 0; i < backends->nelts; i++) {
    struct proxy_conn *pconn;
    const char *backend_uri;
    size_t backend_urisz;

    pconn = ((struct proxy_conn **) backends->elts)[i];
    backend_uri = proxy_conn_get_uri(pconn);
    *((char **) push_array(backend_uris)) = pstrdup(tmp_pool, backend_uri);

    backend_urisz = strlen(backend_uri);
    *((size_t *) push_array(backend_uriszs)) = backend_urisz;

    pr_trace_msg(trace_channel, 19, "adding %s list backend #%u: '%.*s'",
      policy, i+1, (int) backend_urisz, backend_uri);
  }

  res = pr_redis_list_setall(redis, &proxy_module, key, backend_uris,
    backend_uriszs);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 6,
      "error adding %s Redis entries: %s", policy, strerror(xerrno));
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

/* Redis Sorted Set helpers */

static int redis_set_sorted_set_backends(pool *p, pr_redis_t *redis,
    const char *policy, unsigned int vhost_id, array_header *backends,
    float init_score) {
  register unsigned int i;
  int res = 0, xerrno;
  pool *tmp_pool;
  char *key;
  array_header *backend_uris, *backend_uriszs, *backend_scores;

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, policy, vhost_id, NULL);
  backend_uris = make_array(tmp_pool, 0, sizeof(char *));
  backend_uriszs = make_array(tmp_pool, 0, sizeof(size_t));
  backend_scores = make_array(tmp_pool, 0, sizeof(float));

  for (i = 0; i < backends->nelts; i++) {
    struct proxy_conn *pconn;
    const char *backend_uri;
    size_t backend_urisz;

    pconn = ((struct proxy_conn **) backends->elts)[i];
    backend_uri = proxy_conn_get_uri(pconn);
    *((char **) push_array(backend_uris)) = pstrdup(tmp_pool, backend_uri);

    backend_urisz = strlen(backend_uri);
    *((size_t *) push_array(backend_uriszs)) = backend_urisz;

    *((float *) push_array(backend_scores)) = init_score;

    pr_trace_msg(trace_channel, 19,
      "adding %s sorted set backend #%u: '%.*s' (%0.3f)", policy, i+1,
      (int) backend_urisz, backend_uri, init_score);
  }

  res = pr_redis_sorted_set_setall(redis, &proxy_module, key, backend_uris,
    backend_uriszs, backend_scores);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 6,
      "error adding %s Redis entries: %s", policy, strerror(xerrno));
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

/* ProxyReverseConnectPolicy: Shuffle */

/* The implementation of shuffling here requires two Redis lists, the A and B
 * lists.  URIs are consumed (via random selection) from the A list and added
 * to the B list, until the A list is empty.  At which point, the B list is
 * renamed to the A list, and we start again.
 */

static int reverse_redis_shuffle_init(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, array_header *backends) {
  return redis_set_list_backends(p, redis, "Shuffle", vhost_id, "A", backends);
}

static long reverse_redis_shuffle_next(pool *p, pr_redis_t *redis,
    unsigned int vhost_id) {
  int res, xerrno;
  pool *tmp_pool;
  char *akey, *bkey;
  const char *val;
  size_t valsz;
  uint64_t count = 0;
  long idx;

  tmp_pool = make_sub_pool(p);
  akey = make_key(tmp_pool, "Shuffle", vhost_id, "A");
  res = pr_redis_list_count(redis, &proxy_module, akey, &count);
  xerrno = errno;

  if (res < 0) {
    if (xerrno != ENOENT) {
      pr_trace_msg(trace_channel, 6,
        "error getting count of Redis list '%s': %s", akey, strerror(xerrno));

      destroy_pool(tmp_pool);
      errno = xerrno;
      return -1;
    }

    count = 0;
  }
 
  if (count == 0) {
    res = reverse_redis_shuffle_init(p, redis, vhost_id, redis_backends);
    xerrno = errno;

    if (res < 0) {
      destroy_pool(tmp_pool);
      errno = xerrno;
      return -1;
    }

    count = redis_backends->nelts;
  }

  idx = proxy_random_next(0, count-1);

/* XXX Now we want to remove that backend URI from the A list, and add it to
 * the B list.
 */

  val = backend_uri_by_idx((int) idx);
  xerrno = errno;

  if (val == NULL) {
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  valsz = strlen(val);
  res = pr_redis_list_delete(redis, &proxy_module, akey, (void *) val, valsz);
  xerrno = errno;

  if (res < 0) {
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  bkey = make_key(tmp_pool, "Shuffle", vhost_id, "B");

  res = pr_redis_list_append(redis, &proxy_module, bkey, (void *) val, valsz);
  xerrno = errno;

  if (res < 0) {
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  /* If count is one, it means we just removed the last backend from the A
   * list.  Thus rename the B list to be the A list.
   */
  if (count == 1) {
    res = pr_redis_rename(redis, &proxy_module, bkey, akey);
    xerrno = errno;

    if (res < 0) {
      pr_trace_msg(trace_channel, 3,
        "error renaming Shuffle key '%s' to '%s': %s", bkey, akey,
        strerror(xerrno));
      idx = -1;
    }
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return idx;
}

static int reverse_redis_shuffle_used(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx) {
  /* Nothing to do here. */
  return 0;
}

/* ProxyReverseConnectPolicy: RoundRobin */

static int reverse_redis_roundrobin_init(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, array_header *backends) {
  return redis_set_list_backends(p, redis, "RoundRobin", vhost_id, NULL,
    backends);
}

static const struct proxy_conn *reverse_redis_roundrobin_next(pool *p,
    pr_redis_t *redis, unsigned int vhost_id) {
  int res, xerrno;
  pool *tmp_pool;
  char *key, *backend_uri = NULL;
  size_t backend_urisz = 0;
  const struct proxy_conn *pconn;

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, "RoundRobin", vhost_id, NULL);

  res = pr_redis_list_rotate(tmp_pool, redis, &proxy_module, key,
    (void **) &backend_uri, &backend_urisz);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error rotating RoundRobin Redis list using key '%s': %s", key,
      strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  pconn = proxy_conn_create(p, pstrndup(tmp_pool, backend_uri, backend_urisz),
    0);
  xerrno = errno;

  if (pconn == NULL) {
    pr_trace_msg(trace_channel, 3,
      "error creating proxy connection from URI '%.*s': %s",
      (int) backend_urisz, backend_uri, strerror(xerrno));
  }

  destroy_pool(tmp_pool);

  errno = xerrno;
  return pconn;
}

static int reverse_redis_roundrobin_used(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx) {
  /* Nothing to do here. */
  return 0;
}

/* ProxyReverseConnectPolicy: LeastConns */

static int reverse_redis_leastconns_init(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, array_header *backends) {
  return redis_set_sorted_set_backends(p, redis, "LeastConns", vhost_id,
    backends, 0.0);
}

static const struct proxy_conn *reverse_redis_leastconns_next(pool *p,
    pr_redis_t *redis, unsigned int vhost_id) {
  int res, xerrno;
  pool *tmp_pool;
  char *key;
  array_header *vals = NULL, *valszs = NULL;
  const struct proxy_conn *pconn = NULL;

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, "LeastConns", vhost_id, NULL);

  res = pr_redis_sorted_set_getn(tmp_pool, redis, &proxy_module, key, 0, 1,
    &vals, &valszs, PR_REDIS_SORTED_SET_FL_ASC);
  xerrno = errno;

  if (res == 0) {
    char *backend_uri;

    backend_uri = ((char **) vals->elts)[0];
    pconn = proxy_conn_create(p, backend_uri, 0);
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return pconn;
}

static int reverse_redis_leastconns_used(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx) {
  /* Nothing to do here. */
  return 0;
}

static int reverse_redis_leastconns_update(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx, int conn_incr, long connect_ms) {
  int res, xerrno;
  pool *tmp_pool;
  char *key;
  const char *val;
  float score;
  size_t valsz;

  val = backend_uri_by_idx(backend_idx);
  if (val == NULL) {
    return -1;
  }

  valsz = strlen(val);

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, "LeastConns", vhost_id, NULL);

  score = (float) conn_incr;
  res = pr_redis_sorted_set_set(redis, &proxy_module, key, (void *) val, valsz,
    score);
  xerrno = errno;

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

/* ProxyReverseConnectPolicy: LeastResponseTime */

/* Note: "least response time" is determined by calculating the following
 * for each backend server:
 *
 *  N = connection count * connect time (ms)
 *
 * and choosing the backend with the lowest value for N.  If there are no
 * backend servers with connect time values, choose the one with the lowest
 * connection count.
 */

static int reverse_redis_leastresponsetime_init(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, array_header *backends) {
  return redis_set_sorted_set_backends(p, redis, "LeastResponseTime", vhost_id,
    backends, 0.0);
}

static const struct proxy_conn *reverse_redis_leastresponsetime_next(pool *p,
    pr_redis_t *redis, unsigned int vhost_id) {
  int res, xerrno;
  pool *tmp_pool;
  char *key;
  array_header *vals = NULL, *valszs = NULL;
  const struct proxy_conn *pconn = NULL;

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, "LeastResponseTime", vhost_id, NULL);

  res = pr_redis_sorted_set_getn(tmp_pool, redis, &proxy_module, key, 0, 1,
    &vals, &valszs, PR_REDIS_SORTED_SET_FL_ASC);
  xerrno = errno;

  if (res == 0) {
    char *backend_uri;

    backend_uri = ((char **) vals->elts)[0];
    pconn = proxy_conn_create(p, backend_uri, 0);
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return pconn;
}

static int reverse_redis_leastresponsetime_used(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx) {
  /* TODO: anything to do here? */
  return 0;
}

static int reverse_redis_leastresponsetime_update(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx, int conn_incr, long connect_ms) {
  int res, xerrno;
  pool *tmp_pool;
  char *key;
  const char *val;
  float score;
  size_t valsz;

  val = backend_uri_by_idx(backend_idx);
  if (val == NULL) {
    return -1;
  }

  valsz = strlen(val);

  tmp_pool = make_sub_pool(p);
  key = make_key(tmp_pool, "LeastResponseTime", vhost_id, NULL);

  score = (float) conn_incr;
  if (connect_ms > 0) {
    score *= (float) connect_ms;
  }

  res = pr_redis_sorted_set_set(redis, &proxy_module, key, (void *) val, valsz,
    score);
  xerrno = errno;

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

/* ProxyReverseConnectPolicy: PerUser */

static array_header *reverse_redis_peruser_get(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, const char *user) {
  return redis_get_list_backend_uris(p, redis, "PerUser", vhost_id, user);
}

static const struct proxy_conn *reverse_redis_peruser_init(pool *p,
    pr_redis_t *redis, unsigned int vhost_id, const char *user) {
  int res;
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns = NULL;
  unsigned int backend_count;
  array_header *backends;

  backends = proxy_reverse_pername_backends(p, user, TRUE);
  if (backends == NULL) {
    return NULL;
  }

  /* Store these backends for later use. */
  res = redis_set_list_backends(p, redis, "PerUser", vhost_id, user, backends);
  if (res < 0) {
    return NULL;
  }

  backend_count = backends->nelts;
  conns = backends->elts;

  if (backend_count == 1) {
    pconn = conns[0];

  } else {
    size_t user_len;
    unsigned int h;
    int idx;

    user_len = strlen(user);
    h = str2hash(user, user_len);
    idx = h % backend_count;

    pconn = conns[idx];
  }

  return pconn;
}

static const struct proxy_conn *reverse_redis_peruser_next(pool *p,
    pr_redis_t *redis, unsigned int vhost_id, const char *user) {
  array_header *backend_uris;
  const struct proxy_conn *pconn = NULL;

  pconn = reverse_redis_peruser_init(p, redis, vhost_id, user);
  if (pconn == NULL &&
      errno != ENOENT) {
    backend_uris = reverse_redis_peruser_get(p, redis, vhost_id, user);
    if (backend_uris != NULL) {
      char **vals;

      vals = backend_uris->elts;
      pconn = proxy_conn_create(p, vals[0], 0);
    }
  }

  if (pconn != NULL) {
    return pconn;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "error preparing PerUser Redis entries for user '%s': %s", user,
    strerror(ENOENT));
  errno = EPERM;
  return NULL;
}

static int reverse_redis_peruser_used(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx) {
  /* Nothing to do here. */
  return 0;
}

/* ProxyReverseConnectPolicy: PerGroup */

static array_header *reverse_redis_pergroup_get(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, const char *group) {
  return redis_get_list_backend_uris(p, redis, "PerGroup", vhost_id, group);
}

static const struct proxy_conn *reverse_redis_pergroup_init(pool *p,
    pr_redis_t *redis, unsigned int vhost_id, const char *group) {
  int res;
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns = NULL;
  unsigned int backend_count;
  array_header *backends;

  backends = proxy_reverse_pername_backends(p, group, FALSE);
  if (backends == NULL) {
    return NULL;
  }

  /* Store these backends for later use. */
  res = redis_set_list_backends(p, redis, "PerGroup", vhost_id, group,
    backends);
  if (res < 0) {
    return NULL;
  }

  backend_count = backends->nelts;
  conns = backends->elts;

  if (backend_count == 1) {
    pconn = conns[0];

  } else {
    size_t group_len;
    unsigned int h;
    int idx;

    group_len = strlen(group);
    h = str2hash(group, group_len);
    idx = h % backend_count;

    pconn = conns[idx];
  }

  return pconn;
}

static const struct proxy_conn *reverse_redis_pergroup_next(pool *p,
    pr_redis_t *redis, unsigned int vhost_id, const char *group) {
  array_header *backend_uris;
  const struct proxy_conn *pconn = NULL;

  pconn = reverse_redis_pergroup_init(p, redis, vhost_id, group);
  if (pconn == NULL &&
      errno != ENOENT) {
    backend_uris = reverse_redis_pergroup_get(p, redis, vhost_id, group);
    if (backend_uris != NULL) {
      char **vals;

      vals = backend_uris->elts;
      pconn = proxy_conn_create(p, vals[0], 0);
    }
  }

  if (pconn != NULL) {
    return pconn;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "error preparing PerGroup Redis entries for group '%s': %s", group,
    strerror(ENOENT));
  errno = EPERM;
  return NULL;
}

static int reverse_redis_pergroup_used(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx) {
  /* Nothing to do here. */
  return 0;
}

/* ProxyReverseConnectPolicy: PerHost */

static array_header *reverse_redis_perhost_get(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, const pr_netaddr_t *addr) {
  return redis_get_list_backend_uris(p, redis, "PerHost", vhost_id,
    pr_netaddr_get_ipstr(addr));
}

static const struct proxy_conn *reverse_redis_perhost_init(pool *p,
    pr_redis_t *redis, unsigned int vhost_id, array_header *backends,
    const pr_netaddr_t *addr) {
  int res;
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns;
  const char *ip;

  ip = pr_netaddr_get_ipstr(addr);

  /* Store these backends for later use. */
  res = redis_set_list_backends(p, redis, "PerHost", vhost_id, ip, backends);
  if (res < 0) {
    return NULL;
  }

  conns = backends->elts;

  if (backends->nelts == 1) {
    pconn = conns[0];

  } else {
    size_t iplen;
    unsigned int h;
    int idx;

    iplen = strlen(ip);
    h = str2hash(ip, iplen);
    idx = h % backends->nelts;

    pconn = conns[idx];
  }

  return pconn;
}

static const struct proxy_conn *reverse_redis_perhost_next(pool *p,
    pr_redis_t *redis, unsigned int vhost_id, const pr_netaddr_t *addr) {
  array_header *backend_uris;
  const struct proxy_conn *pconn = NULL;

  backend_uris = reverse_redis_perhost_get(p, redis, vhost_id, addr);
  if (backend_uris == NULL &&
      errno == ENOENT) {

    /* This can happen the very first time; perform an on-demand discovery
     * of the backends for this host, and try again.
     */
    pconn = reverse_redis_perhost_init(p, redis, vhost_id, redis_backends,
      addr);
    if (pconn == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error preparing PerHost Redis entries for host '%s': %s",
        pr_netaddr_get_ipstr(addr), strerror(errno));
      errno = EPERM;
      return NULL;
    }

  } else {
    char **vals;

    vals = backend_uris->elts;
    pconn = proxy_conn_create(p, vals[0], 0);
  }

  return pconn;
}

static int reverse_redis_perhost_used(pool *p, pr_redis_t *redis,
    unsigned int vhost_id, int backend_idx) {
  /* Nothing to do here. */
  return 0;
}

/* ProxyReverseServers API/handling */

static int reverse_redis_policy_init(pool *p, void *redis, int policy_id,
    unsigned int vhost_id, array_header *backends, unsigned long opts) {
  int res = 0, xerrno;

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      /* No preparation needed at this time. */
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
      if (backends != NULL) {
        res = reverse_redis_roundrobin_init(p, redis, vhost_id, backends);
        if (res < 0) {
          xerrno = errno;
          pr_log_debug(DEBUG3, MOD_PROXY_VERSION
            ": error preparing %s Redis entries: %s",
            proxy_reverse_policy_name(policy_id), strerror(xerrno));
          errno = xerrno;
        }
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      if (backends != NULL) {
        res = reverse_redis_shuffle_init(p, redis, vhost_id, backends);
        if (res < 0) {
          xerrno = errno;
          pr_log_debug(DEBUG3, MOD_PROXY_VERSION
            ": error preparing %s Redis entries: %s",
            proxy_reverse_policy_name(policy_id), strerror(xerrno));
          errno = xerrno;
        }
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      if (backends != NULL) {
        res = reverse_redis_leastconns_init(p, redis, vhost_id, backends);
        if (res < 0) {
          xerrno = errno;
          pr_log_debug(DEBUG3, MOD_PROXY_VERSION
            ": error preparing %s Redis entries: %s",
            proxy_reverse_policy_name(policy_id), strerror(xerrno));
          errno = xerrno;
        }
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      if (backends != NULL) {
        res = reverse_redis_leastresponsetime_init(p, redis, vhost_id,
          backends);
        if (res < 0) {
          xerrno = errno;
          pr_log_debug(DEBUG3, MOD_PROXY_VERSION
            ": error preparing %s Redis entries: %s",
            proxy_reverse_policy_name(policy_id), strerror(xerrno));
          errno = xerrno;
        }
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      if (!(opts & PROXY_OPT_USE_REVERSE_PROXY_AUTH)) {
        pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
          ": PerGroup ProxyReverseConnectPolicy requires the "
          "UseReverseProxyAuth ProxyOption");
        errno = EPERM;
        res = -1;
      }
      break;

    default:
      errno = EINVAL;
      res = -1;
      break;
  }

  return res;
}

static const struct proxy_conn *reverse_redis_policy_next_backend(pool *p,
    void *redis, int policy_id, unsigned int vhost_id,
    array_header *default_backends, const void *policy_data, int *backend_id) {
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns = NULL;
  int idx = -1, nelts = 0;

  if (redis_backends != NULL) {
    conns = redis_backends->elts;
    nelts = redis_backends->nelts;
  }

  if (proxy_reverse_policy_is_sticky(policy_id) != TRUE) {
    if (conns == NULL &&
        default_backends != NULL &&
        redis_backends == NULL) {
      conns = default_backends->elts;
      nelts = default_backends->nelts;
    }
  }

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
      idx = (int) proxy_random_next(0, nelts-1);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11, "%s policy: selected index %d of %u",
          proxy_reverse_policy_name(policy_id), idx, nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
      pconn = reverse_redis_roundrobin_next(p, redis, vhost_id);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn));
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      idx = (int) reverse_redis_shuffle_next(p, redis, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11, "%s policy: selected index %d of %u",
          proxy_reverse_policy_name(policy_id), idx, nelts-1);
        pconn = conns[idx];
      }
      break;

      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      pconn = reverse_redis_leastconns_next(p, redis, vhost_id);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn));
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      pconn = reverse_redis_leastresponsetime_next(p, redis, vhost_id);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn));
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      pconn = reverse_redis_peruser_next(p, redis, vhost_id, policy_data);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s' for user '%s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn),
          (const char *) policy_data);
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      pconn = reverse_redis_pergroup_next(p, redis, vhost_id, policy_data);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s' for user '%s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn),
          (const char *) policy_data);
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      pconn = reverse_redis_perhost_next(p, redis, vhost_id,
        session.c->remote_addr);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s' for host '%s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn),
          pr_netaddr_get_ipstr(session.c->remote_addr));
      }
      break;
 
    default:
      errno = ENOSYS;
      return NULL;
  }

  if (backend_id != NULL) {
    *backend_id = idx;
  }

  return pconn;
}

static int reverse_redis_policy_update_backend(pool *p, void *redis,
    int policy_id, unsigned vhost_id, int backend_idx, int conn_incr,
    long connect_ms) {
  int res = 0, xerrno = 0;

  /* If our ReverseConnectPolicy is one of PerUser, PerGroup, or PerHost,
   * we can skip this step: those policies do not use the connection count/time.
   * This also helps avoid contention under load for these policies.
   */
  if (proxy_reverse_policy_is_sticky(policy_id) == TRUE) {
    pr_trace_msg(trace_channel, 17,
      "sticky policy %s does not require updates, skipping",
      proxy_reverse_policy_name(policy_id));

    return 0;
  }

  /* TODO: Right now, we simply overwrite/track the very latest connect ms.
   * But this could unfairly skew policies such as LeastResponseTime, as when
   * the server in question had higher latency for that particular connection,
   * due to e.g. OCSP response cache expiration.
   *
   * Another way would to be average the given connect ms with the previous
   * one (if present), and store that.  Something to ponder for the future.
   */

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      res = reverse_redis_leastconns_update(p, redis, vhost_id, backend_idx,
        conn_incr, connect_ms);
      xerrno = errno;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      res = reverse_redis_leastresponsetime_update(p, redis, vhost_id,
        backend_idx, conn_incr, connect_ms);
      xerrno = errno;
      break;

    default:
      res = 0;
      break;
  }

  errno = xerrno;
  return res;
}

static int reverse_redis_policy_used_backend(pool *p, void *redis,
    int policy_id, unsigned int vhost_id, int backend_idx) {
  int res, xerrno = 0;

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
      res = 0;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
      res = reverse_redis_roundrobin_used(p, redis, vhost_id, backend_idx);
      xerrno = errno;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      res = reverse_redis_shuffle_used(p, redis, vhost_id, backend_idx);
      xerrno = errno;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      res = reverse_redis_leastconns_used(p, redis, vhost_id, backend_idx);
      xerrno = errno;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      res = reverse_redis_leastresponsetime_used(p, redis, vhost_id,
        backend_idx);
      xerrno = errno;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      res = reverse_redis_peruser_used(p, redis, vhost_id, backend_idx);
      xerrno = errno;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      res = reverse_redis_pergroup_used(p, redis, vhost_id, backend_idx);
      xerrno = errno;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      res = reverse_redis_perhost_used(p, redis, vhost_id, backend_idx);
      xerrno = errno;
      break;

    default:
      xerrno = ENOSYS;
      res = -1;
      break;
  }

  errno = xerrno;
  return res;
}

static void *reverse_redis_init(pool *p, const char *tables_path, int flags) {
  int xerrno = 0;
  pr_redis_t *redis;

  (void) tables_path;
  (void) flags;

  redis = pr_redis_conn_new(p, &proxy_module, 0);
  xerrno = errno;

  if (redis == NULL) {
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening Redis connection: %s", strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  (void) pr_redis_conn_set_namespace(redis, &proxy_module, redis_prefix,
    redis_prefixsz); 
  return redis;
}

static int reverse_redis_close(pool *p, void *redis) {
  if (redis != NULL) {
    if (pr_redis_conn_close(redis) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error closing Redis connection: %s", strerror(errno));
    }
  }

  return 0;
}

static void *reverse_redis_open(pool *p, const char *tables_path,
    array_header *backends) {
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
  redis_backends = backends;
  return redis;
}

int proxy_reverse_redis_as_datastore(struct proxy_reverse_datastore *ds,
    void *ds_data, size_t ds_datasz) {

  if (ds == NULL) {
    errno = EINVAL;
    return -1;
  }

  ds->policy_init = reverse_redis_policy_init;
  ds->policy_next_backend = reverse_redis_policy_next_backend;
  ds->policy_used_backend = reverse_redis_policy_used_backend;
  ds->policy_update_backend = reverse_redis_policy_update_backend;
  ds->init = reverse_redis_init;
  ds->open = reverse_redis_open;
  ds->close = reverse_redis_close;

  redis_prefix = ds_data;
  redis_prefixsz = ds_datasz;

  return 0;
}
