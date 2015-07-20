/*
 * ProFTPD - mod_proxy reverse proxy implementation
 * Copyright (c) 2012-2015 TJ Saunders
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

#include "proxy/db.h"
#include "proxy/conn.h"
#include "proxy/reverse.h"
#include "proxy/random.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/sess.h"

#include <sqlite3.h>

/* From response.c */
extern xaset_t *server_list;

static array_header *reverse_backends = NULL;
static int reverse_backend_id = -1;
static int reverse_connect_policy = PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;
static int reverse_retry_count = PROXY_DEFAULT_RETRY_COUNT;

static const char *trace_channel = "proxy.reverse";

/* Copied from src/table.c#key_hash. */
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

static int reverse_db_add_schema(pool *p, const char *db_path) {
  int res;
  const char *stmt, *errstr = NULL;

  /* CREATE TABLE proxy_vhosts (
   *   vhost_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_name TEXT NOT NULL
   * );
   */
  stmt = "CREATE TABLE proxy_vhosts (vhost_id INTEGER NOT NULL PRIMARY KEY, vhost_name TEXT NOT NULL);";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* TODO: Add these columns:
   *  unhealthy BOOLEAN,
   *  unhealthy_ms BIGINT,
   *  unhealthy_reason TEXT
   */

  /* CREATE TABLE proxy_vhost_backends (
   *   backend_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_id INTEGER NOT NULL,
   *   backend_uri TEXT NOT NULL,
   *   conn_count INTEGER NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE proxy_vhost_backends (backend_id INTEGER NOT NULL PRIMARY KEY, vhost_id INTEGER NOT NULL, backend_uri TEXT NOT NULL, conn_count INTEGER NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_hosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_vhost_reverse_roundrobin (
   *   vhost_id INTEGER NOT NULL,
   *   current_backend_id INTEGER NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id),
   *   FOREIGN KEY (current_backend_id) REFERENCES proxy_vhost_backends (backend_id)
   * );
   */
  stmt = "CREATE TABLE proxy_vhost_reverse_roundrobin (vhost_id INTEGER NOT NULL, current_backend_id INTEGER NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), FOREIGN KEY (current_backend_id) REFERENCES proxy_vhost_backends (backend_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_vhost_reverse_shuffle (
   *   vhost_id INTEGER NOT NULL,
   *   avail_backend_id INTEGER NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id),
   *   FOREIGN KEY (avail_backend_id) REFERENCES proxy_vhost_backends (backend_id)
   * );
   */
  stmt = "CREATE TABLE proxy_vhost_reverse_shuffle (vhost_id INTEGER NOT NULL, avail_backend_id INTEGER NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), FOREIGN KEY (avail_backend_id) REFERENCES proxy_vhost_backends (backend_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_vhost_reverse_per_user (
   *   vhost_id INTEGER NOT NULL,
   *   user TEXT NOT NULL PRIMARY KEY,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE proxy_vhost_reverse_per_user (vhost_id INTEGER NOT NULL, user TEXT NOT NULL PRIMARY KEY, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_vhost_reverse_per_host (
   *   vhost_id INTEGER NOT NULL,
   *   ip_addr TEXT NOT NULL PRIMARY KEY,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE proxy_vhost_reverse_per_host (vhost_id INTEGER NOT NULL, ip_addr TEXT NOT NULL PRIMARY KEY, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_add_vhost(pool *p, server_rec *s) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhosts (vhost_id, vhost_name) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &(s->sid));
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) s->ServerName);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_add_backend(pool *p, unsigned int vhost_id,
    const char *backend_uri, int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhost_backends (vhost_id, backend_uri, backend_id, conn_count) VALUES (?, ?, ?, 0);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) backend_uri);
  if (res < 0) {
    return -1;
  }
  pr_trace_msg(trace_channel, 13,
    "adding backend '%.100s' to database table at index %d", backend_uri,
    backend_id);

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_add_backends(pool *p, unsigned int vhost_id,
    array_header *backends) {
  register unsigned int i;

  for (i = 0; i < backends->nelts; i++) {
    int res;
    struct proxy_conn *pconn;
    const char *backend_uri;

    pconn = ((struct proxy_conn **) backends->elts)[i];
    backend_uri = proxy_conn_get_uri(pconn);

    res = reverse_db_add_backend(p, vhost_id, backend_uri, i);
    if (res < 0) {
      int xerrno = errno;
      pr_trace_msg(trace_channel, 6,
        "error adding database entry for backend '%.100s': %s", backend_uri,
        strerror(xerrno));
      errno = xerrno;
      return -1;
    }
  }

  return 0;
}

static int reverse_db_update_backend(pool *p, unsigned vhost_id,
    int backend_id, int conn_incr, unsigned long response_ms) {
  /* Increment the conn count for this backend ID. */
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* TODO: Use/store the response_ms. */

  stmt = "UPDATE proxy_vhost_backends SET conn_count = conn_count + ? WHERE vhost_id = ? AND backend_id = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &conn_incr);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 3, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

/* ProxyReverseConnectPolicy: Shuffle */

static int reverse_db_add_shuffle(pool *p, unsigned int vhost_id,
    int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhost_reverse_shuffle (vhost_id, avail_backend_id) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_shuffle_init(pool *p, unsigned int vhost_id,
    array_header *backends) {
  register unsigned int i;

  for (i = 0; i < backends->nelts; i++) {
    int res;

    res = reverse_db_add_shuffle(p, vhost_id, i);
    if (res < 0) {
      int xerrno = errno;
      pr_trace_msg(trace_channel, 6,
        "error adding shuffle database entry for ID %d: %s", i,
        strerror(xerrno));
      errno = xerrno;
      return -1;
    }
  }

  return 0;
}

static int reverse_db_shuffle_next(pool *p, unsigned int vhost_id) {
  int backend_id = -1, res;
  const char *stmt, *errstr = NULL;
  array_header *results;
  unsigned int nrows = 0;

  stmt = "SELECT COUNT(*) FROM proxy_vhost_reverse_shuffle WHERE vhost_id = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  if (results->nelts != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "expected 1 result from statement '%s', got %d", stmt,
      results->nelts);
    errno = EINVAL;
    return -1;
  }

  nrows = atoi(((char **) results->elts)[0]);
  if (nrows == 0) {
    res = reverse_db_shuffle_init(p, vhost_id, reverse_backends);
    if (res < 0) {
      return -1;
    }

    nrows = reverse_backends->nelts;
  }

  backend_id = (int) proxy_random_next(0, nrows-1);
  return backend_id;
}

static int reverse_db_shuffle_used(pool *p, unsigned int vhost_id,
    int backend_id) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "DELETE FROM proxy_vhost_reverse_shuffle WHERE vhost_id = ? AND avail_backend_id = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

/* ProxyReverseConnectPolicy: RoundRobin */

static int reverse_db_roundrobin_update(pool *p, unsigned int vhost_id,
    int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "UPDATE proxy_vhost_reverse_roundrobin SET current_backend_id = ? WHERE vhost_id = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_roundrobin_init(pool *p, unsigned int vhost_id,
    int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhost_reverse_roundrobin (vhost_id, current_backend_id) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_roundrobin_next(pool *p, unsigned int vhost_id) {
  int backend_id = 0, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT current_backend_id FROM proxy_vhost_reverse_roundrobin WHERE vhost_id = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  if (results->nelts != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "expected 1 result from statement '%s', got %d", stmt,
      results->nelts);
    errno = EINVAL;
    return -1;
  }

  backend_id = atoi(((char **) results->elts)[0]);

  /* If the current backend ID is the last one, wrap around to index 0. */
  if (backend_id == reverse_backends->nelts-1) {
    backend_id = 0;

  } else {
    backend_id++;
  }

  return backend_id;
}

static int reverse_db_roundrobin_used(pool *p, unsigned int vhost_id,
    int backend_id) {
  return reverse_db_roundrobin_update(p, vhost_id, backend_id);
}

/* ProxyReverseConnectPolicy: LeastConns */

static int reverse_db_leastconns_next(pool *p, unsigned int vhost_id) {
  int backend_id = 0, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_id FROM proxy_vhost_backends WHERE vhost_id = ? ORDER BY conn_count ASC LIMIT 1;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  if (results->nelts == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "expected results from statement '%s', got %d", stmt,
      results->nelts);
    errno = EINVAL;
    return -1;
  }

  /* Just pick the first index/backend returned. */
  backend_id = atoi(((char **) results->elts)[0]);
  return backend_id;
}

static int reverse_db_leastconns_used(pool *p, unsigned int vhost_id,
    int backend_id) {
  /* TODO: anything to do here? */
  return 0;
}

/* ProxyReverseConnectPolicy: PerUser */

static array_header *reverse_db_peruser_get(pool *p, unsigned int vhost_id,
    const char *user) {
  int res;
  const char *stmt, *errstr = NULL, *ip;
  array_header *results;

  stmt = "SELECT backend_uri FROM proxy_vhost_reverse_per_user WHERE vhost_id = ? AND user = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT, (void *) user);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return results;
}

static struct proxy_conn *reverse_db_peruser_init(pool *p,
    unsigned int vhost_id, const char *user) {

/* XXX load the list of backends for this user: from SQL, from file, etc.
 * Randomly choose one, use it.
 *
 * Support %U (user) in file:// URIs, SQL queries?
 *
 * If no user-specific backends are found, use the existing ones!
 */

  struct proxy_conn **conns, *pconn = NULL;
  int res;
  const char *stmt, *uri, *errstr = NULL;
  array_header *results;

  conns = reverse_backends->elts;

  if (reverse_backends->nelts == 1) {
    pconn = conns[0];

  } else {
    size_t user_len;
    unsigned int h;
    int idx;

    user_len = strlen(user);
    h = str2hash(user, user_len);
    idx = h % reverse_backends->nelts;

    pconn = conns[idx];
  }

  stmt = "INSERT INTO proxy_vhost_reverse_per_user (vhost_id, user, backend_uri) VALUES (?, ?, ?);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT, (void *) user);
  if (res < 0) {
    return NULL;
  }

  uri = proxy_conn_get_uri(pconn);
  res = proxy_db_bind_stmt(p, stmt, 3, PROXY_DB_BIND_TYPE_TEXT, (void *) uri);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return pconn;
}

static struct proxy_conn *reverse_db_peruser_next(pool *p,
    unsigned int vhost_id, const char *user) {
  array_header *results;
  struct proxy_conn *pconn = NULL;

  results = reverse_db_peruser_get(p, vhost_id, user);
  if (results == NULL) {
    return NULL;
  }

  if (results->nelts == 0) {
    /* This can happen the very first time; perform an on-demand discovery
     * of the backends for this user, and try again.
     */
 
    pconn = reverse_db_peruser_init(p, vhost_id, user);
    if (pconn == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error preparing database for ProxyReverseConnectPolicy "
        "PerUser for user '%s': %s", user, strerror(errno));
      errno = EPERM;
      return NULL;
    }

  } else {
    char **vals;

    vals = results->elts;
    pconn = proxy_conn_create(p, vals[0]);
  }

  return pconn;
}

static int reverse_db_peruser_used(pool *p, unsigned int vhost_id,
    int backend_id) {
  /* TODO: anything to do here? */
  return 0;
}

/* ProxyReverseConnectPolicy: PerHost */

static array_header *reverse_db_perhost_get(pool *p, unsigned int vhost_id,
    pr_netaddr_t *addr) {
  int res;
  const char *stmt, *errstr = NULL, *ip;
  array_header *results;

  stmt = "SELECT backend_uri FROM proxy_vhost_reverse_per_host WHERE vhost_id = ? AND ip_addr = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return NULL;
  }

  ip = pr_netaddr_get_ipstr(addr);
  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT, (void *) ip);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return results;
}

static struct proxy_conn *reverse_db_perhost_init(pool *p,
    unsigned int vhost_id, pr_netaddr_t *addr) {
  struct proxy_conn **conns, *pconn = NULL;
  int res;
  const char *ip, *stmt, *uri, *errstr = NULL;
  array_header *results;

  ip = pr_netaddr_get_ipstr(addr);
  conns = reverse_backends->elts;

  if (reverse_backends->nelts == 1) {
    pconn = conns[0];

  } else {
    size_t ip_len;
    unsigned int h;
    int idx;

    ip_len = strlen(ip);
    h = str2hash(ip, ip_len);
    idx = h % reverse_backends->nelts;

    pconn = conns[idx];
  }

  stmt = "INSERT INTO proxy_vhost_reverse_per_host (vhost_id, ip_addr, backend_uri) VALUES (?, ?, ?);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT, (void *) ip);
  if (res < 0) {
    return NULL;
  }

  uri = proxy_conn_get_uri(pconn);
  res = proxy_db_bind_stmt(p, stmt, 3, PROXY_DB_BIND_TYPE_TEXT, (void *) uri);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return pconn;
}

static struct proxy_conn *reverse_db_perhost_next(pool *p,
    unsigned int vhost_id, pr_netaddr_t *addr) {
  array_header *results;
  struct proxy_conn *pconn = NULL;

  results = reverse_db_perhost_get(p, vhost_id, addr);
  if (results == NULL) {
    return NULL;
  }

  if (results->nelts == 0) {
    /* This can happen the very first time; perform an on-demand discovery
     * of the backends for this host, and try again.
     */
 
    pconn = reverse_db_perhost_init(p, vhost_id, addr);
    if (pconn == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error preparing database for ProxyReverseConnectPolicy "
        "PerHost for host '%s': %s", pr_netaddr_get_ipstr(addr),
        strerror(errno));
      errno = EPERM;
      return NULL;
    }

  } else {
    char **vals;

    vals = results->elts;
    pconn = proxy_conn_create(p, vals[0]);
  }

  return pconn;
}

static int reverse_db_perhost_used(pool *p, unsigned int vhost_id,
    int backend_id) {
  /* TODO: anything to do here? */
  return 0;
}

/* ProxyReverseServers API/handling */

int proxy_reverse_init(pool *p, const char *tables_dir) {
  int res, xerrno = 0;
  server_rec *s;
  char *db_path;

  if (p == NULL ||
      tables_dir == NULL) {
    errno = EINVAL;
    return -1;
  }

  db_path = pdircat(p, tables_dir, "proxy.db", NULL);
  if (file_exists(db_path)) {
    pr_log_debug(DEBUG9, MOD_PROXY_VERSION
      ": deleting existing database file '%s'", db_path);
    if (unlink(db_path) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
        ": error deleting '%s': %s", db_path, strerror(errno));
    }
  }

  res = proxy_db_open(p, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening database '%s': %s", db_path, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = reverse_db_add_schema(p, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error adding schema to database '%s': %s", db_path, strerror(xerrno));
    (void) proxy_db_close(p);
    errno = xerrno;
    return -1;
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    config_rec *c;

    c = find_config(s->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
    if (c != NULL) {
      array_header *backends;

      res = reverse_db_add_vhost(p, s);
      if (res < 0) {
        xerrno = errno;
        (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
          ": error adding database entry for server '%s': %s", s->ServerName,
          strerror(xerrno));
        (void) proxy_db_close(p);
        errno = xerrno;
        return -1;
      }

      backends = c->argv[0];

      res = reverse_db_add_backends(p, s->sid, backends);
      if (res < 0) {
        xerrno = errno;
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error adding database entries for ProxyReverseServers: %s",
          strerror(xerrno));
        errno = xerrno;
        return -1;
      }

      c = find_config(s->conf, CONF_PARAM, "ProxyReverseConnectPolicy", FALSE);
      if (c != NULL) {
        int connect_policy;

        connect_policy = *((int *) c->argv[0]);
        switch (connect_policy) {
          case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
          case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
          case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
          case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
            /* No preparation needed at this time. */
            break;

          case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
            res = reverse_db_roundrobin_init(p, s->sid, backends->nelts-1);
            if (res < 0) {
              xerrno = errno;
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "error preparing database for ProxyReverseConnectPolicy "
                "RoundRobin: %s", strerror(xerrno));
            }
            break;

          case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
            res = reverse_db_shuffle_init(p, s->sid, backends);
            if (res < 0) {
              xerrno = errno;
              (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
                "error preparing database for ProxyReverseConnectPolicy "
                "Shuffle: %s", strerror(xerrno));
            }
            break;

          default:
            break;
        }
      }
    }
  }

  return 0;
}

int proxy_reverse_free(pool *p) {
  /* TODO: Implement any necessary cleanup */
  return 0;
}

int proxy_reverse_sess_exit(pool *p) {
  if (reverse_backends != NULL &&
      reverse_backend_id >= 0) {
    int res;

    res = reverse_db_update_backend(p, main_server->sid, reverse_backend_id,
      -1, 0);
    if (res < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error updating backend ID %d: %s", reverse_backend_id,
        strerror(errno));
    }
  }

  return 0;
}

int proxy_reverse_sess_init(pool *p, const char *tables_dir) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyRetryCount", FALSE);
  if (c != NULL) {
    reverse_retry_count = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers",
    FALSE);
  if (c == NULL) {
    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "'ProxyRole reverse' in effect, but no ProxyReverseServers configured");
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": 'ProxyRole reverse' in effect, but no ProxyReverseServers configured");
    errno = EPERM;
    return -1;
  }

  reverse_backends = c->argv[0];

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseConnectPolicy",
    FALSE);
  if (c != NULL) {
    reverse_connect_policy = *((int *) c->argv[0]);
  }

  return 0;
}

int proxy_reverse_have_authenticated(cmd_rec *cmd) {
  int authd = FALSE;

  /* Authenticated here means authenticated *to the proxy*, i.e. should we
   * allow more commands, or reject them because the client hasn't authenticated
   * yet.
   */

  if (proxy_sess_state & PROXY_SESS_STATE_BACKEND_AUTHENTICATED) {
    authd = TRUE;
  }

  if (authd == FALSE) {
    pr_response_send(R_530, _("Please login with USER and PASS"));
  }

  return authd;
}

static int check_parent_dir_perms(pool *p, const char *path) {
  struct stat st;
  int res;
  char *dir_path, *ptr = NULL;

  ptr = strrchr(path, '/');
  if (ptr != path) {
    dir_path = pstrndup(p, path, ptr - path);

  } else {
    dir_path = "/";
  }

  res = stat(dir_path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to stat ProxyReverseServers %s directory '%s': %s",
      path, dir_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (st.st_mode & S_IWOTH) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use ProxyReverseServers %s from world-writable "
      "directory '%s' (perms %04o): %s", path, dir_path,
      st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int check_file_perms(pool *p, const char *path) {
  struct stat st;
  int res;
  const char *orig_path;

  orig_path = path;

  res = lstat(path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to lstat ProxyReverseServers '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (S_ISLNK(st.st_mode)) {
    char buf[PR_TUNABLE_PATH_MAX+1];

    /* Check the permissions on the parent directory; if they're world-writable,
     * then this symlink can be deleted/pointed somewhere else.
     */
    res = check_parent_dir_perms(p, path);
    if (res < 0) {
      return -1;
    }

    /* Follow the link to the target path; that path will then have its
     * parent directory checked.
     */
    memset(buf, '\0', sizeof(buf));
    res = readlink(path, buf, sizeof(buf)-1);
    if (res > 0) {
      path = pstrdup(p, buf);
    }

    res = stat(orig_path, &st);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": unable to stat ProxyReverseServers '%s': %s", orig_path,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  if (S_ISDIR(st.st_mode)) {
    int xerrno = EISDIR;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use ProxyReverseServers '%s': %s", orig_path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* World-writable files are insecure, and are thus not usable/trusted. */
  if (st.st_mode & S_IWOTH) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use world-writable ProxyReverseServers '%s' "
      "(perms %04o): %s", orig_path, st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* TODO: This will warn about files such as FIFOs, BUT will leave them
   * usable.  Good idea, or bad idea?
   */
  if (!S_ISREG(st.st_mode)) {
    pr_log_pri(PR_LOG_WARNING, MOD_PROXY_VERSION
      ": ProxyReverseServers '%s' is not a regular file", orig_path);
  }

  /* Check the parent directory of this file.  If the parent directory
   * is world-writable, that too is insecure.
   */
  res = check_parent_dir_perms(p, path);
  if (res < 0) {
    return -1;
  }

  return 0;
}

array_header *proxy_reverse_file_parse_uris(pool *p, const char *path) {
  int res;
  char buf[PR_TUNABLE_BUFFER_SIZE+1];
  pr_fh_t *fh;
  unsigned int lineno = 0;
  array_header *uris = NULL;
  struct stat st;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*path != '/') {
    /* A relative path?  Unacceptable. */
    errno = EINVAL;
    return NULL;
  }

  res = check_file_perms(p, path);
  if (res < 0) {
    return NULL;
  }

  /* Use a nonblocking open() for the path; it could be a FIFO, and we don't
   * want to block forever if the other end of the FIFO is not running.
   */
  fh = pr_fsio_open(path, O_RDONLY|O_NONBLOCK);
  if (fh == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7,
      "error opening ProxyReverseServers file '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  pr_fsio_set_block(fh);

  /* Stat the file to find the optimal buffer size for reading. */
  res = pr_fsio_fstat(fh, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "unable to fstat '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  fh->fh_iosz = st.st_blksize;

  memset(buf, '\0', sizeof(buf));
  uris = make_array(p, 1, sizeof(struct proxy_conn *));

  while ((pr_fsio_getline(buf, sizeof(buf)-1, fh, &lineno) != NULL)) {
    int have_eol = FALSE;
    char *bufp = NULL;
    size_t buflen;
    struct proxy_conn *pconn;

    pr_signals_handle();

    buflen = strlen(buf);

    /* Trim off the trailing newline, if present. */
    if (buflen &&
        buf[buflen - 1] == '\n') {
      have_eol = TRUE;
      buf[buflen-1] = '\0';
      buflen--;
    }

    while (buflen &&
           buf[buflen - 1] == '\r') {
      pr_signals_handle();
      buf[buflen-1] = '\0';
      buflen--;
    }

    if (!have_eol) {
      pr_trace_msg(trace_channel, 3,
        "warning: skipping possibly truncated ProxyReverseServers data (%s:%u)",
        path, lineno);
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    /* Advance past any leading whitespace. */
    for (bufp = buf; *bufp && PR_ISSPACE(*bufp); bufp++);

    /* Check for commented or blank lines at this point, and just continue on
     * to the next configuration line if found.
     */
    if (*bufp == '#' || !*bufp) {
      pr_trace_msg(trace_channel, 9,
        "skipping commented/empty line (%s:%u)", path, lineno);
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    pconn = proxy_conn_create(p, bufp);
    if (pconn == NULL) {
      pr_trace_msg(trace_channel, 9,
        "skipping malformed URL '%s' (%s:%u)", bufp, path, lineno);
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    *((struct proxy_conn **) push_array(uris)) = pconn; 
    memset(buf, '\0', sizeof(buf));
  }

  (void) pr_fsio_close(fh);
  return uris;
}

int proxy_reverse_connect_get_policy(const char *policy) {
  if (policy == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (strncasecmp(policy, "Random", 7) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_RANDOM;

  } else if (strncasecmp(policy, "RoundRobin", 11) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;

  } else if (strncasecmp(policy, "Shuffle", 8) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_SHUFFLE;

  } else if (strncasecmp(policy, "LeastConns", 11) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS;

  } else if (strncasecmp(policy, "PerUser", 8) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_USER;

  } else if (strncasecmp(policy, "PerHost", 8) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_HOST;

#if 0
  } else if (strncasecmp(policy, "PerTLS", 7) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_TLS;

  } else if (strncasecmp(policy, "LowestResponseTime", 19) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_LOWEST_RESPONSE_TIME;
#endif
  }

  errno = ENOENT;
  return -1;
}

static struct proxy_conn *reverse_connect_next_backend(pool *p,
    unsigned int vhost_id, void *policy_data) {
  struct proxy_conn **conns, *pconn = NULL;
  int idx = -1;

  conns = reverse_backends->elts;

  if (reverse_backends->nelts == 1) {
    reverse_backend_id = 0;
    return conns[0];
  }

  switch (reverse_connect_policy) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
      idx = (int) proxy_random_next(0, reverse_backends->nelts-1);      
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11,
          "RANDOM policy: selected index %d of %u", idx,
          reverse_backends->nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
      idx = reverse_db_roundrobin_next(p, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11,
          "ROUND_ROBIN policy: selected index %d of %u", idx,
          reverse_backends->nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      idx = reverse_db_shuffle_next(p, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11,
          "SHUFFLE policy: selected index %d of %u", idx,
          reverse_backends->nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      idx = reverse_db_leastconns_next(p, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11,
          "LEAST_CONNS policy: selected index %d of %u", idx,
          reverse_backends->nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      pconn = reverse_db_peruser_next(p, vhost_id, policy_data);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "PER_USER policy: selected backend '%.100s' for user '%s'",
          proxy_conn_get_uri(pconn), (const char *) policy_data);
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      pconn = reverse_db_perhost_next(p, vhost_id, session.c->remote_addr);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "PER_HOST policy: selected backend '%.100s' for host '%s'",
          proxy_conn_get_uri(pconn),
          pr_netaddr_get_ipstr(session.c->remote_addr));
      }
      break;
 
    default:
      errno = ENOSYS;
      return NULL;
  }

  if (idx >= 0) {
    reverse_backend_id = idx;
  }

  return pconn;
}

static int reverse_connect_index_used(pool *p, unsigned int vhost_id,
    int idx, unsigned long response_ms) {
  int res;

  if (reverse_backends->nelts == 1) {
    return 0;
  }

  res = reverse_db_update_backend(p, vhost_id, idx, 1, response_ms);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error updating database entry for backend ID %d: %s", idx,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  switch (reverse_connect_policy) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
      res = 0;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
      res = reverse_db_roundrobin_used(p, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      res = reverse_db_shuffle_used(p, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      res = reverse_db_leastconns_used(p, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      res = reverse_db_peruser_used(p, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      res = reverse_db_perhost_used(p, vhost_id, idx);
      break;

    default:
      errno = ENOSYS;
      return -1;
  }

  if (res < 0) {
    int xerrno = errno;

    errno = xerrno;
    return -1;
  }

  return 0;
}

static pr_netaddr_t *get_reverse_server_addr(pool *p,
    struct proxy_session *proxy_sess, int *backend_id, void *policy_data,
    array_header **other_addrs) {
  struct proxy_conn *pconn;
  pr_netaddr_t *addr;

  pconn = reverse_connect_next_backend(p, main_server->sid, policy_data);
  if (pconn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error selecting backend server: %s", strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "selected backend server '%s'", proxy_conn_get_uri(pconn));

  *backend_id = reverse_backend_id;

  addr = proxy_conn_get_addr(pconn, other_addrs);
  return addr;
}

static int reverse_connect(pool *p, struct proxy_session *proxy_sess,
    void *connect_data) {
  int backend_id = -1;
  conn_t *server_conn = NULL;
  pr_response_t *resp = NULL;
  unsigned int resp_nlines = 0;
  pr_netaddr_t *dst_addr;
  array_header *other_addrs = NULL;
  uint64_t connecting_ms, connected_ms;

  dst_addr = get_reverse_server_addr(p, proxy_sess, &backend_id, connect_data,
    &other_addrs);
  if (dst_addr == NULL) {
    return -1;
  }

  proxy_sess->dst_addr = dst_addr;
  proxy_sess->other_addrs = other_addrs;

  pr_gettimeofday_millis(&connecting_ms);
  server_conn = proxy_conn_get_server_conn(p, proxy_sess, dst_addr);
  if (server_conn == NULL) {
    int xerrno = errno;

    if (other_addrs != NULL) {
      register unsigned int i;

      /* Try the other IP addresses for the configured name (if any) as well. */
      for (i = 0; i < other_addrs->nelts; i++) {
        dst_addr = ((pr_netaddr_t **) other_addrs->elts)[i];

        pr_gettimeofday_millis(&connecting_ms);

        pr_trace_msg(trace_channel, 8,
          "attempting to connect to other address #%u (%s) for requested "
          "URI '%.100s'", i+1, pr_netaddr_get_ipstr(dst_addr),
          proxy_conn_get_uri(proxy_sess->dst_pconn));
        server_conn = proxy_conn_get_server_conn(p, proxy_sess, dst_addr);
        if (server_conn != NULL) {
          proxy_sess->dst_addr = dst_addr;
          break;
        }
      }
    }

    if (server_conn == NULL) {
      xerrno = errno;

      /* TODO: Under what errno values will we mark this backend/idx as
       * "unhealthy"?  When we do, how will that unhealthy flag be taken into
       * account with the existing queries?  JOIN the index on the backend table
       * to get that unhealthy flag?
       */

      if (reverse_connect_index_used(p, main_server->sid, backend_id, 0) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error updating database for backend server index %d: %s", backend_id,
          strerror(xerrno));
      }
    }
 
    errno = xerrno;
    return -1;
  }

  if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
    if (proxy_conn_send_proxy(p, server_conn) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error sending PROXY message to %s#%u: %s",
        pr_netaddr_get_ipstr(server_conn->remote_addr),
        ntohs(pr_netaddr_get_port(server_conn->remote_addr)),
        strerror(errno));
    }
  }

  /* XXX Support/send a CLNT command of our own?  Configurable via e.g.
   * "UserAgent" string?
   */

  proxy_sess->frontend_ctrl_conn = session.c;
  proxy_sess->backend_ctrl_conn = server_conn;

  /* Read the response from the backend server and send it to the connected
   * client as if it were our own banner.
   */
  resp = proxy_ftp_ctrl_recv_resp(p, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    int xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
      strerror(xerrno));

    errno = xerrno;
    return -1;

  } else {
    int banner_ok = TRUE;

    pr_gettimeofday_millis(&connected_ms);

    if (resp->num[0] != '2') {
      banner_ok = FALSE;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "received banner from backend %s:%u%s: %s %s",
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr),
      ntohs(pr_netaddr_get_port(proxy_sess->backend_ctrl_conn->remote_addr)),
      banner_ok ? "" : ", DISCONNECTING", resp->num, resp->msg);

    if (proxy_ftp_ctrl_send_resp(p, session.c, resp, resp_nlines) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to send banner to client: %s", strerror(errno));
    }

    if (banner_ok == FALSE) {
      pr_inet_close(p, proxy_sess->backend_ctrl_conn);
      proxy_sess->backend_ctrl_conn = NULL;
      return -1;
    }
  }

  if (reverse_connect_index_used(p, main_server->sid, backend_id,
    (unsigned long) connected_ms - connecting_ms) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error updating database for backend server index %d: %s", backend_id,
      strerror(errno));
  }

  /* Get the features supported by the backend server */
  if (proxy_ftp_sess_get_feat(p, proxy_sess) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to determine features of backend server: %s", strerror(errno));
  }

  (void) proxy_ftp_sess_send_host(p, proxy_sess);

  proxy_sess_state |= PROXY_SESS_STATE_CONNECTED;
  pr_response_block(TRUE);

  return 0;
}

int proxy_reverse_connect(pool *p, struct proxy_session *proxy_sess) {
  register unsigned int i;
  int res;

  /* If the ConnectPolicy is one of a subset of sticky policies, then the
   * actual backend server selection/connection is deferred; see
   * proxy_reverse_handle_user().
   */
  if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_USER) {
    return 0;
  }

  for (i = 0; i < reverse_retry_count; i++) {
    pr_signals_handle();

    res = reverse_connect(p, proxy_sess, NULL);
    if (res == 0) {
      return 0;
    }
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "ProxyRetryCount %d reached with no successful connection, failing",
    reverse_retry_count);
  errno = EPERM;
  return -1;
}

int proxy_reverse_handle_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_USER) {
    register unsigned int i;
    int connected = FALSE;

    for (i = 0; i < reverse_retry_count; i++) {
      pr_signals_handle();

      res = reverse_connect(proxy_pool, proxy_sess, cmd->arg);
      if (res == 0) {
        connected = TRUE;
        break;
      }
    }

    if (!connected) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "ProxyRetryCount %d reached with no successful connection, failing",
        reverse_retry_count);
      *successful = FALSE;
      errno = EPERM;
      return -1;
    }
  }

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", cmd->argv[0], strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (resp->num[0] == '2' ||
      resp->num[0] == '3') {
    *successful = TRUE;
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return -1;
  }

  return 1;
}

int proxy_reverse_handle_pass(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", cmd->argv[0], strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* XXX What about other response codes for PASS? */
  if (resp->num[0] == '2') {
    *successful = TRUE;

    proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
    pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE); 
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return -1;
  }

  return 1;
}
