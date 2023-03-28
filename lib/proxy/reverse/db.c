/*
 * ProFTPD - mod_proxy reverse datastore implementation
 * Copyright (c) 2012-2021 TJ Saunders
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
#include "proxy/reverse/db.h"
#include "proxy/random.h"
#include "proxy/tls.h"
#include "proxy/ftp/ctrl.h"

#include <sqlite3.h>

extern xaset_t *server_list;

#define PROXY_REVERSE_DB_SCHEMA_NAME		"proxy_reverse"
#define PROXY_REVERSE_DB_SCHEMA_VERSION		6

/* PerHost/PerUser/PerGroup table limits */
#define PROXY_REVERSE_DB_PERHOST_MAX_ENTRIES		8192
#define PROXY_REVERSE_DB_PERUSER_MAX_ENTRIES		8192
#define PROXY_REVERSE_DB_PERGROUP_MAX_ENTRIES		8192

static array_header *db_backends = NULL;

static const char *trace_channel = "proxy.reverse.db";

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

static int reverse_db_add_schema(pool *p, struct proxy_dbh *dbh,
    const char *db_path) {
  int res;
  const char *stmt, *errstr = NULL;

  /* CREATE TABLE proxy_vhosts (
   *   vhost_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_name TEXT NOT NULL
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_vhosts (vhost_id INTEGER NOT NULL PRIMARY KEY, vhost_name TEXT NOT NULL);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
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
   *   vhost_id INTEGER NOT NULL,
   *   backend_id INTEGER NOT NULL,
   *   backend_uri TEXT NOT NULL,
   *   conn_count INTEGER NOT NULL,
   *   connect_ms INTEGER
   * );
   *
   * Note: while it might be tempting to have a FOREIGN KEY constraint on
   * vhost_id to the proxy_vhosts.vhost_id column, doing so also means that
   * vhost_id MUST be unique.  And there will be vhosts that have MULTIPLE
   * backend URIs, which would violate that uniqueness constraint.  Thus we
   * create our own separate index on the vhost_id column.
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_vhost_backends (vhost_id INTEGER NOT NULL, backend_id INTEGER NOT NULL, backend_uri TEXT NOT NULL, conn_count INTEGER NOT NULL, connect_ms INTEGER);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE INDEX proxy_vhost_backends_vhost_id_idx */
  stmt = "CREATE INDEX IF NOT EXISTS proxy_vhost_backends_vhost_id_idx ON proxy_vhost_backends (vhost_id);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
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
  stmt = "CREATE TABLE IF NOT EXISTS proxy_vhost_reverse_roundrobin (vhost_id INTEGER NOT NULL, current_backend_id INTEGER NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), FOREIGN KEY (current_backend_id) REFERENCES proxy_vhost_backends (backend_id));";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
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
  stmt = "CREATE TABLE IF NOT EXISTS proxy_vhost_reverse_shuffle (vhost_id INTEGER NOT NULL, avail_backend_id INTEGER NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), FOREIGN KEY (avail_backend_id) REFERENCES proxy_vhost_backends (backend_id));";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_vhost_reverse_per_user (
   *   vhost_id INTEGER NOT NULL,
   *   user_name TEXT NOT NULL,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id),
   *   UNIQUE (vhost_id, user_name)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_vhost_reverse_per_user (vhost_id INTEGER NOT NULL, user_name TEXT NOT NULL, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), UNIQUE (vhost_id, user_name));";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE INDEX proxy_vhost_reverse_per_user_name_idx */
  stmt = "CREATE INDEX IF NOT EXISTS proxy_vhost_reverse_per_user_name_idx ON proxy_vhost_reverse_per_user (user_name);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_vhost_reverse_per_group (
   *   vhost_id INTEGER NOT NULL,
   *   group_name TEXT NOT NULL,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id),
   *   UNIQUE (vhost_id, group_name)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_vhost_reverse_per_group (vhost_id INTEGER NOT NULL, group_name TEXT NOT NULL, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), UNIQUE (vhost_id, group_name));";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE INDEX proxy_vhost_reverse_per_group_name_idx */
  stmt = "CREATE INDEX IF NOT EXISTS proxy_vhost_reverse_per_group_name_idx ON proxy_vhost_reverse_per_group (group_name);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_vhost_reverse_per_host (
   *   vhost_id INTEGER NOT NULL,
   *   ip_addr TEXT NOT NULL,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id),
   *   UNIQUE (vhost_id, ip_addr)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_vhost_reverse_per_host (vhost_id INTEGER NOT NULL, ip_addr TEXT NOT NULL, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), UNIQUE (vhost_id, ip_addr));";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE INDEX proxy_vhost_reverse_per_host_ipaddr_idx */
  stmt = "CREATE INDEX IF NOT EXISTS proxy_vhost_reverse_per_host_ipaddr_idx ON proxy_vhost_reverse_per_host (ip_addr);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_truncate_tables(pool *p, struct proxy_dbh *dbh) {
  int res;
  const char *index_name, *stmt, *errstr = NULL;

  stmt = "DELETE FROM proxy_vhosts;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM proxy_vhost_backends;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM proxy_vhost_reverse_roundrobin;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM proxy_vhost_reverse_shuffle;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM proxy_vhost_reverse_per_user;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM proxy_vhost_reverse_per_group;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM proxy_vhost_reverse_per_host;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* Note: don't forget to rebuild the indices, too! */

  index_name = "proxy_vhost_backends_vhost_id_idx";
  res = proxy_db_reindex(p, dbh, index_name, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error reindexing '%s': %s", index_name, errstr);
    errno = EPERM;
    return -1;
  }

  index_name = "proxy_vhost_reverse_per_user_name_idx";
  res = proxy_db_reindex(p, dbh, index_name, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error reindexing '%s': %s", index_name, errstr);
    errno = EPERM;
    return -1;
  }

  index_name = "proxy_vhost_reverse_per_group_name_idx";
  res = proxy_db_reindex(p, dbh, index_name, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error reindexing '%s': %s", index_name, errstr);
    errno = EPERM;
    return -1;
  }

  index_name = "proxy_vhost_reverse_per_host_ipaddr_idx";
  res = proxy_db_reindex(p, dbh, index_name, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error reindexing '%s': %s", index_name, errstr);
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_add_vhost(pool *p, struct proxy_dbh *dbh, server_rec *s) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhosts (vhost_id, vhost_name) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &(s->sid), 0);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) s->ServerName, -1);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_add_backend(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, const char *backend_uri, int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhost_backends (vhost_id, backend_uri, backend_id, conn_count) VALUES (?, ?, ?, 0);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) backend_uri, -1);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 3, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id, 0);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 13,
    "adding backend '%.100s' to database table at index %d", backend_uri,
    backend_id);

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_add_backends(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, array_header *backends) {
  register unsigned int i;

  for (i = 0; i < backends->nelts; i++) {
    int res;
    struct proxy_conn *pconn;
    const char *backend_uri;

    pconn = ((struct proxy_conn **) backends->elts)[i];
    backend_uri = proxy_conn_get_uri(pconn);

    res = reverse_db_add_backend(p, dbh, vhost_id, backend_uri, i);
    if (res < 0) {
      int xerrno = errno;
      pr_trace_msg(trace_channel, 6,
        "error adding database entry for backend '%.100s': %s", backend_uri,
        strerror(xerrno));
      errno = xerrno;
      return -1;
    }

    pr_trace_msg(trace_channel, 18,
      "added database entry for backend '%.100s' (ID %u)", backend_uri, i);
  }

  return 0;
}

/* ProxyReverseConnectPolicy: Shuffle */

static int reverse_db_add_shuffle(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhost_reverse_shuffle (vhost_id, avail_backend_id) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_shuffle_init(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, array_header *backends) {
  register unsigned int i;

  for (i = 0; i < backends->nelts; i++) {
    int res;

    res = reverse_db_add_shuffle(p, dbh, vhost_id, i);
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

static int reverse_db_shuffle_next(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id) {
  int backend_id = -1, res;
  const char *stmt, *errstr = NULL;
  array_header *results;
  unsigned int nrows = 0;

  stmt = "SELECT COUNT(*) FROM proxy_vhost_reverse_shuffle WHERE vhost_id = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
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
    res = reverse_db_shuffle_init(p, dbh, vhost_id, db_backends);
    if (res < 0) {
      return -1;
    }

    nrows = db_backends->nelts;
  }

  backend_id = (int) proxy_random_next(0, nrows-1);
  return backend_id;
}

static int reverse_db_shuffle_used(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "DELETE FROM proxy_vhost_reverse_shuffle WHERE vhost_id = ? AND avail_backend_id = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

/* ProxyReverseConnectPolicy: RoundRobin */

static int reverse_db_roundrobin_update(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "UPDATE proxy_vhost_reverse_roundrobin SET current_backend_id = ? WHERE vhost_id = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id, 0);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_roundrobin_init(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_vhost_reverse_roundrobin (vhost_id, current_backend_id) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_roundrobin_next(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id) {
  int backend_id = 0, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT current_backend_id FROM proxy_vhost_reverse_roundrobin WHERE vhost_id = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
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
  if (backend_id == ((int) db_backends->nelts-1)) {
    backend_id = 0;

  } else {
    backend_id++;
  }

  return backend_id;
}

static int reverse_db_roundrobin_used(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  return reverse_db_roundrobin_update(p, dbh, vhost_id, backend_id);
}

/* ProxyReverseConnectPolicy: LeastConns */

static int reverse_db_leastconns_next(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id) {
  int backend_id = 0, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_id FROM proxy_vhost_backends WHERE vhost_id = ? ORDER BY conn_count ASC LIMIT 1;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
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

static int reverse_db_leastconns_used(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  /* TODO: anything to do here? */
  return 0;
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
static int reverse_db_leastresponsetime_next(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id) {
  int backend_id = 0, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_id FROM proxy_vhost_backends WHERE vhost_id = ? ORDER BY (conn_count * connect_ms) ASC LIMIT 1;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
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

static int reverse_db_leastresponsetime_used(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  /* TODO: anything to do here? */
  return 0;
}

/* ProxyReverseConnectPolicy: PerUser */

static array_header *reverse_db_peruser_get(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, const char *user) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_uri FROM proxy_vhost_reverse_per_user WHERE vhost_id = ? AND user_name = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) user, -1);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return results;
}

static const struct proxy_conn *reverse_db_peruser_init(pool *p,
    struct proxy_dbh *dbh, unsigned int vhost_id, const char *user) {
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns = NULL;
  int backend_count = 0, res;
  const char *stmt, *uri, *errstr = NULL;
  array_header *backends, *results;

  backends = proxy_reverse_pername_backends(p, user, TRUE);
  if (backends == NULL) {
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

  /* TODO: What happens if the chosen backend URI cannot be used, e.g.
   * because it is down/unreachable?  In reverse_try_connect(), we'll know
   * that it failed to connect, but how to tunnel that back down here, to
   * choose another?
   */

  stmt = "INSERT OR IGNORE INTO proxy_vhost_reverse_per_user (vhost_id, user_name, backend_uri) VALUES (?, ?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) user, -1);
  if (res < 0) {
    return NULL;
  }

  uri = proxy_conn_get_uri(pconn);
  res = proxy_db_bind_stmt(p, dbh, stmt, 3, PROXY_DB_BIND_TYPE_TEXT,
    (void *) uri, -1);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return pconn;
}

static const struct proxy_conn *reverse_db_peruser_next(pool *p,
    struct proxy_dbh *dbh, unsigned int vhost_id, const char *user) {
  array_header *results;
  const struct proxy_conn *pconn = NULL;

  pconn = reverse_db_peruser_init(p, dbh, vhost_id, user);
  if (pconn == NULL &&
      errno != ENOENT) {
    results = reverse_db_peruser_get(p, dbh, vhost_id, user);
    if (results != NULL &&
        results->nelts > 0) {
      char **vals;

      vals = results->elts;
      pconn = proxy_conn_create(p, vals[0], 0);
    }
  }

  if (pconn != NULL) {
    return pconn;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "error preparing database for ProxyReverseConnectPolicy PerUser for "
    "user '%s': %s", user, strerror(ENOENT));
  errno = EPERM;
  return NULL;
}

static int reverse_db_peruser_used(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  int count, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* To prevent database bloating too much, delete all of the entries
   * in the table if we're over our limit.
   */

  stmt = "SELECT COUNT(*) FROM proxy_vhost_reverse_per_user;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
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

  count = atoi(((char **) results->elts)[0]);
  if (count <= PROXY_REVERSE_DB_PERUSER_MAX_ENTRIES) {
    return 0;
  }

  pr_trace_msg(trace_channel, 5,
    "PerUser entry count (%d) exceeds max (%d), purging", count,
    PROXY_REVERSE_DB_PERUSER_MAX_ENTRIES);

  stmt = "DELETE FROM proxy_vhost_reverse_per_user;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

/* ProxyReverseConnectPolicy: PerGroup */

static array_header *reverse_db_pergroup_get(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, const char *group) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_uri FROM proxy_vhost_reverse_per_group WHERE vhost_id = ? AND group_name = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) group, -1);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return results;
}

static const struct proxy_conn *reverse_db_pergroup_init(pool *p,
    struct proxy_dbh *dbh, unsigned int vhost_id, const char *group) {
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns = NULL;
  int backend_count = 0, res;
  const char *stmt, *uri, *errstr = NULL;
  array_header *backends, *results;

  backends = proxy_reverse_pername_backends(p, group, FALSE);
  if (backends == NULL) {
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

  /* TODO: What happens if the chosen backend URI cannot be used, e.g.
   * because it is down/unreachable?  In reverse_try_connect(), we'll know
   * that it failed to connect, but how to tunnel that back down here, to
   * choose another?
   */

  stmt = "INSERT OR IGNORE INTO proxy_vhost_reverse_per_group (vhost_id, group_name, backend_uri) VALUES (?, ?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) group, -1);
  if (res < 0) {
    return NULL;
  }

  uri = proxy_conn_get_uri(pconn);
  res = proxy_db_bind_stmt(p, dbh, stmt, 3, PROXY_DB_BIND_TYPE_TEXT,
    (void *) uri, -1);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return pconn;
}

static const struct proxy_conn *reverse_db_pergroup_next(pool *p,
    struct proxy_dbh *dbh, unsigned int vhost_id, const char *group) {
  array_header *results;
  const struct proxy_conn *pconn = NULL;

  pconn = reverse_db_pergroup_init(p, dbh, vhost_id, group);
  if (pconn == NULL &&
      errno != ENOENT) {
    results = reverse_db_pergroup_get(p, dbh, vhost_id, group);
    if (results != NULL &&
        results->nelts > 0) {
      char **vals;

      vals = results->elts;
      pconn = proxy_conn_create(p, vals[0], 0);
    }
  }

  if (pconn != NULL) {
    return pconn;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "error preparing database for ProxyReverseConnectPolicy PerGroup for "
    "group '%s': %s", group, strerror(ENOENT));
  errno = EPERM;
  return NULL;
}

static int reverse_db_pergroup_used(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  int count, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* To prevent database bloating too much, delete all of the entries
   * in the table if we're over our limit.
   */

  stmt = "SELECT COUNT(*) FROM proxy_vhost_reverse_per_group;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
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

  count = atoi(((char **) results->elts)[0]);
  if (count <= PROXY_REVERSE_DB_PERGROUP_MAX_ENTRIES) {
    return 0;
  }

  pr_trace_msg(trace_channel, 5,
    "PerGroup entry count (%d) exceeds max (%d), purging", count,
    PROXY_REVERSE_DB_PERGROUP_MAX_ENTRIES);

  stmt = "DELETE FROM proxy_vhost_reverse_per_group;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

/* ProxyReverseConnectPolicy: PerHost */

static array_header *reverse_db_perhost_get(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, const pr_netaddr_t *addr) {
  int res;
  const char *stmt, *errstr = NULL, *ip;
  array_header *results;

  stmt = "SELECT backend_uri FROM proxy_vhost_reverse_per_host WHERE vhost_id = ? AND ip_addr = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return NULL;
  }

  ip = pr_netaddr_get_ipstr(addr);
  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) ip, -1);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return results;
}

static const struct proxy_conn *reverse_db_perhost_init(pool *p,
    struct proxy_dbh *dbh, unsigned int vhost_id, array_header *backends,
    const pr_netaddr_t *addr) {
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns;
  int res;
  const char *ip, *stmt, *uri, *errstr = NULL;
  array_header *results;

  ip = pr_netaddr_get_ipstr(addr);
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

  stmt = "INSERT OR IGNORE INTO proxy_vhost_reverse_per_host (vhost_id, ip_addr, backend_uri) VALUES (?, ?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) ip, -1);
  if (res < 0) {
    return NULL;
  }

  uri = proxy_conn_get_uri(pconn);
  res = proxy_db_bind_stmt(p, dbh, stmt, 3, PROXY_DB_BIND_TYPE_TEXT,
    (void *) uri, -1);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return pconn;
}

static const struct proxy_conn *reverse_db_perhost_next(pool *p,
    struct proxy_dbh *dbh, unsigned int vhost_id, const pr_netaddr_t *addr) {
  array_header *results;
  const struct proxy_conn *pconn = NULL;

  results = reverse_db_perhost_get(p, dbh, vhost_id, addr);
  if (results == NULL) {
    return NULL;
  }

  if (results->nelts == 0) {
    /* This can happen the very first time; perform an on-demand discovery
     * of the backends for this host, and try again.
     */

    pconn = reverse_db_perhost_init(p, dbh, vhost_id, db_backends, addr);
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
    pconn = proxy_conn_create(p, vals[0], 0);
  }

  return pconn;
}

static int reverse_db_perhost_used(pool *p, struct proxy_dbh *dbh,
    unsigned int vhost_id, int backend_id) {
  int count, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* To prevent database bloating too much, delete all of the entries
   * in the table if we're over our limit.
   */

  stmt = "SELECT COUNT(*) FROM proxy_vhost_reverse_per_host;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
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

  count = atoi(((char **) results->elts)[0]);
  if (count <= PROXY_REVERSE_DB_PERHOST_MAX_ENTRIES) {
    return 0;
  }

  pr_trace_msg(trace_channel, 5,
    "PerHost entry count (%d) exceeds max (%d), purging", count,
    PROXY_REVERSE_DB_PERHOST_MAX_ENTRIES);

  stmt = "DELETE FROM proxy_vhost_reverse_per_host;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

/* ProxyReverseServers API/handling */

static int reverse_db_policy_init(pool *p, void *dbh, int policy_id,
    unsigned int vhost_id, array_header *backends, unsigned long opts) {
  int res, xerrno;

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      /* No preparation needed at this time. */
      res = 0;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN: {
      int backend_id = 0;

      if (backends != NULL) {
        backend_id = backends->nelts-1;
      }

      res = reverse_db_roundrobin_init(p, dbh, vhost_id, backend_id);
      if (res < 0) {
        xerrno = errno;
        pr_log_debug(DEBUG3, MOD_PROXY_VERSION
          ": error preparing database for ProxyReverseConnectPolicy "
          "RoundRobin: %s", strerror(xerrno));

        errno = xerrno;
      }
      break;
    }

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      if (backends != NULL) {
        res = reverse_db_shuffle_init(p, dbh, vhost_id, backends);
        if (res < 0) {
          xerrno = errno;
          pr_log_debug(DEBUG3, MOD_PROXY_VERSION
            ": error preparing database for ProxyReverseConnectPolicy "
            "Shuffle: %s", strerror(xerrno));
          errno = xerrno;
        }

      } else {
        res = 0;
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      if (!(opts & PROXY_OPT_USE_REVERSE_PROXY_AUTH)) {
        pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
          ": PerGroup ProxyReverseConnectPolicy requires the "
          "UseReverseProxyAuth ProxyOption");
        errno = EPERM;
        res = -1;

      } else {
        res = 0;
      }
      break;

    default:
      errno = EINVAL;
      res = -1;
      break;
  }

  return res;
}

static const struct proxy_conn *reverse_db_policy_next_backend(pool *p,
    void *dbh, int policy_id, unsigned int vhost_id,
    array_header *default_backends, const void *policy_data, int *backend_id) {
  const struct proxy_conn *pconn = NULL;
  struct proxy_conn **conns = NULL;
  int idx = -1, nelts = 0;

  if (db_backends != NULL) {
    conns = db_backends->elts;
    nelts = db_backends->nelts;
  }

  if (proxy_reverse_policy_is_sticky(policy_id) != TRUE) {
    if (conns == NULL &&
        default_backends != NULL &&
        db_backends == NULL) {
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
      idx = reverse_db_roundrobin_next(p, dbh, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11, "%s policy: selected index %d of %u",
          proxy_reverse_policy_name(policy_id), idx, nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      idx = reverse_db_shuffle_next(p, dbh, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11, "%s policy: selected index %d of %u",
          proxy_reverse_policy_name(policy_id), idx, nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      idx = reverse_db_leastconns_next(p, dbh, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11, "%s policy: selected index %d of %u",
          proxy_reverse_policy_name(policy_id), idx, nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      idx = reverse_db_leastresponsetime_next(p, dbh, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11, "%s policy: selected index %d of %u",
          proxy_reverse_policy_name(policy_id), idx, nelts-1);
        pconn = conns[idx];
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      pconn = reverse_db_peruser_next(p, dbh, vhost_id, policy_data);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s' for user '%s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn),
          (const char *) policy_data);
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      pconn = reverse_db_pergroup_next(p, dbh, vhost_id, policy_data);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "%s policy: selected backend '%.100s' for user '%s'",
          proxy_reverse_policy_name(policy_id), proxy_conn_get_uri(pconn),
          (const char *) policy_data);
      }
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      pconn = reverse_db_perhost_next(p, dbh, vhost_id, session.c->remote_addr);
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

static int reverse_db_policy_update_backend(pool *p, void *dbh, int policy_id,
    unsigned vhost_id, int backend_id, int conn_incr, long connect_ms) {
  /* Increment the conn count for this backend ID. */
  int res, idx = 1;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* If our ReverseConnectPolicy is one of PerUser, PerGroup, or PerHost,
   * we can skip this step: those policies do not use the connection count/time.
   * This also helps avoid database contention under load for these policies.
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

  if (connect_ms > 0) {
    stmt = "UPDATE proxy_vhost_backends SET conn_count = conn_count + ?, connect_ms = ? WHERE vhost_id = ? AND backend_id = ?;";
  } else {
    stmt = "UPDATE proxy_vhost_backends SET conn_count = conn_count + ? WHERE vhost_id = ? AND backend_id = ?;";
  }

  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT,
    (void *) &conn_incr, 0);
  if (res < 0) {
    return -1;
  }

  idx++;

  if (connect_ms > 0) {
    res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_LONG,
      (void *) &connect_ms, 0);
    if (res < 0) {
      return -1;
    }

    idx++;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  idx++;

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id, 0);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_db_policy_used_backend(pool *p, void *dbh, int policy_id,
    unsigned int vhost_id, int idx) {
  int res;

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
      res = 0;
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
      res = reverse_db_roundrobin_used(p, dbh, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      res = reverse_db_shuffle_used(p, dbh, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      res = reverse_db_leastconns_used(p, dbh, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      res = reverse_db_leastresponsetime_used(p, dbh, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      res = reverse_db_peruser_used(p, dbh, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      res = reverse_db_pergroup_used(p, dbh, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      res = reverse_db_perhost_used(p, dbh, vhost_id, idx);
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

static void *reverse_db_init(pool *p, const char *tables_path, int flags) {
  int db_flags, res, xerrno = 0;
  const char *db_path = NULL;
  server_rec *s;
  struct proxy_dbh *dbh;

  if (tables_path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  db_path = pdircat(p, tables_path, "proxy-reverse.db", NULL);

  db_flags = PROXY_DB_OPEN_FL_SCHEMA_VERSION_CHECK|PROXY_DB_OPEN_FL_INTEGRITY_CHECK|PROXY_DB_OPEN_FL_VACUUM;
  if (flags & PROXY_DB_OPEN_FL_SKIP_VACUUM) {
    /* If the caller needs us to skip the vacuum, we will. */
    db_flags &= ~PROXY_DB_OPEN_FL_VACUUM;
  }

  PRIVS_ROOT
  dbh = proxy_db_open_with_version(p, db_path, PROXY_REVERSE_DB_SCHEMA_NAME,
    PROXY_REVERSE_DB_SCHEMA_VERSION, db_flags);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROXY_REVERSE_DB_SCHEMA_NAME, PROXY_REVERSE_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  res = reverse_db_add_schema(p, dbh, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error creating schema in database '%s' for '%s': %s", db_path,
      PROXY_REVERSE_DB_SCHEMA_NAME, strerror(xerrno));
    (void) proxy_db_close(p, dbh);
    errno = xerrno;
    return NULL;
  }

  res = reverse_db_truncate_tables(p, dbh);
  if (res < 0) {
    xerrno = errno;
    (void) proxy_db_close(p, dbh);
    errno = xerrno;
    return NULL;
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    config_rec *c;
    array_header *backends = NULL;

    res = reverse_db_add_vhost(p, dbh, s);
    if (res < 0) {
      xerrno = errno;
      (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": error adding database entry for server '%s' in schema '%s': %s",
        s->ServerName, PROXY_REVERSE_DB_SCHEMA_NAME, strerror(xerrno));
      (void) proxy_db_close(p, dbh);
      errno = xerrno;
      return NULL;
    }

    c = find_config(s->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
    while (c != NULL) {
      const char *uri;

      pr_signals_handle();

      uri = c->argv[1];
      if (uri != NULL) {
        int defer = FALSE;

        /* Handling of sql:// URIs is done later, in the session init
         * call, assuming we've connected to a SQL server.
         */
        if (strncmp(uri, "sql:/", 5) == 0) {
          defer = TRUE;
        }

        /* Skip any %U- or %g-bearing URIs. */
        if (defer == FALSE &&
            (strstr(uri, "%U") != NULL ||
             strstr(uri, "%g") != NULL)) {
          defer = TRUE;
        }

        if (defer) {
          c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
            FALSE);
          continue;
        }
      }

      if (backends == NULL) {
        backends = c->argv[0];

      } else {
        array_cat(backends, c->argv[0]);
      }

      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
    }

    /* What if ALL of the ProxyReverseServers are deferred?  In that case, we
     * have no backend servers to add at this time.
     */
    if (backends != NULL) {
      res = reverse_db_add_backends(p, dbh, s->sid, backends);
      if (res < 0) {
        xerrno = errno;
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error adding database entries for ProxyReverseServers: %s",
          strerror(xerrno));
        (void) proxy_db_close(p, dbh);
        errno = xerrno;
        return NULL;
      }
    }
  }

  return dbh;
}

static int reverse_db_close(pool *p, void *dbh) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* TODO: Implement any necessary cleanup */

  if (dbh != NULL) {
    if (proxy_db_close(p, dbh) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error detaching database with schema '%s': %s",
        PROXY_REVERSE_DB_SCHEMA_NAME, strerror(errno));
    }
  }

  return 0;
}

static void *reverse_db_open(pool *p, const char *tables_path,
    array_header *backends) {
  int xerrno = 0;
  struct proxy_dbh *dbh;
  const char *db_path;

  db_path = pdircat(p, tables_path, "proxy-reverse.db", NULL);

  /* Make sure we have our own per-session database handle, per SQLite3
   * recommendation.
   */

  PRIVS_ROOT
  dbh = proxy_db_open_with_version(p, db_path, PROXY_REVERSE_DB_SCHEMA_NAME,
    PROXY_REVERSE_DB_SCHEMA_VERSION, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROXY_REVERSE_DB_SCHEMA_NAME, PROXY_REVERSE_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  db_backends = backends;
  return dbh;
}

int proxy_reverse_db_as_datastore(struct proxy_reverse_datastore *ds,
    void *ds_data, size_t ds_datasz) {

  if (ds == NULL) {
    errno = EINVAL;
    return -1;
  }

  (void) ds_data;
  (void) ds_datasz;

  ds->policy_init = reverse_db_policy_init;
  ds->policy_next_backend = reverse_db_policy_next_backend;
  ds->policy_used_backend = reverse_db_policy_used_backend;
  ds->policy_update_backend = reverse_db_policy_update_backend;
  ds->init = reverse_db_init;
  ds->open = reverse_db_open;
  ds->close = reverse_db_close;

  return 0;
}
