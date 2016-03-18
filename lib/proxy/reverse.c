/*
 * ProFTPD - mod_proxy reverse proxy implementation
 * Copyright (c) 2012-2016 TJ Saunders
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
#include "proxy/netio.h"
#include "proxy/inet.h"
#include "proxy/reverse.h"
#include "proxy/random.h"
#include "proxy/tls.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/sess.h"

#include <sqlite3.h>

extern xaset_t *server_list;

static array_header *reverse_backends = NULL;
static int reverse_backend_id = -1;
static int reverse_connect_policy = PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;
static unsigned long reverse_flags = 0UL;
static int reverse_retry_count = PROXY_DEFAULT_RETRY_COUNT;

static const char *reverse_db_path = NULL;
#define PROXY_REVERSE_DB_SCHEMA_NAME		"proxy_reverse"
#define PROXY_REVERSE_DB_SCHEMA_VERSION		1

/* Flag that indicates that we should select/connect to the backend server
 * at session init time, i.e. when proxy auth is not required, and we're using
 * a balancing policy.
 */
#define PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT		1

/* Flag that indicates that we should select/connect to the backend server
 * at USER time, i.e. when proxy auth is not required, and we're using a
 * sticky policy.
 */
#define PROXY_REVERSE_FL_CONNECT_AT_USER		2

/* Flag that indicates that we should select/connect to the backend server
 * at PASS time, i.e. when proxy auth IS required (balancing/sticky policy
 * doesn't really matter).
 */
#define PROXY_REVERSE_FL_CONNECT_AT_PASS		3

/* JSON handling */
#define PROXY_REVERSE_JSON_MAX_FILE_SIZE		(1024 * 1024 * 5)
#define PROXY_REVERSE_JSON_MAX_ITEMS			1000

/* PerHost/PerUser/PerGroup table limits */
#define PROXY_REVERSE_PERHOST_MAX_ENTRIES		8192
#define PROXY_REVERSE_PERUSER_MAX_ENTRIES		8192
#define PROXY_REVERSE_PERGROUP_MAX_ENTRIES		8192

static const char *trace_channel = "proxy.reverse";

static void clear_user_creds(void) {
  register unsigned int i;

  if (reverse_backends == NULL ||
      reverse_backends->nelts == 0) {
    /* Nothing to do. */
    return;
  }

  for (i = 0; i < reverse_backends->nelts; i++) {
    struct proxy_conn *pconn;

    pconn = ((struct proxy_conn **) reverse_backends->elts)[i];
    proxy_conn_clear_username(pconn);
    proxy_conn_clear_password(pconn);
  }
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

  /* CREATE TABLE proxy_reverse.proxy_vhosts (
   *   vhost_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_name TEXT NOT NULL
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhosts (vhost_id INTEGER NOT NULL PRIMARY KEY, vhost_name TEXT NOT NULL);";
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

  /* CREATE TABLE proxy_reverse.proxy_vhost_backends (
   *   backend_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_id INTEGER NOT NULL,
   *   backend_uri TEXT NOT NULL,
   *   conn_count INTEGER NOT NULL,
   *   connect_ms INTEGER,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_backends (backend_id INTEGER NOT NULL PRIMARY KEY, vhost_id INTEGER NOT NULL, backend_uri TEXT NOT NULL, conn_count INTEGER NOT NULL, connect_ms INTEGER, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_reverse.proxy_vhost_reverse_roundrobin (
   *   vhost_id INTEGER NOT NULL,
   *   current_backend_id INTEGER NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id),
   *   FOREIGN KEY (current_backend_id) REFERENCES proxy_vhost_backends (backend_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_roundrobin (vhost_id INTEGER NOT NULL, current_backend_id INTEGER NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), FOREIGN KEY (current_backend_id) REFERENCES proxy_vhost_backends (backend_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_reverse.proxy_vhost_reverse_shuffle (
   *   vhost_id INTEGER NOT NULL,
   *   avail_backend_id INTEGER NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id),
   *   FOREIGN KEY (avail_backend_id) REFERENCES proxy_vhost_backends (backend_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_shuffle (vhost_id INTEGER NOT NULL, avail_backend_id INTEGER NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id), FOREIGN KEY (avail_backend_id) REFERENCES proxy_vhost_backends (backend_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_reverse.proxy_vhost_reverse_per_user (
   *   vhost_id INTEGER NOT NULL,
   *   user_name TEXT NOT NULL PRIMARY KEY,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_user (vhost_id INTEGER NOT NULL, user_name TEXT NOT NULL PRIMARY KEY, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_reverse.proxy_vhost_reverse_per_group (
   *   vhost_id INTEGER NOT NULL,
   *   group_name TEXT NOT NULL PRIMARY KEY,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_group (vhost_id INTEGER NOT NULL, group_name TEXT NOT NULL PRIMARY KEY, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_reverse.proxy_vhost_reverse_per_host (
   *   vhost_id INTEGER NOT NULL,
   *   ip_addr TEXT NOT NULL PRIMARY KEY,
   *   backend_uri TEXT,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_host (vhost_id INTEGER NOT NULL, ip_addr TEXT NOT NULL PRIMARY KEY, backend_uri TEXT, FOREIGN KEY (vhost_id) REFERENCES proxy_vhosts (vhost_id));";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int reverse_truncate_db_tables(pool *p) {
  int res;
  const char *stmt, *errstr = NULL;

  stmt = "DELETE FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhosts;";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_backends;";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_roundrobin;";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_shuffle;";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_user;";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_group;";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_host;";
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

  stmt = "INSERT INTO " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhosts (vhost_id, vhost_name) VALUES (?, ?);";
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

  stmt = "INSERT INTO " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_backends (vhost_id, backend_uri, backend_id, conn_count) VALUES (?, ?, ?, 0);";
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

  res = proxy_db_bind_stmt(p, stmt, 3, PROXY_DB_BIND_TYPE_INT,
    (void *) &backend_id);
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

    pr_trace_msg(trace_channel, 18,
      "added database entry for backend '%.100s' (ID %u)", backend_uri, i);
  }

  return 0;
}

static int reverse_db_update_backend(pool *p, unsigned vhost_id,
    int backend_id, int conn_incr, long connect_ms) {
  /* Increment the conn count for this backend ID. */
  int res, idx = 1;
  const char *stmt, *errstr = NULL;
  array_header *results;

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

  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, idx, PROXY_DB_BIND_TYPE_INT,
    (void *) &conn_incr);
  if (res < 0) {
    return -1;
  }

  idx++;

  if (connect_ms > 0) {
    res = proxy_db_bind_stmt(p, stmt, idx, PROXY_DB_BIND_TYPE_LONG,
      (void *) &connect_ms);
    if (res < 0) {
      return -1;
    }

    idx++;
  }

  res = proxy_db_bind_stmt(p, stmt, idx, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  idx++;

  res = proxy_db_bind_stmt(p, stmt, idx, PROXY_DB_BIND_TYPE_INT,
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

  stmt = "INSERT INTO " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_shuffle (vhost_id, avail_backend_id) VALUES (?, ?);";
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

  stmt = "SELECT COUNT(*) FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_shuffle WHERE vhost_id = ?;";
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

  stmt = "INSERT INTO " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_roundrobin (vhost_id, current_backend_id) VALUES (?, ?);";
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

  stmt = "SELECT current_backend_id FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_roundrobin WHERE vhost_id = ?;";
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

  stmt = "SELECT backend_id FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_backends WHERE vhost_id = ? ORDER BY conn_count ASC LIMIT 1;";
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
static int reverse_db_leastresponsetime_next(pool *p, unsigned int vhost_id) {
  int backend_id = 0, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_id FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_backends WHERE vhost_id = ? ORDER BY (conn_count * connect_ms) ASC LIMIT 1;";
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

static int reverse_db_leastresponsetime_used(pool *p, unsigned int vhost_id,
    int backend_id) {
  /* TODO: anything to do here? */
  return 0;
}

/* Shared/common routines for PerUser and PerGroup. */

static array_header *reverse_db_parse_uris(pool *p, array_header *uris) {
  array_header *pconns = NULL;
  register unsigned int i;

  pconns = make_array(p, 0, sizeof(struct proxy_conn *));

  for (i = 0; i < uris->nelts; i++) {
    char *uri;
    struct proxy_conn *pconn;

    pr_signals_handle();
    uri = ((char **) uris->elts)[i];

    /* Skip blank/empty URIs. */
    if (*uri == '\0') {
      continue;
    }

    pconn = proxy_conn_create(p, uri);
    if (pconn == NULL) {
      pr_trace_msg(trace_channel, 9, "skipping malformed URL '%s'", uri);
      continue;
    }

    *((struct proxy_conn **) push_array(pconns)) = pconn;
  }

  return pconns;
}

/* SQL support routines. */

static cmd_rec *reverse_db_sql_cmd_create(pool *parent_pool, int argc, ...) {
  pool *cmd_pool = NULL;
  cmd_rec *cmd = NULL;
  register unsigned int i = 0;
  va_list argp;

  cmd_pool = make_sub_pool(parent_pool);
  cmd = (cmd_rec *) pcalloc(cmd_pool, sizeof(cmd_rec));
  cmd->pool = cmd_pool;

  cmd->argc = argc;
  cmd->argv = pcalloc(cmd->pool, argc * sizeof(void *));

  /* Hmmm... */
  cmd->tmp_pool = cmd->pool;

  va_start(argp, argc);
  for (i = 0; i < argc; i++) {
    cmd->argv[i] = va_arg(argp, char *);
  }
  va_end(argp);

  return cmd;
}

static const char *reverse_db_sql_quote_str(pool *p, char *str) {
  size_t len;
  cmdtable *cmdtab;
  cmd_rec *cmd;
  modret_t *res;

  len = strlen(str);
  if (len == 0) {
    return str;
  }

  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_escapestr", NULL, NULL, NULL);
  if (cmdtab == NULL) {
    return str;
  }

  cmd = reverse_db_sql_cmd_create(p, 1, pr_str_strip(p, str));
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);
  if (MODRET_ISDECLINED(res) ||
      MODRET_ISERROR(res)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing 'sql_escapestr'");
    return str;
  }

  return res->data;
}

/* Look for any user/group-specific ProxyReverseServers and load them, either
 * from file or SQL or whatever.  Randomly choose from one of those
 * backends.  If no user/group-specific backends are found, use the existing
 * "global" list.
 */

static array_header *reverse_db_pername_sql_parse_uris(pool *p,
    cmdtable *sql_cmdtab, const char *name, int per_user,
    const char *named_query) {
  array_header *backends, *results;
  pool *tmp_pool;
  cmd_rec *cmd;
  modret_t *res;

  tmp_pool = make_sub_pool(p);
  cmd = reverse_db_sql_cmd_create(tmp_pool, 3, "sql_lookup", named_query, name);
  res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, cmd);
  if (res == NULL ||
      MODRET_ISERROR(res)) {
    destroy_pool(tmp_pool);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error processing SQLNamedQuery '%s'", named_query);
    errno = EPERM;
    return NULL;
  }

  results = res->data;
  if (results->nelts == 0) {
    destroy_pool(tmp_pool);
    pr_trace_msg(trace_channel, 10,
      "SQLNamedQuery '%s' returned zero rows for %s '%s'", named_query,
      per_user ? "user" : "group", name);
    errno = ENOENT;
    return NULL;
  }

  backends = reverse_db_parse_uris(p, results);
  destroy_pool(tmp_pool);

  if (backends != NULL) {
    if (backends->nelts == 0) {
      errno = ENOENT;
      return NULL;
    }

    pr_trace_msg(trace_channel, 10,
      "SQLNamedQuery '%s' returned %d URLs for %s '%s'", named_query,
       backends->nelts, per_user ? "user" : "group", name);
  }

  return backends;
}

static array_header *reverse_db_pername_backends_by_sql(pool *p,
    const char *name, int per_user) {
  config_rec *c;
  array_header *sql_backends = NULL;
  const char *quoted_name = NULL;
  cmdtable *sql_cmdtab;

  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    /* No mod_sql backend loaded; no lookups to do. */
    pr_trace_msg(trace_channel, 18,
      "no 'sql_lookup' symbol found (mod_sql not loaded?), skipping "
      "%s SQL lookups", per_user ? "per-user" : "per-group");
    errno = EPERM;
    return NULL;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
  while (c != NULL) {
    const char *named_query, *uri;
    array_header *backends = NULL;

    pr_signals_handle();

    uri = c->argv[1];
    if (uri == NULL) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (strncmp(uri, "sql:/", 5) != 0) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    named_query = uri + 5;

    if (quoted_name == NULL) {
      quoted_name = reverse_db_sql_quote_str(p, (char *) name);
    }

    pr_trace_msg(trace_channel, 17,
      "loading %s-specific ProxyReverseServers SQLNamedQuery '%s'",
      per_user ? "user" : "group", named_query);

    backends = reverse_db_pername_sql_parse_uris(p, sql_cmdtab, quoted_name,
      per_user, named_query);
    if (backends == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error reading ProxyReverseServers SQLNamedQuery '%s': %s", named_query,
        strerror(errno));
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (backends->nelts == 0) {
      pr_trace_msg(trace_channel, 3,
        "no usable URLs found by ProxyReverseServers SQLNamedQuery '%s', "
        "ignoring", named_query);

    } else {
      if (sql_backends == NULL) {
        sql_backends = backends;

      } else {
        (void) array_cat2(sql_backends, backends);
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers", FALSE);
  }

  return sql_backends;
}

static array_header *reverse_db_pername_backends_by_json(pool *p,
    const char *name, int per_user) {
  config_rec *c;
  array_header *file_backends = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
  while (c != NULL) {
    const char *path, *uri;
    int xerrno;
    array_header *backends = NULL;

    pr_signals_handle();

    uri = c->argv[1];
    if (uri == NULL) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (per_user) {
      if (strstr(uri, "%U") == NULL) {
        c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
          FALSE);
        continue;
      }

    } else {
      if (strstr(uri, "%g") == NULL) {
        c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
          FALSE);
        continue;
      }
    }

    if (strncmp(uri, "file:", 5) != 0) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (per_user) {
      path = sreplace(p, (char *) (uri + 5), "%U", name, NULL);

    } else {
      path = sreplace(p, (char *) (uri + 5), "%g", name, NULL);
    }

    pr_trace_msg(trace_channel, 17,
      "loading %s-specific ProxyReverseServers file '%s'",
      per_user ? "user" : "group", path);

    PRIVS_ROOT
    backends = proxy_reverse_json_parse_uris(p, path);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (backends == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error reading ProxyReverseServers file '%s': %s", path,
        strerror(xerrno));
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (backends->nelts == 0) {
      pr_trace_msg(trace_channel, 3,
        "no usable URLs found in ProxyReverseServers file '%s', ignoring",
        path); 

    } else {
      if (file_backends == NULL) {
        file_backends = backends;

      } else {
        (void) array_cat2(file_backends, backends);
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers", FALSE);
  }

  return file_backends;
}

static array_header *reverse_db_pername_backends(pool *p, const char *name,
    int per_user) {
  array_header *file_backends, *sql_backends, *backends = NULL;

  file_backends = reverse_db_pername_backends_by_json(p, name, per_user);
  if (file_backends != NULL) {
    backends = file_backends;
  }

  sql_backends = reverse_db_pername_backends_by_sql(p, name, per_user);
  if (sql_backends != NULL) {
    if (backends != NULL) {
      (void) array_cat2(backends, sql_backends);
    } else {
      backends = sql_backends;
    }
  }

  return backends;
}

/* ProxyReverseConnectPolicy: PerUser */

static array_header *reverse_db_peruser_get(pool *p, unsigned int vhost_id,
    const char *user) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_uri FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_user WHERE vhost_id = ? AND user_name = ?;";
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
  struct proxy_conn **conns, *pconn = NULL;
  int backend_count = 0, res;
  const char *stmt, *uri, *errstr = NULL;
  array_header *user_backends = NULL, *results;

  user_backends = reverse_db_pername_backends(p, user, TRUE);
  if (user_backends != NULL) {
    backend_count = user_backends->nelts;
    conns = user_backends->elts;

  } else {
    pr_trace_msg(trace_channel, 11,
      "using global ProxyReverseServers list for user '%s'", user);
    backend_count = reverse_backends->nelts;
    conns = reverse_backends->elts;
  }

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

  stmt = "INSERT INTO " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_user (vhost_id, user_name, backend_uri) VALUES (?, ?, ?);";
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
  int count, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* To prevent database bloating too much, delete all of the entries
   * in the table if we're over our limit.
   */

  stmt = "SELECT COUNT(*) FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_user;";
  res = proxy_db_prepare_stmt(p, stmt);
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

  count = atoi(((char **) results->elts)[0]);
  if (count <= PROXY_REVERSE_PERUSER_MAX_ENTRIES) {
    return 0;
  }

  pr_trace_msg(trace_channel, 5,
    "PerUser entry count (%d) exceeds max (%d), purging", count,
    PROXY_REVERSE_PERUSER_MAX_ENTRIES);

  stmt = "DELETE FROM proxy_vhost_reverse_per_user;";
  res = proxy_db_prepare_stmt(p, stmt);
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

/* ProxyReverseConnectPolicy: PerGroup */

static array_header *reverse_db_pergroup_get(pool *p, unsigned int vhost_id,
    const char *group) {
  int res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT backend_uri FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_group WHERE vhost_id = ? AND group_name = ?;";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT, (void *) group);
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

static struct proxy_conn *reverse_db_pergroup_init(pool *p,
    unsigned int vhost_id, const char *group) {
  struct proxy_conn **conns, *pconn = NULL;
  int backend_count = 0, res;
  const char *stmt, *uri, *errstr = NULL;
  array_header *group_backends = NULL, *results;

  group_backends = reverse_db_pername_backends(p, group, FALSE);
  if (group_backends != NULL) {
    backend_count = group_backends->nelts;
    conns = group_backends->elts;

  } else {
    pr_trace_msg(trace_channel, 11,
      "using global ProxyReverseServers list for group '%s'", group);
    backend_count = reverse_backends->nelts;
    conns = reverse_backends->elts;
  }

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

  stmt = "INSERT INTO " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_group (vhost_id, group_name, backend_uri) VALUES (?, ?, ?);";
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_TEXT, (void *) group);
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

static struct proxy_conn *reverse_db_pergroup_next(pool *p,
    unsigned int vhost_id, const char *group) {
  array_header *results;
  struct proxy_conn *pconn = NULL;

  results = reverse_db_pergroup_get(p, vhost_id, group);
  if (results == NULL) {
    return NULL;
  }

  if (results->nelts == 0) {
    /* This can happen the very first time; perform an on-demand discovery
     * of the backends for this group, and try again.
     */

    pconn = reverse_db_pergroup_init(p, vhost_id, group);
    if (pconn == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error preparing database for ProxyReverseConnectPolicy "
        "PerGroup for group '%s': %s", group, strerror(errno));
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

static int reverse_db_pergroup_used(pool *p, unsigned int vhost_id,
    int backend_id) {
  int count, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* To prevent database bloating too much, delete all of the entries
   * in the table if we're over our limit.
   */

  stmt = "SELECT COUNT(*) FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_group;";
  res = proxy_db_prepare_stmt(p, stmt);
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

  count = atoi(((char **) results->elts)[0]);
  if (count <= PROXY_REVERSE_PERGROUP_MAX_ENTRIES) {
    return 0;
  }

  pr_trace_msg(trace_channel, 5,
    "PerGroup entry count (%d) exceeds max (%d), purging", count,
    PROXY_REVERSE_PERGROUP_MAX_ENTRIES);

  stmt = "DELETE FROM proxy_vhost_reverse_per_group;";
  res = proxy_db_prepare_stmt(p, stmt);
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

/* ProxyReverseConnectPolicy: PerHost */

static array_header *reverse_db_perhost_get(pool *p, unsigned int vhost_id,
    pr_netaddr_t *addr) {
  int res;
  const char *stmt, *errstr = NULL, *ip;
  array_header *results;

  stmt = "SELECT backend_uri FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_host WHERE vhost_id = ? AND ip_addr = ?;";
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

  stmt = "INSERT INTO " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_host (vhost_id, ip_addr, backend_uri) VALUES (?, ?, ?);";
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
  int count, res;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* To prevent database bloating too much, delete all of the entries
   * in the table if we're over our limit.
   */

  stmt = "SELECT COUNT(*) FROM " PROXY_REVERSE_DB_SCHEMA_NAME ".proxy_vhost_reverse_per_host;";
  res = proxy_db_prepare_stmt(p, stmt);
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

  count = atoi(((char **) results->elts)[0]);
  if (count <= PROXY_REVERSE_PERHOST_MAX_ENTRIES) {
    return 0;
  }

  pr_trace_msg(trace_channel, 5,
    "PerHost entry count (%d) exceeds max (%d), purging", count,
    PROXY_REVERSE_PERHOST_MAX_ENTRIES);

  stmt = "DELETE FROM proxy_vhost_reverse_per_host;";
  res = proxy_db_prepare_stmt(p, stmt);
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

/* ProxyReverseServers API/handling */

static int reverse_policy_is_sticky(int policy_id) {
  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      return TRUE;

    default:
      break;
  }

  return FALSE;
}

static struct proxy_conn *reverse_connect_next_backend(pool *p,
    unsigned int vhost_id, void *policy_data) {
  struct proxy_conn **conns, *pconn = NULL;
  int idx = -1;

  conns = reverse_backends->elts;

  /* Sticky policies such as PerUser might have their own ways of looking up
   * other backends to use.
   */
  if (reverse_policy_is_sticky(reverse_connect_policy) == TRUE) {
    if (reverse_backends->nelts == 1) {
      reverse_backend_id = 0;
      return conns[0];
    }
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

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      idx = reverse_db_leastresponsetime_next(p, vhost_id);
      if (idx >= 0) {
        pr_trace_msg(trace_channel, 11,
          "LEAST_RESPONSE_TIME policy: selected index %d of %u", idx,
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

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      pconn = reverse_db_pergroup_next(p, vhost_id, policy_data);
      if (pconn != NULL) {
        pr_trace_msg(trace_channel, 11,
          "PER_GROUP policy: selected backend '%.100s' for user '%s'",
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
    int idx, long connect_ms) {
  int res;

  if (reverse_backends->nelts == 1) {
    return 0;
  }

  res = reverse_db_update_backend(p, vhost_id, idx, 1, connect_ms);
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

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      res = reverse_db_leastresponsetime_used(p, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      res = reverse_db_peruser_used(p, vhost_id, idx);
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      res = reverse_db_pergroup_used(p, vhost_id, idx);
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

static struct proxy_conn *get_reverse_server_conn(pool *p,
    struct proxy_session *proxy_sess, int *backend_id, void *policy_data) {
  struct proxy_conn *pconn;

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
  return pconn;
}

static int reverse_try_connect(pool *p, struct proxy_session *proxy_sess,
    void *connect_data) {
  int backend_id = -1, use_tls, xerrno = 0;
  conn_t *server_conn = NULL;
  pr_response_t *resp = NULL;
  unsigned int resp_nlines = 0;
  struct proxy_conn *pconn;
  pr_netaddr_t *dst_addr;
  array_header *other_addrs = NULL;
  uint64_t connecting_ms, connected_ms;

  pconn = get_reverse_server_conn(p, proxy_sess, &backend_id, connect_data);
  if (pconn == NULL) {
    return -1;
  }

  dst_addr = proxy_conn_get_addr(pconn, &other_addrs);
  proxy_sess->dst_addr = dst_addr;
  proxy_sess->dst_pconn = pconn;
  proxy_sess->other_addrs = other_addrs;

  pr_gettimeofday_millis(&connecting_ms);
  server_conn = proxy_conn_get_server_conn(p, proxy_sess, dst_addr);
  if (server_conn == NULL) {
    xerrno = errno;

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

      if (reverse_connect_index_used(p, main_server->sid, backend_id, -1) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error updating database for backend server index %d: %s", backend_id,
          strerror(xerrno));
      }
    }
 
    errno = xerrno;
    return -1;
  }

  if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
    pr_trace_msg(trace_channel, 17,
      "sending PROXY protocol message to %s#%u",
      pr_netaddr_get_ipstr(server_conn->remote_addr),
      ntohs(pr_netaddr_get_port(server_conn->remote_addr)));

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

  use_tls = proxy_tls_using_tls();

  resp = proxy_ftp_ctrl_recv_resp(p, server_conn, &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(server_conn->remote_addr),
      ntohs(pr_netaddr_get_port(server_conn->remote_addr)), strerror(xerrno));

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
      pr_netaddr_get_ipstr(server_conn->remote_addr),
      ntohs(pr_netaddr_get_port(server_conn->remote_addr)),
      banner_ok ? "" : ", DISCONNECTING", resp->num, resp->msg);

    if (banner_ok == FALSE) {
      pr_inet_close(p, server_conn);
      proxy_sess->backend_ctrl_conn = NULL;
      errno = EPERM;
      return -1;
    }
  }

  pr_trace_msg(trace_channel, 8,
    "connected to backend '%.100s' in %ld ms",
    proxy_conn_get_uri(proxy_sess->dst_pconn),
    (long) (connected_ms - connecting_ms));

  if (reverse_connect_index_used(p, main_server->sid, backend_id,
      (long) (connected_ms - connecting_ms)) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error updating database for backend server index %d: %s", backend_id,
      strerror(errno));
  }

  /* Get the features supported by the backend server. */
  if (proxy_ftp_sess_get_feat(p, proxy_sess) < 0) {
    if (errno != EPERM) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to determine features of backend server: %s", strerror(errno));
    }
  }

  pr_response_block(TRUE);

  if (use_tls != PROXY_TLS_ENGINE_OFF) {
    if (proxy_ftp_sess_send_auth_tls(p, proxy_sess) < 0 &&
        errno != ENOSYS) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error enabling TLS on control connection to backend server: %s",
        strerror(xerrno));
      pr_inet_close(p, server_conn);
      proxy_sess->backend_ctrl_conn = NULL;

      pr_response_block(FALSE);
      errno = xerrno;
      return -1;
    }

    use_tls = proxy_tls_using_tls();
  }

  if (proxy_netio_postopen(server_conn->instrm) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "postopen error for backend control connection input stream: %s",
      strerror(xerrno));
    proxy_inet_close(session.pool, server_conn);
    proxy_sess->backend_ctrl_conn = NULL;

    pr_response_block(FALSE);

    /* Note that we explicitly return EINVAL here, to indicate to the calling
     * code in mod_proxy that it should return e.g. "Login incorrect."
     */
    errno = EINVAL;
    return -1;
  }

  if (proxy_netio_postopen(server_conn->outstrm) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "postopen error for backend control connection output stream: %s",
      strerror(xerrno));
    proxy_inet_close(session.pool, server_conn);
    proxy_sess->backend_ctrl_conn = NULL;

    pr_response_block(FALSE);

    /* Note that we explicitly return EINVAL here, to indicate to the calling
     * code in mod_proxy that it should return e.g. "Login incorrect."
     */
    errno = EINVAL;
    return -1;
  }

  if (use_tls != PROXY_TLS_ENGINE_OFF) {
    if (proxy_sess_state & PROXY_SESS_STATE_BACKEND_HAS_CTRL_TLS) {
      /* NOTE: should this be a fatal error? */
      (void) proxy_ftp_sess_send_pbsz_prot(p, proxy_sess);
    }
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT) {
    pr_response_block(FALSE);
  }

  if (proxy_ftp_ctrl_send_resp(p, session.c, resp, resp_nlines) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to send banner to client: %s", strerror(errno));
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT) {
    pr_response_block(TRUE);
  }

  (void) proxy_ftp_sess_send_host(p, proxy_sess);

  proxy_sess_state |= PROXY_SESS_STATE_CONNECTED;
  return 0;
}

static int reverse_connect(pool *p, struct proxy_session *proxy_sess) {
  register unsigned int i;
  int res;

  for (i = 0; i < reverse_retry_count; i++) {
    pr_signals_handle();

    res = reverse_try_connect(p, proxy_sess, NULL);
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

int proxy_reverse_use_proxy_auth(void) {
  if (proxy_opts & PROXY_OPT_USE_REVERSE_PROXY_AUTH) {
    return TRUE;
  }

  return FALSE;
}

int proxy_reverse_init(pool *p, const char *tables_dir) {
  int res, xerrno = 0;
  server_rec *s;

  if (p == NULL ||
      tables_dir == NULL) {
    errno = EINVAL;
    return -1;
  }

  reverse_db_path = pdircat(p, tables_dir, "proxy-reverse.db", NULL);

  PRIVS_ROOT
  res = proxy_db_open_with_version(p, reverse_db_path,
    PROXY_REVERSE_DB_SCHEMA_NAME, PROXY_REVERSE_DB_SCHEMA_VERSION, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res < 0) {
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening database '%s' for schema '%s', version %u: %s",
      reverse_db_path, PROXY_REVERSE_DB_SCHEMA_NAME,
      PROXY_REVERSE_DB_SCHEMA_VERSION, strerror(xerrno));
    reverse_db_path = NULL;
    errno = xerrno;
    return -1;
  }

  res = reverse_db_add_schema(p, reverse_db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error creating schema in database '%s' for '%s': %s", reverse_db_path,
      PROXY_REVERSE_DB_SCHEMA_NAME, strerror(xerrno));
    (void) proxy_db_close(p, PROXY_REVERSE_DB_SCHEMA_NAME);
    reverse_db_path = NULL;
    errno = xerrno;
    return -1;
  }

  res = reverse_truncate_db_tables(p);
  if (res < 0) {
    xerrno = errno;
    (void) proxy_db_close(p, PROXY_REVERSE_DB_SCHEMA_NAME);
    reverse_db_path = NULL;
    errno = xerrno;
    return -1;
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    config_rec *c;
    array_header *backends = NULL;
    int connect_policy = reverse_connect_policy;
    unsigned long opts = 0UL;

    res = reverse_db_add_vhost(p, s);
    if (res < 0) {
      xerrno = errno;
      (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": error adding database entry for server '%s' in schema '%s': %s",
        s->ServerName, PROXY_REVERSE_DB_SCHEMA_NAME, strerror(xerrno));
      (void) proxy_db_close(p, PROXY_REVERSE_DB_SCHEMA_NAME);
      reverse_db_path = NULL;
      errno = xerrno;
      return -1;
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
        array_cat2(backends, c->argv[0]);
      }

      res = reverse_db_add_backends(p, s->sid, backends);
      if (res < 0) {
        xerrno = errno;
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error adding database entries for ProxyReverseServers: %s",
          strerror(xerrno));
        errno = xerrno;
        return -1;
      }

      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
    }

    c = find_config(s->conf, CONF_PARAM, "ProxyReverseConnectPolicy", FALSE);
    if (c != NULL) {
      connect_policy = *((int *) c->argv[0]);
    }

    c = find_config(s->conf, CONF_PARAM, "ProxyOptions", FALSE);
    while (c != NULL) {
      unsigned long o;

      pr_signals_handle();

      o = *((unsigned long *) c->argv[0]);
      opts |= o;

      c = find_config_next(c, c->next, CONF_PARAM, "ProxyOptions", FALSE);
    }

    /* Note that we use a separate variable for the ConnectPolicy here, so
     * that we do NOT switch the per-vhost default; we want to track each
     * vhost's ConnectPolicy separately in this loop.
     */
    switch (connect_policy) {
      case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
      case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
        /* No preparation needed at this time. */
        break;

      case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN: {
        int backend_id = 0; 

        if (backends != NULL) {
          backend_id = backends->nelts-1;
        }

        res = reverse_db_roundrobin_init(p, s->sid, backend_id);
        if (res < 0) {
          xerrno = errno;
          pr_log_debug(DEBUG3, MOD_PROXY_VERSION
            ": error preparing database for ProxyReverseConnectPolicy "
            "RoundRobin: %s", strerror(xerrno));
        }
        break;
      }

      case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
        if (backends != NULL) {
          res = reverse_db_shuffle_init(p, s->sid, backends);
          if (res < 0) {
            xerrno = errno;
            pr_log_debug(DEBUG3, MOD_PROXY_VERSION
              ": error preparing database for ProxyReverseConnectPolicy "
              "Shuffle: %s", strerror(xerrno));
          }
        }
        break;

      case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
        if (!(opts & PROXY_OPT_USE_REVERSE_PROXY_AUTH)) {
          pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
            ": PerGroup ProxyReverseConnectPolicy for server '%s' requires the "
            "UseReverseProxyAuth ProxyOption", s->ServerName);
          errno = EPERM;
          return -1;
        }
        break;

      default:
        break;
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
      -1, -1);
    if (res < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error updating backend ID %d: %s", reverse_backend_id,
        strerror(errno));
    }
  }

  return 0;
}

static int set_reverse_flags(void) {
  if (proxy_opts & PROXY_OPT_USE_REVERSE_PROXY_AUTH) {
    reverse_flags = PROXY_REVERSE_FL_CONNECT_AT_PASS;

  } else {
    if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_USER) {
      reverse_flags = PROXY_REVERSE_FL_CONNECT_AT_USER;

    } else if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_GROUP) {
      /* Incompatible configuration: PerGroup balancing requires that the USER
       * name be authenticated, in order to discovery the primary group name.
       */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "ReverseProxyConnectPolicy PerGroup requires the UseReverseProxyAuth ProxyOption, rejecting connection due to incompatible configuration");
      pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
        ": ReverseProxyConnectPolicy PerGroup requires the UseReverseProxyAuth ProxyOption, rejecting connection due to incompatible configuration");
      errno = EINVAL;
      return -1;

    } else {
      reverse_flags = PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT;
    }
  }

  return 0;
}

int proxy_reverse_sess_free(pool *p, struct proxy_session *proxy_sess) {
  /* Reset any state. */

  reverse_backends = NULL;
  reverse_backend_id = -1;
  reverse_connect_policy = PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;
  reverse_flags = 0UL;
  reverse_retry_count = PROXY_DEFAULT_RETRY_COUNT;

  proxy_db_close(p, PROXY_REVERSE_DB_SCHEMA_NAME);
  return 0;
}

int proxy_reverse_sess_init(pool *p, const char *tables_dir,
    struct proxy_session *proxy_sess) {
  int res, xerrno = 0;
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

  /* Make sure we have our own per-session database handle, per SQLite3
   * recommendation.
   */
  PRIVS_ROOT
  res = proxy_db_open_with_version(proxy_pool, reverse_db_path,
    PROXY_REVERSE_DB_SCHEMA_NAME, PROXY_REVERSE_DB_SCHEMA_VERSION, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error opening database '%s' for schema '%s', version %u: %s",
      reverse_db_path, PROXY_REVERSE_DB_SCHEMA_NAME,
      PROXY_REVERSE_DB_SCHEMA_VERSION, strerror(xerrno));
  }

  if (set_reverse_flags() < 0) {
    return -1;
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT) {
    res = reverse_connect(p, proxy_sess);
    if (res < 0) {
      return -1;
    }
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

static JsonNode *read_json_array(pool *p, pr_fh_t *fh, off_t filesz) {
  JsonNode *json = NULL;
  char *buf, *ptr;
  int res;
  off_t len;

  len = filesz;
  buf = ptr = palloc(p, len+1);
  buf[len] = '\0';

  res = pr_fsio_read(fh, buf, len);
  while (res != len) {
    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        res = pr_fsio_read(fh, buf, len);
        continue;
      }

      return NULL;
    }

    if (res == 0) {
      /* EOF, but we shouldn't reach this. */
      pr_trace_msg(trace_channel, 14,
        "unexpectedly reached EOF when reading '%s'", fh->fh_path);
      errno = EOF;
      return NULL;
    }

    /* Paranoia, paranoia...*/
    if (len > res) {
      errno = EIO;
      return NULL;
    }

    /* Short read: advance the buffer, decrement the length, and read more. */
    buf += res;
    len -= res; 

    pr_signals_handle();
    res = pr_fsio_read(fh, buf, len);
  }

  json = json_decode(ptr);
  if (json == NULL) {
    pr_trace_msg(trace_channel, 3,
      "invalid JSON format found in '%s'", fh->fh_path);
    errno = EINVAL;
    return NULL;
  }

  if (json->tag != JSON_ARRAY) {
    /* Not expected JSON format */
    pr_trace_msg(trace_channel, 3,
      "JSON array not found as expected in '%s'", fh->fh_path);
    errno = EINVAL;
    return NULL;
  }

  return json;
}

static char *read_json_string(JsonNode *node) {
  if (node == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (node->tag != JSON_STRING) {
    errno = EPERM;
    return NULL;
  }

  return node->string_;
}

array_header *proxy_reverse_json_parse_uris(pool *p, const char *path) {
  register unsigned int i;
  int reached_eol = FALSE, res, xerrno = 0;
  pr_fh_t *fh;
  array_header *uris = NULL;
  struct stat st;
  pool *tmp_pool;
  JsonNode *json = NULL;

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
    xerrno = errno;

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
    xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "unable to fstat '%s': %s", path, strerror(xerrno));
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return NULL;
  }

  if (st.st_size == 0) {
    /* Return an empty array for this empty file. */
    pr_trace_msg(trace_channel, 15,
      "found no items in empty file '%s'", fh->fh_path);

    (void) pr_fsio_close(fh);
    uris = make_array(p, 1, sizeof(struct proxy_conn *));
    return uris;
  }

  if (st.st_size > PROXY_REVERSE_JSON_MAX_FILE_SIZE) {
    pr_trace_msg(trace_channel, 1,
      "'%s' file size (%lu bytes) exceeds max JSON file size (%lu bytes)",
      path, (unsigned long) st.st_size,
      (unsigned long) PROXY_REVERSE_JSON_MAX_FILE_SIZE);
    (void) pr_fsio_close(fh);
    errno = EPERM;
    return NULL;
  }

  fh->fh_iosz = st.st_blksize;

  tmp_pool = make_sub_pool(p);
  json = read_json_array(tmp_pool, fh, st.st_size);
  xerrno = errno;

  (void) pr_fsio_close(fh);

  if (json == NULL) {
    pr_trace_msg(trace_channel, 1,
      "unable to read JSON array from '%s': %s", path, strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  uris = make_array(p, 1, sizeof(struct proxy_conn *));

  for (i = 0; i < PROXY_REVERSE_JSON_MAX_ITEMS; i++) {
    JsonNode *item;
    char *uri;
    struct proxy_conn *pconn;

    pr_signals_handle();

    item = json_find_element(json, i);
    if (item == NULL) {
      /* End of array reached. */
      reached_eol = TRUE;
      pr_trace_msg(trace_channel, 12,
        "found items (count %u) in JSON file '%s'", i, path);
      break;
    }

    uri = read_json_string(item);
    if (uri == NULL) {
      pr_trace_msg(trace_channel, 1,
        "error obtaining JSON string from item #%u in array: %s", i,
        strerror(errno));
      continue;
    }

    pconn = proxy_conn_create(p, uri);
    if (pconn == NULL) {
      pr_trace_msg(trace_channel, 9,
        "skipping malformed URL '%s' found in file '%s'", uri, path);
      continue;
    }

    *((struct proxy_conn **) push_array(uris)) = pconn;  
  }

  json_delete(json);
  destroy_pool(tmp_pool);

  if (reached_eol == FALSE) {
    pr_trace_msg(trace_channel, 3,
      "warning: skipped ProxyReverseServers '%s' data (only used "
      "first %u items)", path, i);
  }

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

  } else if (strncasecmp(policy, "PerGroup", 9) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_GROUP;

  } else if (strncasecmp(policy, "PerHost", 8) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_HOST;

  } else if (strncasecmp(policy, "LeastResponseTime", 18) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME;
  }

  errno = ENOENT;
  return -1;
}

static int send_user(struct proxy_session *proxy_sess, cmd_rec *cmd,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  char *orig_user;
  const char *uri_user;

  orig_user = cmd->arg;
  uri_user = proxy_conn_get_username(proxy_sess->dst_pconn);
  if (uri_user != NULL) {
    /* We have URI-specific USER name to use, instead of the client-provided
     * one.
     */
    pr_trace_msg(trace_channel, 18,
      "using URI-specific username '%s' instead of client-provided '%s'",
      uri_user, orig_user);
    cmd->argv[1] = cmd->arg = pstrdup(cmd->pool, uri_user);
  }

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  cmd->argv[1] = cmd->arg = orig_user;

  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Note that the response message may contain the per-URI user name we
   * sent; be sure to preserve the illusion, and re-write the response as
   * necessary.
   */
  if (uri_user != NULL) {
    /* TODO: handle the case where there are multiple response lines. */
    if (strstr(resp->msg, uri_user) != NULL) {
      resp->msg = sreplace(cmd->pool, resp->msg, uri_user, orig_user, NULL);
    }
  }

  if (resp->num[0] == '2' ||
      resp->num[0] == '3') {
    *successful = TRUE;

    if (strcmp(resp->num, R_232) == 0) {
      proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
      clear_user_creds();
      pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
    }
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return -1;
  }

  return 0;
}

int proxy_reverse_handle_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful, int *block_responses) {
  int res;

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_PASS) {
    /* If we're already connected, then proxy this USER command through to the
     * backend, otherwise we let the proftpd internals deal with it locally,
     * leading to proxy auth.
     */
    if (!(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED)) {
      *block_responses = FALSE;
      return 0;
    }
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_USER) {
    register unsigned int i;
    int connected = FALSE, xerrno = 0;

    for (i = 0; i < reverse_retry_count; i++) {
      pr_signals_handle();

      res = reverse_try_connect(proxy_pool, proxy_sess, cmd->arg);
      if (res == 0) {
        connected = TRUE;
        break;
      }

      xerrno = errno;
    }

    pr_response_block(FALSE);

    if (connected == FALSE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "ProxyRetryCount %d reached with no successful connection, failing",
        reverse_retry_count);
      *successful = FALSE;

      if (xerrno != EINVAL) {
        errno = EPERM;
      } else {
        errno = xerrno;
      }

      return -1;
    }
  }

  res = send_user(proxy_sess, cmd, successful);
  if (res < 0) {
    return -1;
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_USER) {
    /* Restore the normal response blocking, undone for the PerUser policy. */
    pr_response_block(TRUE);
  }

  return 1;
}

static int send_pass(struct proxy_session *proxy_sess, cmd_rec *cmd,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  const char *uri_user, *uri_pass;
  char *orig_pass;

  orig_pass = cmd->arg;
  uri_user = proxy_conn_get_username(proxy_sess->dst_pconn);
  uri_pass = proxy_conn_get_password(proxy_sess->dst_pconn);
  if (uri_pass != NULL) {
    /* We have URI-specific password to use, instead of the client-provided
     * one.
     */
    pr_trace_msg(trace_channel, 18,
      "using URI-specific password instead of client-provided one");
    cmd->argv[1] = cmd->arg = pstrdup(cmd->pool, uri_pass);
  }

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  cmd->argv[1] = cmd->arg = orig_pass;

  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    /* If we receive an EPERM here, it is probably because the backend
     * closed its control connection, yielding an EOF.  To better indicate
     * this situation, propagate the error using EPIPE.
     */
    if (xerrno == EPERM) {
      xerrno = EPIPE;
    }

    errno = xerrno;
    return -1;
  }

  /* Note that the response message may contain the per-URI user name we
   * sent; be sure to preserve the illusion, and re-write the response as
   * necessary.
   */
  if (uri_user != NULL) {
    char *orig_user;

    orig_user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);

    /* TODO: handle the case where there are multiple response lines. */
    if (strstr(resp->msg, uri_user) != NULL) {
      resp->msg = sreplace(cmd->pool, resp->msg, uri_user, orig_user, NULL);
    }
  }

  /* XXX What about other response codes for PASS? */
  if (resp->num[0] == '2') {
    *successful = TRUE;

    proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
    clear_user_creds();
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

  return 0;
}

int proxy_reverse_handle_pass(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful, int *block_responses) {
  int res, xerrno;

  /* This CONNECT_AT_PASS flag indicates that we are using proxy auth when
   * reverse proxying.
   */
  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_PASS) {
    if (!(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED)) {
      char *user = NULL;

      user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      res = proxy_session_check_password(cmd->pool, user, cmd->arg);
      if (res < 0) {
        errno = EINVAL;
        return -1;
      }

      res = proxy_session_setup_env(proxy_pool, user,
        PROXY_SESSION_FL_CHECK_LOGIN_ACL);
      if (res < 0) {
        errno = EINVAL;
        return -1;
      }

      if (session.auth_mech) {
        pr_log_debug(DEBUG2, "user '%s' authenticated by %s", user,
          session.auth_mech);
      }
    }

    if (!(proxy_sess_state & PROXY_SESS_STATE_CONNECTED)) {
      register unsigned int i;
      int connected = FALSE;
      char *user = NULL, *connect_name = NULL;
      cmd_rec *user_cmd;

      /* If we're using a sticky policy, we need to know the USER name that was
       * sent.
       */
      if (reverse_policy_is_sticky(reverse_connect_policy) == TRUE) {
        user = connect_name = pr_table_get(session.notes, "mod_auth.orig-user",
          NULL);

        /* If the sticky policy in question is PerGroup, then we also need
         * to know the authenticated user's primary group name.
         */
        if (proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED) {
          if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_GROUP) {
            connect_name = session.group;
          }
        }
      }

      for (i = 0; i < reverse_retry_count; i++) {
        pr_signals_handle();

        res = reverse_try_connect(proxy_pool, proxy_sess, connect_name);
        if (res == 0) {
          connected = TRUE;
          break;
        }

        xerrno = errno;
      }

      pr_response_block(FALSE);

      if (connected == FALSE) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "ProxyRetryCount %d reached with no successful connection, failing",
          reverse_retry_count);
        *successful = FALSE;

        if (xerrno != EINVAL) {
          errno = EPERM;
        } else {
          errno = xerrno;
        }

        return -1;
      }

      if (user == NULL) {
        user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      }

      user_cmd = pr_cmd_alloc(cmd->tmp_pool, 2, C_USER, user);
      user_cmd->arg = pstrdup(cmd->tmp_pool, user);

      /* Since we're replaying the USER command here, we want to make sure
       * that the USER response from the backend isn't played back to the
       * frontend client.
       */
      pr_response_block(TRUE);
      res = send_user(proxy_sess, user_cmd, successful);
      xerrno = errno;
      pr_response_block(FALSE);

      if (res < 0) {
        errno = xerrno;
        return -1;
      }
    }
  }

  res = send_pass(proxy_sess, cmd, successful);
  if (res < 0) {
    return -1;
  }

  if (reverse_flags != PROXY_REVERSE_FL_CONNECT_AT_PASS &&
      *successful == TRUE) {
    char *user = NULL;

    /* If we're not using proxy auth, still make sure that everything is
     * set up properly.
     */

    user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    res = proxy_session_setup_env(proxy_pool, user, 0);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }
  }

  return 1;
}
