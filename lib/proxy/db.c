/*
 * ProFTPD - mod_proxy database implementation
 * Copyright (c) 2015-2017 TJ Saunders
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

#include <sqlite3.h>

struct proxy_dbh {
  pool *pool;
  sqlite3 *db;
  const char *schema;
  pr_table_t *prepared_stmts;
};

static const char *current_schema = NULL;

static const char *trace_channel = "proxy.db";

#define PROXY_DB_SQLITE_TRACE_LEVEL		17

static int db_busy(void *user_data, int busy_count) {
  if (current_schema != NULL) {
    pr_trace_msg(trace_channel, 1, "(sqlite3): schema '%s': busy count = %d",
      current_schema, busy_count);

  } else {
    pr_trace_msg(trace_channel, 1, "(sqlite3): busy count = %d", busy_count);
  }

  return 0;
}

static void db_err(void *user_data, int err_code, const char *err_msg) {
  if (current_schema != NULL) {
    pr_trace_msg(trace_channel, 1, "(sqlite3): schema '%s': [error %d] %s",
      current_schema, err_code, err_msg);

  } else {
    pr_trace_msg(trace_channel, 1, "(sqlite3): [error %d] %s", err_code,
      err_msg);
  }
}

#ifdef SQLITE_CONFIG_SQLLOG
static void db_sql(void *user_data, sqlite3 *db, const char *info,
    int event_type) {
  switch (event_type) {
    case 0:
      /* Opening database. */
      pr_trace_msg(trace_channel, 1, "(sqlite3): opened database: %s", info);
      break;

    case 1:
      if (current_schema != NULL) {
        pr_trace_msg(trace_channel, 1,
          "(sqlite3): schema '%s': executed statement: %s", current_schema,
          info);

      } else {
        pr_trace_msg(trace_channel, 1, "(sqlite3): executed statement: %s",
          info);
      }
      break;

    case 2:
      /* Closing database. */
      pr_trace_msg(trace_channel, 1, "(sqlite3): closed database: %s",
        sqlite3_db_filename(db, "main"));
      break;
  }
}
#endif /* SQLITE_CONFIG_SQLLOG */

static void db_trace(void *user_data, const char *trace_msg) {
  if (user_data != NULL) {
    const char *schema;

    schema = user_data;
    pr_trace_msg(trace_channel, PROXY_DB_SQLITE_TRACE_LEVEL,
      "(sqlite3): schema '%s': %s", schema, trace_msg);

  } else {
    pr_trace_msg(trace_channel, PROXY_DB_SQLITE_TRACE_LEVEL,
      "(sqlite3): %s", trace_msg);
  }
}

static int stmt_cb(void *v, int ncols, char **cols, char **col_names) {
  register int i;
  const char *stmt;

  stmt = v;
  pr_trace_msg(trace_channel, 9, "results for '%s':", stmt);

  for (i = 0; i < ncols; i++) {
    pr_trace_msg(trace_channel, 9, "col #%d [%s]: %s", i+1,
      col_names[i], cols[i]);
  }

  return 0;
}

int proxy_db_exec_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt,
    const char **errstr) {
  int res;
  char *ptr = NULL;
  unsigned int nretries = 0;

  if (dbh == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 10, "schema '%s': executing statement '%s'",
    dbh->schema, stmt);

  current_schema = dbh->schema;
  res = sqlite3_exec(dbh->db, stmt, stmt_cb, (void *) stmt, &ptr);
  while (res != SQLITE_OK) {
    if (res == SQLITE_BUSY) {
      struct timeval tv;

      sqlite3_free(ptr);

      nretries++;
      pr_trace_msg(trace_channel, 3,
       "attempt #%u, database busy, trying '%s' again", nretries, stmt);

      /* Sleep for short bit, then try again. */
      tv.tv_sec = 0;
      tv.tv_usec = 500000L;

      if (select(0, NULL, NULL, NULL, &tv) < 0) {
        if (errno == EINTR) {
          pr_signals_handle();
        }
      }

      res = sqlite3_exec(dbh->db, stmt, NULL, NULL, &ptr);
      continue;
    }

    pr_trace_msg(trace_channel, 1,
      "error executing '%s': (%d) %s", stmt, res, ptr);

    if (errstr != NULL) {
      *errstr = pstrdup(p, ptr);
    }

    current_schema = NULL;
    sqlite3_free(ptr);
    errno = EINVAL;
    return -1;
  }

  if (ptr != NULL) {
    sqlite3_free(ptr);
  }

  current_schema = NULL;
  pr_trace_msg(trace_channel, 13, "successfully executed '%s'", stmt);
  return 0;
}

/* Prepared statements */

int proxy_db_prepare_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt) {
  sqlite3_stmt *pstmt = NULL;
  int res;

  if (p == NULL ||
      dbh == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(dbh->prepared_stmts, stmt, NULL);
  if (pstmt != NULL) {
    res = sqlite3_reset(pstmt);
    if (res != SQLITE_OK) {
      pr_trace_msg(trace_channel, 3,
        "error resetting prepared statement '%s': %s", stmt,
        sqlite3_errmsg(dbh->db));
      errno = EPERM;
      return -1;
    }

    return 0;
  }

  res = sqlite3_prepare_v2(dbh->db, stmt, -1, &pstmt, NULL);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 4,
      "schema '%s': error preparing statement '%s': %s", dbh->schema, stmt,
      sqlite3_errmsg(dbh->db));
    errno = EINVAL;
    return -1;
  }

  /* The prepared statement handling here relies on this cache, thus if we fail
   * to stash the prepared statement here, it will cause problems later.
   */
  res = pr_table_add(dbh->prepared_stmts, pstrdup(dbh->pool, stmt), pstmt,
    sizeof(sqlite3_stmt *));
  if (res < 0) {
    int xerrno = errno;
    pr_trace_msg(trace_channel, 4,
      "error stashing prepared statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1; 
  }

  return 0; 
}

int proxy_db_bind_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt,
    int idx, int type, void *data) {
  sqlite3_stmt *pstmt;
  int res;
 
  if (p == NULL ||
      dbh == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* SQLite3 bind parameters start at index 1. */
  if (idx < 1) {
    errno = EINVAL;
    return -1;
  }

  if (dbh->prepared_stmts == NULL) {
    errno = ENOENT;
    return -1;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(dbh->prepared_stmts, stmt, NULL);
  if (pstmt == NULL) {
    pr_trace_msg(trace_channel, 19,
      "unable to find prepared statement for '%s'", stmt);
    errno = ENOENT;
    return -1;
  }

  switch (type) {
    case PROXY_DB_BIND_TYPE_INT: {
      int i;

      if (data == NULL) {
        errno = EINVAL;
        return -1;
      }

      i = *((int *) data);
      res = sqlite3_bind_int(pstmt, idx, i);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to INT %d: %s", idx, stmt, i,
          sqlite3_errmsg(dbh->db));
        errno = EPERM;
        return -1;
      }
      break;
    }

    case PROXY_DB_BIND_TYPE_LONG: {
      long l;

      if (data == NULL) {
        errno = EINVAL;
        return -1;
      }

      l = *((long *) data);
      res = sqlite3_bind_int(pstmt, idx, l);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to LONG %ld: %s", idx, stmt, l,
          sqlite3_errmsg(dbh->db));
        errno = EPERM;
        return -1;
      }
      break;
    }

    case PROXY_DB_BIND_TYPE_TEXT: {
      const char *text;

      if (data == NULL) {
        errno = EINVAL;
        return -1;
      }

      text = (const char *) data;
      res = sqlite3_bind_text(pstmt, idx, text, -1, NULL);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to TEXT '%s': %s", idx, stmt,
          text, sqlite3_errmsg(dbh->db));
        errno = EPERM;
        return -1;
      }
      break;
    }

    case PROXY_DB_BIND_TYPE_NULL:
      res = sqlite3_bind_null(pstmt, idx);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to NULL: %s", idx, stmt,
          sqlite3_errmsg(dbh->db));
        errno = EPERM;
        return -1;
      }
      break;

    default:
      pr_trace_msg(trace_channel, 2,
        "unknown/unsupported bind data type %d", type);
      errno = EINVAL;
      return -1;
  }

  return 0;
}

int proxy_db_finish_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt) {
  sqlite3_stmt *pstmt;
  int res;

  if (p == NULL ||
      dbh == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (dbh->prepared_stmts == NULL) {
    errno = ENOENT;
    return -1;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(dbh->prepared_stmts, stmt, NULL);
  if (pstmt == NULL) {
    pr_trace_msg(trace_channel, 19,
      "unable to find prepared statement for '%s'", stmt);
    errno = ENOENT;
    return -1;
  }

  res = sqlite3_finalize(pstmt);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 3,
      "schema '%s': error finishing prepared statement '%s': %s", dbh->schema,
      stmt, sqlite3_errmsg(dbh->db));
    errno = EPERM;
    return -1;
  }

  (void) pr_table_remove(dbh->prepared_stmts, stmt, NULL); 
  return 0;
}

array_header *proxy_db_exec_prepared_stmt(pool *p, struct proxy_dbh *dbh,
    const char *stmt, const char **errstr) {
  sqlite3_stmt *pstmt;
  int readonly = FALSE, res;
  array_header *results = NULL;

  if (p == NULL ||
      dbh == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (dbh->prepared_stmts == NULL) {
    errno = ENOENT;
    return NULL;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(dbh->prepared_stmts, stmt, NULL);
  if (pstmt == NULL) {
    pr_trace_msg(trace_channel, 19,
      "unable to find prepared statement for '%s'", stmt);
    errno = ENOENT;
    return NULL;
  }

  current_schema = dbh->schema;

  readonly = sqlite3_stmt_readonly(pstmt);
  if (!readonly) {
    /* Assume this is an INSERT/UPDATE/DELETE. */
    res = sqlite3_step(pstmt);
    if (res != SQLITE_DONE) {
      const char *errmsg;

      errmsg = sqlite3_errmsg(dbh->db);
      if (errstr) {
        *errstr = pstrdup(p, errmsg);
      }
      pr_trace_msg(trace_channel, 2,
        "error executing '%s': %s", stmt, errmsg);

      current_schema = NULL;
      errno = EPERM;
      return NULL;
    }

    current_schema = NULL;

    /* Indicate success for non-readonly statements by returning an empty
     * result set.
     */
    pr_trace_msg(trace_channel, 13, "successfully executed '%s'", stmt);
    results = make_array(p, 0, sizeof(char *));
    return results;
  }

  results = make_array(p, 0, sizeof(char *));

  res = sqlite3_step(pstmt);
  while (res == SQLITE_ROW) {
    register int i;
    int ncols;

    ncols = sqlite3_column_count(pstmt);
    pr_trace_msg(trace_channel, 12,
      "schema '%s': executing prepared statement '%s' returned row "
      "(columns: %d)", dbh->schema, stmt, ncols);

    for (i = 0; i < ncols; i++) {
      char *val = NULL;

      pr_signals_handle();

      /* By using sqlite3_column_text, SQLite will coerce the column value
       * into a string.
       */
      val = pstrdup(p, (const char *) sqlite3_column_text(pstmt, i));

      pr_trace_msg(trace_channel, 17,
        "column %s [%u]: %s", sqlite3_column_name(pstmt, i), i, val);
      *((char **) push_array(results)) = val;
    }

    res = sqlite3_step(pstmt);
  }

  if (res != SQLITE_DONE) {
    const char *errmsg;

    errmsg = sqlite3_errmsg(dbh->db);
    if (errstr != NULL) {
      *errstr = pstrdup(p, errmsg);
    }

    current_schema = NULL;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "schema '%s': executing prepared statement '%s' did not complete "
      "successfully: %s", dbh->schema, stmt, errmsg);
    errno = EPERM;
    return NULL;
  }

  current_schema = NULL;
  pr_trace_msg(trace_channel, 13, "successfully executed '%s'", stmt);
  return results;
}

/* Database opening/closing. */

struct proxy_dbh *proxy_db_open(pool *p, const char *table_path,
    const char *schema_name) {
  int res, flags;
  pool *sub_pool;
  const char *stmt;
  sqlite3 *db = NULL;
  struct proxy_dbh *dbh;

  if (p == NULL ||
      table_path == NULL ||
      schema_name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 19, "attempting to open %s tables at path '%s'",
    schema_name, table_path);

  flags = SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE;
#ifdef SQLITE_OPEN_PRIVATECACHE
  /* By default, disable the shared cache mode. */
  flags |= SQLITE_OPEN_PRIVATECACHE;
#endif

  res = sqlite3_open_v2(table_path, &db, flags, NULL);
  if (res != SQLITE_OK) {
    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error opening SQLite database '%s': %s", table_path,
      sqlite3_errmsg(db));
    if (db != NULL) {
      sqlite3_close(db);
    }
    errno = EPERM;
    return NULL;
  }

  if (pr_trace_get_level(trace_channel) >= PROXY_DB_SQLITE_TRACE_LEVEL) {
    sqlite3_busy_handler(db, db_busy, (void *) schema_name);
    sqlite3_trace(db, db_trace, (void *) schema_name);
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "Proxy Database Pool");
  dbh = pcalloc(sub_pool, sizeof(struct proxy_dbh));
  dbh->pool = sub_pool;
  dbh->db = db;
  dbh->schema = pstrdup(dbh->pool, schema_name);

  stmt = "PRAGMA temp_store = MEMORY;";
  res = proxy_db_exec_stmt(p, dbh, stmt, NULL);
  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
      "error setting MEMORY temp store on SQLite database '%s': %s",
      table_path, sqlite3_errmsg(dbh->db));
  }

  /* Tell SQLite to only use in-memory journals.  This is necessary for
   * working properly when a chroot is used.  Note that the MEMORY journal mode
   * of SQLite is supported only for SQLite-3.6.5 and later.
   */

  stmt = "PRAGMA journal_mode = MEMORY;";
  res = proxy_db_exec_stmt(p, dbh, stmt, NULL);
  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
      "error setting MEMORY journal mode on SQLite database '%s': %s",
      table_path, sqlite3_errmsg(dbh->db));
  }

  dbh->prepared_stmts = pr_table_nalloc(dbh->pool, 0, 4);
  pr_trace_msg(trace_channel, 9, "opened SQLite table '%s'", table_path);

  return dbh;
}

static int get_schema_version(pool *p, struct proxy_dbh *dbh,
    const char *schema_name, unsigned int *schema_version) {
  int res, version;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "SELECT version FROM schema_version WHERE schema = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    /* This can happen when the schema_version table does not exist; treat
     * as "missing".
     */
    pr_trace_msg(trace_channel, 5,
      "error preparing statement '%s', treating as missing schema version",
      stmt);
    *schema_version = 0;
    return 0;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_TEXT,
    (void *) schema_name);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    *schema_version = 0;
    return 0;
  }

  if (results->nelts != 1) {
    pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": expected 1 result from statement '%s', got %d", stmt,
      results->nelts);
    errno = EINVAL;
    return -1;
  }

  version = atoi(((char **) results->elts)[0]);
  if (version < 0) {
    /* Invalid schema version; treat as "missing". */
    pr_trace_msg(trace_channel, 5,
      "statement '%s' yielded invalid schema version %d, treating as missing",
      stmt, version);
    *schema_version = 0;
    return 0;
  }

  *schema_version = version;
  return 0;
}

static int set_schema_version(pool *p, struct proxy_dbh *dbh,
    const char *schema_name, unsigned int schema_version) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* CREATE TABLE schema_version (
   *   schema TEXT NOT NULL PRIMARY KEY,
   *   version INTEGER NOT NULL
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS schema_version (schema TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error executing statement '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "INSERT INTO schema_version (schema, version) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    xerrno = errno;

    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": schema '%s': error preparing statement '%s': %s", dbh->schema, stmt,
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_TEXT,
    (void *) schema_name);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &schema_version);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error executing statement '%s': %s", stmt,
      errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static void check_db_integrity(pool *p, struct proxy_dbh *dbh, int flags) {
  int res;
  const char *stmt, *errstr = NULL;

  if (!(flags & PROXY_DB_OPEN_FL_SKIP_INTEGRITY_CHECK)) {
    stmt =  "PRAGMA integrity_check;";
    res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
    if (res < 0) {
      (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
        ": error executing statement '%s': %s", stmt, errstr);
    }
  }

  if (!(flags & PROXY_DB_OPEN_FL_SKIP_VACUUM)) {
    stmt = "VACUUM;";
    res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
    if (res < 0) {
      (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
        ": error executing statement '%s': %s", stmt, errstr);
    }
  }
}

struct proxy_dbh *proxy_db_open_with_version(pool *p, const char *table_path,
    const char *schema_name, unsigned int schema_version, int flags) {
  pool *tmp_pool;
  struct proxy_dbh *dbh;
  int res, xerrno = 0;
  unsigned int current_version = 0;

  dbh = proxy_db_open(p, table_path, schema_name);
  if (dbh == NULL) {
    return NULL;
  }

  pr_trace_msg(trace_channel, 19,
    "ensuring that schema at path '%s' has at least schema version %u",
    table_path, schema_version);

  tmp_pool = make_sub_pool(p);
  res = get_schema_version(tmp_pool, dbh, schema_name, &current_version);
  if (res < 0) {
    xerrno = errno;

    proxy_db_close(p, dbh);
    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  if (current_version >= schema_version) {
    pr_trace_msg(trace_channel, 11,
      "schema version %u >= desired version %u for path '%s'",
      current_version, schema_version, table_path);

    check_db_integrity(tmp_pool, dbh, flags);
    destroy_pool(tmp_pool);

    return dbh;
  }

  if (flags & PROXY_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW) {
    pr_trace_msg(trace_channel, 5,
      "schema version %u < desired version %u for path '%s', failing",
      current_version, schema_version, table_path);
    proxy_db_close(p, dbh);
    destroy_pool(tmp_pool);
    errno = EPERM;
    return NULL;
  }

  /* The schema version is skewed; delete the old table, create a new one. */
  pr_trace_msg(trace_channel, 4,
    "schema version %u < desired version %u for path '%s', deleting file",
    current_version, schema_version, table_path);

  proxy_db_close(p, dbh);
  if (unlink(table_path) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error deleting '%s': %s", table_path, strerror(errno));
  }

  dbh = proxy_db_open(p, table_path, schema_name);
  if (dbh == NULL) {
    xerrno = errno;

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  res = set_schema_version(tmp_pool, dbh, schema_name, schema_version);
  xerrno = errno;

  destroy_pool(tmp_pool);

  if (res < 0) {
    errno = xerrno;
    return NULL;
  }

  return dbh;
}

int proxy_db_close(pool *p, struct proxy_dbh *dbh) {
  pool *tmp_pool;
  sqlite3_stmt *pstmt;
  int res;

  if (p == NULL ||
      dbh == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 19, "closing '%s' database handle", dbh->schema);
  tmp_pool = make_sub_pool(p);

  /* Make sure to close/finish any prepared statements associated with
   * the database.
   */
  pstmt = sqlite3_next_stmt(dbh->db, NULL);
  while (pstmt != NULL) {
    sqlite3_stmt *next;
    const char *sql;

    pr_signals_handle();

    next = sqlite3_next_stmt(dbh->db, pstmt);
    sql = pstrdup(tmp_pool, sqlite3_sql(pstmt));

    res = sqlite3_finalize(pstmt);
    if (res != SQLITE_OK) {
      pr_trace_msg(trace_channel, 2,
        "schema '%s': error finishing prepared statement '%s': %s", dbh->schema,
        sql, sqlite3_errmsg(dbh->db));

    } else {
      pr_trace_msg(trace_channel, 18, "finished prepared statement '%s'", sql);
    }

    pstmt = next;
  }

  destroy_pool(tmp_pool);

  res = sqlite3_close(dbh->db);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 2,
      "error closing SQLite database: %s", sqlite3_errmsg(dbh->db));
    errno = EPERM;
    return -1;
  }

  pr_table_empty(dbh->prepared_stmts);
  pr_table_free(dbh->prepared_stmts);
  destroy_pool(dbh->pool);

  pr_trace_msg(trace_channel, 18, "%s", "closed SQLite database");
  return 0;
}

int proxy_db_reindex(pool *p, struct proxy_dbh *dbh, const char *index_name,
    const char **errstr) {
  int res;
  const char *stmt;

  if (p == NULL ||
      dbh == NULL ||
      index_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  stmt = pstrcat(p, "REINDEX ", index_name, ";", NULL);
  res = proxy_db_exec_stmt(p, dbh, stmt, errstr);
  return res;
}

int proxy_db_init(pool *p) {
  const char *version;

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Register an error logging callback with SQLite3. */
  sqlite3_config(SQLITE_CONFIG_LOG, db_err, NULL);
#ifdef SQLITE_CONFIG_SQLLOG
  sqlite3_config(SQLITE_CONFIG_SQLLOG, db_sql, NULL);
#endif /* SQLITE_CONFIG_SQLLOG */

  /* Check that the SQLite headers used match the version of the SQLite
   * library used.
   *
   * For now, we only log if there is a difference.
   */
  version = sqlite3_libversion();
  if (strcmp(version, SQLITE_VERSION) != 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "compiled using SQLite version '%s' headers, but linked to "
      "SQLite version '%s' library", SQLITE_VERSION, version);
  }

  pr_trace_msg(trace_channel, 9, "using SQLite %s", version);
  return 0;
}

int proxy_db_free(void) {
  return 0;
}
