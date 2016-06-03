/*
 * ProFTPD - mod_proxy database implementation
 * Copyright (c) 2015-2016 TJ Saunders
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

static pool *db_pool = NULL;
static pr_table_t *prepared_stmts = NULL;
static sqlite3 *proxy_dbh = NULL;

static const char *trace_channel = "proxy.db";

#define PROXY_DB_SQLITE_TRACE_LEVEL		17

static void db_err(void *user_data, int err_code, const char *err_msg) {
  pr_trace_msg(trace_channel, 1, "(sqlite3): [error %d] %s", err_code,
    err_msg);
}

static void db_trace(void *user_data, const char *trace_msg) {
  pr_trace_msg(trace_channel, PROXY_DB_SQLITE_TRACE_LEVEL,
    "(sqlite3): %s", trace_msg);
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

int proxy_db_exec_stmt(pool *p, const char *stmt, const char **errstr) {
  int res;
  char *ptr = NULL;
  unsigned int nretries = 0;

  if (p == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (proxy_dbh == NULL) {
    pr_trace_msg(trace_channel, 3,
      "unable to execute statement '%s': no open database handle", stmt);
    errno = EPERM;
    return -1;
  }

  res = sqlite3_exec(proxy_dbh, stmt, stmt_cb, (void *) stmt, &ptr);
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

      res = sqlite3_exec(proxy_dbh, stmt, NULL, NULL, &ptr);
      continue;
    }

    pr_trace_msg(trace_channel, 1,
      "error executing '%s': (%d) %s", stmt, res, ptr);

    if (errstr != NULL) {
      *errstr = pstrdup(p, ptr);
    }

    sqlite3_free(ptr);
    errno = EINVAL;
    return -1;
  }

  if (ptr != NULL) {
    sqlite3_free(ptr);
  }

  pr_trace_msg(trace_channel, 13, "successfully executed '%s'", stmt);
  return 0;
}

/* Prepared statements */

int proxy_db_prepare_stmt(pool *p, const char *stmt) {
  sqlite3_stmt *pstmt = NULL;
  int res;

  if (p == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (proxy_dbh == NULL) {
    pr_trace_msg(trace_channel, 3,
      "unable to prepare statement '%s': no open database handle", stmt);
    errno = EPERM;
    return -1;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(prepared_stmts, stmt, NULL);
  if (pstmt != NULL) {
    res = sqlite3_reset(pstmt);
    if (res != SQLITE_OK) {
      pr_trace_msg(trace_channel, 3,
        "error resetting prepared statement '%s': %s", stmt,
        sqlite3_errmsg(proxy_dbh));
      errno = EPERM;
      return -1;
    }

    return 0;
  }

  res = sqlite3_prepare_v2(proxy_dbh, stmt, -1, &pstmt, NULL);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 4,
      "error preparing statement '%s': %s", stmt, sqlite3_errmsg(proxy_dbh));
    errno = EINVAL;
    return -1;
  }

  /* The prepared statement handling here relies on this cache, thus if we fail
   * to stash the prepared statement here, it will cause problems later.
   */
  res = pr_table_add(prepared_stmts, pstrdup(db_pool, stmt), pstmt,
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

int proxy_db_bind_stmt(pool *p, const char *stmt, int idx, int type,
    void *data) {
  sqlite3_stmt *pstmt;
  int res;
 
  if (p == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* SQLite3 bind parameters start at index 1. */
  if (idx < 1) {
    errno = EINVAL;
    return -1;
  }

  if (prepared_stmts == NULL) {
    errno = ENOENT;
    return -1;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(prepared_stmts, stmt, NULL);
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
          sqlite3_errmsg(proxy_dbh));
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
          sqlite3_errmsg(proxy_dbh));
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
          text, sqlite3_errmsg(proxy_dbh));
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
          sqlite3_errmsg(proxy_dbh));
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

int proxy_db_finish_stmt(pool *p, const char *stmt) {
  sqlite3_stmt *pstmt;
  int res;

  if (p == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (prepared_stmts == NULL) {
    errno = ENOENT;
    return -1;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(prepared_stmts, stmt, NULL);
  if (pstmt == NULL) {
    pr_trace_msg(trace_channel, 19,
      "unable to find prepared statement for '%s'", stmt);
    errno = ENOENT;
    return -1;
  }

  res = sqlite3_finalize(pstmt);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 3,
      "error finishing prepared statement '%s': %s", stmt,
      sqlite3_errmsg(proxy_dbh));
    errno = EPERM;
    return -1;
  }

  (void) pr_table_remove(prepared_stmts, stmt, NULL); 
  return 0;
}

array_header *proxy_db_exec_prepared_stmt(pool *p, const char *stmt,
    const char **errstr) {
  sqlite3_stmt *pstmt;
  int readonly = FALSE, res;
  array_header *results = NULL;

  if (p == NULL ||
      stmt == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (proxy_dbh == NULL) {
    pr_trace_msg(trace_channel, 3,
      "unable to execute prepared statement '%s': no open database handle",
      stmt);
    errno = EPERM;
    return NULL;
  }

  if (prepared_stmts == NULL) {
    errno = ENOENT;
    return NULL;
  }

  pstmt = (sqlite3_stmt *) pr_table_get(prepared_stmts, stmt, NULL);
  if (pstmt == NULL) {
    pr_trace_msg(trace_channel, 19,
      "unable to find prepared statement for '%s'", stmt);
    errno = ENOENT;
    return NULL;
  }

  readonly = sqlite3_stmt_readonly(pstmt);
  if (!readonly) {
    /* Assume this is an INSERT/UPDATE/DELETE. */
    res = sqlite3_step(pstmt);
    if (res != SQLITE_DONE) {
      const char *errmsg;

      errmsg = sqlite3_errmsg(proxy_dbh);
      if (errstr) {
        *errstr = pstrdup(p, errmsg);
      }
      pr_trace_msg(trace_channel, 2,
        "error executing '%s': %s", stmt, errmsg);
      errno = EPERM;
      return NULL;
    }

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
      "executing prepared statement '%s' returned row (columns: %d)",
      stmt, ncols);

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

    errmsg = sqlite3_errmsg(proxy_dbh);
    if (errstr != NULL) {
      *errstr = pstrdup(p, errmsg);
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "executing prepared statement '%s' did not complete successfully: %s",
      stmt, errmsg);
    errno = EPERM;
    return NULL;
  }

  pr_trace_msg(trace_channel, 13, "successfully executed '%s'", stmt);
  return results;
}

/* Database opening/closing. */

int proxy_db_open(pool *p, const char *table_path, const char *schema_name) {
  int res;
  pool *tmp_pool;
  const char *stmt;

  if (p == NULL ||
      table_path == NULL ||
      schema_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* If we already have a database handle open, then attach the given
   * path to our handle.  Otherwise, open/create the database file first.
   */

  if (proxy_dbh == NULL) {
    res = sqlite3_open(table_path, &proxy_dbh);
    if (res != SQLITE_OK) {
      pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": error opening SQLite database '%s': %s", table_path,
        sqlite3_errmsg(proxy_dbh));
      errno = EPERM;
      return -1;
    }

    res = sqlite3_exec(proxy_dbh, "PRAGMA temp_store = MEMORY;", NULL, NULL,
      NULL);
    if (res != SQLITE_OK) {
      pr_trace_msg(trace_channel, 2,
        "error setting MEMORY temp store on SQLite database '%s': %s",
        table_path, sqlite3_errmsg(proxy_dbh));
    }

    if (pr_trace_get_level(trace_channel) >= PROXY_DB_SQLITE_TRACE_LEVEL) {
      sqlite3_trace(proxy_dbh, db_trace, NULL);
    }

    prepared_stmts = pr_table_nalloc(db_pool, 0, 4);

    pr_trace_msg(trace_channel, 9, "opened SQLite table '%s' (schema '%s')",
      table_path, schema_name);
  }

  tmp_pool = make_sub_pool(p);

  stmt = pstrcat(tmp_pool, "ATTACH DATABASE '", table_path, "' AS ",
    schema_name, ";", NULL);
  res = sqlite3_exec(proxy_dbh, stmt, NULL, NULL, NULL);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 2,
      "error attaching database '%s' (as '%s') to existing SQLite handle "
      "using '%s': %s", table_path, schema_name, stmt,
      sqlite3_errmsg(proxy_dbh));
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  /* Tell SQLite to only use in-memory journals.  This is necessary for
   * working properly when a chroot is used.  Note that the MEMORY journal mode
   * of SQLite is supported only for SQLite-3.6.5 and later.
   */

  stmt = pstrcat(p, "PRAGMA ", schema_name, ".journal_mode = MEMORY;", NULL);
  res = sqlite3_exec(proxy_dbh, stmt, NULL, NULL, NULL);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 2,
      "error setting MEMORY journal mode on SQLite database '%s', "
      "schema '%s': %s", table_path, schema_name, sqlite3_errmsg(proxy_dbh));
  }

  destroy_pool(tmp_pool);
  return 0;
}

static int get_schema_version(pool *p, const char *schema_name,
    unsigned int *schema_version) {
  int res, version;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = pstrcat(p, "SELECT version FROM ", schema_name, ".schema_version WHERE schema = ?;", NULL);
  res = proxy_db_prepare_stmt(p, stmt);
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

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_TEXT,
    (void *) schema_name);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
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

static int set_schema_version(pool *p, const char *schema_name,
    unsigned int schema_version) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  /* CREATE TABLE $schema_name.schema_version (
   *   schema TEXT NOT NULL PRIMARY KEY,
   *   version INTEGER NOT NULL
   * );
   */
  stmt = pstrcat(p, "CREATE TABLE IF NOT EXISTS ", schema_name, ".schema_version (schema TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);", NULL);
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error executing statement '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = pstrcat(p, "INSERT INTO ", schema_name, ".schema_version (schema, version) VALUES (?, ?);", NULL);
  res = proxy_db_prepare_stmt(p, stmt);
  if (res < 0) {
    xerrno = errno;

    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 1, PROXY_DB_BIND_TYPE_TEXT,
    (void *) schema_name);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, stmt, 2, PROXY_DB_BIND_TYPE_INT,
    (void *) &schema_version);
  if (res < 0) {
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error executing statement '%s': %s", stmt,
      errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static void check_db_integrity(pool *p, const char *schema_name) {
  int res;
  const char *stmt, *errstr = NULL;

  if (proxy_dbh == NULL) {
    pr_trace_msg(trace_channel, 9,
      "unable to check integrity of schema '%s': no open database handle",
      schema_name);
    return;
  }

  stmt = pstrcat(p, "PRAGMA ", schema_name, ".integrity_check;", NULL);
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error executing statement '%s': %s", stmt, errstr);
  }

  stmt = "VACUUM;";
  res = proxy_db_exec_stmt(p, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error executing statement '%s': %s", stmt, errstr);
  }
}

int proxy_db_open_with_version(pool *p, const char *table_path,
    const char *schema_name, unsigned int schema_version, int flags) {
  pool *tmp_pool;
  int res, xerrno = 0;
  unsigned int current_version = 0;

  res = proxy_db_open(p, table_path, schema_name);
  if (res < 0) {
    return -1;
  }

  tmp_pool = make_sub_pool(p);
  res = get_schema_version(tmp_pool, schema_name, &current_version);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (current_version >= schema_version) {
    pr_trace_msg(trace_channel, 11,
      "schema version %u >= desired version %u for schema '%s'",
      current_version, schema_version, schema_name);

    check_db_integrity(tmp_pool, schema_name);
    destroy_pool(tmp_pool);

    return 0;
  }

  if (flags & PROXY_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW) {
    pr_trace_msg(trace_channel, 5,
      "schema version %u < desired version %u for schema '%s', failing",
      current_version, schema_version, schema_name);
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  /* TODO: Use:
   *
   *  PRAGMA database_list;
   *
   * to list any other attached databases with this handle.  Note that if
   * there ARE other attached databases, then simply unlinking the database
   * file associated with this schema will cause a problem (i.e. corrupting
   * the SQLite database).  We could avoid this by closing the database handle
   * itself IFF there are no other attached databases.  Otherwise, we need
   * to close the database handle, and then re-attach those other databases.
   *
   * The output from the `database_list` pragma looks like e.g.:
   *
   *  sqlite> pragma database_list;
   *  0|main|/Users/tj/test.db
   *  2|test2|/Users/tj/test2.db
   */

  proxy_db_close(p, schema_name);
  if (unlink(table_path) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error deleting '%s': %s", table_path, strerror(errno));
  }

  res = proxy_db_open(p, table_path, schema_name);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  res = set_schema_version(tmp_pool, schema_name, schema_version);
  xerrno = errno;

  destroy_pool(tmp_pool);

  if (res < 0) {
    errno = xerrno;
    return -1;
  }

  return 0;
}

int proxy_db_close(pool *p, const char *schema_name) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (proxy_dbh != NULL) {
    pool *tmp_pool;
    sqlite3_stmt *pstmt;
    int res;

    tmp_pool = make_sub_pool(p);

    /* If we're given a schema name, then just detach that schema from the
     * database handle.
     */
    if (schema_name != NULL) {
      const char *stmt;

      stmt = pstrcat(tmp_pool, "DETACH DATABASE ", schema_name, ";", NULL);
      res = sqlite3_exec(proxy_dbh, stmt, NULL, NULL, NULL);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 2,
          "error detaching '%s' from existing SQLite handle using '%s': %s",
          schema_name, stmt, sqlite3_errmsg(proxy_dbh));
        destroy_pool(tmp_pool);
        errno = EPERM;
        return -1;
      }

      destroy_pool(tmp_pool);
      return 0;
    }

    /* Make sure to close/finish any prepared statements associated with
     * the database.
     */
    pstmt = sqlite3_next_stmt(proxy_dbh, NULL);
    while (pstmt != NULL) {
      sqlite3_stmt *next;
      const char *sql;

      pr_signals_handle();

      next = sqlite3_next_stmt(proxy_dbh, pstmt);
      sql = pstrdup(tmp_pool, sqlite3_sql(pstmt));

      res = sqlite3_finalize(pstmt);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 2,
          "error finishing prepared statement '%s': %s", sql,
          sqlite3_errmsg(proxy_dbh));

      } else {
        pr_trace_msg(trace_channel, 18,
          "finished prepared statement '%s'", sql);
      }

      pstmt = next;
    }

    destroy_pool(tmp_pool);

    res = sqlite3_close(proxy_dbh);
    if (res != SQLITE_OK) {
      pr_trace_msg(trace_channel, 2,
        "error closing SQLite database: %s", sqlite3_errmsg(proxy_dbh));
      errno = EPERM;
      return -1;
    }

    if (schema_name == NULL) {
      pr_trace_msg(trace_channel, 18, "%s", "closed SQLite database");

    } else {
      pr_trace_msg(trace_channel, 18, "closed SQLite database (schema '%s')",
        schema_name);
    }

    proxy_dbh = NULL;
  }

  pr_table_empty(prepared_stmts);
  pr_table_free(prepared_stmts);
  prepared_stmts = NULL;

  return 0;
}

int proxy_db_reindex(pool *p, const char *index_name, const char **errstr) {
  int res;
  const char *stmt;

  if (p == NULL ||
      index_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  stmt = pstrcat(p, "REINDEX ", index_name, ";", NULL);
  res = proxy_db_exec_stmt(p, stmt, errstr);
  return res;
}

int proxy_db_init(pool *p) {
  const char *version;

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (db_pool != NULL) {
    return 0;
  }

  /* Register an error logging callback with SQLite3. */
  sqlite3_config(SQLITE_CONFIG_LOG, db_err, NULL);

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

  db_pool = make_sub_pool(p);
  pr_pool_tag(db_pool, "Proxy Database Pool");
  
  return 0;
}

int proxy_db_free(void) {

  if (db_pool != NULL) {
    destroy_pool(db_pool);
    db_pool = NULL;
    prepared_stmts = NULL;
  }

  return 0;
}
