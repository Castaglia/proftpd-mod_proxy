/*
 * ProFTPD - mod_proxy database implementation
 * Copyright (c) 2015 TJ Saunders
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

int proxy_db_exec_stmt(pool *p, const char *stmt, const char **errstr) {
  int res;
  char *ptr = NULL;
  unsigned int nretries = 0;

  if (stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = sqlite3_exec(proxy_dbh, stmt, NULL, NULL, &ptr);
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

  if (stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  pstmt = pr_table_get(prepared_stmts, stmt, NULL);
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
 
  if (stmt == NULL) {
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

  pstmt = pr_table_get(prepared_stmts, stmt, NULL);
  if (pstmt == NULL) {
    pr_trace_msg(trace_channel, 19,
      "unable to find prepared statement for '%s'", stmt);
    errno = ENOENT;
    return -1;
  }

  switch (type) {
    case PROXY_DB_BIND_TYPE_INT: {
      int i;

      i = *((int *) data);
      res = sqlite3_bind_int(pstmt, idx, i);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to INT %d: %s", idx, stmt, i,
          sqlite3_errmsg(proxy_dbh));
      }
      break;
    }

    case PROXY_DB_BIND_TYPE_LONG: {
      long l;

      l = *((long *) data);
      res = sqlite3_bind_int(pstmt, idx, l);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to LONG %ld: %s", idx, stmt, l,
          sqlite3_errmsg(proxy_dbh));
      }
      break;
    }

    case PROXY_DB_BIND_TYPE_TEXT: {
      const char *text;

      text = (const char *) data;
      res = sqlite3_bind_text(pstmt, idx, text, -1, NULL);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to TEXT '%s': %s", idx, stmt,
          text, sqlite3_errmsg(proxy_dbh));
      }
      break;
    }

    case PROXY_DB_BIND_TYPE_NULL:
      res = sqlite3_bind_null(pstmt, idx);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 4,
          "error binding parameter %d of '%s' to NULL: %s", idx, stmt,
          sqlite3_errmsg(proxy_dbh));
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

  if (stmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (prepared_stmts == NULL) {
    errno = ENOENT;
    return -1;
  }

  pstmt = pr_table_get(prepared_stmts, stmt, NULL);
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

  if (stmt == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (prepared_stmts == NULL) {
    errno = ENOENT;
    return NULL;
  }

  pstmt = pr_table_get(prepared_stmts, stmt, NULL);
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
    register unsigned int i;
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

int proxy_db_open(pool *p, const char *table_path) {
  int res;

  if (p == NULL ||
      table_path == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* If we already have a database handle open, then attach the given
   * path to our handle.
   */
  if (proxy_dbh != NULL) {
    pool *tmp_pool;
    const char *stmt;
    char *db_name = NULL, *ptr;

    tmp_pool = make_sub_pool(p);

    /* Suss out the file name from the table path to use as the database
     * name.
     */
    ptr = strrchr(table_path, '/');
    if (ptr != NULL) {
      db_name = pstrdup(tmp_pool, ptr+1);

    } else {
      db_name = pstrdup(tmp_pool, table_path);
    }

    ptr = strrchr(db_name, '.');
    if (ptr != NULL) {
      *ptr = '\0';
    }

    ptr = strchr(db_name, '-');
    if (ptr != NULL) {
      db_name = sreplace(tmp_pool, db_name, "-", "_", NULL);
    }

    stmt = pstrcat(tmp_pool, "ATTACH DATABASE '", table_path, "' AS ",
      db_name, ";", NULL);
    res = sqlite3_exec(proxy_dbh, stmt, NULL, NULL, NULL);
    if (res != SQLITE_OK) {
      pr_trace_msg(trace_channel, 2,
        "error attaching database '%s' to existing SQLite handle "
        "using '%s': %s", table_path, stmt, sqlite3_errmsg(proxy_dbh));
      destroy_pool(tmp_pool);
      errno = EPERM;
      return -1;
    }

    destroy_pool(tmp_pool);
    return 0;
  }

  res = sqlite3_open(table_path, &proxy_dbh);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 2,
      "error opening SQLite database '%s': %s", table_path,
      sqlite3_errmsg(proxy_dbh));
    errno = EPERM;
    return -1;
  }

  /* Tell SQLite to only use in-memory journals.  This is necessary for
   * working properly when a chroot is used.  Note that the MEMORY journal mode
   * of SQLite is supported only for SQLite-3.6.5 and later.
   */
  res = sqlite3_exec(proxy_dbh, "PRAGMA journal_mode = MEMORY;", NULL, NULL,
    NULL);
  if (res != SQLITE_OK) {
    pr_trace_msg(trace_channel, 2,
      "error setting MEMORY journal mode on SQLite database '%s': %s",
      table_path, sqlite3_errmsg(proxy_dbh));
  }

  prepared_stmts = pr_table_nalloc(db_pool, 0, 4);
  return 0;
}

int proxy_db_close(pool *p) {
  if (proxy_dbh != NULL) {
    sqlite3_stmt *pstmt;
    int res;

    /* Make sure to close/finish any prepared statements associated with
     * the database.
     */
    pstmt = sqlite3_next_stmt(proxy_dbh, NULL);
    while (pstmt != NULL) {
      sqlite3_stmt *next;

      pr_signals_handle();

      next = sqlite3_next_stmt(proxy_dbh, pstmt);

      res = sqlite3_finalize(pstmt);
      if (res != SQLITE_OK) {
        pr_trace_msg(trace_channel, 2,
          "error finishing prepared statement '%s': %s",
          sqlite3_sql(pstmt), sqlite3_errmsg(proxy_dbh));
      }

      pstmt = next;
    }

    res = sqlite3_close(proxy_dbh);
    if (res != SQLITE_OK) {
      pr_trace_msg(trace_channel, 2,
        "error closing SQLite database: %s", sqlite3_errmsg(proxy_dbh));
      errno = EPERM;
      return -1;
    }

    proxy_dbh = NULL;
  }

  pr_table_empty(prepared_stmts);
  pr_table_free(prepared_stmts);
  prepared_stmts = NULL;

  return 0;
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
