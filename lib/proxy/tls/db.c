/*
 * ProFTPD - mod_proxy TLS Database implementation
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

#include "proxy/db.h"
#include "proxy/tls.h"

#ifdef PR_USE_OPENSSL

extern xaset_t *server_list;

static const char *trace_channel = "proxy.tls.db";

#define PROXY_TLS_DB_SCHEMA_NAME		"proxy_tls"
#define PROXY_TLS_DB_SCHEMA_VERSION		3

static int tls_db_add_sess(pool *p, void *dbh, const char *key,
    SSL_SESSION *sess) {
  int res, vhost_id, xerrno = 0;
  const char *stmt, *errstr = NULL;
  BIO *bio;
  char *data = NULL;
  long datalen = 0;
  array_header *results;

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

  if (proxy_tls_opts & PROXY_TLS_OPT_ENABLE_DIAGS) {
    BIO *diags_bio;

    diags_bio = BIO_new(BIO_s_mem());
    if (diags_bio != NULL) {
      if (SSL_SESSION_print(diags_bio, sess) == 1) {
        char *diags_data = NULL;
        long diags_datalen = 0;

        diags_datalen = BIO_get_mem_data(diags_bio, &diags_data);
        if (diags_data != NULL) {
          data[diags_datalen] = '\0';
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "[tls] caching SSL session (%ld bytes):\n%s", diags_datalen,
            diags_data);
        }
      }
    }
  }

  /* We use INSERT OR REPLACE here to get upsert semantics; we only want/
   * need one cached SSL session per URI.
   */
  stmt = "INSERT OR REPLACE INTO proxy_tls_sessions (vhost_id, backend_uri, session) VALUES (?, ?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    xerrno = errno;

    BIO_free(bio);
    errno = xerrno;
    return -1;
  }

  vhost_id = main_server->sid;
  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    xerrno = errno;

    BIO_free(bio);
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) key);
  if (res < 0) {
    xerrno = errno;

    BIO_free(bio);
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 3, PROXY_DB_BIND_TYPE_TEXT,
    (void *) data);
  if (res < 0) {
    xerrno = errno;

    BIO_free(bio);
    errno = xerrno;
    return -1;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));

    BIO_free(bio);
    errno = EPERM;
    return -1;
  }

  BIO_free(bio);

  pr_trace_msg(trace_channel, 17, "cached SSL session for key '%s'", key);
  return 0;
}

static int tls_db_remove_sess(pool *p, void *dbh, const char *key) {
  int res, vhost_id;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "DELETE FROM proxy_tls_sessions WHERE vhost_id = ? AND backend_uri = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  vhost_id = main_server->sid;
  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) key);
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

static SSL_SESSION *tls_db_get_sess(pool *p, void *dbh, const char *key) {
  int res, vhost_id;
  BIO *bio;
  const char *stmt, *errstr = NULL;
  array_header *results;
  char *data = NULL;
  size_t datalen;
  SSL_SESSION *sess = NULL;

  stmt = "SELECT session FROM proxy_tls_sessions WHERE vhost_id = ? AND backend_uri = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  vhost_id = main_server->sid;
  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) key);
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

  if (results->nelts == 0) {
    errno = ENOENT;
    return NULL;
  }

  data = ((char **) results->elts)[0];
  datalen = strlen(data) + 1;

  bio = BIO_new_mem_buf(data, datalen);
  sess = PEM_read_bio_SSL_SESSION(bio, NULL, 0, NULL);

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

  return sess;
}

static int tls_db_count_sess(pool *p, void *dbh) {
  int count = 0, res;
  const char *stmt, *errstr = NULL;
  array_header *results;
  
  stmt = "SELECT COUNT(*) FROM proxy_tls_sessions;";
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
  return count;
}

/* Initialization routines */

static int tls_db_add_schema(pool *p, void *dbh, const char *db_path) {
  int res;
  const char *stmt, *errstr = NULL;

  /* CREATE TABLE proxy_tls_vhosts (
   *   vhost_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_name TEXT NOT NULL
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_tls_vhosts (vhost_id INTEGER NOT NULL PRIMARY KEY, vhost_name TEXT NOT NULL);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_tls_sessions (
   *   backend_uri STRING NOT NULL PRIMARY KEY,
   *   vhost_id INTEGER NOT NULL,
   *   session TEXT NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_tls_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_tls_sessions (backend_uri STRING NOT NULL PRIMARY KEY, vhost_id INTEGER NOT NULL, session TEXT NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_tls_hosts (vhost_id));";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* Note that we deliberately do NOT truncate the session cache table. */

  return 0;
}

static int tls_truncate_db_tables(pool *p, void *dbh) {
  int res;
  const char *stmt, *errstr = NULL;

  stmt = "DELETE FROM proxy_tls_vhosts;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* Note that we deliberately do NOT truncate the session cache table. */
  return 0;
}

static int tls_db_add_vhost(pool *p, void *dbh, server_rec *s) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_tls_vhosts (vhost_id, vhost_name) VALUES (?, ?);";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &(s->sid));
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) s->ServerName);
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

static int tls_db_init(pool *p, const char *tables_path, int flags) {
  int db_flags, res, xerrno = 0;
  server_rec *s;
  struct proxy_dbh *dbh = NULL;
  const char *db_path = NULL;

  db_path = pdircat(p, tables_path, "proxy-tls.db", NULL);
  db_flags = PROXY_DB_OPEN_FL_SCHEMA_VERSION_CHECK|PROXY_DB_OPEN_FL_INTEGRITY_CHECK|PROXY_DB_OPEN_FL_VACUUM;
  if (flags & PROXY_DB_OPEN_FL_SKIP_VACUUM) {
    /* If the caller needs us to skip the vacuum, we will. */
    db_flags &= ~PROXY_DB_OPEN_FL_VACUUM;
  }

  dbh = proxy_db_open_with_version(p, db_path, PROXY_TLS_DB_SCHEMA_NAME,
    PROXY_TLS_DB_SCHEMA_VERSION, db_flags);
  xerrno = errno;

  if (dbh == NULL) {
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROXY_TLS_DB_SCHEMA_NAME, PROXY_TLS_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = tls_db_add_schema(p, dbh, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error creating schema in database '%s' for '%s': %s", db_path,
      PROXY_TLS_DB_SCHEMA_NAME, strerror(xerrno));
    (void) proxy_db_close(p, dbh);
    errno = xerrno;
    return -1;
  }

  res = tls_truncate_db_tables(p, dbh);
  if (res < 0) {
    xerrno = errno;
    (void) proxy_db_close(p, dbh);
    errno = xerrno;
    return -1;
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    res = tls_db_add_vhost(p, dbh, s);
    if (res < 0) {
      xerrno = errno;
      (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": error adding database entry for server '%s' in '%s': %s",
        s->ServerName, PROXY_TLS_DB_SCHEMA_NAME, strerror(xerrno));
      (void) proxy_db_close(p, dbh);
      errno = xerrno;
      return -1;
    }
  }

  (void) proxy_db_close(p, dbh);
  return 0;
}

static int tls_db_close(pool *p, void *dbh) {
  if (dbh != NULL) {
    if (proxy_db_close(p, dbh) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error closing %s database: %s", PROXY_TLS_DB_SCHEMA_NAME,
        strerror(errno));
    }
  }

  return 0;
}

static void *tls_db_open(pool *p, const char *tables_dir) {
  int xerrno = 0;
  struct proxy_dbh *dbh;
  const char *db_path;

  db_path = pdircat(p, tables_dir, "proxy-tls.db", NULL);

  PRIVS_ROOT
  dbh = proxy_db_open_with_version(p, db_path, PROXY_TLS_DB_SCHEMA_NAME,
    PROXY_TLS_DB_SCHEMA_VERSION, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROXY_TLS_DB_SCHEMA_NAME, PROXY_TLS_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  return dbh;
}
#endif /* PR_USE_OPENSSL */

int proxy_tls_db_for_datastore(struct proxy_tls_datastore *ds, void *ds_data,
    size_t ds_datasz) {
  if (ds == NULL) {
    errno = EINVAL;
    return -1;
  }

  (void) ds_data;
  (void) ds_datasz;

#ifdef PR_USE_OPENSSL
  ds->add_sess = tls_db_add_sess;
  ds->remove_sess = tls_db_remove_sess;
  ds->get_sess = tls_db_get_sess;
  ds->count_sess = tls_db_count_sess;

  ds->init = tls_db_init;
  ds->open = tls_db_open;
  ds->close = tls_db_close;
#endif /* PR_USE_OPENSSL */

  return 0;
}
