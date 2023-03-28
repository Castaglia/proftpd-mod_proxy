/*
 * ProFTPD - mod_proxy SSH database implementation
 * Copyright (c) 2021 TJ Saunders
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
#include "proxy/ssh.h"
#include "proxy/ssh/db.h"

#if defined(PR_USE_OPENSSL)

extern xaset_t *server_list;

static const char *trace_channel = "proxy.ssh.db";

#define PROXY_SSH_DB_SCHEMA_NAME		"proxy_ssh"
#define PROXY_SSH_DB_SCHEMA_VERSION		1

static unsigned long db_opts = 0UL;

static int ssh_db_add_hostkey(pool *p, void *dsh, unsigned int vhost_id,
    const char *backend_uri, const char *algo,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen) {
  int res, xerrno = 0;
  struct proxy_dbh *dbh;
  const char *stmt, *errstr = NULL;
  array_header *results;

  dbh = dsh;

  stmt = "INSERT INTO proxy_ssh_hostkeys (vhost_id, backend_uri, algo, hostkey) VALUES (?, ?, ?, ?);";
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

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) backend_uri, -1);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 3, PROXY_DB_BIND_TYPE_TEXT,
    (void *) algo, -1);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 4, PROXY_DB_BIND_TYPE_BLOB,
    (void *) hostkey_data, (int) hostkey_datalen);
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

static const unsigned char *ssh_db_get_hostkey(pool *p, void *dsh,
    unsigned int vhost_id, const char *backend_uri, const char **algo,
    uint32_t *hostkey_datalen) {
  int res, xerrno;
  struct proxy_dbh *dbh;
  const char *stmt, *errstr = NULL;
  array_header *results;
  const unsigned char *hostkey_data = NULL;

  dbh = dsh;

  stmt = "SELECT algo, hostkey FROM proxy_ssh_hostkeys WHERE vhost_id = ? AND backend_uri = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return NULL;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_TEXT,
    (void *) backend_uri, -1);
  if (res < 0) {
    return NULL;
  }

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  if (results == NULL ||
      results->nelts == 0) {
    errno = ENOENT;
    return NULL;
  }

  /* We expect 3 items: one for the algo, one for the hostkey BLOB, and one for
   * BLOB length.
   */
  if (results->nelts != 3) {
    pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": expected 3 results from statement '%s', got %d", stmt,
      results->nelts);
    errno = EINVAL;
    return NULL;
  }

  *algo = ((char **) results->elts)[0];
  hostkey_data = (const unsigned char *) ((char **) results->elts)[1];
  *hostkey_datalen = atoi(((char **) results->elts)[2]);

  pr_trace_msg(trace_channel, 19,
    "retrieved hostkey (algo '%s', %lu bytes) for vhost ID %u, URI '%s'",
    *algo, (unsigned long) *hostkey_datalen, vhost_id, backend_uri);
  return hostkey_data;
}

static int ssh_db_update_hostkey(pool *p, void *dsh, unsigned int vhost_id,
    const char *backend_uri, const char *algo,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen) {
  int res, xerrno = 0;
  struct proxy_dbh *dbh;
  const char *stmt, *errstr = NULL;
  array_header *results;

  dbh = dsh;

  stmt = "UPDATE proxy_ssh_hostkeys SET algo = ?, hostkey = ? WHERE vhost_id = ? AND backend_uri = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG3, MOD_PROXY_VERSION
      ": error preparing statement '%s': %s", stmt, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 1, PROXY_DB_BIND_TYPE_TEXT,
    (void *) algo, -1);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 2, PROXY_DB_BIND_TYPE_BLOB,
    (void *) hostkey_data, (int) hostkey_datalen);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 3, PROXY_DB_BIND_TYPE_INT,
    (void *) &vhost_id, 0);
  if (res < 0) {
    return -1;
  }

  res = proxy_db_bind_stmt(p, dbh, stmt, 4, PROXY_DB_BIND_TYPE_TEXT,
    (void *) backend_uri, -1);
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

/* Initialization routines */

static int ssh_db_add_schema(pool *p, void *dbh, const char *db_path) {
  int res;
  const char *stmt, *errstr = NULL;

  /* CREATE TABLE proxy_ssh_vhosts (
   *   vhost_id INTEGER NOT NULL PRIMARY KEY,
   *   vhost_name TEXT NOT NULL
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_ssh_vhosts (vhost_id INTEGER NOT NULL PRIMARY KEY, vhost_name TEXT NOT NULL);";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE proxy_ssh_hostkeys (
   *   backend_uri STRING NOT NULL PRIMARY KEY,
   *   vhost_id INTEGER NOT NULL,
   *   algo TEXT NOT NULL,
   *   hostkey BLOB NOT NULL,
   *   FOREIGN KEY (vhost_id) REFERENCES proxy_ssh_vhosts (vhost_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS proxy_ssh_hostkeys (backend_uri STRING NOT NULL PRIMARY KEY, vhost_id INTEGER NOT NULL, algo TEXT NOT NULL, hostkey BLOB NOT NULL, FOREIGN KEY (vhost_id) REFERENCES proxy_ssh_hosts (vhost_id));";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* Note that we deliberately do NOT truncate the hostkeys table. */

  return 0;
}

static int ssh_truncate_db_tables(pool *p, void *dbh) {
  int res;
  const char *stmt, *errstr = NULL;

  stmt = "DELETE FROM proxy_ssh_vhosts;";
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* Note that we deliberately do NOT truncate the hostkeys table. */
  return 0;
}

static int ssh_db_add_vhost(pool *p, void *dbh, server_rec *s) {
  int res, xerrno = 0;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO proxy_ssh_vhosts (vhost_id, vhost_name) VALUES (?, ?);";
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

static int ssh_db_init(pool *p, const char *tables_path, int flags) {
  int db_flags, res, xerrno = 0;
  server_rec *s;
  struct proxy_dbh *dbh = NULL;
  const char *db_path = NULL;

  if (tables_path == NULL) {
    errno = EINVAL;
    return -1;
  }

  db_path = pdircat(p, tables_path, "proxy-ssh.db", NULL);
  db_flags = PROXY_DB_OPEN_FL_SCHEMA_VERSION_CHECK|PROXY_DB_OPEN_FL_INTEGRITY_CHECK|PROXY_DB_OPEN_FL_VACUUM;
  if (flags & PROXY_DB_OPEN_FL_SKIP_VACUUM) {
    /* If the caller needs us to skip the vacuum, we will. */
    db_flags &= ~PROXY_DB_OPEN_FL_VACUUM;
  }

  PRIVS_ROOT
  dbh = proxy_db_open_with_version(p, db_path, PROXY_SSH_DB_SCHEMA_NAME,
    PROXY_SSH_DB_SCHEMA_VERSION, db_flags);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROXY_SSH_DB_SCHEMA_NAME, PROXY_SSH_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = ssh_db_add_schema(p, dbh, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": error creating schema in database '%s' for '%s': %s", db_path,
      PROXY_SSH_DB_SCHEMA_NAME, strerror(xerrno));
    (void) proxy_db_close(p, dbh);
    errno = xerrno;
    return -1;
  }

  res = ssh_truncate_db_tables(p, dbh);
  if (res < 0) {
    xerrno = errno;
    (void) proxy_db_close(p, dbh);
    errno = xerrno;
    return -1;
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    res = ssh_db_add_vhost(p, dbh, s);
    if (res < 0) {
      xerrno = errno;
      (void) pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": error adding database entry for server '%s' in '%s': %s",
        s->ServerName, PROXY_SSH_DB_SCHEMA_NAME, strerror(xerrno));
      (void) proxy_db_close(p, dbh);
      errno = xerrno;
      return -1;
    }
  }

  (void) proxy_db_close(p, dbh);
  return 0;
}

static int ssh_db_close(pool *p, void *dbh) {
  if (dbh != NULL) {
    if (proxy_db_close(p, dbh) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error closing %s database: %s", PROXY_SSH_DB_SCHEMA_NAME,
        strerror(errno));
    }
  }

  return 0;
}

static void *ssh_db_open(pool *p, const char *tables_dir, unsigned long opts) {
  int xerrno = 0;
  struct proxy_dbh *dbh;
  const char *db_path;

  db_path = pdircat(p, tables_dir, "proxy-ssh.db", NULL);

  PRIVS_ROOT
  dbh = proxy_db_open_with_version(p, db_path, PROXY_SSH_DB_SCHEMA_NAME,
    PROXY_SSH_DB_SCHEMA_VERSION, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROXY_SSH_DB_SCHEMA_NAME, PROXY_SSH_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  db_opts = opts;
  return dbh;
}

int proxy_ssh_db_as_datastore(struct proxy_ssh_datastore *ds, void *ds_data,
    size_t ds_datasz) {
  if (ds == NULL) {
    errno = EINVAL;
    return -1;
  }

  (void) ds_data;
  (void) ds_datasz;

  ds->hostkey_add = ssh_db_add_hostkey;
  ds->hostkey_get = ssh_db_get_hostkey;
  ds->hostkey_update = ssh_db_update_hostkey;

  ds->init = ssh_db_init;
  ds->open = ssh_db_open;
  ds->close = ssh_db_close;

  return 0;
}
#endif /* PR_USE_OPENSSL */
