/*
 * ProFTPD - mod_proxy database API
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

#ifndef MOD_PROXY_DB_H
#define MOD_PROXY_DB_H

#include "mod_proxy.h"

struct proxy_dbh;

int proxy_db_init(pool *p);
int proxy_db_free(void);

/* Create/prepare the database (with the given schema name) at the given path */
struct proxy_dbh *proxy_db_open(pool *p, const char *table_path);

/* Create/prepare the database (with the given schema name) at the given path.
 * If the database/schema already exists, check that its schema version is
 * greater than or equal to the given minimum version.  If not, delete that
 * database and create a new one.
 */
struct proxy_dbh *proxy_db_open_with_version(pool *p, const char *table_path,
  const char *schema_name, unsigned int schema_version, int flags);
#define PROXY_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW		0x001
#define PROXY_DB_OPEN_FL_SKIP_INTEGRITY_CHECK			0x002
#define PROXY_DB_OPEN_FL_SKIP_VACUUM				0x004

/* Close the database. */
int proxy_db_close(pool *p, struct proxy_dbh *dbh);

int proxy_db_prepare_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt);
int proxy_db_finish_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt);
int proxy_db_bind_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt,
  int idx, int type, void *data);
#define PROXY_DB_BIND_TYPE_INT		1
#define PROXY_DB_BIND_TYPE_LONG		2
#define PROXY_DB_BIND_TYPE_TEXT		3
#define PROXY_DB_BIND_TYPE_NULL		4

/* Executes the given statement.  Assumes that the caller is not using a SELECT,
 * and/or is uninterested in the statement results.
 */
int proxy_db_exec_stmt(pool *p, struct proxy_dbh *dbh, const char *stmt,
  const char **errstr);

/* Executes the given statement as a previously prepared statement. */
array_header *proxy_db_exec_prepared_stmt(pool *p, struct proxy_dbh *dbh,
  const char *stmt, const char **errstr);

/* Rebuild the named index. */
int proxy_db_reindex(pool *p, struct proxy_dbh *dbh, const char *index_name,
  const char **errstr);

#endif /* MOD_PROXY_DB_H */
