/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2015-2021 TJ Saunders <tj@castaglia.org>
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

/* Database API tests. */

#include "tests.h"

static pool *p = NULL;

static const char *db_test_table = "/tmp/prt-mod_proxy-db.dat";

static void set_up(void) {
  (void) unlink(db_test_table);

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.db", 1, 20);
  }

  mark_point();
  proxy_db_init(p);
}

static void tear_down(void) {
  proxy_db_free();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.db", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  }

  (void) unlink(db_test_table);
}

START_TEST (db_close_test) {
  int res;

  res = proxy_db_close(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = proxy_db_close(p, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_open_test) {
  int res;
  const char *table_path, *schema_name;
  struct proxy_dbh *dbh;

  dbh = proxy_db_open(NULL, NULL, NULL);
  fail_unless(dbh == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  dbh = proxy_db_open(p, NULL, NULL);
  fail_unless(dbh == NULL, "Failed to handle null table path");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";

  dbh = proxy_db_open(p, table_path, NULL);
  fail_unless(dbh == NULL, "Failed to handle null schema name");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  dbh = proxy_db_open(p, table_path, schema_name);
  fail_unless(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close table '%s': %s", table_path,
    strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_open_with_version_test) {
  int res, flags = 0;
  struct proxy_dbh *dbh;
  const char *table_path, *schema_name;
  unsigned int schema_version;

  dbh = proxy_db_open_with_version(NULL, NULL, NULL, 0, 0);
  fail_unless(dbh == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";
  schema_version = 0;

  mark_point();
  dbh = proxy_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  fail_unless(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  flags |= PROXY_DB_OPEN_FL_INTEGRITY_CHECK;

  mark_point();
  dbh = proxy_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  fail_unless(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  if (getenv("CI") == NULL &&
      getenv("TRAVIS") == NULL) {
    /* Enable the vacuuming for these tests. */
    flags |= PROXY_DB_OPEN_FL_VACUUM;

    mark_point();
    dbh = proxy_db_open_with_version(p, table_path, schema_name, schema_version,
      flags);
    fail_unless(dbh != NULL,
      "Failed to open table '%s', schema '%s', version %u: %s", table_path,
      schema_name, schema_version, strerror(errno));

    res = proxy_db_close(p, dbh);
    fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

    flags &= ~PROXY_DB_OPEN_FL_VACUUM;
  }

  flags &= ~PROXY_DB_OPEN_FL_INTEGRITY_CHECK;

  mark_point();
  schema_version = 76;
  flags |= PROXY_DB_OPEN_FL_SCHEMA_VERSION_CHECK|PROXY_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW;
  dbh = proxy_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  fail_unless(dbh == NULL, "Opened table with version skew unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  flags &= ~PROXY_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW;
  dbh = proxy_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  fail_unless(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  mark_point();
  schema_version = 76;
  dbh = proxy_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  fail_unless(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close databas: %s", strerror(errno));

  mark_point();
  schema_version = 99;
  dbh = proxy_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  fail_unless(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_exec_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt, *errstr;
  struct proxy_dbh *dbh;

  res = proxy_db_exec_stmt(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_db_exec_stmt(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";

  dbh = proxy_db_open(p, table_path, schema_name);
  fail_unless(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  res = proxy_db_exec_stmt(p, dbh, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null statement");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  stmt = "SELECT COUNT(*) FROM foo;";
  errstr = NULL;
  res = proxy_db_exec_stmt(p, dbh, stmt, &errstr);
  fail_unless(res < 0, "Failed to execute statement '%s'", stmt);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

static int create_table(pool *stmt_pool, struct proxy_dbh *dbh,
    const char *table_name) {
  int res;
  const char *stmt, *errstr = NULL;

  stmt = pstrcat(stmt_pool, "CREATE TABLE ", table_name,
    " (id INTEGER, name TEXT);", NULL);
  res = proxy_db_exec_stmt(stmt_pool, dbh, stmt, &errstr);
  return res;
}

START_TEST (db_prepare_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt;
  struct proxy_dbh *dbh;

  res = proxy_db_prepare_stmt(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_db_prepare_stmt(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";

  dbh = proxy_db_open(p, table_path, schema_name);
  fail_unless(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  res = proxy_db_prepare_stmt(p, dbh, NULL);
  fail_unless(res < 0, "Failed to handle null statement");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  stmt = "foo bar baz?";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res < 0, "Prepared invalid statement '%s' unexpectedly", stmt);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  fail_unless(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  stmt = "SELECT COUNT(*) FROM foo;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  res = create_table(p, dbh, "bar");
  fail_unless(res == 0, "Failed to create table 'bar': %s", strerror(errno));

  stmt = "SELECT COUNT(*) FROM bar;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_finish_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt;
  struct proxy_dbh *dbh;

  res = proxy_db_finish_stmt(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_db_finish_stmt(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";

  dbh = proxy_db_open(p, table_path, schema_name);
  fail_unless(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  res = proxy_db_finish_stmt(p, dbh, NULL);
  fail_unless(res < 0, "Failed to handle null statement");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  stmt = "SELECT COUNT(*) FROM foo";
  res = proxy_db_finish_stmt(p, dbh, stmt);
  fail_unless(res < 0, "Failed to handle unprepared statement");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  fail_unless(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  res = proxy_db_finish_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to finish statement '%s': %s", stmt,
    strerror(errno));

  res = proxy_db_finish_stmt(p, dbh, stmt);
  fail_unless(res < 0, "Failed to handle unprepared statement");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_bind_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt;
  struct proxy_dbh *dbh;
  int idx, int_val;
  long long_val;
  char *text_val;
  void *blob_val;

  res = proxy_db_bind_stmt(NULL, NULL, NULL, -1, -1, NULL, -1);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_db_bind_stmt(p, NULL, NULL, -1, -1, NULL, -1);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";

  dbh = proxy_db_open(p, table_path, schema_name);
  fail_unless(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  res = proxy_db_bind_stmt(p, dbh, NULL, -1, -1, NULL, -1);
  fail_unless(res < 0, "Failed to handle null statement");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  stmt = "SELECT COUNT(*) FROM table";
  idx = -1;
  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT, NULL, -1);
  fail_unless(res < 0, "Failed to handle invalid index %d", idx);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  idx = 1;
  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT, NULL, -1);
  fail_unless(res < 0, "Failed to handle unprepared statement");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  fail_unless(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  stmt = "SELECT COUNT(*) FROM foo;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT, NULL, -1);
  fail_unless(res < 0, "Failed to handle missing INT value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  int_val = 7;
  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT, &int_val,
    -1);
  fail_unless(res < 0, "Failed to handle invalid index value");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_LONG, NULL,
    -1);
  fail_unless(res < 0, "Failed to handle missing LONG value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  long_val = 7;
  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_LONG,
    &long_val, -1);
  fail_unless(res < 0, "Failed to handle invalid index value");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_TEXT, NULL, 0);
  fail_unless(res < 0, "Failed to handle missing TEXT value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  text_val = "testing";
  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_TEXT,
    text_val, 0);
  fail_unless(res < 0, "Failed to handle invalid index value");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_BLOB, NULL,
    -1);
  fail_unless(res < 0, "Failed to handle missing BLOB value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  blob_val = "testing";
  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_BLOB,
    blob_val, strlen(blob_val));
  fail_unless(res < 0, "Failed to handle invalid index value");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle invalid NULL value");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  stmt = "SELECT COUNT(*) FROM foo WHERE id = ?;";
  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  int_val = 7;
  res = proxy_db_bind_stmt(p, dbh, stmt, idx, PROXY_DB_BIND_TYPE_INT, &int_val,     -1);
  fail_unless(res == 0, "Failed to bind INT value: %s", strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_exec_prepared_stmt_test) {
  int res;
  array_header *results;
  const char *table_path, *schema_name, *stmt, *errstr = NULL;
  struct proxy_dbh *dbh;

  results = proxy_db_exec_prepared_stmt(NULL, NULL, NULL, NULL);
  fail_unless(results == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  results = proxy_db_exec_prepared_stmt(p, NULL, NULL, NULL);
  fail_unless(results == NULL, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";

  dbh = proxy_db_open(p, table_path, schema_name);
  fail_unless(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  results = proxy_db_exec_prepared_stmt(p, dbh, NULL, NULL);
  fail_unless(results == NULL, "Failed to handle null statement");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  stmt = "SELECT COUNT(*) FROM foo;";
  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  fail_unless(results == NULL, "Failed to handle unprepared statement");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  fail_unless(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  res = proxy_db_prepare_stmt(p, dbh, stmt);
  fail_unless(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  results = proxy_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  fail_unless(results != NULL,
    "Failed to execute prepared statement '%s': %s (%s)", stmt, errstr,
    strerror(errno));

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_reindex_test) {
  int res;
  const char *table_path, *schema_name, *index_name, *errstr = NULL;
  struct proxy_dbh *dbh;

  res = proxy_db_reindex(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_db_reindex(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "proxy_test";

  dbh = proxy_db_open(p, table_path, schema_name);
  fail_unless(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  res = proxy_db_reindex(p, dbh, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null index name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  index_name = "test_idx";
  res = proxy_db_reindex(p, dbh, index_name, &errstr);
  fail_unless(res < 0, "Failed to handle invalid index");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(errstr != NULL, "Failed to provide error string");

  res = proxy_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

Suite *tests_get_db_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("db");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, db_close_test);
  tcase_add_test(testcase, db_open_test);
  tcase_add_test(testcase, db_open_with_version_test);
  tcase_add_test(testcase, db_exec_stmt_test);
  tcase_add_test(testcase, db_prepare_stmt_test);
  tcase_add_test(testcase, db_finish_stmt_test);
  tcase_add_test(testcase, db_bind_stmt_test);
  tcase_add_test(testcase, db_exec_prepared_stmt_test);
  tcase_add_test(testcase, db_reindex_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
