/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2015-2016 TJ Saunders <tj@castaglia.org>
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

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
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
    p = NULL;
  }
}

START_TEST (db_open_test) {
  int res;
  char *table_path;

  res = proxy_db_open(NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_close_test) {
  int res;

  res = proxy_db_close(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_prepare_stmt_test) {
  int res;

  res = proxy_db_prepare_stmt(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_finish_stmt_test) {
  int res;
  const char *stmt;

  res = proxy_db_finish_stmt(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  stmt = "SELECT COUNT(*) FROM table";
  res = proxy_db_finish_stmt(p, stmt);
  fail_unless(res == -1, "Failed to handle unprepared statement");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_bind_stmt_test) {
  int res;
  const char *stmt;
  int idx;

  res = proxy_db_bind_stmt(NULL, NULL, -1, -1, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  stmt = "SELECT COUNT(*) FROM table";
  idx = -1;
  res = proxy_db_bind_stmt(p, stmt, idx, PROXY_DB_BIND_TYPE_INT, NULL);
  fail_unless(res == -1, "Failed to handle invalid index %d", idx);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  idx = 1;
  res = proxy_db_bind_stmt(p, stmt, idx, PROXY_DB_BIND_TYPE_INT, NULL);
  fail_unless(res == -1, "Failed to handle unprepared statement");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_exec_stmt_test) {
  int res;

  res = proxy_db_exec_stmt(NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_exec_prepared_stmt_test) {
  array_header *res;

  res = proxy_db_exec_prepared_stmt(NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_db_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("db");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, db_open_test);
  tcase_add_test(testcase, db_close_test);
  tcase_add_test(testcase, db_prepare_stmt_test);
  tcase_add_test(testcase, db_finish_stmt_test);
  tcase_add_test(testcase, db_bind_stmt_test);
  tcase_add_test(testcase, db_exec_stmt_test);
  tcase_add_test(testcase, db_exec_prepared_stmt_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
