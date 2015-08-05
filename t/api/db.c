/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2015 TJ Saunders <tj@castaglia.org>
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

  mark_point();
  proxy_db_init(p);
}

static void tear_down(void) {
  proxy_db_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  }
}

START_TEST (db_open_test) {
  int res;
  char *table_path;

  res = proxy_db_open(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_close_test) {
}
END_TEST

START_TEST (db_prepare_stmt_test) {
}
END_TEST

START_TEST (db_finish_stmt_test) {
}
END_TEST

START_TEST (db_bind_stmt_test) {
}
END_TEST

START_TEST (db_exec_stmt_test) {
}
END_TEST

START_TEST (db_exec_prepared_stmt_test) {
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
