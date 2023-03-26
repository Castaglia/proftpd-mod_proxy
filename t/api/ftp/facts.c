/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2020 TJ Saunders <tj@castaglia.org>
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

/* FTP Facts API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.facts", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.facts", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
  }
}

START_TEST (get_facts_test) {
}
END_TEST

START_TEST (parse_facts_test) {
}
END_TEST

Suite *tests_get_ftp_facts_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.facts");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, get_facts_test);
  tcase_add_test(testcase, parse_facts_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
