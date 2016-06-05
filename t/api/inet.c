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

/* Proxy Inet API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_netaddr();
  init_netio();
  init_inet();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("inet", 1, 20);
    pr_trace_set_levels("proxy.inet", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("inet", 0, 0);
    pr_trace_set_levels("proxy.inet", 0, 0);
  }

  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (inet_accept_test) {
  /* XXX TODO */
}
END_TEST

START_TEST (inet_close_test) {
  /* XXX TODO */
}
END_TEST

START_TEST (inet_connect_test) {
  /* XXX TODO */
}
END_TEST

START_TEST (inet_listen_test) {
  /* XXX TODO */
}
END_TEST

START_TEST (inet_openrw_test) {
  conn_t *res, *conn;

  res = proxy_inet_openrw(NULL, NULL, NULL, PR_NETIO_STRM_CTRL, -1, -1, -1,
    FALSE);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_inet_openrw(p, NULL, NULL, PR_NETIO_STRM_CTRL, -1, -1, -1,
    FALSE);
  fail_unless(res == NULL, "Failed to handle null conn");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = proxy_inet_openrw(p, conn, NULL, PR_NETIO_STRM_OTHR, -1, -1, -1,
    FALSE);
  fail_unless(res == NULL, "Failed to handle null addr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

Suite *tests_get_inet_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("inet");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, inet_accept_test);
  tcase_add_test(testcase, inet_close_test);
  tcase_add_test(testcase, inet_connect_test);
  tcase_add_test(testcase, inet_listen_test);
  tcase_add_test(testcase, inet_openrw_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
