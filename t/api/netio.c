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

/* Proxy NetIO API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_netio();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 1, 20);
    pr_trace_set_levels("proxy.netio", 1, 20);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
    pr_trace_set_levels("proxy.netio", 0, 0);
  }
}

START_TEST (netio_set_test) {
  pr_netio_t *netio = NULL;
  int res, strm_type = PR_NETIO_STRM_OTHR;

  netio = proxy_netio_unset(strm_type, NULL);
  fail_unless(netio == NULL, "Failed to handle null function string");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  netio = proxy_netio_unset(strm_type, "foo");
  fail_unless(netio == NULL, "Expected null othr NetIO, got %p", netio);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_netio_set(strm_type, netio);
  fail_unless(res == 0, "Failed to set null othr netio: %s", strerror(errno));
}
END_TEST

START_TEST (netio_use_test) {
  pr_netio_t *netio = NULL;
  int res, strm_type = PR_NETIO_STRM_OTHR;

  res = proxy_netio_using(strm_type, NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_netio_using(strm_type, &netio);
  fail_unless(res < 0, "Failed to handle othr stream type");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = proxy_netio_using(PR_NETIO_STRM_CTRL, &netio);
  fail_unless(res == 0, "Failed to handle ctrl stream type: %s",
    strerror(errno));
  fail_unless(netio == NULL, "Expected null ctrl netio, got %p", netio);

  res = proxy_netio_using(PR_NETIO_STRM_DATA, &netio);
  fail_unless(res == 0, "Failed to handle data stream type: %s",
    strerror(errno));
  fail_unless(netio == NULL, "Expected null data netio, got %p", netio);

  res = proxy_netio_use(strm_type, NULL);
  fail_unless(res < 0, "Failed to handle othr stream type");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got '%s' (%d)", ENOSYS,
    strerror(errno), errno);

  res = proxy_netio_use(PR_NETIO_STRM_CTRL, NULL);
  fail_unless(res == 0, "Failed to handle ctrl stream type: %s",
    strerror(errno));

  res = proxy_netio_use(PR_NETIO_STRM_DATA, NULL);
  fail_unless(res == 0, "Failed to handle data stream type: %s",
    strerror(errno));
}
END_TEST

Suite *tests_get_netio_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("netio");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, netio_set_test);
  tcase_add_test(testcase, netio_use_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
