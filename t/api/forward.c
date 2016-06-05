/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2016 TJ Saunders <tj@castaglia.org>
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

/* Forward-proxy API tests */

#include "tests.h"

static pool *p = NULL;
static const char *test_dir = "/tmp/mod_proxy-test-forward";

static void test_cleanup(void) {
  (void) rmdir(test_dir);
}

static void set_up(void) {
  test_cleanup();

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.forward", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.forward", 0, 0);
  }

  test_cleanup();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (forward_get_method_test) {
  int res;
  const char *method;

  res = proxy_forward_get_method(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  method = "foo";
  res = proxy_forward_get_method(method);
  fail_unless(res < 0, "Failed to handle unsupported method '%s'", method);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  method = "proxyuser,user@host";
  res = proxy_forward_get_method(method);
  fail_unless(res == PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH,
    "Failed to handle method '%s'", method);

  method = "user@host";
  res = proxy_forward_get_method(method);
  fail_unless(res == PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH,
    "Failed to handle method '%s'", method);

  method = "proxyuser@host,user";
  res = proxy_forward_get_method(method);
  fail_unless(res == PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH,
    "Failed to handle method '%s'", method);
}
END_TEST

START_TEST (forward_use_proxy_auth_test) {
  int res;

  res = proxy_forward_use_proxy_auth();
  fail_unless(res == TRUE, "Expected true, got %d", res);
}
END_TEST

Suite *tests_get_forward_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("forward");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, forward_get_method_test);
  tcase_add_test(testcase, forward_use_proxy_auth_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
