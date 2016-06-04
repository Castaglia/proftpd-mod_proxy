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

/* Session API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.session", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.session", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (session_free_test) {
  int res;

  res = proxy_session_free(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (session_alloc_test) {
  const struct proxy_session *proxy_sess;

  proxy_sess = proxy_session_alloc(NULL);
  fail_unless(proxy_sess == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = proxy_session_alloc(p);
  fail_unless(proxy_sess != NULL, "Failed to allocate proxy session: %s",
    strerror(errno));

  proxy_session_free(proxy_sess);
}
END_TEST

Suite *tests_get_session_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("session");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, session_free_test);
  tcase_add_test(testcase, session_alloc_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
