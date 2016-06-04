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

/* Proxy TLS API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.tls", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.tls", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = NULL;
  }
}

START_TEST (tls_using_tls_test) {
  int res, tls;

  tls = proxy_tls_using_tls();
#ifdef PR_USE_OPENSSL
  fail_unless(tls == PROXY_TLS_ENGINE_AUTO, "Expected TLS auto, got %d", tls);
#else
  fail_unless(tls == PROXY_TLS_ENGINE_OFF, "Expected TLS off, got %d", tls);
#endif /* PR_USE_OPENSSL */

  res = proxy_tls_set_tls(7);
  fail_unless(res < 0, "Set TLS unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_tls_set_tls(PROXY_TLS_ENGINE_ON;
  tls = proxy_tls_using_tls();
  fail_unless(tls == PROXY_TLS_ENGINE_ON, "Expected TLS on, got %d", tls);

  res = proxy_tls_set_tls(PROXY_TLS_ENGINE_OFF;
  tls = proxy_tls_using_tls();
  fail_unless(tls == PROXY_TLS_ENGINE_OFF, "Expected TLS off, got %d", tls);

  res = proxy_tls_set_tls(PROXY_TLS_ENGINE_AUTO;
  tls = proxy_tls_using_tls();
  fail_unless(tls == PROXY_TLS_ENGINE_AUTO, "Expected TLS auto, got %d", tls);
}
END_TEST

Suite *tests_get_tls_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("tls");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, tls_using_tls_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
