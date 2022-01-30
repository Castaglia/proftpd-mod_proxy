/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2020-2022 TJ Saunders <tj@castaglia.org>
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

/* DNS API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.dns", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.dns", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (dns_resolve_einval_test) {
  int res;
  const char *name = NULL;
  proxy_dns_type_e dns_type = PROXY_DNS_UNKNOWN;
  array_header *resp = NULL;

  mark_point();
  res = proxy_dns_resolve(NULL, NULL, dns_type, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_dns_resolve(p, NULL, dns_type, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null name argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  name = "www.google.com";
  res = proxy_dns_resolve(p, name, dns_type, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null resp argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle UNKNOWN type argument");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
}
END_TEST

START_TEST (dns_resolve_bad_response_test) {
  int res;
  const char *name;
  proxy_dns_type_e dns_type;
  array_header *resp = NULL;

  /* SRV */
  dns_type = PROXY_DNS_SRV;

  mark_point();
  name = "foobarbaz";
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle no SRV records for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  mark_point();
  name = "  ";
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle no SRV records for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  mark_point();
  name = ".";
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle no SRV records for '%s'", name);
  fail_unless(errno == ENOENT || errno == EPERM,
    "Expected EPERM (%d) or ENOENT (%d), got %s (%d)", EPERM, ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  /* TXT */
  dns_type = PROXY_DNS_TXT;

  mark_point();
  name = "foobarbaz";
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle no TXT records for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  mark_point();
  name = "  ";
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle no TXT records for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  mark_point();
  name = ".";
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle no TXT records for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  mark_point();
  name = "+";
  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  fail_unless(res < 0, "Failed to handle no TXT records for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");
}
END_TEST

START_TEST (dns_resolve_type_srv_test) {
  int res;
  const char *name = NULL;
  proxy_dns_type_e dns_type = PROXY_DNS_SRV;
  array_header *resp = NULL;
  uint32_t ttl = 0;

  mark_point();
  name = "_ftps._tcp.castaglia.org";
  res = proxy_dns_resolve(p, name, dns_type, &resp, &ttl);
  fail_unless(res < 0, "Failed to handle no SRV records for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  mark_point();
  name = "_imap._tcp.gmail.com";
  res = proxy_dns_resolve(p, name, dns_type, &resp, &ttl);
  fail_unless(res < 0, "Failed to handle explicit 'no service' for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(resp == NULL, "Expected null responses");

  mark_point();
  name = "_imaps._tcp.gmail.com";
  res = proxy_dns_resolve(p, name, dns_type, &resp, &ttl);
  fail_unless(res > 0, "Failed to resolve SRV records for '%s': %s", name,
    strerror(errno));
  fail_unless(resp != NULL, "Expected non-null responses");

  mark_point();
  name = "_ldap._tcp.ru.ac.za";
  res = proxy_dns_resolve(p, name, dns_type, &resp, &ttl);

  /* This particular DNS record may not always be there... */
  if (res < 0 &&
      errno != NOENT) {
    fail_unless(res > 0, "Failed to resolve SRV records for '%s': %s", name,
      strerror(errno));
    fail_unless(resp != NULL, "Expected non-null responses");
  }
}
END_TEST

START_TEST (dns_resolve_type_txt_test) {
  int res;
  const char *name = NULL;
  proxy_dns_type_e dns_type = PROXY_DNS_TXT;
  array_header *resp = NULL;
  uint32_t ttl = 0;

  /* These sometimes fail unexpected for CI builds. */

  mark_point();
  name = "google.com";
  res = proxy_dns_resolve(p, name, dns_type, &resp, &ttl);

  if (getenv("CI") == NULL) {
    fail_unless(res > 0, "Failed to resolve TXT records for '%s': %s", name,
      strerror(errno));
    fail_unless(resp != NULL, "Expected non-null responses");
  }

  mark_point();
  name = "amazon.com";
  res = proxy_dns_resolve(p, name, dns_type, &resp, &ttl);

  if (getenv("CI") == NULL) {
    fail_unless(res > 0, "Failed to resolve TXT records for '%s': %s", name,
      strerror(errno));
    fail_unless(resp != NULL, "Expected non-null responses");
  }
}
END_TEST

Suite *tests_get_dns_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("dns");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, dns_resolve_einval_test);
  tcase_add_test(testcase, dns_resolve_bad_response_test);
  tcase_add_test(testcase, dns_resolve_type_srv_test);
  tcase_add_test(testcase, dns_resolve_type_txt_test);

  /* Allow a longer timeout on these tests, as they depend on external DNS
   * latency.
   */
  tcase_set_timeout(testcase, 30);

  suite_add_tcase(suite, testcase);
  return suite;
}
