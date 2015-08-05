/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2013-2015 TJ Saunders <tj@castaglia.org>
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

/* Conn API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (conn_create_test) {
  struct proxy_conn *pconn;
  const char *url;

  pconn = proxy_conn_create(NULL, NULL);
  fail_unless(pconn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(NULL, url);
  fail_unless(pconn == NULL, "Failed to handle null pool argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  pconn = proxy_conn_create(p, NULL);
  fail_unless(pconn == NULL, "Failed to handle null URL argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  /* We're already testing URL parsing elsewhere, so we only need to
   * supply well-formed URLs in these tests.
   */

  mark_point();

  url = "http://127.0.0.1:80";
  pconn = proxy_conn_create(p, url);
  fail_unless(pconn == NULL, "Failed to handle unsupported protocol/scheme");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  mark_point();

  url = "ftp://foo.bar.baz";
  pconn = proxy_conn_create(p, url);
  fail_unless(pconn == NULL, "Failed to handle unresolvable host");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url);
  fail_if(pconn == NULL, "Failed to create pconn for URL '%s' as expected",
    url);
}
END_TEST

START_TEST (conn_get_addr_test) {
  struct proxy_conn *pconn;
  const char *ipstr, *url;
  pr_netaddr_t *pconn_addr;
  array_header *other_addrs = NULL;
 
  pconn_addr = proxy_conn_get_addr(NULL, NULL);
  fail_unless(pconn_addr == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
 
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url);
  fail_if(pconn == NULL, "Failed to create pconn for URL '%s' as expected",
    url);

  pconn_addr = proxy_conn_get_addr(pconn, &other_addrs);
  fail_if(pconn_addr == NULL, "Failed to get address for pconn");
  ipstr = pr_netaddr_get_ipstr(pconn_addr);
  fail_unless(strcmp(ipstr, "127.0.0.1") == 0,
    "Expected IP address '127.0.0.1', got '%s'", ipstr);
}
END_TEST

START_TEST (conn_get_hostport_test) {
  struct proxy_conn *pconn;
  const char *hostport, *url;

  hostport = proxy_conn_get_hostport(NULL);
  fail_unless(hostport == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
 
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url);
  fail_if(pconn == NULL, "Failed to create pconn for URL '%s' as expected",
    url);

  hostport = proxy_conn_get_hostport(pconn);
  fail_if(hostport == NULL, "Failed to get host/port for pconn");
  fail_unless(strcmp(hostport, "127.0.0.1:21") == 0,
    "Expected host/port '127.0.0.1:21', got '%s'", hostport);

  /* Implicit/assumed ports */
  url = "ftp://127.0.0.1";
  pconn = proxy_conn_create(p, url);
  fail_if(pconn == NULL, "Failed to create pconn for URL '%s' as expected",
    url);

  hostport = proxy_conn_get_hostport(pconn);
  fail_if(hostport == NULL, "Failed to get host/port for pconn");
  fail_unless(strcmp(hostport, "127.0.0.1:21") == 0,
    "Expected host/port '127.0.0.1:21', got '%s'", hostport);
}
END_TEST

START_TEST (conn_get_uri_test) {
  struct proxy_conn *pconn;
  const char *pconn_url, *url;

  pconn_url = proxy_conn_get_uri(NULL);
  fail_unless(pconn_url == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
 
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url);
  fail_if(pconn == NULL, "Failed to create pconn for URL '%s' as expected",
    url);

  pconn_url = proxy_conn_get_uri(pconn);
  fail_if(pconn_url == NULL, "Failed to get URL for pconn");
  fail_unless(strcmp(pconn_url, url) == 0,
    "Expected URL '%s', got '%s'", url, pconn_url);
}
END_TEST

Suite *tests_get_conn_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("conn");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, conn_create_test);
  tcase_add_test(testcase, conn_get_addr_test);
  tcase_add_test(testcase, conn_get_hostport_test);
  tcase_add_test(testcase, conn_get_uri_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
