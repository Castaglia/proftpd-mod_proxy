/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2015-2017 TJ Saunders <tj@castaglia.org>
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

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  init_netaddr();
  init_netio();
  init_inet();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 1, 20);
    pr_trace_set_levels("inet", 1, 20);
    pr_trace_set_levels("proxy.inet", 1, 20);
  }

  pr_inet_set_default_family(p, AF_INET);
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
    pr_trace_set_levels("inet", 0, 0);
    pr_trace_set_levels("proxy.inet", 0, 0);
  }

  pr_inet_set_default_family(p, 0);
  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

/* Tests */

START_TEST (inet_accept_test) {
  conn_t *conn;

  mark_point();
  conn = proxy_inet_accept(NULL, NULL, NULL, -1, -1, FALSE);
  fail_unless(conn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (inet_close_test) {
  conn_t *conn;

  mark_point();
  proxy_inet_close(NULL, NULL);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  conn->rfd = conn->wfd = 999;
  proxy_inet_close(NULL, conn);
}
END_TEST

START_TEST (inet_connect_ipv4_test) {
  int res;
  conn_t *conn;
  const pr_netaddr_t *addr;

  mark_point();
  res = proxy_inet_connect(NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_inet_connect(p, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null conn");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  res = proxy_inet_connect(p, conn, NULL, 0);
  fail_unless(res < 0, "Failed to handle null addr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '127.0.0.1': %s",
    strerror(errno));

  mark_point();
  res = proxy_inet_connect(p, conn, addr, 80);
  fail_unless(res < 0, "Connected to 127.0.0.1#80 unexpectedly");
  fail_unless(errno == ECONNREFUSED,
    "Expected ECONNREFUSED (%d), got '%s' (%d)", ECONNREFUSED,
    strerror(errno), errno);
  proxy_inet_close(p, conn);

  /* Try connecting to Google's DNS server. */

  addr = pr_netaddr_get_addr(p, "8.8.8.8", NULL);
  fail_unless(addr != NULL, "Failed to resolve '8.8.8.8': %s",
    strerror(errno));

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  res = proxy_inet_connect(p, conn, addr, 53);
  fail_if(res < 0, "Failed to connect to 8.8.8.8#53: %s", strerror(errno));

  mark_point();
  proxy_inet_close(p, conn);

  /* Now start supplying in/out streams. */

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  conn->instrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl reading stream: %s",
    strerror(errno));

  mark_point();
  res = proxy_inet_connect(p, conn, addr, 53);
  fail_if(res < 0, "Failed to connect to 8.8.8.8#53: %s", strerror(errno));

  mark_point();
  proxy_inet_close(p, conn);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  conn->instrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl reading stream: %s",
    strerror(errno));

  conn->outstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, -1, PR_NETIO_IO_WR);
  fail_unless(conn->outstrm != NULL, "Failed to open othr writing stream: %s",
    strerror(errno));

  mark_point();
  res = proxy_inet_connect(p, conn, addr, 53);
  fail_if(res < 0, "Failed to connect to 8.8.8.8#53: %s", strerror(errno));

  mark_point();
  proxy_inet_close(p, conn);

}
END_TEST

START_TEST (inet_connect_ipv6_test) {
#ifdef PR_USE_IPV6
  int res;
  conn_t *conn;
  const pr_netaddr_t *addr;
  unsigned char use_ipv6;

  use_ipv6 = pr_netaddr_use_ipv6();
  pr_netaddr_enable_ipv6();
  pr_inet_set_default_family(p, AF_INET6);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  addr = pr_netaddr_get_addr(p, "::1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '::1': %s", strerror(errno));

  mark_point();
  res = proxy_inet_connect(p, conn, addr, 80);
  fail_unless(res < 0, "Connected to 127.0.0.1#80 unexpectedly");
  fail_unless(errno == ECONNREFUSED || errno == ENETUNREACH || errno == EADDRNOTAVAIL,
    "Expected ECONNREFUSED (%d), ENETUNREACH (%d), or EADDRNOTAVAIL (%d), got %s (%d)",
    ECONNREFUSED, ENETUNREACH, EADDRNOTAVAIL, strerror(errno), errno);
  proxy_inet_close(p, conn);

  /* Try connecting to Google's DNS server. */

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  addr = pr_netaddr_get_addr(p, "2001:4860:4860::8888", NULL);
  fail_unless(addr != NULL, "Failed to resolve '2001:4860:4860::8888': %s",
    strerror(errno));

  mark_point();
  res = proxy_inet_connect(p, conn, addr, 53);
  if (res < 0) {
    /* This could be expected, e.g. if there's no route. */
    fail_unless(errno == ECONNREFUSED || errno == ENETUNREACH || errno == EADDRNOTAVAIL,
      "Expected ECONNREFUSED (%d), ENETUNREACH (%d), or EADDRNOTAVAIL (%d), got %s (%d)",
      ECONNREFUSED, ENETUNREACH, EADDRNOTAVAIL, strerror(errno), errno);
  }

  mark_point();
  proxy_inet_close(p, conn);

  pr_inet_set_default_family(p, AF_INET);

  if (use_ipv6 == FALSE) {
    pr_netaddr_disable_ipv6();
  }
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (inet_listen_test) {
  int res;
  conn_t *conn;

  mark_point();
  res = proxy_inet_listen(NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_inet_listen(p, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null conn");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  res = proxy_inet_listen(p, conn, 5, 0);
  fail_unless(res == 0, "Failed to listen on conn: %s", strerror(errno));

  mark_point();
  proxy_inet_close(p, conn);

  /* Now start providing in/out streams. */

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  conn->instrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl reading stream: %s",
    strerror(errno));

  mark_point();
  res = proxy_inet_listen(p, conn, 5, 0);
  fail_unless(res == 0, "Failed to listen on conn: %s", strerror(errno));

  mark_point();
  proxy_inet_close(p, conn);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  conn->instrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl reading stream: %s",
    strerror(errno));

  conn->outstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, -1, PR_NETIO_IO_WR);
  fail_unless(conn->outstrm != NULL, "Failed to open othr writing stream: %s",
    strerror(errno));

  mark_point();
  res = proxy_inet_listen(p, conn, 5, 0);
  fail_unless(res == 0, "Failed to listen on conn: %s", strerror(errno));

  mark_point();
  proxy_inet_close(p, conn);
}
END_TEST

START_TEST (inet_openrw_test) {
  conn_t *res, *conn;
  const pr_netaddr_t *addr;

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
  proxy_inet_close(p, conn);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '127.0.0.1': %s",
    strerror(errno));

  res = proxy_inet_openrw(p, conn, addr, PR_NETIO_STRM_OTHR, -1, -1, -1,
    FALSE);
  fail_unless(res != NULL, "Failed to open rw conn: %s", strerror(errno));
  proxy_inet_close(p, conn);
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
  tcase_add_test(testcase, inet_connect_ipv4_test);
  tcase_add_test(testcase, inet_connect_ipv6_test);
  tcase_add_test(testcase, inet_listen_test);
  tcase_add_test(testcase, inet_openrw_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
