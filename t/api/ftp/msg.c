/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2016-2022 TJ Saunders <tj@castaglia.org>
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

/* FTP Message API tests. */

#include "../tests.h"

static pool *p = NULL;
static unsigned char use_ipv6 = FALSE;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = proxy_pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  init_netaddr();
  use_ipv6 = pr_netaddr_use_ipv6();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.msg", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.msg", 0, 0);
  }

  if (use_ipv6 == FALSE) {
    pr_netaddr_disable_ipv6();
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = proxy_pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  } 
}

START_TEST (fmt_addr_test) {
  const char *res, *expected;
  const pr_netaddr_t *addr;
  unsigned short port = 2121;

  mark_point();
  res = proxy_ftp_msg_fmt_addr(NULL, NULL, 0, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_msg_fmt_addr(p, NULL, 0, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null addr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  ck_assert_msg(addr != NULL, "Failed to get addr for 127.0.0.1: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_msg_fmt_addr(p, addr, port, FALSE);
  ck_assert_msg(res != NULL, "Failed to format addr: %s", strerror(errno));
  expected = "127,0,0,1,8,73";
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  addr = pr_netaddr_get_addr(p, "169.254.254.254", NULL);
  ck_assert_msg(addr != NULL, "Failed to get addr for 169.254.254.254: %s",
    strerror(errno));
  res = proxy_ftp_msg_fmt_addr(p, addr, 38550, FALSE);
  ck_assert_msg(res != NULL, "Failed to format addr: %s", strerror(errno));
  expected = "169,254,254,254,150,150";
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

}
END_TEST

START_TEST (fmt_ext_addr_test) {
  const char *res, *expected;
  const pr_netaddr_t *addr;
  unsigned short port = 2121;

  mark_point();
  res = proxy_ftp_msg_fmt_ext_addr(NULL, NULL, 0, 0, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_msg_fmt_ext_addr(p, NULL, 0, 0, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null addr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  ck_assert_msg(addr != NULL, "Failed to get addr for 127.0.0.1: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_msg_fmt_ext_addr(p, addr, port, 0, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null addr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_msg_fmt_ext_addr(p, addr, port, PR_CMD_EPRT_ID, FALSE);
  ck_assert_msg(res != NULL, "Failed to format addr: %s", strerror(errno));
  expected = "|1|127.0.0.1|2121|";
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  mark_point();
  res = proxy_ftp_msg_fmt_ext_addr(p, addr, port, PR_CMD_EPSV_ID, FALSE);
  ck_assert_msg(res != NULL, "Failed to format addr: %s", strerror(errno));
  expected = "|||2121|";
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

#if PR_USE_IPV6
  addr = pr_netaddr_get_addr(p, "::1", NULL);
  ck_assert_msg(addr != NULL, "Failed to get addr for ::1: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_msg_fmt_ext_addr(p, addr, port, PR_CMD_EPRT_ID, FALSE);
  ck_assert_msg(res != NULL, "Failed to format addr: %s", strerror(errno));
  expected = "|2|::1|2121|";
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  mark_point();
  res = proxy_ftp_msg_fmt_ext_addr(p, addr, port, PR_CMD_EPSV_ID, FALSE);
  ck_assert_msg(res != NULL, "Failed to format addr: %s", strerror(errno));
  expected = "|||2121|";
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (parse_addr_test) {
  const pr_netaddr_t *res;
  const char *msg, *expected, *ip_str;

  res = proxy_ftp_msg_parse_addr(NULL, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_msg_parse_addr(p, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null msg");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  msg = "foo";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res == NULL, "Failed to handle invalid format");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  msg = "(a,b,c,d,e,f)";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res == NULL, "Failed to handle invalid format");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  msg = "(1000,2000,3000,4000,5000,6000)";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res == NULL, "Failed to handle invalid format");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(1,2,3,4,5000,6000)";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res == NULL, "Failed to handle invalid format");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(0,0,0,0,1,2)";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res == NULL, "Failed to handle invalid format");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(1,2,3,4,0,0)";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res == NULL, "Failed to handle invalid format");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(127,0,0,1,8,73)";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res != NULL, "Failed to parse message '%s': %s", msg,
    strerror(errno));
  ip_str = pr_netaddr_get_ipstr(res);
  expected = "127.0.0.1";
  ck_assert_msg(strcmp(ip_str, expected) == 0, "Expected '%s', got '%s'",
    expected, ip_str);
  ck_assert_msg(ntohs(pr_netaddr_get_port(res)) == 2121,
    "Expected 2121, got %u", ntohs(pr_netaddr_get_port(res)));

  msg = "(195,144,107,198,8,73)";
  res = proxy_ftp_msg_parse_addr(p, msg, 0);
  ck_assert_msg(res != NULL, "Failed to parse message '%s': %s", msg,
    strerror(errno));
  ip_str = pr_netaddr_get_ipstr(res);
  expected = "195.144.107.198";
  ck_assert_msg(strcmp(ip_str, expected) == 0, "Expected '%s', got '%s'",
    expected, ip_str);
  ck_assert_msg(ntohs(pr_netaddr_get_port(res)) == 2121,
    "Expected 2121, got %u", ntohs(pr_netaddr_get_port(res)));

#ifdef PR_USE_IPV6
  msg = "(127,0,0,1,8,73)";
  res = proxy_ftp_msg_parse_addr(p, msg, AF_INET);
  ck_assert_msg(res != NULL, "Failed to parse message '%s': %s", msg,
    strerror(errno));
  ip_str = pr_netaddr_get_ipstr(res);
  expected = "127.0.0.1";
  ck_assert_msg(strcmp(ip_str, expected) == 0, "Expected '%s', got '%s'",
    expected, ip_str);

  msg = "(127,0,0,1,8,73)";
  res = proxy_ftp_msg_parse_addr(p, msg, AF_INET6);
  ck_assert_msg(res != NULL, "Failed to parse message '%s': %s", msg,
    strerror(errno));
  ip_str = pr_netaddr_get_ipstr(res);
  expected = "::ffff:127.0.0.1";
  ck_assert_msg(strcmp(ip_str, expected) == 0, "Expected '%s', got '%s'",
    expected, ip_str);

  msg = "(195,144,107,198,8,73)";
  res = proxy_ftp_msg_parse_addr(p, msg, AF_INET6);
  ck_assert_msg(res != NULL, "Failed to parse message '%s': %s", msg,
    strerror(errno));
  ip_str = pr_netaddr_get_ipstr(res);
  expected = "::ffff:195.144.107.198";
  ck_assert_msg(strcmp(ip_str, expected) == 0, "Expected '%s', got '%s'",
    expected, ip_str);
  ck_assert_msg(ntohs(pr_netaddr_get_port(res)) == 2121,
    "Expected 2121, got %u", ntohs(pr_netaddr_get_port(res)));

  pr_netaddr_disable_ipv6();

  msg = "(127,0,0,1,8,73)";
  res = proxy_ftp_msg_parse_addr(p, msg, AF_INET6);
  ck_assert_msg(res != NULL, "Failed to parse message '%s': %s", msg,
    strerror(errno));
  ip_str = pr_netaddr_get_ipstr(res);
  expected = "127.0.0.1";
  ck_assert_msg(strcmp(ip_str, expected) == 0, "Expected '%s', got '%s'",
    expected, ip_str);

  pr_netaddr_enable_ipv6();
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (parse_ext_addr_test) {
  const pr_netaddr_t *addr, *res;
  const char *msg; 

  res = proxy_ftp_msg_parse_ext_addr(NULL, NULL, NULL, 0, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_msg_parse_ext_addr(p, NULL, NULL, 0, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null msg");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  msg = "foo";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, NULL, 0, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null addr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  ck_assert_msg(addr != NULL, "Failed to get address for 127.0.0.1: %s",
    strerror(errno));

  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, 0, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad network protocol");
  ck_assert_msg(errno == EPROTOTYPE, "Expected EPROTOTYPE (%d), got '%s' (%d)",
    EPROTOTYPE, strerror(errno), errno);

  /* EPSV response formats */

  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad EPSV response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(foo";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad EPSV response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(foo)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad network protocol");
  ck_assert_msg(errno == EPROTOTYPE, "Expected EPROTOTYPE (%d), got '%s' (%d)",
    EPROTOTYPE, strerror(errno), errno);

  msg = "(1)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad network protocol");
  ck_assert_msg(errno == EPROTOTYPE, "Expected EPROTOTYPE (%d), got '%s' (%d)",
    EPROTOTYPE, strerror(errno), errno);

  msg = "(|4)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad network protocol");
  ck_assert_msg(errno == EPROTOTYPE, "Expected EPROTOTYPE (%d), got '%s' (%d)",
    EPROTOTYPE, strerror(errno), errno);

  msg = "(|0)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad network protocol");
  ck_assert_msg(errno == EPROTOTYPE, "Expected EPROTOTYPE (%d), got '%s' (%d)",
    EPROTOTYPE, strerror(errno), errno);

  msg = "(|1)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad network protocol");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  msg = "(|2)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle bad network protocol");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  /* Where the network protocol matches that of the address... */
  msg = "(|1|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle badly formatted message");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(|1|1.2.3.4)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle badly formatted message");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  msg = "(|1|1.2.3.4|5)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle badly formatted message");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  msg = "(|1|1.2.3.4|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(||1.2.3.4|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(||1.2.3.4|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, "all");
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(||1.2.3.4|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, "1");
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(|||5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));
  ck_assert_msg(
    strcmp(pr_netaddr_get_ipstr(addr), pr_netaddr_get_ipstr(res)) == 0,
    "Expected '%s', got '%s'", pr_netaddr_get_ipstr(addr),
    pr_netaddr_get_ipstr(res));

  /* ...and where the network protocol does not match that of the address. */

  msg = "(||::1|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle network protocol mismatch");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  msg = "(|2|1.2.3.4|5)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle network protocol mismatch");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

#ifdef PR_USE_IPV6
  addr = pr_netaddr_get_addr(p, "::1", NULL);
  ck_assert_msg(addr != NULL, "Failed to get address for ::1: %s",
    strerror(errno));

  msg = "(|2|1.2.3.4|5)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle network protocol mismatch");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  msg = "(|1|::1|5)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle network protocol mismatch");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  msg = "(|2|::1|5)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle network protocol mismatch");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  msg = "(|2|::1|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(|2|::1|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, "ALL");
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(||::1|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, "2");
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(||::1|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));

  msg = "(|||5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res != NULL, "Failed to handle formatted message '%s': %s", msg,
    strerror(errno));
  ck_assert_msg(
    strcmp(pr_netaddr_get_ipstr(addr), pr_netaddr_get_ipstr(res)) == 0,
    "Expected '%s', got '%s'", pr_netaddr_get_ipstr(addr),
    pr_netaddr_get_ipstr(res));

  msg = "(||1.2.3.4|5|)";
  res = proxy_ftp_msg_parse_ext_addr(p, msg, addr, PR_CMD_EPSV_ID, NULL);
  ck_assert_msg(res == NULL, "Failed to handle network protocol mismatch");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
#endif /* PR_USE_IPV6 */
}
END_TEST

Suite *tests_get_ftp_msg_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.msg");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, fmt_addr_test);
  tcase_add_test(testcase, fmt_ext_addr_test);
  tcase_add_test(testcase, parse_addr_test);
  tcase_add_test(testcase, parse_ext_addr_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
