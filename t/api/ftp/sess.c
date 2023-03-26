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

/* FTP Session API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  init_netaddr();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.sess", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.sess", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

START_TEST (get_feat_test) {
  int res;
  const struct proxy_session *proxy_sess = NULL;

  res = proxy_ftp_sess_get_feat(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_sess_get_feat(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = proxy_session_alloc(p);

  mark_point();
  res = proxy_ftp_sess_get_feat(p, proxy_sess);
  ck_assert_msg(res < 0, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (send_auth_tls_test) {
  int res;
  const struct proxy_session *proxy_sess = NULL;

  res = proxy_ftp_sess_send_auth_tls(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_sess_send_auth_tls(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = proxy_session_alloc(p);

  mark_point();
  res = proxy_ftp_sess_send_auth_tls(p, proxy_sess);
#ifdef PR_USE_OPENSSL
  ck_assert_msg(res < 0, "Sent AUTH TLS unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
#endif /* PR_USE_OPENSSL */

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (send_host_test) {
  int res;
  const struct proxy_session *proxy_sess = NULL;

  res = proxy_ftp_sess_send_host(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_sess_send_host(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = proxy_session_alloc(p);

  mark_point();
  res = proxy_ftp_sess_send_host(p, proxy_sess);
  ck_assert_msg(res == 0, "Failed to (maybe) send HOST: %s", strerror(errno));

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (send_pbsz_prot_test) {
  int res;
  const struct proxy_session *proxy_sess = NULL;

  res = proxy_ftp_sess_send_pbsz_prot(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_sess_send_pbsz_prot(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = proxy_session_alloc(p);

  mark_point();
  res = proxy_ftp_sess_send_pbsz_prot(p, proxy_sess);
  ck_assert_msg(res == 0, "Failed to (maybe) send PBSZ/PROT: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
}
END_TEST

Suite *tests_get_ftp_sess_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.sess");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, get_feat_test);
  tcase_add_test(testcase, send_auth_tls_test);
  tcase_add_test(testcase, send_host_test);
  tcase_add_test(testcase, send_pbsz_prot_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
