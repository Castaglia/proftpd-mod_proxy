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

/* FTP Transfer API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
  }

  init_netaddr();
  init_netio();
  init_inet();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.xfer", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.xfer", 0, 0);
  }

  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
  } 
}

START_TEST (prepare_active_test) {
  int res;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess = NULL;

  res = proxy_ftp_xfer_prepare_active(0, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null command");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "FOO");

  res = proxy_ftp_xfer_prepare_active(0, cmd, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error code");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", NULL, 0);
  fail_unless(res < 0, "Failed to handle null proxy session");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);

  mark_point();
  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", proxy_sess, 0);
  fail_unless(res < 0, "Failed to handle null proxy session");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess->backend_ctrl_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY,
    FALSE);
  fail_unless(proxy_sess->backend_ctrl_conn != NULL,
    "Failed to open backend control conn: %s", strerror(errno));

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", proxy_sess, 0);
  fail_unless(res < 0, "Failed to handle illegal FTP command");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, session.c);
  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (prepare_passive_test) {
  const pr_netaddr_t *addr;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess;

  addr = proxy_ftp_xfer_prepare_passive(0, NULL, NULL, NULL, 0);
  fail_unless(addr == NULL, "Failed to handle null command");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "FOO");

  addr = proxy_ftp_xfer_prepare_passive(0, cmd, NULL, NULL, 0);
  fail_unless(addr == NULL, "Failed to handle null error code");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", NULL, 0);
  fail_unless(addr == NULL, "Failed to handle null proxy session");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", proxy_sess, 0);
  fail_unless(addr == NULL, "Failed to handle null proxy session");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess->backend_ctrl_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY,
    FALSE);
  fail_unless(proxy_sess->backend_ctrl_conn != NULL,
    "Failed to open backend control conn: %s", strerror(errno));
  
  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", proxy_sess, 0);
  fail_unless(addr == NULL, "Failed to handle illegal FTP command");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, session.c);
  proxy_session_free(p, proxy_sess);
}
END_TEST

Suite *tests_get_ftp_xfer_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.xfer");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, prepare_active_test);
  tcase_add_test(testcase, prepare_passive_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
