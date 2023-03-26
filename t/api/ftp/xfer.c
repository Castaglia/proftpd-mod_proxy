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

/* FTP Transfer API tests. */

#include "../tests.h"

extern xaset_t *server_list;

static pool *p = NULL;

static void create_main_server(void) {
  server_rec *s;

  s = pr_parser_server_ctxt_open("127.0.0.1");
  s->ServerName = "Test Server";

  main_server = s;
}

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
    main_server = NULL;
    server_list = NULL;
    session.c = NULL;
    session.notes = NULL;
  }

  init_config();
  init_netaddr();
  init_netio();
  init_inet();

  server_list = xaset_create(p, NULL);
  pr_parser_prepare(p, &server_list);
  create_main_server();

  pr_response_set_pool(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.conn", 1, 20);
    pr_trace_set_levels("proxy.ftp.xfer", 1, 20);
  }

  pr_inet_set_default_family(p, AF_INET);
}

static void tear_down(void) {
  pr_inet_set_default_family(p, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.conn", 0, 0);
    pr_trace_set_levels("proxy.ftp.xfer", 0, 0);
  }

  pr_response_set_pool(NULL);
  pr_parser_cleanup();
  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    main_server = NULL;
    server_list = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

START_TEST (prepare_active_test) {
  int res;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess = NULL;

  res = proxy_ftp_xfer_prepare_active(0, NULL, NULL, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "FOO");

  res = proxy_ftp_xfer_prepare_active(0, cmd, NULL, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null error code");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);

  mark_point();
  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(res < 0, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess->backend_ctrl_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY,
    FALSE);
  ck_assert_msg(proxy_sess->backend_ctrl_conn != NULL,
    "Failed to open backend control conn: %s", strerror(errno));

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", NULL);
  ck_assert_msg(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(res < 0, "Failed to handle illegal FTP command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  /* Prevent NULL pointer dereferences which would only happen during
   * testing.
   */
  proxy_sess->backend_ctrl_conn->remote_addr = session.c->remote_addr;

  mark_point();
  res = proxy_ftp_xfer_prepare_active(PR_CMD_PORT_ID, cmd, "500", proxy_sess,
    0);
  ck_assert_msg(res < 0, "Failed to handle bad PORT command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_xfer_prepare_active(PR_CMD_EPRT_ID, cmd, "500", proxy_sess,
    0);
  ck_assert_msg(res < 0, "Failed to handle bad EPRT command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "EPRT");

  mark_point();
  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(res < 0, "Failed to handle bad EPRT command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "PORT");

  mark_point();
  res = proxy_ftp_xfer_prepare_active(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(res < 0, "Failed to handle bad PORT command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
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
  ck_assert_msg(addr == NULL, "Failed to handle null command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "FOO");

  addr = proxy_ftp_xfer_prepare_passive(0, cmd, NULL, NULL, 0);
  ck_assert_msg(addr == NULL, "Failed to handle null error code");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", NULL, 0);
  ck_assert_msg(addr == NULL, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(addr == NULL, "Failed to handle null proxy session");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess->backend_ctrl_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY,
    FALSE);
  ck_assert_msg(proxy_sess->backend_ctrl_conn != NULL,
    "Failed to open backend control conn: %s", strerror(errno));

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", NULL);
  ck_assert_msg(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(addr == NULL, "Failed to handle illegal FTP command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  /* Prevent NULL pointer dereferences which would only happen during
   * testing.
   */
  proxy_sess->backend_ctrl_conn->remote_addr = session.c->remote_addr;

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(PR_CMD_PASV_ID, cmd, "500", proxy_sess,
    0);
  ck_assert_msg(addr == NULL, "Failed to handle bad PASV command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(PR_CMD_EPSV_ID, cmd, "500", proxy_sess,
    0);
  ck_assert_msg(addr == NULL, "Failed to handle bad EPSV command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "EPSV");

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(addr == NULL, "Failed to handle bad EPSV command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "PASV");

  mark_point();
  addr = proxy_ftp_xfer_prepare_passive(0, cmd, "500", proxy_sess, 0);
  ck_assert_msg(addr == NULL, "Failed to handle bad PASV command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
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
