/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2016-2017 TJ Saunders <tj@castaglia.org>
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
  init_auth();

  server_list = xaset_create(p, NULL);
  pr_parser_prepare(p, &server_list);
  create_main_server();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.session", 1, 20);
  }

  pr_inet_set_default_family(p, AF_INET);
}

static void tear_down(void) {
  pr_inet_set_default_family(p, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.session", 0, 0);
  }

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

START_TEST (session_free_test) {
  int res;

  res = proxy_session_free(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_session_free(p, NULL);
  fail_unless(res < 0, "Failed to handle null session");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (session_alloc_test) {
  struct proxy_session *proxy_sess;

  proxy_sess = (struct proxy_session *) proxy_session_alloc(NULL);
  fail_unless(proxy_sess == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);
  fail_unless(proxy_sess != NULL, "Failed to allocate proxy session: %s",
    strerror(errno));

  mark_point();
  proxy_session_free(p, proxy_sess);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);
  fail_unless(proxy_sess != NULL, "Failed to allocate proxy session: %s",
    strerror(errno));

  proxy_sess->frontend_data_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY,
    FALSE);
  proxy_sess->backend_ctrl_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY,
    FALSE);
  proxy_sess->backend_data_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY,
    FALSE);

  mark_point();
  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (session_check_password_test) {
  int res;
  const char *user, *passwd;

  mark_point();
  res = proxy_session_check_password(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_session_check_password(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null user");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  user = "foo";

  mark_point();
  res = proxy_session_check_password(p, user, NULL);
  fail_unless(res < 0, "Failed to handle null passwd");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  passwd = "bar";

  mark_point();
  res = proxy_session_check_password(p, user, passwd);
  fail_unless(res < 0, "Failed to handle unknown user");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (session_setup_env_test) {
  int res, flags = 0;
  const char *user;

  mark_point();
  res = proxy_session_setup_env(NULL, NULL, flags);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_session_setup_env(p, NULL, flags);
  fail_unless(res < 0, "Failed to handle null user");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));
  session.c->remote_name = pstrdup(p, "127.0.0.1");

  user = "foo";

  mark_point();
  res = proxy_session_setup_env(p, user, flags);
  fail_unless(res == 0, "Failed to setup environment: %s", strerror(errno));
  fail_unless(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED,
    "Expected PROXY_AUTHENTICATED state set");

  proxy_sess_state &= ~PROXY_SESS_STATE_PROXY_AUTHENTICATED;

  user = "root";

  mark_point();
  res = proxy_session_setup_env(p, user, flags);
  fail_unless(res == 0, "Failed to setup environment: %s", strerror(errno));
  fail_unless(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED,
    "Expected PROXY_AUTHENTICATED state set");

  proxy_sess_state &= ~PROXY_SESS_STATE_PROXY_AUTHENTICATED;
  pr_inet_close(p, session.c);
  session.c = NULL;
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
  tcase_add_test(testcase, session_check_password_test);
  tcase_add_test(testcase, session_setup_env_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
