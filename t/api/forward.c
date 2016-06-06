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

/* Forward-proxy API tests */

#include "tests.h"

extern xaset_t *server_list;

static pool *p = NULL;
static const char *test_dir = "/tmp/mod_proxy-test-forward";

static void create_main_server(void) {
  pool *main_pool;

  main_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(main_pool, "testsuite#main_server pool");

  server_list = xaset_create(main_pool, NULL);

  main_server = (server_rec *) pcalloc(main_pool, sizeof(server_rec));
  xaset_insert(server_list, (xasetmember_t *) main_server);

  main_server->pool = main_pool;
  main_server->conf = xaset_create(main_pool, NULL);
  main_server->set = server_list;
  main_server->sid = 1;
  main_server->notes = pr_table_nalloc(main_pool, 0, 8);

  /* TCP KeepAlive is enabled by default, with the system defaults. */
  main_server->tcp_keepalive = palloc(main_server->pool,
    sizeof(struct tcp_keepalive));
  main_server->tcp_keepalive->keepalive_enabled = TRUE;
  main_server->tcp_keepalive->keepalive_idle = -1;
  main_server->tcp_keepalive->keepalive_count = -1;
  main_server->tcp_keepalive->keepalive_intvl = -1;

  main_server->ServerName = "Test Server";
  main_server->ServerPort = 21;
}

static void test_cleanup(pool *cleanup_pool) {
  (void) tests_rmpath(cleanup_pool, test_dir);
}

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
    server_list = NULL;
  }

  test_cleanup(p);
  create_main_server();
  init_fs();
  init_netaddr();
  init_netio();
  init_inet();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.forward", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.forward", 0, 0);
  }

  test_cleanup(p);
  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
    server_list = NULL;
  }
}

START_TEST (forward_free_test) {
  int res;

  res = proxy_forward_free(NULL);
  fail_unless(res == 0, "Failed to free Forward API resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_init_test) {
  int res;

  res = proxy_forward_init(NULL, NULL);
  fail_unless(res == 0, "Failed to init Forward API resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_sess_free_test) {
  int res;

  res = proxy_forward_sess_free(NULL, NULL);
  fail_unless(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_sess_init_test) {
  int res;

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = proxy_forward_sess_init(p, test_dir, NULL);
  fail_unless(res < 0,
    "Initialized Forward API session resources unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  /* Make the connections look like they're from an RFC1918 address. */
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "192.168.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = proxy_forward_sess_init(p, test_dir, NULL);
  fail_unless(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  res = proxy_forward_sess_free(p, NULL);
  fail_unless(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_get_method_test) {
  int res;
  const char *method;

  res = proxy_forward_get_method(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  method = "foo";
  res = proxy_forward_get_method(method);
  fail_unless(res < 0, "Failed to handle unsupported method '%s'", method);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  method = "proxyuser,user@host";
  res = proxy_forward_get_method(method);
  fail_unless(res == PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH,
    "Failed to handle method '%s'", method);

  method = "user@host";
  res = proxy_forward_get_method(method);
  fail_unless(res == PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH,
    "Failed to handle method '%s'", method);

  method = "proxyuser@host,user";
  res = proxy_forward_get_method(method);
  fail_unless(res == PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH,
    "Failed to handle method '%s'", method);
}
END_TEST

START_TEST (forward_use_proxy_auth_test) {
  int res;

  res = proxy_forward_use_proxy_auth();
  fail_unless(res == TRUE, "Expected true, got %d", res);
}
END_TEST

START_TEST (forward_have_authenticated_test) {
  int res;
  cmd_rec *cmd = NULL;

  res = proxy_forward_have_authenticated(cmd);
  fail_unless(res == FALSE, "Expected false, got %d", res);
}
END_TEST

Suite *tests_get_forward_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("forward");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, forward_free_test);
  tcase_add_test(testcase, forward_init_test);
  tcase_add_test(testcase, forward_sess_free_test);
  tcase_add_test(testcase, forward_sess_init_test);
  tcase_add_test(testcase, forward_get_method_test);
  tcase_add_test(testcase, forward_use_proxy_auth_test);
  tcase_add_test(testcase, forward_have_authenticated_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
