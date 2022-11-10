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

/* Forward-proxy API tests */

#include "tests.h"

extern xaset_t *server_list;

static pool *p = NULL;
static const char *test_dir = "/tmp/mod_proxy-test-forward";

static void create_main_server(void) {
  server_rec *s;

  s = pr_parser_server_ctxt_open("127.0.0.1");
  s->ServerName = "Test Server";

  main_server = s;
}

static int create_test_dir(void) {
  int res;
  mode_t perms;

  perms = 0770;
  res = mkdir(test_dir, perms);
  ck_assert_msg(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
    strerror(errno));

  res = chmod(test_dir, perms);
  ck_assert_msg(res == 0, "Failed to set perms %04o on directory '%s': %s",
    perms, test_dir, strerror(errno));

  return 0;
}

static void test_cleanup(pool *cleanup_pool) {
  (void) tests_rmpath(cleanup_pool, test_dir);
}

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = proxy_pool = session.pool = make_sub_pool(NULL);
    server_list = NULL;
    session.c = NULL;
    session.notes = NULL;
  }

  test_cleanup(p);
  init_config();
  init_fs();
  init_netaddr();
  init_netio();
  init_inet();

  server_list = xaset_create(p, NULL);
  pr_parser_prepare(p, &server_list);
  create_main_server();
  (void) create_test_dir();

  proxy_db_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 1, 20);
    pr_trace_set_levels("proxy.db", 1, 20);
    pr_trace_set_levels("proxy.forward", 1, 20);
    pr_trace_set_levels("proxy.tls", 1, 20);
    pr_trace_set_levels("proxy.uri", 1, 20);
    pr_trace_set_levels("proxy.ftp.ctrl", 1, 20);
    pr_trace_set_levels("proxy.ftp.sess", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
    pr_trace_set_levels("proxy.db", 0, 0);
    pr_trace_set_levels("proxy.forward", 0, 0);
    pr_trace_set_levels("proxy.tls", 0, 0);
    pr_trace_set_levels("proxy.uri", 0, 0);
    pr_trace_set_levels("proxy.ftp.ctrl", 0, 0);
    pr_trace_set_levels("proxy.ftp.sess", 0, 0);
  }

  proxy_db_free();
  pr_parser_cleanup();
  pr_inet_clear();
  test_cleanup(p);

  if (p) {
    destroy_pool(p);
    p = permanent_pool = proxy_pool = session.pool = NULL;
    main_server = NULL;
    server_list = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

START_TEST (forward_free_test) {
  int res;

  res = proxy_forward_free(NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_init_test) {
  int res;

  res = proxy_forward_init(NULL, NULL);
  ck_assert_msg(res == 0, "Failed to init Forward API resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_sess_free_test) {
  int res;

  res = proxy_forward_sess_free(NULL, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_sess_init_test) {
  int res;

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", NULL);
  ck_assert_msg(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = proxy_forward_sess_init(p, test_dir, NULL);
  ck_assert_msg(res < 0,
    "Initialized Forward API session resources unexpectedly");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  /* Make the connections look like they're from an RFC1918 address. */
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "192.168.0.1", NULL);
  ck_assert_msg(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = proxy_forward_sess_init(p, test_dir, NULL);
  ck_assert_msg(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  res = proxy_forward_sess_free(p, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (forward_get_method_test) {
  int res;
  const char *method;

  res = proxy_forward_get_method(NULL);
  ck_assert_msg(res < 0, "Failed to handle null argument");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  method = "foo";
  res = proxy_forward_get_method(method);
  ck_assert_msg(res < 0, "Failed to handle unsupported method '%s'", method);
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  method = "proxyuser,user@host";
  res = proxy_forward_get_method(method);
  ck_assert_msg(res == PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH,
    "Failed to handle method '%s'", method);

  method = "user@host";
  res = proxy_forward_get_method(method);
  ck_assert_msg(res == PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH,
    "Failed to handle method '%s'", method);

  method = "proxyuser@host,user";
  res = proxy_forward_get_method(method);
  ck_assert_msg(res == PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH,
    "Failed to handle method '%s'", method);

  method = "user@sni";
  res = proxy_forward_get_method(method);
  ck_assert_msg(res == PROXY_FORWARD_METHOD_USER_SNI_NO_PROXY_AUTH,
    "Failed to handle method '%s'", method);
}
END_TEST

START_TEST (forward_use_proxy_auth_test) {
  int res;

  res = proxy_forward_use_proxy_auth();
  ck_assert_msg(res == TRUE, "Expected true, got %d", res);
}
END_TEST

START_TEST (forward_have_authenticated_test) {
  int res;
  cmd_rec *cmd = NULL;

  res = proxy_forward_have_authenticated(cmd);
  ck_assert_msg(res == FALSE, "Expected false, got %d", res);
}
END_TEST

static int forward_sess_init(int method_id) {
  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  if (session.c == NULL) {
    return -1;
  }

  /* Make the connections look like they're from an RFC1918 address. */
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "192.168.0.1", NULL);
  if (session.c->remote_addr == NULL) {
    return -1;
  }
  pr_netaddr_set_port((pr_netaddr_t *) session.c->local_addr, htons(7777));

  if (method_id > 0) {
    config_rec *c;

    c = add_config_param("ProxyForwardMethod", 1, NULL);
    c->argv[0] = palloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = method_id;
  }

  return proxy_forward_sess_init(p, test_dir, NULL);
}

static struct proxy_session *forward_get_proxy_sess(void) {
  struct proxy_session *proxy_sess;

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);
  proxy_sess->src_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);

  return proxy_sess;
}

START_TEST (forward_handle_user_noproxyauth_test) {
  int res, successful = FALSE, block_responses = FALSE;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess;

  res = forward_sess_init(PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH);
  ck_assert_msg(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  proxy_sess = forward_get_proxy_sess();

  /* No destination host in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "test");
  cmd->arg = pstrdup(p, "test");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res < 0, "Handled USER command unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Invalid host (no port) in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "test@host");
  cmd->arg = pstrdup(p, "test@host");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res < 0, "Handled USER command unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Valid host (no port) in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "test@127.0.0.1");
  cmd->arg = pstrdup(p, "test@127.0.0.1");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 1, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 2, "USER", "test@192.168.0.1");
  cmd->arg = pstrdup(p, "test@192.168.0.1:7777");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 1, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Destination host (WITH bad port syntax) in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "test@host:foo");
  cmd->arg = pstrdup(p, "test@host:foo");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res < 0, "Handled USER command unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Destination host (WITH invalid port) in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "test@host:70000");
  cmd->arg = pstrdup(p, "test@host:70000");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res < 0, "Handled USER command unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Destination host (WITH port) in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "test@127.0.0.1:2121");
  cmd->arg = pstrdup(p, "test@127.0.0.1:2121");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 1, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_forward_sess_free(p, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (forward_handle_user_userwithproxyauth_test) {
  int res, successful = FALSE, block_responses = FALSE;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess;

  res = forward_sess_init(PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH);
  ck_assert_msg(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  proxy_sess = forward_get_proxy_sess();

  cmd = pr_cmd_alloc(p, 2, "USER", "test@127.0.0.1");
  cmd->arg = pstrdup(p, "test@127.0.0.1");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 0, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(block_responses == FALSE, "Expected false, got %d",
    block_responses);

  proxy_sess_state |= PROXY_SESS_STATE_PROXY_AUTHENTICATED;

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 1, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess_state &= ~PROXY_SESS_STATE_PROXY_AUTHENTICATED;

  res = proxy_forward_sess_free(p, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (forward_handle_user_proxyuserwithproxyauth_test) {
  int res, successful = FALSE, block_responses = FALSE;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess;

  res = forward_sess_init(PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH);
  ck_assert_msg(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  proxy_sess = forward_get_proxy_sess();

  cmd = pr_cmd_alloc(p, 2, "USER", "test@127.0.0.1");
  cmd->arg = pstrdup(p, "test@127.0.0.1");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 0, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(block_responses == FALSE, "Expected false, got %d",
    block_responses);

  proxy_sess_state |= PROXY_SESS_STATE_PROXY_AUTHENTICATED;

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 1, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess_state &= ~PROXY_SESS_STATE_PROXY_AUTHENTICATED;

  res = proxy_forward_sess_free(p, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (forward_handle_pass_noproxyauth_test) {
  int res, successful = FALSE, block_responses = FALSE;
  cmd_rec *cmd;
#ifdef PR_USE_OPENSSL
  config_rec *c;
#endif /* PR_USE_OPENSSL */
  struct proxy_session *proxy_sess;

  /* Skip this test for CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  res = forward_sess_init(PROXY_FORWARD_METHOD_USER_NO_PROXY_AUTH);
  ck_assert_msg(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  proxy_sess = forward_get_proxy_sess();

  /* No destination host in PASS command. */
  cmd = pr_cmd_alloc(p, 2, "PASS", "test");
  cmd->arg = pstrdup(p, "test");

  mark_point();
  res = proxy_forward_handle_pass(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res < 0, "Handled PASS command unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

/* XXX TODO: Use a file fd for the "backend control conn" fd (/dev/null?) */

  /* Valid external host (with port) in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "anonymous@ftp.cisco.com:21");
  cmd->arg = pstrdup(p, "anonymous@ftp.cisco.com:21");

  mark_point();
  res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res == 1, "Failed to handle USER command: %s", strerror(errno));
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  if (getenv("CI") == NULL &&
      getenv("TRAVIS") == NULL) {
    cmd = pr_cmd_alloc(p, 2, "PASS", "ftp@nospam.org");
    cmd->arg = pstrdup(p, "ftp@nospam.org");

    mark_point();
    res = proxy_forward_handle_pass(cmd, proxy_sess, &successful,
      &block_responses);
    ck_assert_msg(res == 1, "Failed to handle PASS command: %s", strerror(errno));
    ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
      strerror(errno), errno);
  }

#ifdef PR_USE_OPENSSL
  /* This time, try an FTPS-capable site. */

  session.notes = pr_table_alloc(p, 0);
  pr_table_add(session.notes, "mod_proxy.proxy-session", proxy_sess,
    sizeof(struct proxy_session));

  res = proxy_tls_init(p, test_dir, PROXY_DB_OPEN_FL_SKIP_VACUUM);
  ck_assert_msg(res == 0, "Failed to init TLS API resources: %s",
    strerror(errno));

  c = add_config_param("ProxyTLSEngine", 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = PROXY_TLS_ENGINE_AUTO;

  c = add_config_param("ProxyTLSVerifyServer", 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = FALSE;

  c = add_config_param("ProxyTLSOptions", 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = PROXY_TLS_OPT_ENABLE_DIAGS;

/* XXX if we want to successfully verify the Cisco cert, we'd need to include
 * its CA certs as a test resource, and configure it here.
 */

  res = proxy_tls_sess_init(p, proxy_sess, PROXY_DB_OPEN_FL_SKIP_VACUUM);
  ck_assert_msg(res == 0, "Failed to init TLS API session resources: %s",
    strerror(errno));

  /* Valid external host (with port) in USER command. */
  cmd = pr_cmd_alloc(p, 2, "USER", "anonymous@ftp.cisco.com:990");
  cmd->arg = pstrdup(p, "anonymous@ftp.cisco.com:990");

  if (getenv("CI") == NULL &&
      getenv("TRAVIS") == NULL) {
    mark_point();
    res = proxy_forward_handle_user(cmd, proxy_sess, &successful,
      &block_responses);

    /* Once you've performed a TLS handshake with ftp.cisco.com, it does not
     * accept anonymous logins.  Fine.
     */
    ck_assert_msg(res != 1, "Handled USER command unexpectedly");
    ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
      strerror(errno), errno);
  }

  mark_point();
  res = proxy_tls_sess_free(p);
  ck_assert_msg(res == 0, "Failed to free TLS API session resources: %s",
    strerror(errno));

  mark_point();
  res = proxy_tls_free(p);
  ck_assert_msg(res == 0, "Failed to free TLS API resources: %s",
    strerror(errno));

  mark_point();
  (void) proxy_db_close(p, NULL);
#endif /* PR_USE_OPENSSL */

  mark_point();
  res = proxy_forward_sess_free(p, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (forward_handle_pass_userwithproxyauth_test) {
  int res, successful = FALSE, block_responses = FALSE;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess;

  res = forward_sess_init(PROXY_FORWARD_METHOD_USER_WITH_PROXY_AUTH);
  ck_assert_msg(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  proxy_sess = forward_get_proxy_sess();

  /* No destination host in PASS command. */
  cmd = pr_cmd_alloc(p, 2, "PASS", "test");
  cmd->arg = pstrdup(p, "test");

  mark_point();
  res = proxy_forward_handle_pass(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res < 0, "Handled PASS command unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

/* XXX TODO: Use a file fd for the "backend control conn" fd (/dev/null?) */

  res = proxy_forward_sess_free(p, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (forward_handle_pass_proxyuserwithproxyauth_test) {
  int res, successful = FALSE, block_responses = FALSE;
  cmd_rec *cmd;
  struct proxy_session *proxy_sess;

  res = forward_sess_init(PROXY_FORWARD_METHOD_PROXY_USER_WITH_PROXY_AUTH);
  ck_assert_msg(res == 0, "Failed to init Forward API session resources: %s",
    strerror(errno));

  proxy_sess = forward_get_proxy_sess();

  /* No destination host in PASS command. */
  cmd = pr_cmd_alloc(p, 2, "PASS", "test");
  cmd->arg = pstrdup(p, "test");

  mark_point();
  res = proxy_forward_handle_pass(cmd, proxy_sess, &successful,
    &block_responses);
  ck_assert_msg(res < 0, "Handled PASS command unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

/* XXX TODO: Use a file fd for the "backend control conn" fd (/dev/null?) */

  res = proxy_forward_sess_free(p, NULL);
  ck_assert_msg(res == 0, "Failed to free Forward API session resources: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
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

  tcase_add_test(testcase, forward_handle_user_noproxyauth_test);
  tcase_add_test(testcase, forward_handle_user_userwithproxyauth_test);
  tcase_add_test(testcase, forward_handle_user_proxyuserwithproxyauth_test);
  tcase_add_test(testcase, forward_handle_pass_noproxyauth_test);
  tcase_add_test(testcase, forward_handle_pass_userwithproxyauth_test);
  tcase_add_test(testcase, forward_handle_pass_proxyuserwithproxyauth_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
