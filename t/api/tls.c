/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2015-2016 TJ Saunders <tj@castaglia.org>
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

/* Proxy TLS API tests. */

#include "tests.h"

extern xaset_t *server_list;

static pool *p = NULL;
static const char *test_dir = "/tmp/mod_proxy-test-tls";

static void create_main_server(void) {
  pool *main_pool;

  main_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(main_pool, "testsuite#main_server pool");

  server_list = xaset_create(main_pool, NULL);

  main_server = (server_rec *) pcalloc(main_pool, sizeof(server_rec));
  xaset_insert(server_list, (xasetmember_t *) main_server);

  main_server->pool = main_pool;
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

static int create_test_dir(void) {
  int res;
  mode_t perms;

  perms = 0770;
  res = mkdir(test_dir, perms);
  fail_unless(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
    strerror(errno));

  res = chmod(test_dir, perms);
  fail_unless(res == 0, "Failed to set perms %04o on directory '%s': %s",
    perms, test_dir, strerror(errno));

  return 0;
}

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = proxy_pool = make_sub_pool(NULL);
    server_list = NULL;
    main_server = NULL;
  }

  (void) tests_rmpath(p, test_dir);
  create_main_server();
  (void) create_test_dir();
  proxy_db_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.tls", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.tls", 0, 0);
  }

  proxy_db_free();
  (void) tests_rmpath(p, test_dir);

  if (p) {
    destroy_pool(p);
    p = permanent_pool = proxy_pool = NULL;
    server_list = NULL;
    main_server = NULL;
  }
}

START_TEST (tls_free_test) {
  int res;

  res = proxy_tls_free(NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_tls_free(p);
  fail_unless(res == 0, "Failed to free TLS API resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (tls_init_test) {
  int res;

  res = proxy_tls_init(NULL, NULL);
#ifdef PR_USE_OPENSSL
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_tls_init(p, NULL);
  fail_unless(res < 0, "Failed to handle null tables directory");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_tls_init(p, test_dir);
  fail_unless(res == 0, "Failed to init TLS API resources: %s",
    strerror(errno));

  res = proxy_tls_free(p);
  fail_unless(res == 0, "Failed to free TLS API resources: %s",
    strerror(errno));
#else
  fail_unless(res == 0, "Failed to init TLS API resources: %s",
    strerror(errno));
#endif /* PR_USE_OPENSSL */
}
END_TEST

START_TEST (tls_using_tls_test) {
  int res, tls;

  tls = proxy_tls_using_tls();
#ifdef PR_USE_OPENSSL
  fail_unless(tls == PROXY_TLS_ENGINE_AUTO, "Expected TLS auto, got %d", tls);
#else
  fail_unless(tls == PROXY_TLS_ENGINE_OFF, "Expected TLS off, got %d", tls);
#endif /* PR_USE_OPENSSL */

  res = proxy_tls_set_tls(7);
  fail_unless(res < 0, "Set TLS unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_tls_set_tls(PROXY_TLS_ENGINE_ON);
  tls = proxy_tls_using_tls();
  fail_unless(tls == PROXY_TLS_ENGINE_ON, "Expected TLS on, got %d", tls);

  res = proxy_tls_set_tls(PROXY_TLS_ENGINE_OFF);
  tls = proxy_tls_using_tls();
  fail_unless(tls == PROXY_TLS_ENGINE_OFF, "Expected TLS off, got %d", tls);

  res = proxy_tls_set_tls(PROXY_TLS_ENGINE_AUTO);
  tls = proxy_tls_using_tls();
  fail_unless(tls == PROXY_TLS_ENGINE_AUTO, "Expected TLS auto, got %d", tls);
}
END_TEST

Suite *tests_get_tls_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("tls");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, tls_free_test);
  tcase_add_test(testcase, tls_init_test);
  tcase_add_test(testcase, tls_using_tls_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
