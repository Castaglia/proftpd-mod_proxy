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

/* FTP Connection API tests. */

#include "../tests.h"

static pool *p = NULL;

static void create_main_server(void) {
  pool *main_pool;
  xaset_t *servers;

  main_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(main_pool, "testsuite#main_server pool");

  servers = xaset_create(main_pool, NULL);

  main_server = (server_rec *) pcalloc(main_pool, sizeof(server_rec));
  xaset_insert(servers, (xasetmember_t *) main_server);

  main_server->pool = main_pool;
  main_server->set = servers;
  main_server->sid = 1;
  main_server->notes = pr_table_nalloc(main_pool, 0, 8);

  /* TCP KeepAlive is enabled by default, with the system defaults. */
  main_server->tcp_keepalive = palloc(main_server->pool,
    sizeof(struct tcp_keepalive));
  main_server->tcp_keepalive->keepalive_enabled = TRUE;
  main_server->tcp_keepalive->keepalive_idle = -1;
  main_server->tcp_keepalive->keepalive_count = -1;
  main_server->tcp_keepalive->keepalive_intvl = -1;

  main_server->ServerPort = 21;
}

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
  }

  init_netaddr();
  init_netio();
  init_inet();

  create_main_server();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.conn", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.conn", 0, 0);
  }

  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    main_server = NULL;
  } 
}

START_TEST (accept_test) {
  conn_t *res, *ctrl_conn = NULL, *data_conn = NULL;

  res = proxy_ftp_conn_accept(NULL, NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_conn_accept(p, NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null data conn");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  data_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  fail_unless(data_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_conn_accept(p, data_conn, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null ctrl conn");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  ctrl_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  fail_unless(ctrl_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_conn_accept(p, data_conn, ctrl_conn, 0);
  fail_unless(res == NULL, "Failed to handle null ctrl conn");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got '%s' (%d)", EBADF,
    strerror(errno), errno);

  pr_inet_close(p, ctrl_conn);
  pr_inet_close(p, data_conn);
}
END_TEST

START_TEST (connect_test) {
  conn_t *res;
  const pr_netaddr_t *remote_addr = NULL;

  res = proxy_ftp_conn_connect(NULL, NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_conn_connect(p, NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null remote addr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(remote_addr != NULL, "Failed to address for 127.0.0.1: %s",
    strerror(errno));
  pr_netaddr_set_port((pr_netaddr_t *) remote_addr, htons(6555));

  res = proxy_ftp_conn_connect(p, NULL, remote_addr, 0);
  fail_unless(res == NULL, "Failed to handle bad address family");
  fail_unless(errno == EAFNOSUPPORT,
    "Expected EAFNOSUPPORT (%d), got '%s' (%d)", EAFNOSUPPORT,
    strerror(errno), errno);
}
END_TEST

START_TEST (listen_test) {
  conn_t *res;
  const pr_netaddr_t *bind_addr = NULL;

  res = proxy_ftp_conn_listen(NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_conn_listen(p, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null bind address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  bind_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(bind_addr != NULL, "Failed to address for 127.0.0.1: %s",
    strerror(errno));
  pr_netaddr_set_port((pr_netaddr_t *) bind_addr, htons(0));

  res = proxy_ftp_conn_listen(p, bind_addr, 0);
  fail_unless(res != NULL, "Failed to listen: %s", strerror(errno));

  pr_inet_close(p, res);
}
END_TEST

Suite *tests_get_ftp_conn_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.conn");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, accept_test);
  tcase_add_test(testcase, connect_test);
  tcase_add_test(testcase, listen_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
