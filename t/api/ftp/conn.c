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
  main_server->conf = xaset_create(main_pool, NULL);

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

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  init_netaddr();
  init_netio();
  init_inet();

  create_main_server();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 1, 20);
    pr_trace_set_levels("inet", 1, 20);
    pr_trace_set_levels("proxy.ftp.conn", 1, 20);
  }

  pr_inet_set_default_family(p, AF_INET);
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
    pr_trace_set_levels("inet", 0, 0);
    pr_trace_set_levels("proxy.ftp.conn", 0, 0);
  }

  pr_inet_set_default_family(p, 0);
  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    main_server = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

START_TEST (accept_test) {
  conn_t *res, *ctrl_conn = NULL, *data_conn = NULL;

  res = proxy_ftp_conn_accept(NULL, NULL, NULL, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_conn_accept(p, NULL, NULL, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null data conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  data_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(data_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_conn_accept(p, data_conn, NULL, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null ctrl conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  ctrl_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(ctrl_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  session.xfer.direction = PR_NETIO_IO_RD;

  mark_point();
  res = proxy_ftp_conn_accept(p, data_conn, ctrl_conn, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null ctrl conn");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got '%s' (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_conn_accept(p, data_conn, ctrl_conn, TRUE);
  ck_assert_msg(res == NULL, "Failed to handle null ctrl conn");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got '%s' (%d)", EBADF,
    strerror(errno), errno);

  session.xfer.direction = PR_NETIO_IO_WR;

  mark_point();
  res = proxy_ftp_conn_accept(p, data_conn, ctrl_conn, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null ctrl conn");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got '%s' (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_conn_accept(p, data_conn, ctrl_conn, TRUE);
  ck_assert_msg(res == NULL, "Failed to handle null ctrl conn");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got '%s' (%d)", EBADF,
    strerror(errno), errno);

  pr_inet_close(p, ctrl_conn);
  pr_inet_close(p, data_conn);
}
END_TEST

START_TEST (connect_test) {
  conn_t *res;
  const pr_netaddr_t *remote_addr = NULL;

  res = proxy_ftp_conn_connect(NULL, NULL, NULL, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_conn_connect(p, NULL, NULL, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null remote addr");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  ck_assert_msg(remote_addr != NULL, "Failed to address for 127.0.0.1: %s",
    strerror(errno));
  pr_netaddr_set_port((pr_netaddr_t *) remote_addr, htons(6555));

  session.xfer.direction = PR_NETIO_IO_RD;

  mark_point();
  res = proxy_ftp_conn_connect(p, NULL, remote_addr, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle bad address family");
  ck_assert_msg(errno == ECONNREFUSED, "Expected ECONNREFUSED (%d), got %s (%d)",
    ECONNREFUSED, strerror(errno), errno);

  mark_point();
  res = proxy_ftp_conn_connect(p, NULL, remote_addr, TRUE);
  ck_assert_msg(res == NULL, "Failed to handle bad address family");
  ck_assert_msg(errno == ECONNREFUSED, "Expected ECONNREFUSED (%d), got %s (%d)",
    ECONNREFUSED, strerror(errno), errno);

  session.xfer.direction = PR_NETIO_IO_WR;

  mark_point();
  res = proxy_ftp_conn_connect(p, NULL, remote_addr, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle bad address family");
  ck_assert_msg(errno == ECONNREFUSED, "Expected ECONNREFUSED (%d), got %s (%d)",
    ECONNREFUSED, strerror(errno), errno);

  mark_point();
  res = proxy_ftp_conn_connect(p, NULL, remote_addr, TRUE);
  ck_assert_msg(res == NULL, "Failed to handle bad address family");
  ck_assert_msg(errno == ECONNREFUSED, "Expected ECONNREFUSED (%d), got %s (%d)",
    ECONNREFUSED, strerror(errno), errno);

  /* Try connecting to Google's DNS server. */

  remote_addr = pr_netaddr_get_addr(p, "8.8.8.8", NULL);
  ck_assert_msg(remote_addr != NULL, "Failed to resolve '8.8.8.8': %s",
    strerror(errno));
  pr_netaddr_set_port((pr_netaddr_t *) remote_addr, htons(53));

  mark_point();
  res = proxy_ftp_conn_connect(p, NULL, remote_addr, FALSE);
  ck_assert_msg(res != NULL, "Failed to connect: %s", strerror(errno));
  pr_inet_close(p, res);

  mark_point();
  res = proxy_ftp_conn_connect(p, NULL, remote_addr, TRUE);
  ck_assert_msg(res != NULL, "Failed to connect: %s", strerror(errno));
  pr_inet_close(p, res);
}
END_TEST

START_TEST (listen_test) {
  conn_t *res;
  const pr_netaddr_t *bind_addr = NULL;

  res = proxy_ftp_conn_listen(NULL, NULL, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_conn_listen(p, NULL, FALSE);
  ck_assert_msg(res == NULL, "Failed to handle null bind address");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  bind_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  ck_assert_msg(bind_addr != NULL, "Failed to address for 127.0.0.1: %s",
    strerror(errno));
  pr_netaddr_set_port((pr_netaddr_t *) bind_addr, htons(0));

  mark_point();
  res = proxy_ftp_conn_listen(p, bind_addr, FALSE);
  ck_assert_msg(res != NULL, "Failed to listen: %s", strerror(errno));
  pr_inet_close(p, res);

  mark_point();
  res = proxy_ftp_conn_listen(p, bind_addr, TRUE);
  ck_assert_msg(res != NULL, "Failed to listen: %s", strerror(errno));
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
