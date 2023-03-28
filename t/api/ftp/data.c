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

/* FTP Data API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  init_netaddr();
  init_netio();
  init_inet();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.data", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.data", 0, 0);
  }

  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

START_TEST (recv_test) {
  pr_buffer_t *pbuf;
  conn_t *conn;

  mark_point();
  pbuf = proxy_ftp_data_recv(NULL, NULL, FALSE);
  ck_assert_msg(pbuf == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  pbuf = proxy_ftp_data_recv(p, NULL, FALSE);
  ck_assert_msg(pbuf == NULL, "Failed to handle null conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  pbuf = proxy_ftp_data_recv(p, conn, FALSE);
  ck_assert_msg(pbuf == NULL, "Failed to handle missing instream");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn->instrm = pr_netio_open(p, PR_NETIO_STRM_DATA, -1, PR_NETIO_IO_RD);
  ck_assert_msg(conn->instrm != NULL, "Failed open data stream: %s",
    strerror(errno));

  mark_point();
  pbuf = proxy_ftp_data_recv(p, conn, FALSE);
  ck_assert_msg(pbuf == NULL, "Failed to handle bad instream fd");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  pbuf = proxy_ftp_data_recv(p, conn, TRUE);
  ck_assert_msg(pbuf == NULL, "Failed to handle bad instream fd");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

/* Fill in the instrm fd with an fd to an empty file */

/* Fill in the instrm fd with an fd to /dev/null */

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (send_test) {
  int res;
  pr_buffer_t *pbuf;
  conn_t *conn;

  mark_point();
  res = proxy_ftp_data_send(NULL, NULL, NULL, FALSE);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_data_send(p, NULL, NULL, FALSE);
  ck_assert_msg(res < 0, "Failed to handle null conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  res = proxy_ftp_data_send(p, conn, NULL, FALSE);
  ck_assert_msg(res < 0, "Failed to handle null buffer");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn->outstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, -1, PR_NETIO_IO_WR);
  ck_assert_msg(conn->outstrm != NULL, "Failed open data stream: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_data_send(p, conn, NULL, FALSE);
  ck_assert_msg(res < 0, "Failed to handle null buffer");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pbuf = pcalloc(p, sizeof(pr_buffer_t));
  pbuf->buflen = 1024;
  pbuf->buf = palloc(p, pbuf->buflen);
  pbuf->current = pbuf->buf + 2;

  mark_point();
  res = proxy_ftp_data_send(p, conn, pbuf, FALSE);
  ck_assert_msg(res < 0, "Sent data unexpectedly");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_data_send(p, conn, pbuf, TRUE);
  ck_assert_msg(res < 0, "Sent data unexpectedly");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

Suite *tests_get_ftp_data_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.data");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, recv_test);
  tcase_add_test(testcase, send_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
