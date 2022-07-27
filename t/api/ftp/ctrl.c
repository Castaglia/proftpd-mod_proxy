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

/* FTP Control API tests. */

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
    pr_trace_set_levels("netio", 1, 20);
    pr_trace_set_levels("proxy.ftp.ctrl", 1, 20);
  }

  pr_inet_set_default_family(p, AF_INET);
  pr_response_set_pool(NULL);
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
    pr_trace_set_levels("proxy.ftp.ctrl", 0, 0);
  }

  pr_inet_set_default_family(p, 0);
  pr_inet_clear();
  pr_response_set_pool(NULL);

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  } 
}

START_TEST (handle_async_test) {
  int res, flags = PROXY_FTP_CTRL_FL_IGNORE_EOF;
  conn_t *frontend_conn, *backend_conn;
  pr_netio_stream_t *nstrm;

  mark_point();
  res = proxy_ftp_ctrl_handle_async(NULL, NULL, NULL, flags);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_ctrl_handle_async(p, NULL, NULL, flags);
  ck_assert_msg(res < 0, "Failed to handle null backend conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  backend_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(backend_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_ctrl_handle_async(p, backend_conn, NULL, flags);
  ck_assert_msg(res < 0, "Failed to handle null frontend conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  frontend_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(frontend_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_ctrl_handle_async(p, backend_conn, frontend_conn, flags);
  ck_assert_msg(res < 0, "Failed to handle null backend conn stream");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, 8, PR_NETIO_IO_RD);
  backend_conn->instrm = nstrm;

  mark_point();
  res = proxy_ftp_ctrl_handle_async(p, backend_conn, frontend_conn, flags);
  ck_assert_msg(res == 0, "Failed to handle async IO: %s", strerror(errno));

  proxy_sess_state |= PROXY_SESS_STATE_CONNECTED;

  mark_point();
  res = proxy_ftp_ctrl_handle_async(p, backend_conn, frontend_conn, flags);
  ck_assert_msg(res == 0, "Failed to handle async IO: %s", strerror(errno));

  proxy_sess_state &= ~PROXY_SESS_STATE_CONNECTED;

  pr_inet_close(p, frontend_conn);
  pr_inet_close(p, backend_conn);
}
END_TEST

START_TEST (recv_resp_test) {
  int flags = PROXY_FTP_CTRL_FL_IGNORE_EOF, len;
  pr_response_t *resp;
  unsigned int nlines = 0;
  conn_t *ctrl_conn = NULL;
  size_t buflen;
  pr_buffer_t *pbuf;
  pr_netio_stream_t *nstrm;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(NULL, NULL, NULL, flags);
  ck_assert_msg(resp == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, NULL, NULL, flags);
  ck_assert_msg(resp == NULL, "Failed to handle null ctrl conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  ctrl_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(ctrl_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, NULL, flags);
  ck_assert_msg(resp == NULL, "Failed to handle null response nlines");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle EOF");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  ck_assert_msg(nstrm != NULL, "Failed to open ctrl stream: %s", strerror(errno));

  pbuf = pr_netio_buffer_alloc(nstrm);
  ck_assert_msg(pbuf != NULL, "Failed to allocate stream buffer: %s",
    strerror(errno));
  buflen = pbuf->buflen;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "Foo");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;
  ctrl_conn->instrm = nstrm;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == E2BIG, "Expected E2BIG (%d), got %s (%d)", E2BIG,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "Foo\r\n");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "Foo\r\n");
  pbuf->remaining = pbuf->buflen = len;
  pbuf->current = pbuf->buf;
  ctrl_conn->instrm = nstrm;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "Food\r\n");
  pbuf->buflen = buflen;
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "1ood\r\n");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "12od\r\n");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "123d\r\n");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "001 Foo\r\n");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "999 Foo\r\n");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp == NULL, "Failed to handle invalid response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", "200 Foo\r\n");
  pbuf->remaining = len;
  pbuf->current = pbuf->buf;

  mark_point();
  resp = proxy_ftp_ctrl_recv_resp(p, ctrl_conn, &nlines, flags);
  ck_assert_msg(resp != NULL, "Failed to receive response: %s", strerror(errno));
  ck_assert_msg(strcmp(resp->num, R_200) == 0, "Expected '%s', got '%s'", R_200,
    resp->num);
  ck_assert_msg(nlines == 1, "Expected 1, got %u", nlines);

  /* XXX TODO: multiline responses! */

  pr_inet_close(p, ctrl_conn);
}
END_TEST

START_TEST (send_cmd_test) {
  int res;
  conn_t *ctrl_conn;
  cmd_rec *cmd;

  res = proxy_ftp_ctrl_send_cmd(NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_ctrl_send_cmd(p, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  ctrl_conn = pr_inet_create_conn(p, -2, NULL, INPORT_ANY, FALSE);
  ck_assert_msg(ctrl_conn != NULL, "Failed to create conn: %s",
    strerror(errno));

  res = proxy_ftp_ctrl_send_cmd(p, ctrl_conn, NULL);
  ck_assert_msg(res < 0, "Failed to handle null command");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 2, "FOO", "bar");

  mark_point();
  res = proxy_ftp_ctrl_send_cmd(p, ctrl_conn, cmd);
  ck_assert_msg(res < 0, "Failed to handle command without stream");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "FOO");

  mark_point();
  res = proxy_ftp_ctrl_send_cmd(p, ctrl_conn, cmd);
  ck_assert_msg(res < 0, "Failed to handle command without stream");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, ctrl_conn);
}
END_TEST

START_TEST (send_resp_test) {
  int res;
  pr_response_t *resp;

  res = proxy_ftp_ctrl_send_resp(NULL, NULL, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_ftp_ctrl_send_resp(p, NULL, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null response");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  resp = pcalloc(p, sizeof(pr_response_t));
  resp->num = "123";
  resp->msg = pstrdup(p, "foo bar?");

  res = proxy_ftp_ctrl_send_resp(p, NULL, resp, 0);
  ck_assert_msg(res == 0, "Failed to handle response: %s", strerror(errno));

  res = proxy_ftp_ctrl_send_resp(p, NULL, resp, 3);
  ck_assert_msg(res == 0, "Failed to handle response: %s", strerror(errno));
}
END_TEST

Suite *tests_get_ftp_ctrl_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.ctrl");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, handle_async_test);
  tcase_add_test(testcase, recv_resp_test);
  tcase_add_test(testcase, send_cmd_test);
  tcase_add_test(testcase, send_resp_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
