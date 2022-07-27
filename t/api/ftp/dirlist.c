/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2020-2022 TJ Saunders <tj@castaglia.org>
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

/* FTP Dirlist API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = session.pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.dirlist", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.ftp.dirlist", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  } 
}

START_TEST (init_test) {
  int res;

  mark_point();
  res = proxy_ftp_dirlist_init(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_dirlist_init(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null proxy_sess");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (finish_test) {
  int res;

  mark_point();
  res = proxy_ftp_dirlist_finish(NULL);
  ck_assert_msg(res < 0, "Failed to handle null proxy_sess");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (from_dos_test) {
  struct proxy_dirlist_fileinfo *res = NULL;
  const char *text = NULL;
  size_t textlen = 0;

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_dos(NULL, NULL, 0, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_dos(p, NULL, 0, 0);
  ck_assert_msg(res == NULL, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "foo bar baz";

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_dos(p, text, 0, 0);
  ck_assert_msg(res == NULL, "Failed to handle zero text len");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  textlen = strlen(text);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_dos(p, text, textlen, 0);
  ck_assert_msg(res == NULL, "Failed to handle bad text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (from_unix_test) {
  struct proxy_dirlist_fileinfo *res = NULL;
  const char *text = NULL;
  size_t textlen = 0;
  time_t now;
  struct tm *tm;

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_unix(NULL, NULL, 0, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_unix(p, NULL, 0, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "foo bar baz";

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_unix(p, text, 0, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle zero text len");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  textlen = strlen(text);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_unix(p, text, textlen, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null tm");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  time(&now);
  tm = pr_gmtime(p, &now);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_unix(p, text, textlen, tm, 0);
  ck_assert_msg(res == NULL, "Failed to handle bad text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (from_text_test) {
  struct proxy_session *proxy_sess = NULL;
  struct proxy_dirlist_fileinfo *res = NULL;
  const char *text = NULL;
  size_t textlen = 0;
  time_t now;
  struct tm *tm;

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_text(NULL, NULL, 0, NULL, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_text(p, NULL, 0, NULL, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "foo bar baz";

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_text(p, text, 0, NULL, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle zero text len");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  textlen = strlen(text);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_text(p, text, textlen, NULL, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null tm");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  time(&now);
  tm = pr_gmtime(p, &now);

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_text(p, text, textlen, tm, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null userdata");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);
  ck_assert_msg(proxy_sess != NULL, "Failed to allocate proxy session: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_dirlist_fileinfo_from_text(p, text, textlen, tm, proxy_sess,
    0);
  ck_assert_msg(res == NULL, "Failed to handle null proxy_sess->dirlist_ctx");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (to_facts_test) {
  const char *text;
  struct proxy_dirlist_fileinfo *pdf;

  mark_point();
  text = proxy_ftp_dirlist_fileinfo_to_facts(NULL, NULL, NULL);
  ck_assert_msg(text == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = proxy_ftp_dirlist_fileinfo_to_facts(p, NULL, NULL);
  ck_assert_msg(text == NULL, "Failed to handle null fileinfo");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pdf = pcalloc(p, sizeof(struct proxy_dirlist_fileinfo));

  mark_point();
  text = proxy_ftp_dirlist_fileinfo_to_facts(p, pdf, NULL);
  ck_assert_msg(text == NULL, "Failed to handle null textlen");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (to_text_test) {
  int res;
  struct proxy_session *proxy_sess = NULL;
  char *buf, *output_text = NULL;
  size_t buflen, maxlen, output_textlen = 0;

  mark_point();
  res = proxy_ftp_dirlist_to_text(NULL, NULL, 0, 0, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
  
  mark_point();
  res = proxy_ftp_dirlist_to_text(p, NULL, 0, 0, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null buf");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  buf = "foo bar baz";

  mark_point();
  res = proxy_ftp_dirlist_to_text(p, buf, 0, 0, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle zero buflen");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  buflen = strlen(buf);

  mark_point();
  res = proxy_ftp_dirlist_to_text(p, buf, buflen, 0, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle zero max textsz");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  maxlen = 1024;

  mark_point();
  res = proxy_ftp_dirlist_to_text(p, buf, buflen, maxlen, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null output text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_dirlist_to_text(p, buf, buflen, maxlen, &output_text, NULL,
    NULL);
  ck_assert_msg(res < 0, "Failed to handle null output textlen");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_ftp_dirlist_to_text(p, buf, buflen, maxlen, &output_text,
    &output_textlen, NULL);
  ck_assert_msg(res < 0, "Failed to handle null userdata");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);
  ck_assert_msg(proxy_sess != NULL, "Failed to allocate proxy session: %s",
    strerror(errno));

  mark_point();
  res = proxy_ftp_dirlist_to_text(p, buf, buflen, maxlen, &output_text,
    &output_textlen, proxy_sess);
  ck_assert_msg(res < 0, "Failed to handle null proxy_sess->dirlist_ctx");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  proxy_session_free(p, proxy_sess);
}
END_TEST

Suite *tests_get_ftp_dirlist_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ftp.dirlist");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, init_test);
  tcase_add_test(testcase, finish_test);

  tcase_add_test(testcase, from_dos_test);
  tcase_add_test(testcase, from_unix_test);
  tcase_add_test(testcase, from_text_test);

  tcase_add_test(testcase, to_facts_test);

  tcase_add_test(testcase, to_text_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
