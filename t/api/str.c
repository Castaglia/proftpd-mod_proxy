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

/* String API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (strnstr_test) {
  const char *s1, *s2;
  size_t len;
  char *res;

  mark_point();
  res = proxy_strnstr(NULL, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null s1");

  mark_point();
  s1 = "haystack";
  res = proxy_strnstr(s1, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null s2");

  mark_point();
  s2 = "needle";
  res = proxy_strnstr(s1, s2, 0);
  ck_assert_msg(res == NULL, "Failed to handle zero len");

  mark_point();
  len = 2;
  res = proxy_strnstr(s1, s2, len);
  ck_assert_msg(res == NULL, "Expected null, got %p for len %lu", res,
    (unsigned long) len);

  mark_point();
  s1 = "  ";
  res = proxy_strnstr(s1, s2, len);
  ck_assert_msg(res == NULL, "Expected null, got %p for s1 spaces", res);

  mark_point();
  s1 = "haystack";
  s2 = "";
  res = proxy_strnstr(s1, s2, len);
  ck_assert_msg(res == NULL, "Expected null, got %p for s2 empty", res);

  mark_point();
  s1 = "haystack";
  s2 = "haystack";
  len = 8;
  res = proxy_strnstr(s1, s2, len);
  ck_assert_msg(res != NULL, "Expected %p, got %p for s1 == s2", s1, res);

  mark_point();
  s1 = "haystack";
  s2 = "sta";
  len = 7;
  res = proxy_strnstr(s1, s2, len);
  ck_assert_msg(res != NULL, "Expected %p, got %p", s1 + 3, res);
}
END_TEST

Suite *tests_get_str_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("str");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, strnstr_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
