/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2012-2013 TJ Saunders <tj@castaglia.org>
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

/* Reverse-proxy API tests
 * $Id: env.c,v 1.2 2011/05/23 20:50:31 castaglia Exp $
 */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (reverse_file_parse_uris_args_test) {
}
END_TEST

START_TEST (reverse_file_parse_uris_perms_test) {
}
END_TEST

START_TEST (reverse_file_parse_uris_isreg_test) {
}
END_TEST

START_TEST (reverse_file_parse_uris_comments_test) {
}
END_TEST

START_TEST (reverse_file_parse_uris_empty_test) {
}
END_TEST

START_TEST (reverse_file_parse_uris_malformed_test) {
}
END_TEST

START_TEST (reverse_file_parse_uris_usable_test) {
}
END_TEST

Suite *tests_get_reverse_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("reverse");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, reverse_file_parse_uris_args_test);
  tcase_add_test(testcase, reverse_file_parse_uris_perms_test);
  tcase_add_test(testcase, reverse_file_parse_uris_isreg_test);
  tcase_add_test(testcase, reverse_file_parse_uris_comments_test);
  tcase_add_test(testcase, reverse_file_parse_uris_malformed_test);
  tcase_add_test(testcase, reverse_file_parse_uris_empty_test);
  tcase_add_test(testcase, reverse_file_parse_uris_usable_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
