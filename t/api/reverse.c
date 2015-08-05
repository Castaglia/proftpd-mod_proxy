/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2013-2015 TJ Saunders <tj@castaglia.org>
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

/* Reverse-proxy API tests */

#include "tests.h"

static pool *p = NULL;
static const char *test_dir = "/tmp/mod_proxy-test-reverse";
static const char *test_file = "/tmp/mod_proxy-test-reverse/servers.json";

static void test_cleanup(void) {
  (void) unlink(test_file);
  (void) rmdir(test_dir);
}

static FILE *test_prep(void) {
  int res;
  mode_t perms;
  FILE *fh;

  perms = 0770;
  res = mkdir(test_dir, perms);
  fail_unless(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
    strerror(errno));

  res = chmod(test_dir, perms);
  fail_unless(res == 0, "Failed to set perms %04o on directory '%s': %s",
    perms, test_dir, strerror(errno));

  fh = fopen(test_file, "w+");
  fail_if(fh == NULL, "Failed to create tmp file '%s': %s", test_file,
    strerror(errno));

  perms = 0660;
  res = chmod(test_file, perms);
  fail_unless(res == 0, "Failed to set perms %04o on file '%s': %s",
    perms, test_file, strerror(errno));

  return fh;
}

static void set_up(void) {
  test_cleanup();

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  } 

  test_cleanup();
}

START_TEST (reverse_json_parse_uris_args_test) {
  array_header *uris;
  const char *path;

  uris = proxy_reverse_json_parse_uris(NULL, NULL);
  fail_unless(uris == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  uris = proxy_reverse_json_parse_uris(p, NULL);
  fail_unless(uris == NULL, "Failed to handle null path argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  path = "/tmp/test.dat";
  uris = proxy_reverse_json_parse_uris(NULL, path);
  fail_unless(uris == NULL, "Failed to handle null pool argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
}
END_TEST

START_TEST (reverse_json_parse_uris_isreg_test) {
  array_header *uris;
  const char *path;
  int res;

  test_cleanup();

  path = "servers.json";
  uris = proxy_reverse_json_parse_uris(p, path);
  fail_unless(uris == NULL, "Failed to handle relative path '%s'", path);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  path = test_file;
  uris = proxy_reverse_json_parse_uris(p, path);
  fail_unless(uris == NULL, "Failed to handle nonexistent file '%s'", path);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = mkdir(test_dir, 0777);
  fail_unless(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
    strerror(errno));
  uris = proxy_reverse_json_parse_uris(p, test_dir);
  fail_unless(uris == NULL, "Failed to handle directory path '%s'", test_dir);
  fail_unless(errno == EISDIR, "Failed to set errno to EISDIR");

  test_cleanup();
}
END_TEST

START_TEST (reverse_json_parse_uris_perms_test) {
  array_header *uris;
  const char *path;
  int fd, res;
  mode_t perms;

  /* Note: any extra chmods are necessary to workaround any umask in the
   * environment.  Sigh.
   */

  perms = 0777;
  res = mkdir(test_dir, perms);
  fail_unless(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
    strerror(errno));

  res = chmod(test_dir, perms);
  fail_unless(res == 0, "Failed to set perms %04o on directory '%s': %s",
    perms, test_dir, strerror(errno));

  /* First, make a world-writable file. */
  perms = 0666;
  fd = open(test_file, O_WRONLY|O_CREAT, perms);
  fail_if(fd < 0, "Failed to create tmp file '%s': %s", test_file,
    strerror(errno));

  res = fchmod(fd, perms);
  fail_unless(res == 0, "Failed to set perms %04o on file '%s': %s",
    perms, test_file, strerror(errno));

  path = test_file;
  uris = proxy_reverse_json_parse_uris(p, path);
  fail_unless(uris == NULL, "Failed to handle world-writable file '%s'",
    path);
  fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %d (%s)",
    errno, strerror(errno));

  /* Now make the file user/group-writable only, but leave the parent
   * directory world-writable.
   */

  perms = 0660;
  res = fchmod(fd, perms);
  fail_unless(res == 0, "Failed to set perms %04o on file '%s': %s",
    perms, test_file, strerror(errno));

  uris = proxy_reverse_json_parse_uris(p, path);
  fail_unless(uris == NULL, "Failed to handle world-writable directory '%s'",
    test_file);
  fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %d (%s)",
    errno, strerror(errno));

  (void) close(fd);
  test_cleanup();
}
END_TEST

START_TEST (reverse_json_parse_uris_empty_test) {
  array_header *uris;
  FILE *fh = NULL;
  int res;

  test_cleanup();
  fh = test_prep();

  /* Write a file with no lines. */
  res = fclose(fh);
  fail_if(res < 0, "Failed to write file '%s': %s", test_file,
    strerror(errno));

  mark_point();

  uris = proxy_reverse_json_parse_uris(p, test_file);
  fail_unless(uris != NULL, "Did not receive parsed list as expected");
  fail_unless(uris->nelts == 0, "Expected zero elements, found %d",
    uris->nelts);

  test_cleanup();
}
END_TEST

START_TEST (reverse_json_parse_uris_malformed_test) {
  array_header *uris;
  FILE *fh = NULL;
  int res;

  test_cleanup();
  fh = test_prep();

  fprintf(fh, "[ \"http://127.0.0.1:80\",\n");
  fprintf(fh, "\"ftp:/127.0.0.1::21\",\n");
  fprintf(fh, "\"ftp://foo.bar.baz:21\" ]\n");

  res = fclose(fh);
  fail_if(res < 0, "Failed to write file '%s': %s", test_file,
    strerror(errno));

  mark_point();

  uris = proxy_reverse_json_parse_uris(p, test_file);
  fail_unless(uris != NULL, "Did not receive parsed list as expected");
  fail_unless(uris->nelts == 0, "Expected zero elements, found %d",
    uris->nelts);

  test_cleanup();
}
END_TEST

START_TEST (reverse_json_parse_uris_usable_test) {
  array_header *uris;
  FILE *fh = NULL;
  int res, expected;

  test_cleanup();
  fh = test_prep();

  /* Write a file with usable URLs. */
  fprintf(fh, "[ \"ftp://127.0.0.1\",\n");
  fprintf(fh, "\"ftp://localhost:2121\",\n");
  fprintf(fh, "\"ftp://[::1]:21212\" ]\n");

  res = fclose(fh);
  fail_if(res < 0, "Failed to write file '%s': %s", test_file,
    strerror(errno));

  mark_point();

  uris = proxy_reverse_json_parse_uris(p, test_file);
  fail_unless(uris != NULL, "Did not receive parsed list as expected");

  expected = 3;
  fail_unless(uris->nelts == expected, "Expected %d elements, found %d",
    expected, uris->nelts);

  test_cleanup();
}
END_TEST

Suite *tests_get_reverse_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("reverse");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, reverse_json_parse_uris_args_test);
  tcase_add_test(testcase, reverse_json_parse_uris_isreg_test);
  tcase_add_test(testcase, reverse_json_parse_uris_perms_test);
  tcase_add_test(testcase, reverse_json_parse_uris_empty_test);
  tcase_add_test(testcase, reverse_json_parse_uris_malformed_test);
  tcase_add_test(testcase, reverse_json_parse_uris_usable_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
