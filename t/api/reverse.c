/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2013-2016 TJ Saunders <tj@castaglia.org>
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

extern xaset_t *server_list;

static pool *p = NULL;
static const char *test_dir = "/tmp/mod_proxy-test-reverse";
static const char *test_file = "/tmp/mod_proxy-test-reverse/servers.json";

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

static void test_cleanup(pool *cleanup_pool) {
  (void) unlink(test_file);
  (void) tests_rmpath(cleanup_pool, test_dir);
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
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
    server_list = NULL;
  }

  test_cleanup(p);
  create_main_server();
  init_fs();
  proxy_db_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.reverse", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.reverse", 0, 0);
  }

  proxy_db_free();
  test_cleanup(p);

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
    main_server = NULL;
    server_list = NULL;
  } 
}

START_TEST (reverse_free_test) {
  int res;

  res = proxy_reverse_free(NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (reverse_init_test) {
  int res;

  res = proxy_reverse_init(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_reverse_init(p, NULL);
  fail_unless(res < 0, "Failed to handle null tables dir");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  test_prep();

  mark_point();
  res = proxy_reverse_init(p, test_dir);
  fail_unless(res == 0, "Failed to init Reverse API resources: %s",
    strerror(errno));

  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

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

  test_cleanup(p);

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

  test_cleanup(p);
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
  test_cleanup(p);
}
END_TEST

START_TEST (reverse_json_parse_uris_empty_test) {
  array_header *uris;
  FILE *fh = NULL;
  int res;

  test_cleanup(p);
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

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_json_parse_uris_malformed_test) {
  array_header *uris;
  FILE *fh = NULL;
  int res;

  test_cleanup(p);
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

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_json_parse_uris_usable_test) {
  array_header *uris;
  FILE *fh = NULL;
  int res;
  unsigned int expected;

  test_cleanup(p);
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

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_get_policy_test) {
  int res;
  const char *policy;

  res = proxy_reverse_connect_get_policy(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  policy = "foo";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res < 0, "Failed to handle unsupported policy '%s'", policy);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  policy = "random2";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res < 0, "Failed to handle unsupported policy '%s'", policy);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  policy = "random";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_RANDOM,
    "Failed to handle supported policy '%s'", policy);

  policy = "roundrobin";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN,
    "Failed to handle supported policy '%s'", policy);

  policy = "shuffle";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_SHUFFLE,
    "Failed to handle supported policy '%s'", policy);

  policy = "leastconns";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS,
    "Failed to handle supported policy '%s'", policy);

  policy = "peruser";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_PER_USER,
    "Failed to handle supported policy '%s'", policy);

  policy = "pergroup";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_PER_GROUP,
    "Failed to handle supported policy '%s'", policy);

  policy = "perhost";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_PER_HOST,
    "Failed to handle supported policy '%s'", policy);

  policy = "leastresponsetime";
  res = proxy_reverse_connect_get_policy(policy);
  fail_unless(res == PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME,
    "Failed to handle supported policy '%s'", policy);
}
END_TEST

START_TEST (reverse_use_proxy_auth_test) {
  int res;

  res = proxy_reverse_use_proxy_auth();
  fail_unless(res == FALSE, "Expected false, got %d", res);
}
END_TEST

Suite *tests_get_reverse_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("reverse");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, reverse_free_test);
  tcase_add_test(testcase, reverse_init_test);
  tcase_add_test(testcase, reverse_json_parse_uris_args_test);
  tcase_add_test(testcase, reverse_json_parse_uris_isreg_test);
  tcase_add_test(testcase, reverse_json_parse_uris_perms_test);
  tcase_add_test(testcase, reverse_json_parse_uris_empty_test);
  tcase_add_test(testcase, reverse_json_parse_uris_malformed_test);
  tcase_add_test(testcase, reverse_json_parse_uris_usable_test);
  tcase_add_test(testcase, reverse_connect_get_policy_test);
  tcase_add_test(testcase, reverse_use_proxy_auth_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
