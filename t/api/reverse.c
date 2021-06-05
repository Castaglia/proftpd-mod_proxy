/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2013-2021 TJ Saunders <tj@castaglia.org>
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
static config_rec *policy_config = NULL;

static void create_main_server(void) {
  server_rec *s;

  s = pr_parser_server_ctxt_open("127.0.0.1");
  s->ServerName = "Test Server";

  main_server = s;
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
  if (res < 0 &&
      errno != EEXIST) {
    fail_unless(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
      strerror(errno));
  }

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
    p = permanent_pool = session.pool = make_sub_pool(NULL);
    main_server = NULL;
    server_list = NULL;
    session.c = NULL;
    session.notes = NULL;
  }

  test_cleanup(p);
  init_config();
  init_fs();
  init_netaddr();
  init_netio();
  init_inet();

  server_list = xaset_create(p, NULL);
  pr_parser_prepare(p, &server_list);
  create_main_server();
  proxy_db_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 1, 20);
    pr_trace_set_levels("proxy.conn", 1, 20);
    pr_trace_set_levels("proxy.db", 1, 20);
    pr_trace_set_levels("proxy.reverse", 1, 20);
    pr_trace_set_levels("proxy.tls", 1, 20);
    pr_trace_set_levels("proxy.uri", 1, 20);
    pr_trace_set_levels("proxy.ftp.ctrl", 1, 20);
    pr_trace_set_levels("proxy.ftp.sess", 1, 20);
  }

  pr_inet_set_default_family(p, AF_INET);
}

static void tear_down(void) {
  pr_inet_set_default_family(p, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
    pr_trace_set_levels("proxy.conn", 0, 0);
    pr_trace_set_levels("proxy.db", 0, 0);
    pr_trace_set_levels("proxy.reverse", 0, 0);
    pr_trace_set_levels("proxy.tls", 0, 0);
    pr_trace_set_levels("proxy.uri", 0, 0);
    pr_trace_set_levels("proxy.ftp.ctrl", 0, 0);
    pr_trace_set_levels("proxy.ftp.sess", 0, 0);
  }

  pr_inet_clear();
  pr_parser_cleanup();
  proxy_db_free();
  test_cleanup(p);

  if (p) {
    destroy_pool(p);
    p = permanent_pool = session.pool = NULL;
    main_server = NULL;
    server_list = NULL;
    session.c = NULL;
    session.notes = NULL;
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
  int res, flags = PROXY_DB_OPEN_FL_SKIP_VACUUM;
  FILE *fh;

  res = proxy_reverse_init(NULL, NULL, flags);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_reverse_init(p, NULL, flags);
  fail_unless(res < 0, "Failed to handle null tables dir");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  fh = test_prep();
  fclose(fh);

  mark_point();
  res = proxy_reverse_init(p, test_dir, flags);
  fail_unless(res == 0, "Failed to init Reverse API resources: %s",
    strerror(errno));

  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_sess_free_test) {
  int res;

  mark_point();
  res = proxy_reverse_sess_free(p, NULL);
  fail_unless(res == 0, "Failed to free Reverse API session resources: %s",
    strerror(errno));
}
END_TEST

START_TEST (reverse_sess_init_test) {
  int res, flags = PROXY_DB_OPEN_FL_SKIP_VACUUM;
  config_rec *c;
  array_header *backends;
  const char *uri;
  const struct proxy_conn *pconn;

  mark_point();
  res = proxy_reverse_sess_init(NULL, NULL, NULL, flags);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_reverse_sess_init(p, NULL, NULL, flags);
  fail_unless(res < 0, "Unexpectedly init'd Reverse API session resources");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  c = add_config_param("ProxyReverseServers", 2, NULL, NULL);
  backends = make_array(c->pool, 1, sizeof(struct proxy_conn *));
  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(c->pool, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;
  c->argv[0] = backends;

  c = add_config_param("ProxyReverseServers", 2, NULL, NULL);
  backends = make_array(c->pool, 1, sizeof(struct proxy_conn *));
  uri = "ftp://127.0.0.1:2121";
  pconn = proxy_conn_create(c->pool, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;
  c->argv[0] = backends;

  mark_point();
  res = proxy_reverse_sess_init(NULL, NULL, NULL, flags);
  fail_unless(res < 0, "Unexpectedly init'd Reverse API session resources");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_reverse_sess_free(p, NULL);
  fail_unless(res == 0, "Failed to free Reverse API session resources: %s",
    strerror(errno));
}
END_TEST

static int test_connect_policy(int policy_id, array_header *src_backends) {
  int flags = PROXY_DB_OPEN_FL_SKIP_VACUUM;
  FILE *fh;
  config_rec *c;
  array_header *backends;

  fh = test_prep();
  fclose(fh);

  mark_point();

  if (policy_config != NULL) {
    c = policy_config;

  } else {
    policy_config = c = add_config_param("ProxyReverseConnectPolicy", 1, NULL);
    c->argv[0] = palloc(c->pool, sizeof(int));
  }

  *((int *) c->argv[0]) = policy_id;

  mark_point();
  c = add_config_param("ProxyReverseServers", 2, NULL, NULL);

  backends = make_array(c->pool, 1, sizeof(struct proxy_conn *));

  if (src_backends == NULL) {
    const char *uri;
    const struct proxy_conn *pconn;

    uri = "ftp://127.0.0.1:21";
    pconn = proxy_conn_create(c->pool, uri, 0);
    *((const struct proxy_conn **) push_array(backends)) = pconn;

  } else {
    array_cat(backends, src_backends);
  }

  c->argv[0] = backends;

  mark_point();
  return proxy_reverse_init(p, test_dir, flags);
}

START_TEST (reverse_connect_policy_random_test) {
  int res;

  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_RANDOM, NULL);
  fail_unless(res == 0, "Failed to test ReverseConnectPolicy Random: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_policy_roundrobin_test) {
  int res;

  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN, NULL);
  fail_unless(res == 0, "Failed to test ReverseConnectPolicy RoundRobin: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_policy_leastconns_test) {
  int res;

  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS, NULL);
  fail_unless(res == 0, "Failed to test ReverseConnectPolicy LeastConns: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_policy_leastresponsetime_test) {
  int res;

  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME,
    NULL);
  fail_unless(res == 0,
    "Failed to test ReverseConnectPolicy LeastResponseTime: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_policy_shuffle_test) {
  int res;

  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_SHUFFLE, NULL);
  fail_unless(res == 0, "Failed to test ReverseConnectPolicy Shuffle: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_policy_peruser_test) {
  int res;

  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_PER_USER, NULL);
  fail_unless(res == 0, "Failed to test ReverseConnectPolicy PerUser: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_policy_pergroup_test) {
  int res;

  /* Note: This should fail without having the UseReverseProxyAuth ProxyOption
   * enabled.
   */
  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_PER_GROUP, NULL);
  fail_unless(res < 0, "Expected ReverseConnectPolicy PerGroup to fail");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

START_TEST (reverse_connect_policy_perhost_test) {
  int res;

  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_PER_HOST, NULL);
  fail_unless(res == 0, "Failed to test ReverseConnectPolicy PerHost: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  test_cleanup(p);
}
END_TEST

static void test_handle_user_pass(int policy_id, array_header *src_backends) {
  int res, successful = FALSE, block_responses = FALSE;
  int flags = PROXY_DB_OPEN_FL_SKIP_VACUUM;
  struct proxy_session *proxy_sess;
  cmd_rec *cmd;
  FILE *fh;

  fh = test_prep();
  fclose(fh);

  mark_point();
  res = test_connect_policy(PROXY_REVERSE_CONNECT_POLICY_RANDOM, src_backends);
  fail_unless(res == 0, "Failed to test ReverseConnectPolicy Random: %s",
    strerror(errno));

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);

  session.notes = pr_table_alloc(p, 0);
  pr_table_add(session.notes, "mod_proxy.proxy-session", proxy_sess,
    sizeof(struct proxy_session));

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL,
    "Failed to open session control conn: %s", strerror(errno));

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = proxy_reverse_sess_init(p, test_dir, proxy_sess, flags);
  fail_unless(res == 0, "Failed to init Reverse API session resources: %s",
    strerror(errno));

  cmd = pr_cmd_alloc(p, 2, "USER", "anonymous");
  cmd->arg = pstrdup(p, "anonymous");

  mark_point();
  res = proxy_reverse_handle_user(cmd, proxy_sess, &successful,
    &block_responses);
  fail_if(res != 1, "Failed to handle USER");

  cmd = pr_cmd_alloc(p, 2, "PASS", "ftp@nospam.org");
  cmd->arg = pstrdup(p, "ftp@nospam.org");

  mark_point();
  res = proxy_reverse_handle_pass(cmd, proxy_sess, &successful,
    &block_responses);
  fail_unless(res < 0, "Handled PASS unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_reverse_sess_exit(p);
  fail_unless(res == 0, "Failed to exit session: %s", strerror(errno));

  mark_point();
  res = proxy_reverse_free(p);
  fail_unless(res == 0, "Failed to free Reverse API resources: %s",
    strerror(errno));

  proxy_session_free(p, proxy_sess);
  test_cleanup(p);
}

START_TEST (reverse_handle_user_pass_random_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_RANDOM, backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_RANDOM, backends);
}
END_TEST

START_TEST (reverse_handle_user_pass_roundrobin_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN, backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN, backends);
}
END_TEST

START_TEST (reverse_handle_user_pass_leastconns_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS, backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS, backends);
}
END_TEST

START_TEST (reverse_handle_user_pass_leastresponsetime_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME,
    backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME,
    backends);
}
END_TEST

START_TEST (reverse_handle_user_pass_shuffle_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_SHUFFLE, backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_SHUFFLE, backends);
}
END_TEST

START_TEST (reverse_handle_user_pass_peruser_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_PER_USER, backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_PER_USER, backends);
}
END_TEST

START_TEST (reverse_handle_user_pass_pergroup_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_PER_GROUP, backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_PER_GROUP, backends);
}
END_TEST

START_TEST (reverse_handle_user_pass_perhost_test) {
  const char *uri;
  const struct proxy_conn *pconn;
  array_header *backends;

  /* Skip this test on CI builds, for now.  It fails unexpectedly. */
  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  backends = make_array(p, 1, sizeof(struct proxy_conn *));

  uri = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  uri = "ftp://ftp.microsoft.com:21";
  pconn = proxy_conn_create(p, uri, 0);
  *((const struct proxy_conn **) push_array(backends)) = pconn;

  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_PER_HOST, backends);
  test_handle_user_pass(PROXY_REVERSE_CONNECT_POLICY_PER_HOST, backends);
}
END_TEST

START_TEST (reverse_json_parse_uris_args_test) {
  array_header *uris;
  const char *path;

  uris = proxy_reverse_json_parse_uris(NULL, NULL, 0);
  fail_unless(uris == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  uris = proxy_reverse_json_parse_uris(p, NULL, 0);
  fail_unless(uris == NULL, "Failed to handle null path argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  path = "/tmp/test.dat";
  uris = proxy_reverse_json_parse_uris(NULL, path, 0);
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
  uris = proxy_reverse_json_parse_uris(p, path, 0);
  fail_unless(uris == NULL, "Failed to handle relative path '%s'", path);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  path = test_file;
  uris = proxy_reverse_json_parse_uris(p, path, 0);
  fail_unless(uris == NULL, "Failed to handle nonexistent file '%s'", path);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = mkdir(test_dir, 0777);
  fail_unless(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
    strerror(errno));
  uris = proxy_reverse_json_parse_uris(p, test_dir, 0);
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
  uris = proxy_reverse_json_parse_uris(p, path, 0);
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

  uris = proxy_reverse_json_parse_uris(p, path, 0);
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

  uris = proxy_reverse_json_parse_uris(p, test_file, 0);
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

  uris = proxy_reverse_json_parse_uris(p, test_file, 0);
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

  uris = proxy_reverse_json_parse_uris(p, test_file, 0);
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

START_TEST (reverse_have_authenticated_test) {
  int res;
  cmd_rec *cmd = NULL;

  res = proxy_reverse_have_authenticated(cmd);
  fail_unless(res == FALSE, "Expected false, got %d", res);

  proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
  res = proxy_reverse_have_authenticated(cmd);
  fail_unless(res == TRUE, "Expected true, got %d", res);

  proxy_sess_state &= ~PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
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
  tcase_add_test(testcase, reverse_sess_free_test);
  tcase_add_test(testcase, reverse_sess_init_test);

  tcase_add_test(testcase, reverse_connect_policy_random_test);
  tcase_add_test(testcase, reverse_connect_policy_roundrobin_test);
  tcase_add_test(testcase, reverse_connect_policy_leastconns_test);
  tcase_add_test(testcase, reverse_connect_policy_leastresponsetime_test);
  tcase_add_test(testcase, reverse_connect_policy_shuffle_test);
  tcase_add_test(testcase, reverse_connect_policy_peruser_test);
  tcase_add_test(testcase, reverse_connect_policy_pergroup_test);
  tcase_add_test(testcase, reverse_connect_policy_perhost_test);

  tcase_add_test(testcase, reverse_handle_user_pass_random_test);
  tcase_add_test(testcase, reverse_handle_user_pass_roundrobin_test);
  tcase_add_test(testcase, reverse_handle_user_pass_leastconns_test);
  tcase_add_test(testcase, reverse_handle_user_pass_leastresponsetime_test);
  tcase_add_test(testcase, reverse_handle_user_pass_shuffle_test);
  tcase_add_test(testcase, reverse_handle_user_pass_peruser_test);
  tcase_add_test(testcase, reverse_handle_user_pass_pergroup_test);
  tcase_add_test(testcase, reverse_handle_user_pass_perhost_test);

  tcase_add_test(testcase, reverse_json_parse_uris_args_test);
  tcase_add_test(testcase, reverse_json_parse_uris_isreg_test);
  tcase_add_test(testcase, reverse_json_parse_uris_perms_test);
  tcase_add_test(testcase, reverse_json_parse_uris_empty_test);
  tcase_add_test(testcase, reverse_json_parse_uris_malformed_test);
  tcase_add_test(testcase, reverse_json_parse_uris_usable_test);
  tcase_add_test(testcase, reverse_connect_get_policy_test);
  tcase_add_test(testcase, reverse_use_proxy_auth_test);
  tcase_add_test(testcase, reverse_have_authenticated_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
