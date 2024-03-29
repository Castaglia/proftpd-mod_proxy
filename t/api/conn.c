/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2013-2022 TJ Saunders <tj@castaglia.org>
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

/* Conn API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.conn", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.conn", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

START_TEST (conn_create_test) {
  const struct proxy_conn *pconn;
  const char *url;

  pconn = proxy_conn_create(NULL, NULL, 0);
  ck_assert_msg(pconn == NULL, "Failed to handle null arguments");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(NULL, url, 0);
  ck_assert_msg(pconn == NULL, "Failed to handle null pool argument");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();
  pconn = proxy_conn_create(p, NULL, 0);
  ck_assert_msg(pconn == NULL, "Failed to handle null URL argument");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL");

  /* We're already testing URL parsing elsewhere, so we only need to
   * supply well-formed URLs in these tests.
   */

  mark_point();
  url = "http://127.0.0.1:80";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn == NULL, "Failed to handle unsupported protocol/scheme");
  ck_assert_msg(errno == EPERM, "Failed to set errno to EPERM");

  mark_point();
  url = "ftp://foo.bar.baz";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn == NULL, "Failed to handle unresolvable host");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_addr_test) {
  const struct proxy_conn *pconn;
  const char *ipstr, *url;
  const pr_netaddr_t *pconn_addr;
  array_header *other_addrs = NULL;

  pconn_addr = proxy_conn_get_addr(NULL, NULL);
  ck_assert_msg(pconn_addr == NULL, "Failed to handle null argument");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL");

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  pconn_addr = proxy_conn_get_addr(pconn, &other_addrs);
  ck_assert_msg(pconn_addr != NULL, "Failed to get address for pconn");
  ipstr = pr_netaddr_get_ipstr(pconn_addr);
  ck_assert_msg(strcmp(ipstr, "127.0.0.1") == 0,
    "Expected IP address '127.0.0.1', got '%s'", ipstr);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_host_test) {
  const char *host, *url, *expected;
  const struct proxy_conn *pconn;

  host = proxy_conn_get_host(NULL);
  ck_assert_msg(host == NULL, "Got host from null pconn unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  host = proxy_conn_get_host(pconn);
  ck_assert_msg(host != NULL, "Failed to get host from conn: %s",
    strerror(errno));
  expected = "127.0.0.1";
  ck_assert_msg(strcmp(host, expected) == 0, "Expected host '%s', got '%s'",
    expected, host);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_port_test) {
  int port;
  const char *url;
  const struct proxy_conn *pconn;

  port = proxy_conn_get_port(NULL);
  ck_assert_msg(port < 0, "Got port from null pconn unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  port = proxy_conn_get_port(pconn);
  ck_assert_msg(port == 21, "Expected port 21, got %d", port);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_hostport_test) {
  const struct proxy_conn *pconn;
  const char *hostport, *url;

  hostport = proxy_conn_get_hostport(NULL);
  ck_assert_msg(hostport == NULL, "Failed to handle null argument");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  hostport = proxy_conn_get_hostport(pconn);
  ck_assert_msg(hostport != NULL, "Failed to get host/port for pconn");
  ck_assert_msg(strcmp(hostport, "127.0.0.1:21") == 0,
    "Expected host/port '127.0.0.1:21', got '%s'", hostport);

  /* Implicit/assumed ports */
  proxy_conn_free(pconn);

  url = "ftp://127.0.0.1";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  hostport = proxy_conn_get_hostport(pconn);
  ck_assert_msg(hostport != NULL, "Failed to get host/port for pconn");
  ck_assert_msg(strcmp(hostport, "127.0.0.1:21") == 0,
    "Expected host/port '127.0.0.1:21', got '%s'", hostport);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_uri_test) {
  const struct proxy_conn *pconn;
  const char *pconn_url, *url;

  pconn_url = proxy_conn_get_uri(NULL);
  ck_assert_msg(pconn_url == NULL, "Failed to handle null argument");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL");

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  pconn_url = proxy_conn_get_uri(pconn);
  ck_assert_msg(pconn_url != NULL, "Failed to get URL for pconn");
  ck_assert_msg(strcmp(pconn_url, url) == 0,
    "Expected URL '%s', got '%s'", url, pconn_url);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_username_test) {
  const char *username, *url, *expected;
  const struct proxy_conn *pconn;

  username = proxy_conn_get_username(NULL);
  ck_assert_msg(username == NULL, "Got username from null pconn unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  username = proxy_conn_get_username(pconn);
  ck_assert_msg(username == NULL, "Got username unexpectedly");
  proxy_conn_free(pconn);

  url = "ftp://user:passwd@127.0.0.1:2121";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  username = proxy_conn_get_username(pconn);
  ck_assert_msg(username != NULL, "Expected username from conn");
  expected = "user";
  ck_assert_msg(strcmp(username, expected) == 0,
    "Expected username '%s', got '%s'", expected, username);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_password_test) {
  const char *passwd, *url, *expected;
  const struct proxy_conn *pconn;

  passwd = proxy_conn_get_password(NULL);
  ck_assert_msg(passwd == NULL, "Got password from null pconn unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  passwd = proxy_conn_get_password(pconn);
  ck_assert_msg(passwd == NULL, "Got password unexpectedly");
  proxy_conn_free(pconn);

  url = "ftp://user:passwd@127.0.0.1:2121";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  passwd = proxy_conn_get_password(pconn);
  ck_assert_msg(passwd != NULL, "Expected password from conn");
  expected = "passwd";
  ck_assert_msg(strcmp(passwd, expected) == 0,
    "Expected password '%s', got '%s'", expected, passwd);
  proxy_conn_free(pconn);

  url = "ftp://user:@127.0.0.1:2121";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  passwd = proxy_conn_get_password(pconn);
  ck_assert_msg(passwd != NULL, "Expected password from conn");
  expected = "";
  ck_assert_msg(strcmp(passwd, expected) == 0,
    "Expected password '%s', got '%s'", expected, passwd);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_tls_test) {
  int tls;
  const char *url;
  const struct proxy_conn *pconn;

  mark_point();
  tls = proxy_conn_get_tls(NULL);
  ck_assert_msg(tls < 0, "Got TLS from null pconn unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  mark_point();
  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_AUTO, "Expected TLS auto, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftp+srv://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  mark_point();
  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_AUTO, "Expected TLS auto, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftp+txt://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  mark_point();
  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_AUTO, "Expected TLS auto, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_ON, "Expected TLS on, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps+srv://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_ON, "Expected TLS on, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps+txt://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_ON, "Expected TLS on, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps://127.0.0.1:990";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_IMPLICIT,
    "Expected TLS implicit, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps+srv://127.0.0.1:990";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_ON, "Expected TLS on, got %d", tls);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps+txt://127.0.0.1:990";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  tls = proxy_conn_get_tls(pconn);
  ck_assert_msg(tls == PROXY_TLS_ENGINE_ON, "Expected TLS on, got %d", tls);
  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_use_dns_srv_test) {
  int use_dns_srv;
  const char *url;
  const struct proxy_conn *pconn;

  mark_point();
  use_dns_srv = proxy_conn_use_dns_srv(NULL);
  ck_assert_msg(use_dns_srv < 0, "Got DNS SRV from null pconn unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  mark_point();
  use_dns_srv = proxy_conn_use_dns_srv(pconn);
  ck_assert_msg(use_dns_srv == FALSE, "Expected DNS SRV = false, got %d",
    use_dns_srv);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftp+srv://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  mark_point();
  use_dns_srv = proxy_conn_use_dns_srv(pconn);
  ck_assert_msg(use_dns_srv == TRUE, "Expected DNS SRV = true, got %d",
    use_dns_srv);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  use_dns_srv = proxy_conn_use_dns_srv(pconn);
  ck_assert_msg(use_dns_srv == FALSE, "Expected DNS SRV = false, got %d",
    use_dns_srv);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps+srv://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  use_dns_srv = proxy_conn_use_dns_srv(pconn);
  ck_assert_msg(use_dns_srv == TRUE, "Expected DNS SRV = true, got %d",
    use_dns_srv);
  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_use_dns_txt_test) {
  int use_dns_txt;
  const char *url;
  const struct proxy_conn *pconn;

  mark_point();
  use_dns_txt = proxy_conn_use_dns_txt(NULL);
  ck_assert_msg(use_dns_txt < 0, "Got DNS TXT from null pconn unexpectedly");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  mark_point();
  use_dns_txt = proxy_conn_use_dns_txt(pconn);
  ck_assert_msg(use_dns_txt == FALSE, "Expected DNS TXT = false, got %d",
    use_dns_txt);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftp+txt://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  mark_point();
  use_dns_txt = proxy_conn_use_dns_txt(pconn);
  ck_assert_msg(use_dns_txt == TRUE, "Expected DNS TXT = true, got %d",
    use_dns_txt);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  use_dns_txt = proxy_conn_use_dns_txt(pconn);
  ck_assert_msg(use_dns_txt == FALSE, "Expected DNS TXT = false, got %d",
    use_dns_txt);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftps+txt://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  use_dns_txt = proxy_conn_use_dns_txt(pconn);
  ck_assert_msg(use_dns_txt == TRUE, "Expected DNS TXT = true, got %d",
    use_dns_txt);
  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_dns_ttl_test) {
  int res;
  const char *url;
  const struct proxy_conn *pconn;

  mark_point();
  res = proxy_conn_get_dns_ttl(NULL);
  ck_assert_msg(res < 0, "Failed to handle null argument");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  url = "ftp://www.google.com";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  res = proxy_conn_get_dns_ttl(pconn);
  ck_assert_msg(res < 0, "Failed to handle non-TTL URL");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  proxy_conn_free(pconn);

  mark_point();
  url = "ftp+srv://127.0.0.1";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  res = proxy_conn_get_dns_ttl(pconn);
  ck_assert_msg(res < 0, "Failed to handle SRV URL");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  proxy_conn_free(pconn);

  url = "ftps+txt://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  res = proxy_conn_get_dns_ttl(pconn);
  ck_assert_msg(res < 0, "Failed to handle TXT URL");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_get_server_conn_test) {
  /* XXX TODO */
}
END_TEST

START_TEST (conn_clear_username_test) {
  const char *username, *url, *expected;
  const struct proxy_conn *pconn;

  mark_point();
  proxy_conn_clear_username(NULL);

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  username = proxy_conn_get_username(pconn);
  ck_assert_msg(username == NULL, "Got username unexpectedly");

  mark_point();
  proxy_conn_clear_username(pconn);
  proxy_conn_free(pconn);

  url = "ftp://user:passwd@127.0.0.1:2121";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  username = proxy_conn_get_username(pconn);
  ck_assert_msg(username != NULL, "Expected username from conn");
  expected = "user";
  ck_assert_msg(strcmp(username, expected) == 0,
    "Expected username '%s', got '%s'", expected, username);

  mark_point();
  proxy_conn_clear_username(pconn);

  username = proxy_conn_get_username(pconn);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_clear_password_test) {
  const char *passwd, *url, *expected;
  const struct proxy_conn *pconn;

  mark_point();
  proxy_conn_clear_password(NULL);

  url = "ftp://127.0.0.1:21";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  passwd = proxy_conn_get_password(pconn);
  ck_assert_msg(passwd == NULL, "Got password unexpectedly");

  mark_point();
  proxy_conn_clear_password(pconn);
  proxy_conn_free(pconn);

  url = "ftp://user:passwd@127.0.0.1:2121";
  pconn = proxy_conn_create(p, url, 0);
  ck_assert_msg(pconn != NULL,
    "Failed to create pconn for URL '%s' as expected", url);

  passwd = proxy_conn_get_password(pconn);
  ck_assert_msg(passwd != NULL, "Expected password from conn");
  expected = "passwd";
  ck_assert_msg(strcmp(passwd, expected) == 0,
    "Expected password '%s', got '%s'", expected, passwd);

  mark_point();
  proxy_conn_clear_password(pconn);

  passwd = proxy_conn_get_password(pconn);
  ck_assert_msg(passwd == NULL, "Expected null password, got '%s'", passwd);

  proxy_conn_free(pconn);
}
END_TEST

START_TEST (conn_timeout_cb_test) {
  int res;
  struct proxy_session *proxy_sess;
  const pr_netaddr_t *addr;

  session.notes = pr_table_alloc(p, 0);

  proxy_sess = (struct proxy_session *) proxy_session_alloc(p);
  ck_assert_msg(proxy_sess != NULL, "Failed to allocate proxy session: %s",
    strerror(errno));
  pr_table_add(session.notes, "mod_proxy.proxy-session", proxy_sess,
    sizeof(struct proxy_session));

  addr = pr_netaddr_get_addr(p, "1.2.3.4", NULL);
  ck_assert_msg(addr != NULL, "Failed to resolve '1.2.3.4': %s", strerror(errno));
  pr_table_add(session.notes, "mod_proxy.proxy-connect-address", addr,
    sizeof(pr_netaddr_t));

  proxy_sess->connect_timeout = 1;
  res = proxy_conn_connect_timeout_cb(0, 0, 0, NULL);
  ck_assert_msg(res == 0, "Failed to handle timeout: %s", strerror(errno));

  proxy_sess->connect_timeout = 2;
  res = proxy_conn_connect_timeout_cb(0, 0, 0, NULL);
  ck_assert_msg(res == 0, "Failed to handle timeout: %s", strerror(errno));

  session.notes = NULL;
  proxy_session_free(p, proxy_sess);
}
END_TEST

START_TEST (conn_send_proxy_v1_test) {
  int res;
  conn_t *conn;

  res = proxy_conn_send_proxy_v1(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_conn_send_proxy_v1(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v1(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "::1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v1(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.c->local_addr = pr_netaddr_get_addr(p, "::1", FALSE);
  session.c->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v1(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.c->remote_addr = pr_netaddr_get_addr(p, "::1", FALSE);
  session.c->local_addr = pr_netaddr_get_addr(p, "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v1(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v1(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, conn);
  pr_inet_close(p, session.c);
  session.c = NULL;
}
END_TEST

START_TEST (conn_send_proxy_v2_test) {
  int res;
  conn_t *conn;

  res = proxy_conn_send_proxy_v2(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_conn_send_proxy_v2(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v2(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p,
    "::1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v2(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.c->local_addr = pr_netaddr_get_addr(p, "::1", FALSE);
  session.c->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v2(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.c->remote_addr = pr_netaddr_get_addr(p, "::1", FALSE);
  session.c->local_addr = pr_netaddr_get_addr(p, "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v2(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", FALSE);

  mark_point();
  res = proxy_conn_send_proxy_v2(p, conn);
  ck_assert_msg(res < 0, "Failed to handle invalid conn");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, conn);
  pr_inet_close(p, session.c);
  session.c = NULL;
}
END_TEST

Suite *tests_get_conn_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("conn");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, conn_create_test);
  tcase_add_test(testcase, conn_get_addr_test);
  tcase_add_test(testcase, conn_get_host_test);
  tcase_add_test(testcase, conn_get_port_test);
  tcase_add_test(testcase, conn_get_hostport_test);
  tcase_add_test(testcase, conn_get_uri_test);
  tcase_add_test(testcase, conn_get_username_test);
  tcase_add_test(testcase, conn_get_password_test);
  tcase_add_test(testcase, conn_get_tls_test);
  tcase_add_test(testcase, conn_use_dns_srv_test);
  tcase_add_test(testcase, conn_use_dns_txt_test);
  tcase_add_test(testcase, conn_get_dns_ttl_test);
  tcase_add_test(testcase, conn_get_server_conn_test);
  tcase_add_test(testcase, conn_clear_username_test);
  tcase_add_test(testcase, conn_clear_password_test);
  tcase_add_test(testcase, conn_timeout_cb_test);
  tcase_add_test(testcase, conn_send_proxy_v1_test);
  tcase_add_test(testcase, conn_send_proxy_v2_test);

  /* Allow a longer timeout on these tests, especially for the
   * unpredictable CI environment.
   */
  tcase_set_timeout(testcase, 15);

  suite_add_tcase(suite, testcase);
  return suite;
}
