/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2012-2022 TJ Saunders <tj@castaglia.org>
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

/* URI API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.uri", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.uri", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  }
}

START_TEST (uri_parse_args_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  mark_point();
  res = proxy_uri_parse(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_uri_parse(p, NULL, NULL, NULL, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null URI");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  uri = "foo";
  res = proxy_uri_parse(p, uri, NULL, NULL, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null scheme");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_uri_parse(p, uri, &scheme, NULL, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null host");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_uri_parse(p, uri, &scheme, &host, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null port");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle URI missing a colon");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "foo:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle unknown/unsupported scheme");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "foo@:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle illegal scheme character");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle URI lacking double slashes");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp:/";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle URI lacking double slashes");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp:/a";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle URI lacking double slashes");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle URI lacking hostname/port");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://%2f";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle URI using URL encoding");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (uri_parse_ftp_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://foo:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://127.0.0.1:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "127.0.0.1") == 0,
    "Expected host '%s', got '%s'", "127.0.0.1", host);
  ck_assert_msg(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://[::1]:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "::1") == 0,
    "Expected host '%s', got '%s'", "::1", host);
  ck_assert_msg(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://[::1:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res < 0, "Failed to reject URI with bad IPv6 host encoding");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user:password@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  ck_assert_msg(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  ck_assert_msg(username != NULL, "Expected non-null username");
  ck_assert_msg(strcmp(username, "user") == 0,
    "Expected username '%s', got '%s'", "user", username);
  ck_assert_msg(password != NULL, "Expected non-null password");
  ck_assert_msg(strcmp(password, "password") == 0,
    "Expected password '%s', got '%s'", "password", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user:@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  ck_assert_msg(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  ck_assert_msg(username != NULL, "Expected non-null username");
  ck_assert_msg(strcmp(username, "user") == 0,
    "Expected username '%s', got '%s'", "user", username);
  ck_assert_msg(password != NULL, "Expected non-null password");
  ck_assert_msg(strcmp(password, "") == 0,
    "Expected password '%s', got '%s'", "", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  ck_assert_msg(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://anonymous:email@example.com@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  ck_assert_msg(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  ck_assert_msg(username != NULL, "Expected non-null username");
  ck_assert_msg(strcmp(username, "anonymous") == 0,
    "Expected username '%s', got '%s'", "anonymous", username);
  ck_assert_msg(password != NULL, "Expected non-null password");
  ck_assert_msg(strcmp(password, "email@example.com") == 0,
    "Expected password '%s', got '%s'", "email@example.com", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user@domain:email@example.com@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  ck_assert_msg(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  ck_assert_msg(username != NULL, "Expected non-null username");
  ck_assert_msg(strcmp(username, "user@domain") == 0,
    "Expected username '%s', got '%s'", "user@domain", username);
  ck_assert_msg(password != NULL, "Expected non-null password");
  ck_assert_msg(strcmp(password, "email@example.com") == 0,
    "Expected password '%s', got '%s'", "email@example.com", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://host:65555";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to reject URI with too-large port");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://host:65555:foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to reject URI with bad port spec");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://host:70000";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to reject URI with invalid port spec");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (uri_parse_ftps_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps://foo:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);
}
END_TEST

START_TEST (uri_parse_sftp_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "sftp://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 22,
    "Expected port '%u', got '%u'", 22, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "sftp://foo:2222";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 2222,
    "Expected port '%u', got '%u'", 2222, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "sftp://foo:2222/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 2222,
    "Expected port '%u', got '%u'", 2222, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);
}
END_TEST

START_TEST (uri_parse_http_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "http://host";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to reject URI with unsupported scheme");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

/* SRV scheme variants */
START_TEST (uri_parse_srv_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp+srv://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp+srv") == 0,
    "Expected scheme '%s', got '%s'", "ftp+srv", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 0,
    "Expected port '%u', got '%u'", 0, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps+srv://foo.bar";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftps+srv") == 0,
    "Expected scheme '%s', got '%s'", "ftps+srv", scheme);
  ck_assert_msg(strcmp(host, "foo.bar") == 0,
    "Expected host '%s', got '%s'", "foo.bar", host);
  ck_assert_msg(port == 0,
    "Expected port '%u', got '%u'", 0, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);
}
END_TEST

/* TXT scheme variants */
START_TEST (uri_parse_txt_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp+txt://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftp+txt") == 0,
    "Expected scheme '%s', got '%s'", "ftp+txt", scheme);
  ck_assert_msg(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  ck_assert_msg(port == 0,
    "Expected port '%u', got '%u'", 0, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);

  mark_point();
  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps+txt://foo.bar";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  ck_assert_msg(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  ck_assert_msg(strcmp(scheme, "ftps+txt") == 0,
    "Expected scheme '%s', got '%s'", "ftps+txt", scheme);
  ck_assert_msg(strcmp(host, "foo.bar") == 0,
    "Expected host '%s', got '%s'", "foo.bar", host);
  ck_assert_msg(port == 0,
    "Expected port '%u', got '%u'", 0, port);
  ck_assert_msg(username == NULL, "Expected null username, got '%s'", username);
  ck_assert_msg(password == NULL, "Expected null password, got '%s'", password);
}
END_TEST

Suite *tests_get_uri_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("uri");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, uri_parse_args_test);
  tcase_add_test(testcase, uri_parse_ftp_test);
  tcase_add_test(testcase, uri_parse_ftps_test);
  tcase_add_test(testcase, uri_parse_sftp_test);
  tcase_add_test(testcase, uri_parse_http_test);
  tcase_add_test(testcase, uri_parse_srv_test);
  tcase_add_test(testcase, uri_parse_txt_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
