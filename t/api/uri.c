/*
 * ProFTPD - mod_proxy testsuite
 * Copyright (c) 2012-2016 TJ Saunders <tj@castaglia.org>
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
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.uri", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("proxy.uri", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (uri_parse_test) {
  const char *uri;
  char *scheme, *host, *username, *password;
  unsigned int port;
  int res;

  res = proxy_uri_parse(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_uri_parse(p, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null URI");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  uri = "foo";

  res = proxy_uri_parse(p, uri, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null scheme");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_uri_parse(p, uri, &scheme, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null host");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_uri_parse(p, uri, &scheme, &host, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null port");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle URI missing a colon");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  uri = "foo:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle unknown/unsupported scheme");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  uri = "foo@:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle unknown/unsupported scheme");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  uri = "ftp:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle URI lacking double slashes");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  uri = "ftp:/";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle URI lacking double slashes");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  uri = "ftp:/a";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle URI lacking double slashes");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle URI lacking hostname/port");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://%2f";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to handle URI using URL encoding");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "sftp://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 22,
    "Expected port '%u', got '%u'", 22, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://foo:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://127.0.0.1:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "127.0.0.1") == 0,
    "Expected host '%s', got '%s'", "127.0.0.1", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://[::1]:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "::1") == 0,
    "Expected host '%s', got '%s'", "::1", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://[::1:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res < 0, "Failed to reject URI with bad IPv6 host encoding");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps://foo:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "sftp://foo:2222";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2222,
    "Expected port '%u', got '%u'", 2222, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user:password@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  fail_unless(username != NULL, "Expected non-null username");
  fail_unless(strcmp(username, "user") == 0,
    "Expected username '%s', got '%s'", "user", username);
  fail_unless(password != NULL, "Expected non-null password");
  fail_unless(strcmp(password, "password") == 0,
    "Expected password '%s', got '%s'", "password", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user:@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  fail_unless(username != NULL, "Expected non-null username");
  fail_unless(strcmp(username, "user") == 0,
    "Expected username '%s', got '%s'", "user", username);
  fail_unless(password != NULL, "Expected non-null password");
  fail_unless(strcmp(password, "") == 0,
    "Expected password '%s', got '%s'", "", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://anonymous:email@example.com@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  fail_unless(username != NULL, "Expected non-null username");
  fail_unless(strcmp(username, "anonymous") == 0,
    "Expected username '%s', got '%s'", "anonymous", username);
  fail_unless(password != NULL, "Expected non-null password");
  fail_unless(strcmp(password, "email@example.com") == 0,
    "Expected password '%s', got '%s'", "email@example.com", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://user@domain:email@example.com@host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "host") == 0,
    "Expected host '%s', got '%s'", "host", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);
  fail_unless(username != NULL, "Expected non-null username");
  fail_unless(strcmp(username, "user@domain") == 0,
    "Expected username '%s', got '%s'", "user@domain", username);
  fail_unless(password != NULL, "Expected non-null password");
  fail_unless(strcmp(password, "email@example.com") == 0,
    "Expected password '%s', got '%s'", "email@example.com", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://host:65555";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to reject URI with too-large port");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftps://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "sftp://foo:2222/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, &username, &password);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2222,
    "Expected port '%u', got '%u'", 2222, port);
  fail_unless(username == NULL, "Expected null username, got '%s'", username);
  fail_unless(password == NULL, "Expected null password, got '%s'", password);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://host:65555:foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to reject URI with bad port spec");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "ftp://host:70000";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to reject URI with invalid port spec");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  scheme = host = username = password = NULL;
  port = 0;
  uri = "http://host";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port, NULL, NULL);
  fail_unless(res < 0, "Failed to reject URI with unsupported scheme");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_uri_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("uri");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, uri_parse_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
