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

/* URI API tests
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

START_TEST (uri_parse_test) {
  const char *uri;
  char *scheme, *host;
  unsigned int port;
  int res;

  res = proxy_uri_parse(NULL, NULL, NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  uri = "foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to handle URI missing a colon");   
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  uri = "foo:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to handle unknown/unsupported scheme");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  uri = "ftp:";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to handle URI lacking double slashes");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  uri = "ftp:/";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to handle URI lacking double slashes");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to handle URI lacking hostname/port");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://%2f";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to handle URI using URL encoding");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftps://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 21,
    "Expected port '%u', got '%u'", 21, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "sftp://foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 22,
    "Expected port '%u', got '%u'", 22, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://foo:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftps://foo:2121";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "sftp://foo:2222";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2222,
    "Expected port '%u', got '%u'", 2222, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://user@password:host:21";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to reject URI with username/password");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://host:65555";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to reject URI with too-large port");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftp") == 0,
    "Expected scheme '%s', got '%s'", "ftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftps://foo:2121/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "ftps") == 0,
    "Expected scheme '%s', got '%s'", "ftps", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2121,
    "Expected port '%u', got '%u'", 2121, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "sftp://foo:2222/home";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == 0, "Expected successful parsing of URI '%s', got %s", uri,
    strerror(errno));
  fail_unless(strcmp(scheme, "sftp") == 0,
    "Expected scheme '%s', got '%s'", "sftp", scheme);
  fail_unless(strcmp(host, "foo") == 0,
    "Expected host '%s', got '%s'", "foo", host);
  fail_unless(port == 2222,
    "Expected port '%u', got '%u'", 2222, port);

  mark_point();

  scheme = host = NULL;
  port = 0;
  uri = "ftp://host:65555:foo";
  res = proxy_uri_parse(p, uri, &scheme, &host, &port);
  fail_unless(res == -1, "Failed to reject URI with bad port spec");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

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
