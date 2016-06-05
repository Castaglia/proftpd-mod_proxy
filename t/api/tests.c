/*
 * ProFTPD - mod_proxy API testsuite
 * Copyright (c) 2012-2016 TJ Saunders
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

#include "tests.h"

struct testsuite_info {
  const char *name;
  Suite *(*get_suite)(void);
};

static struct testsuite_info suites[] = {
  { "db",		tests_get_db_suite },
  { "conn", 		tests_get_conn_suite },
  { "netio",		tests_get_netio_suite },
  { "inet",		tests_get_inet_suite },
  { "random", 		tests_get_random_suite },
  { "reverse", 		tests_get_reverse_suite },
  { "forward", 		tests_get_forward_suite },
  { "tls", 		tests_get_tls_suite },
  { "uri", 		tests_get_uri_suite },
  { "session", 		tests_get_session_suite },
  { "ftp.msg", 		tests_get_ftp_msg_suite },
  { "ftp.conn",		tests_get_ftp_conn_suite },
  { "ftp.ctrl",		tests_get_ftp_ctrl_suite },
  { "ftp.data",		tests_get_ftp_data_suite },
  { "ftp.sess",		tests_get_ftp_sess_suite },
  { "ftp.xfer",		tests_get_ftp_xfer_suite },

  { NULL, NULL }
};

static Suite *tests_get_suite(const char *suite) { 
  register unsigned int i;

  for (i = 0; suites[i].name != NULL; i++) {
    if (strcmp(suite, suites[i].name) == 0) {
      return (*suites[i].get_suite)();
    }
  }

  errno = ENOENT;
  return NULL;
}

int main(int argc, char *argv[]) {
  const char *log_file = "api-tests.log";
  int nfailed = 0;
  SRunner *runner = NULL;
  char *requested = NULL;

  runner = srunner_create(NULL);

  /* XXX This log name should be set outside this code, e.g. via environment
   * variable or command-line option.
   */
  srunner_set_log(runner, log_file);

  requested = getenv("PROXY_TEST_SUITE");
  if (requested) {
    Suite *suite;

    suite = tests_get_suite(requested);
    if (suite) {
      srunner_add_suite(runner, suite);

    } else {
      fprintf(stderr,
        "No such test suite ('%s') requested via PROXY_TEST_SUITE\n",
        requested);
      return EXIT_FAILURE;
    }

  } else {
    register unsigned int i;

    for (i = 0; suites[i].name; i++) {
      Suite *suite;

      suite = (suites[i].get_suite)();
      if (suite) {
        srunner_add_suite(runner, suite);
      }
    }
  }

  /* Configure the Trace API to write to stderr. */
  pr_trace_use_stderr(TRUE);

  requested = getenv("PROXY_TEST_NOFORK");
  if (requested) {
    srunner_set_fork_status(runner, CK_NOFORK);
  } else {
    requested = getenv("CK_DEFAULT_TIMEOUT");
    if (requested == NULL) {
      setenv("CK_DEFAULT_TIMEOUT", "60", 1);
    }
  }

  srunner_run_all(runner, CK_NORMAL);

  nfailed = srunner_ntests_failed(runner);

  if (runner)
    srunner_free(runner);

  if (nfailed != 0) {
    fprintf(stderr, "-------------------------------------------------\n");
    fprintf(stderr, " FAILED %d %s\n\n", nfailed,
      nfailed != 1 ? "tests" : "test");
    fprintf(stderr, " Please send email to:\n\n");
    fprintf(stderr, "   tj@castaglia.org\n\n");
    fprintf(stderr, " containing the `%s' file (in the t/ directory)\n", log_file);
    fprintf(stderr, " and the output from running `proftpd -V'\n");
    fprintf(stderr, "-------------------------------------------------\n");

    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
