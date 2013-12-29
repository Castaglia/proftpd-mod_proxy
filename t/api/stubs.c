/*
 * ProFTPD - mod_proxy API testsuite
 * Copyright (c) 2012 TJ Saunders <tj@castaglia.org>
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

/* Stubs */

void pr_alarms_block(void) {
}

void pr_alarms_unblock(void) {
}

void pr_log_pri(int prio, const char *fmt, ...) {
}

void pr_signals_handle(void) {
}

int pr_trace_get_level(const char *channel) {
  return 0;
}

int pr_trace_msg(const char *channel, int level, const char *fmt, ...) {
  va_list msg;

  fprintf(stderr, "<%s:%d>: ", channel, level);

  va_start(msg, fmt);
  vfprintf(stderr, fmt, msg);
  va_end(msg);

  fprintf(stderr, "\n");
  return 0;
}

