/*
 * ProFTPD - mod_proxy random number implementation
 * Copyright (c) 2013-2020 TJ Saunders
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

#include "mod_proxy.h"
#include "proxy/random.h"

static const char *trace_channel = "proxy.random";

/* If random(3) is supported on this platform, seed it.  rand(3) is already
 * seeded by the core proftpd code.
 */
int proxy_random_init(void) {
#ifdef HAVE_RANDOM
  struct timeval tv;

  gettimeofday(&tv, NULL);
  srandom(getpid() ^ tv.tv_usec);
#endif /* HAVE_RANDOM */

  return 0;
}

long proxy_random_next(long min, long max) {
  long r, scaled;

#if defined(HAVE_RANDOM)
  r = random();
  pr_trace_msg(trace_channel, 22, "obtained r = %ld from random(3)", r);
#else
  r = (long) rand();
  pr_trace_msg(trace_channel, 22, "obtained r = %ld from rand(3)", r);
#endif /* HAVE_RANDOM */

  scaled = r % (max - min + 1) + min;
  pr_trace_msg(trace_channel, 15,
    "yielding scaled r = %ld (r = %ld, max = %ld, min = %ld)", scaled,
    r, max, min);

  return scaled;
}
