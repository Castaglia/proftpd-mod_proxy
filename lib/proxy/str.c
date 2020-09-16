/*
 * ProFTPD - mod_proxy String implementation
 * Copyright (c) 2020 TJ Saunders
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
#include "proxy/str.h"

char *proxy_strnstr(const char *s1, const char *s2, size_t len) {
#if defined(HAVE_STRNSTR)
  if (s1 == NULL ||
      s2 == NULL ||
      len == 0) {
    return NULL;
  }

  /* strnstr(3) does not check this, but it should. */
  if (s2[0] == '\0') {
    return NULL;
  }

  return strnstr(s1, s2, len);

#else
  register unsigned int i;
  size_t s2_len;

  if (s1 == NULL ||
      s2 == NULL ||
      len == 0) {
    return NULL;
  }

  s2_len = strlen(s2);
  if (s2_len == 0 ||
      s2_len > len) {
    return NULL;
  }

  for (i = 0; i <= (unsigned int) (len - s2_len); i++) {
    if (s1[0] == s2[0] &&
        strncmp(s1, s2, s2_len) == 0) {
      return (char *) s1;
    }

    s1++;
  }

  return NULL;
#endif /* HAVE_STRNSTR */
}
