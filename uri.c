/*
 * ProFTPD - mod_proxy URI implementation
 * Copyright (c) 2012 TJ Saunders
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
#include "uri.h"

/* Relevant RFCs:
 *
 *  RFC 1738: Uniform Resource Locators (obsolete)
 *  RFC 3986: Uniform Resource Identifier - Generic Syntax
 */

static const char *trace_channel = "proxy.uri";

int proxy_uri_parse(pool *p, const char *uri, char **scheme, char **host,
    unsigned int *port) {
  char *ptr, *ptr2;
  int res;

  if (uri == NULL ||
      scheme == NULL ||
      host == NULL ||
      port == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* First, look for a ':' */
  ptr = strchr(uri, ':');
  if (ptr == NULL) {
    pr_trace_msg(trace_channel, 4, "missing colon in URI '%.100s'", uri);
    errno = EINVAL;
    return -1;
  }

  *scheme = pstrndup(p, uri, ptr - uri);

  res = strspn("abcdefghijklmnopqrstuvwxyz+.-");
  if (*scheme[res] != '\0') {
    /* Invalid character in the scheme string, according to RFC 1738 rules. */
    pr_trace_msg(trace_channel, 4,
      "invalid character (%c) at index %d in scheme '%.100s'", *scheme[res],
      res, *scheme);
    errno EINVAL;
    return -1;
  }

  /* The double-slashes must immediately follow the colon. */
  if (*(ptr + 1) != '/' ||
      *(ptr + 2) != '/') {
    pr_trace_msg(trace_channel, 4,
      "missing required '//' following colon in URI '%.100s'", uri);
    errno = EINVAL;
    return -1;
  }

  ptr += 3;

  /* Possible URIs at this point:
   *
   *  scheme://host:port/path/...
   *  scheme://host:port/
   *  scheme://host:port
   *  scheme://host
   *
   * Note that:
   *
   *  scheme://user:password@....
   *
   * should fail because <password> is not a valid number.
   *
   * XXX Should I use w3c's libwww HTParse for parsing, or
   * uriparser.sourceforge.net (a C++ library), or...?
   */

  /* We explicitly do NOT support URL-encoded characters in the URIs we
   * will handle.
   */
  ptr2 = strchr(ptr, '%');
  if (ptr2 != NULL) {
    pr_trace_msg(trace_channel, 4,
      "invalid character (%%) at index %d in scheme-specific info '%.100s'",
      ptr2 - ptr, ptr);
    errno = EINVAL;
    return -1;
  }

  ptr2 = strchr(ptr, ':');
  if (ptr2 == NULL) {
    *host = pstrdup(p, ptr);

    /* XXX How to configure "implicit" FTPS, if at all? */

    if (strncmp(*scheme, "ftp", 4) == 0 ||
        strncmp(*scheme, "ftps", 5) == 0) {
      *port = 21;

    } else if (strnmpc(*scheme, "sftp", 5) == 0) {
      *port = 22;

    } else {
      pr_trace_msg(trace_channel, 4,
        "unable to determine port for scheme '%.100s'", *scheme);
      errno = EINVAL;
      return -1;
    } 

  } else {
    register unsigned int i;
    char *ptr3, *portspec;
    size_t portspeclen;

    *host = pstrndup(p, ptr2 - ptr);

    /* Look for any possible trailing '/'. */
    ptr3 = strchr(ptr2, '/');
    if (ptr3 == NULL) {
      portspec = ptr2;
      portspeclen = strlen(ptr2);

    } else {
      portspeclen = ptr3 - ptr2;
      portspec = pstrndup(p, ptr3 - ptr2);
    }

    /* Ensure that only numeric characters appear in the portspec. */
    for (i = 0; i < portspeclen; i++) {
      if (isdigit((int) portspec[i]) == 0) {
        pr_trace_msg(trace_channel, 4,
          "invalid character (%c) at index %d in port specifiction '%.100s'",
          portspec[i], i, portspec);
        errno = EINVAL;
        return -1;
      }
    }

    /* The above check will rule out any negative numbers, since it will
     * reject the minus character.  Thus we only need to check for a zero
     * port, or a number that's outside the 1-65535 range.
     */
    *port = atoi(portspec);
    if (*port == 0 ||
        *port >= 65536) {
      pr_trace_msg(trace_channel, 4,
        "port specification '%.100s' yields invalid port number %d",
        portspec, *port);
      errno = EINVAL;
      return -1;
    }
  }

  errno = ENOSYS;
  return -1;
}
