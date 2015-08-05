/*
 * ProFTPD - mod_proxy URI implementation
 * Copyright (c) 2012-2015 TJ Saunders
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
#include "proxy/uri.h"

/* Relevant RFCs:
 *
 *  RFC 1738: Uniform Resource Locators (obsolete)
 *  RFC 3986: Uniform Resource Identifier - Generic Syntax
 */

static const char *trace_channel = "proxy.uri";

static char *uri_parse_host(pool *p, const char *orig_uri,
    const char *uri, char **remaining) {
  char *host = NULL, *ptr = NULL;

  /* We have either of:
   *
   *  host<:...>
   *  [host]<:...>
   *
   * Look for an opening square bracket, to see if we have an IPv6 address
   * in the URI.
   */
  if (uri[0] == '[') {
    ptr = strchr(uri + 1, ']');
    if (ptr == NULL) {
      /* If there is no ']', then it's a badly-formatted URI. */
      pr_trace_msg(trace_channel, 4,
        "badly formatted IPv6 address in host info '%.100s'", orig_uri);
      errno = EINVAL;
      return NULL;
    }

    host = pstrndup(p, uri + 1, ptr - uri - 1);

    if (remaining != NULL) {
      size_t urilen;
      urilen = strlen(ptr);

      if (urilen > 0) {
        *remaining = ptr + 1;

      } else {
        *remaining = NULL;
      }
    }

    pr_trace_msg(trace_channel, 17, "parsed host '%s' out of URI '%s'", host,
      orig_uri);
    return host;
  }

  ptr = strchr(uri + 1, ':');
  if (ptr == NULL) {
    if (remaining != NULL) {
      *remaining = NULL;
    }

    host = pstrdup(p, uri);

    pr_trace_msg(trace_channel, 17, "parsed host '%s' out of URI '%s'", host,
      orig_uri);
    return host;
  }

  if (remaining != NULL) {
    *remaining = ptr;
  }

  host = pstrndup(p, uri, ptr - uri);

  pr_trace_msg(trace_channel, 17, "parsed host '%s' out of URI '%s'", host,
    orig_uri);
  return host;
}

/* Determine whether "username:password@" are present.  If so, then parse it
 * out, and return a pointer to the portion of the URI after the parsed-out
 * userinfo.
 */
static char *uri_parse_userinfo(pool *p, const char *orig_uri,
    const char *uri, char **username, char **password) {
  char *ptr, *ptr2, *rem_uri = NULL, *userinfo, *user = NULL, *passwd = NULL;

  /* We have either:
   *
   *  host<:...>
   *  [host]<:...>
   *
   * thus no user info, OR:
   *
   *  username:password@host...
   *  username:password@[host]...
   *  username:@host...
   *  username:pass@word@host...
   *  user@domain.com:pass@word@host...
   *
   * all of which have at least one occurrence of the '@' character.
   */

  ptr = strchr(uri, '@');
  if (ptr == NULL) {
    /* No '@' character at all?  No user info, then. */

    if (username != NULL) {
      *username = NULL;
    }

    if (password != NULL) {
      *password = NULL;
    }

    return uri;
  }

  /* To handle the case where the password field might itself contain an
   * '@' character, we first search from the end for '@'.  If found, then we
   * search for '@' from the beginning.  If also found, AND if both ocurrences
   * are the same, then we have a plain "username:password@" string.
   *
   * Note that we can handle '@' characters within passwords (or usernames),
   * but we currently cannot handle ':' characters within usernames.
   */

  ptr2 = strrchr(uri, '@');
  if (ptr2 != NULL) {
    if (ptr != ptr2) {
      /* Use the last found '@' as the delimiter. */
      ptr = ptr2;
    }
  }

  userinfo = pstrndup(p, uri, ptr - uri);
  rem_uri = ptr + 1;

  ptr = strchr(userinfo, ':');
  if (ptr == NULL) {
    pr_trace_msg(trace_channel, 4,
      "badly formatted userinfo '%.100s' (missing ':' character) in "
      "URI '%.100s', ignoring", userinfo, orig_uri);

    if (username != NULL) {
      *username = NULL;
    }

    if (password != NULL) {
      *password = NULL;
    }

    return rem_uri;
  }

  user = pstrndup(p, userinfo, ptr - userinfo);
  if (username != NULL) {
    *username = user;
  }

  /* Watch for empty passwords. */
  if (*(ptr+1) == '\0') {
    passwd = pstrdup(p, "");

  } else {
    passwd = pstrdup(p, ptr + 1);
  }

  if (password != NULL) {
    *password = passwd;
  }

  pr_trace_msg(trace_channel, 17,
    "parsed username '%s', password '%s' out of URI '%s'", user, passwd,
    orig_uri);
  return rem_uri;
}

int proxy_uri_parse(pool *p, const char *uri, char **scheme, char **host,
    unsigned int *port, char **username, char **password) {
  char *ptr, *ptr2;
  int res;
  size_t len;

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

  len = (ptr - uri);
  *scheme = pstrndup(p, uri, len);

  res = strspn(*scheme, "abcdefghijklmnopqrstuvwxyz+.-");
  if (res < len &&
      *scheme[res] != '\0') {
    /* Invalid character in the scheme string, according to RFC 1738 rules. */
    pr_trace_msg(trace_channel, 4,
      "invalid character (%c) at index %d in scheme '%.100s'", *scheme[res],
      res, *scheme);
    errno = EINVAL;
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

  if (*ptr == '\0') {
    /* The given URL looked like "scheme://". */
    pr_trace_msg(trace_channel, 4,
      "missing required authority following '//' in URI '%.100s'", uri);
    errno = EINVAL;
    return -1;
  }

  /* Possible URIs at this point:
   *
   *  scheme://host:port/path/...
   *  scheme://host:port/
   *  scheme://host:port
   *  scheme://host
   *  scheme://username:password@host...
   *
   * And, in the case where 'host' is an IPv6 address:
   *
   *  scheme://[host]:port/path/...
   *  scheme://[host]:port/
   *  scheme://[host]:port
   *  scheme://[host]
   *  scheme://username:password@[host]...
   */

  /* We explicitly do NOT support URL-encoded characters in the URIs we
   * will handle.
   */
  ptr2 = strchr(ptr, '%');
  if (ptr2 != NULL) {
    pr_trace_msg(trace_channel, 4,
      "invalid character (%%) at index %ld in scheme-specific info '%.100s'",
      (long) (ptr2 - ptr), ptr);
    errno = EINVAL;
    return -1;
  }

  ptr = uri_parse_userinfo(p, uri, ptr, username, password);

  ptr2 = strchr(ptr, ':');
  if (ptr2 == NULL) {
    *host = uri_parse_host(p, uri, ptr, NULL);

    if (strncmp(*scheme, "ftp", 4) == 0 ||
        strncmp(*scheme, "ftps", 5) == 0) {
      *port = 21;

    } else if (strncmp(*scheme, "sftp", 5) == 0) {
      *port = 22;

    } else {
      pr_trace_msg(trace_channel, 4,
        "unable to determine port for scheme '%.100s'", *scheme);
      errno = EINVAL;
      return -1;
    } 

  } else {
    *host = uri_parse_host(p, uri, ptr, &ptr2);
  }

  /* Optional port field present? */
  if (ptr2 != NULL) {
    ptr2 = strchr(ptr2, ':');
  }

  if (ptr2 == NULL) {
    /* XXX How to configure "implicit" FTPS, if at all? */

    if (strncmp(*scheme, "ftp", 4) == 0 ||
        strncmp(*scheme, "ftps", 5) == 0) {
      *port = 21;

    } else if (strncmp(*scheme, "sftp", 5) == 0) {
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

    /* Look for any possible trailing '/'. */
    ptr3 = strchr(ptr2, '/');
    if (ptr3 == NULL) {
      portspec = ptr2 + 1;
      portspeclen = strlen(portspec);

    } else {
      portspeclen = ptr3 - (ptr2 + 1);
      portspec = pstrndup(p, ptr2 + 1, portspeclen);
    }

    /* Ensure that only numeric characters appear in the portspec. */
    for (i = 0; i < portspeclen; i++) {
      if (isdigit((int) portspec[i]) == 0) {
        pr_trace_msg(trace_channel, 4,
          "invalid character (%c) at index %d in port specification '%.100s'",
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

  return 0;
}
