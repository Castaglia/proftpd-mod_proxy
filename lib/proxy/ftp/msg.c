/*
 * ProFTPD - mod_proxy FTP message routines
 * Copyright (c) 2013 TJ Saunders
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
#include "include/proxy/ftp/msg.h"

static const char *trace_channel = "proxy.ftp.msg";

const char *proxy_ftp_msg_fmt_addr(pool *p, pr_netaddr_t *addr,
    unsigned short port) {
  char *addr_str, *msg, *ptr;
  size_t msglen;

  addr_str = pstrdup(p, pr_netaddr_get_ipstr(addr));

  /* Fixup the address string for use in PORT commands/PASV responses. */
  ptr = strrchr(addr_str, ':');
  if (ptr != NULL) {
    addr_str = ptr + 1;
  }

  for (ptr = addr_str; *ptr; ptr++) {
    if (*ptr == '.') {
      *ptr = ',';
    }
  }

  /* Allocate enough room for 6 numbers (3 digits max each), 5 separators,
   * and a trailing NUL.
   */
  msglen = (6 * 3) + (5 * 1) + 1;

  msg = pcalloc(p, msglen);
  snprintf(msg, msglen-1, "%s,%u,%u", addr_str, (port >> 8) & 255, port & 255);

  return msg;
}

const char *proxy_ftp_msg_fmt_ext_addr(pool *p, pr_netaddr_t *addr,
    unsigned short port, int cmd_id) {
  const char *addr_str;
  char delim = '|', *msg;
  int family;
  size_t addr_strlen, msglen;

  /* Format is <d>proto<d>ip address<d>port<d> (ASCII in network order),
   * where <d> is an arbitrary delimiter character.
   */

  switch (pr_netaddr_get_family(addr)) {
    case AF_INET:
      family = 1;
      break;

#ifdef PR_USE_IPV6
    case AF_INET6:
      family = 2;
      break;
#endif /* PR_USE_IPV6 */
  }

  addr_str = pr_netaddr_get_ipstr(addr);
  addr_strlen = strlen(addr_str);

  /* 4 delimiters, the network protocol, the IP address, the port, and a NUL. */
  msglen = (4 * 1) + addr_strlen + 5 + 1;

  msg = pcalloc(p, msglen);
  switch (cmd_id) {
    case PR_CMD_EPRT_ID:
      snprintf(msg, msglen, "%c%d%c%s%c%u%c", delim, family, delim,
        addr_str, delim, port, delim);
      break;

    case PR_CMD_EPSV_ID:
      snprintf(msg, msglen, "%c%c%c%u%c", delim, delim, delim, port, delim);
      break;
  }

  return msg;
}

pr_netaddr_t *proxy_ftp_msg_parse_addr(pool *p, const char *msg,
    int addr_family) {
  int valid_fmt = FALSE;
  const char *ptr;
  char *addr_buf;
  unsigned int h1, h2, h3, h4, p1, p2;
  unsigned short port;
  size_t addrlen;
  pr_netaddr_t *addr;

  /* Have to scan the message for the encoded address/port.  Note that we may
   * see some strange formats for PASV responses from FTP servers here.
   *
   * We can't predict where the expected address/port numbers start in the
   * string, so start from the beginning.
   */
  for (ptr = msg; *ptr; ptr++) {
    if (sscanf(ptr, "%u,%u,%u,%u,%u,%u", &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
      valid_fmt = TRUE;
      break;
    }
  }

  if (valid_fmt == FALSE) {
    pr_trace_msg(trace_channel, 12,
      "unable to find PORT/PASV address/port format in '%s'", msg);
    errno = EPERM;
    return NULL;
  }

  if (h1 > 255 || h2 > 255 || h3 > 255 || h4 > 255 ||
      p1 > 255 || p2 > 255 ||
      (h1|h2|h3|h4) == 0 ||
      (p1|p2) == 0) {
    pr_trace_msg(trace_channel, 9,
      "message '%s' has invalid address/port value(s)", msg);
    errno = EINVAL;
    return NULL;
  }

  /* A dotted quad address has a maximum size of 16 bytes: 4 numbers of 3 digits
   * (max), 3 periods, and 1 terminating NUL.
   */
  addrlen = 16;

#ifdef PR_USE_IPV6
  /* Allow extra room for any necessary "::ffff:" prefix, for IPv6 sessions. */
  addrlen += 7;
#endif /* PR_USE_IPV6 */

  addr_buf = pcalloc(p, addrlen); 

#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    if (addr_family == AF_INET6) {
      snprintf(addr_buf, addrlen-1, "::ffff:%u.%u.%u.%u", h1, h2, h3, h4);

    } else {
      snprintf(addr_buf, addrlen-1, "%u.%u.%u.%u", h1, h2, h3, h4);
    }

  } else {
    snprintf(addr_buf, addrlen-1, "%u.%u.%u.%u", h1, h2, h3, h4);
  }
#else
  snprintf(addr_buf, addrlen-1, "%u.%u.%u.%u", h1, h2, h3, h4);
#endif /* PR_USE_IPV6 */

  /* XXX Ideally we would NOT be using session pool here, but some other
   * pool.  These objects can't be destroyed (they have no pools of their own),
   * so they will just clutter up the session pool.  Perhaps we could have
   * a pool of addrs in this API, for reusing.
   */
  addr = pr_netaddr_get_addr(session.pool, addr_buf, NULL);
  if (addr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7,
      "unable to resolve '%s' from message '%s': %s", addr_buf, msg,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  port = (p1 << 8) + p2;
  pr_netaddr_set_port2(addr, port);

  return addr;
}

pr_netaddr_t *proxy_ftp_msg_parse_ext_addr(pool *p, const char *msg,
    pr_netaddr_t *addr, int cmd_id, const char *net_proto) {
  pr_netaddr_t *res = NULL, na;
  int family = 0;
  unsigned short port = 0;
  char delim, *msg_str, *ptr;
  size_t msglen;

  if (cmd_id == PR_CMD_EPSV_ID) {
    /* First, find the opening '(' character. */
    ptr = strchr(msg, '(');
    if (ptr == NULL) {
      pr_trace_msg(trace_channel, 12,
        "missing starting '(' character for extended address in '%s'", msg);
      errno = EINVAL;
      return NULL;
    }

    /* Make sure that the last character is a closing ')'. */
    msglen = strlen(ptr);
    if (ptr[msglen-1] != ')') {
      pr_trace_msg(trace_channel, 12,
        "missing ending ')' character for extended address in '%s'", msg);
      errno = EINVAL;
      return NULL;
    }

    msg_str = pstrndup(p, ptr+1, msglen-2);

  } else {
    msg_str = pstrdup(p, msg);
  }

  /* Format is <d>proto<d>ip address<d>port<d> (ASCII in network order),
   * where <d> is an arbitrary delimiter character.
   */
  delim = *msg_str++;

  /* If the network protocol string (e.g. sent by client in EPSV command) is
   * null, then determine the protocol family from the address family we were
   * given.
   */

  /* XXX Hack to skip "all", e.g. "EPSV ALL" commands. */
  if (net_proto != NULL) {
    if (strncasecmp(net_proto, "all", 4) == 0) {
      net_proto = NULL;
    }
  }

  if (net_proto == NULL) {
    if (*msg_str == delim) {
      switch (pr_netaddr_get_family(addr)) {
        case AF_INET:
          family = 1;
          break;

        case AF_INET6:
          if (pr_netaddr_use_ipv6()) {
            family = 2;
            break;
          }
      }

    } else {
      family = atoi(msg_str);
    }

  } else {
    family = atoi(net_proto);
  }

  switch (family) {
    case 1:
      break;

#ifdef PR_USE_IPV6
    case 2:
      if (pr_netaddr_use_ipv6()) {
        break;
      }
#endif /* PR_USE_IPV6 */

    default:
      pr_trace_msg(trace_channel, 12,
        "unsupported network protocol %d", family);
      errno = EPROTOTYPE;
      return NULL;
  }

  /* Now, skip past those numeric characters that atoi() used. */
  while (PR_ISDIGIT(*msg_str)) {
    msg_str++;
  }

  /* If the next character is not the delimiter, it's a badly formatted
   * parameter.
   */
  if (*msg_str == delim) {
    msg_str++;

  } else {
    errno = EPERM;
    return NULL;
  }

  pr_netaddr_clear(&na);

  /* If the next character IS the delimiter, then the address portion is
   * omitted (which is permissible).
   */
  if (*msg_str == delim) {
    pr_netaddr_set_family(&na, pr_netaddr_get_family(addr));
    pr_netaddr_set_sockaddr(&na, pr_netaddr_get_sockaddr(addr));
    msg_str++;

  } else {
    ptr = strchr(msg_str, delim);
    if (ptr == NULL) {
      /* Badly formatted message. */
      errno = EINVAL;
      return NULL;
    }

    /* Twiddle the string so that just the address portion will be processed
     * by pr_inet_pton().
     */
    *ptr = '\0';

    /* Use pr_inet_pton() to translate the address string into the address
     * value.
     */
    switch (family) {
      case 1: {
        struct sockaddr *sa = NULL;

        pr_netaddr_set_family(&na, AF_INET);
        sa = pr_netaddr_get_sockaddr(&na);
        if (sa) {
          sa->sa_family = AF_INET;
        }

        if (pr_inet_pton(AF_INET, msg_str, pr_netaddr_get_inaddr(&na)) <= 0) {
          pr_trace_msg(trace_channel, 2,
            "error converting IPv4 address '%s': %s", msg_str, strerror(errno));
          errno = EPERM;
          return NULL;
        }

        break;
      }

      case 2: {
        struct sockaddr *sa = NULL;

        pr_netaddr_set_family(&na, AF_INET6);
        sa = pr_netaddr_get_sockaddr(&na);
        if (sa) {
          sa->sa_family = AF_INET6;
        }

        if (pr_inet_pton(AF_INET6, msg_str, pr_netaddr_get_inaddr(&na)) <= 0) {
          pr_trace_msg(trace_channel, 2,
            "error converting IPv6 address '%s': %s", msg_str, strerror(errno));
          errno = EPERM;
          return NULL;
        }

        break;
      }
    }

    /* Advance past the address portion of the argument. */
    msg_str = ++ptr;
  }

  port = atoi(msg_str);

  while (PR_ISDIGIT(*msg_str)) {
    msg_str++;
  }

  /* If the next character is not the delimiter, it's a badly formatted
   * parameter.
   */
  if (*msg_str != delim) {
    errno = EPERM;
    return NULL;
  }

  /* XXX Use a pool other than session.pool here, in the future. */ 
  res = pr_netaddr_dup(session.pool, &na);
  pr_netaddr_set_port(res, port);

  return res;
}
