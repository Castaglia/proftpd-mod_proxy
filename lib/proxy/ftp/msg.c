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
    unsigned short port) {
  errno = ENOSYS;
  return NULL;
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
    int addr_family) {
#if 0
  /* First, find the opening '(' character. */
  ptr = strchr(resp->msg, '(');
  if (ptr == NULL) {
    /* XXX Badly formatted response, error out */
  }

  /* Make sure that the last character is a closing ')'. */
  msglen = strlen(resp->msg);
  if (ptr[msglen - (ptr - resp->msg) - 1] != ')') {
    /* XXX Badly formatted response, error out */
  }

  /* Format is <d>proto<d>ip address<d>port<d> (ASCII in network order),
   * where <d> is an arbitrary delimiter character.
   */
  arg_str = pstrdup(cmd->tmp_pool, ptr + 1);
  delim = *arg_str++;

#endif

  errno = ENOSYS;
  return NULL;
}
