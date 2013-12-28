/*
 * ProFTPD - mod_proxy conn implementation
 * Copyright (c) 2012-2013 TJ Saunders
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

#include "proxy/conn.h"
#include "proxy/session.h"
#include "proxy/uri.h"

struct proxy_conn {
  pool *pconn_pool;

  const char *pconn_uri;
  const char *pconn_proto;

  pr_netaddr_t *pconn_addr;
};

static const char *supported_protocols[] = {
  "ftp",
  "ftps",
  "sftp",

  NULL
};

static const char *trace_channel = "proxy.conn";

static int supported_protocol(const char *proto) {
  register unsigned int i;

  for (i = 0; supported_protocols[i] != NULL; i++) {
    if (strcmp(proto, supported_protocols[i]) == 0) {
      return 0;
    }
  }

  errno = ENOENT;
  return -1;
}

int proxy_conn_connect_timeout_cb(CALLBACK_FRAME) {
  struct proxy_session *proxy_sess;
  pr_netaddr_t *server_addr;

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  server_addr = pr_table_get(session.notes, "mod_proxy.proxy-connect-address",
    NULL);

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "timed out connecting to %s:%d after %d %s",
    pr_netaddr_get_ipstr(server_addr), ntohs(pr_netaddr_get_port(server_addr)),
    proxy_sess->connect_timeout,
    proxy_sess->connect_timeout != 1 ? "seconds" : "second");

  pr_event_generate("mod_proxy.timeout-connect", NULL);

  pr_log_pri(PR_LOG_NOTICE, "%s", "Connect timed out, disconnected");
  pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_TIMEOUT,
    "ProxyTimeoutConnect");

  /* Do not restart the timer (should never be reached). */
  return 0;
}

struct proxy_conn *proxy_conn_create(pool *p, const char *uri) {
  int res;
  char *proto, *remote_host;
  unsigned int remote_port;
  struct proxy_conn *pconn;
  pool *pconn_pool;

  res = proxy_uri_parse(p, uri, &proto, &remote_host, &remote_port);
  if (res < 0) {
    return NULL;
  }

  if (supported_protocol(proto) < 0) {
    pr_trace_msg(trace_channel, 4, "unsupported protocol '%s' in URI '%.100s'",
      proto, uri);
    errno = EPERM;
    return NULL;
  }

  pconn_pool = pr_pool_create_sz(p, 128); 
  pr_pool_tag(pconn_pool, "proxy connection pool");

  pconn = pcalloc(pconn_pool, sizeof(struct proxy_conn));
  pconn->pconn_pool = pconn_pool;
  pconn->pconn_uri = pstrdup(pconn_pool, uri);
  pconn->pconn_proto = pstrdup(pconn_pool, proto);

  pconn->pconn_addr = pr_netaddr_get_addr(pconn_pool, remote_host, NULL);
  if (pconn->pconn_addr == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to resolve '%s' from URI '%s'", remote_host, uri);
    destroy_pool(pconn_pool);
    errno = EINVAL;
    return NULL;
  }

  if (pr_netaddr_set_port2(pconn->pconn_addr, remote_port) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to set port %d from URI '%s': %s", remote_port, uri,
      strerror(errno));
    destroy_pool(pconn_pool);
    errno = EINVAL;
    return NULL;
  }
 
  return pconn;
}

pr_netaddr_t *proxy_conn_get_addr(struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pconn->pconn_addr;
}

const char *proxy_conn_get_uri(struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pconn->pconn_uri;
}

int proxy_conn_send_proxy(pool *p, conn_t *conn) {
  int res, src_port, dst_port;
  const char *proto, *src_ipstr, *dst_ipstr;
  pool *sub_pool = NULL;

  /* "PROXY" "TCP4"|"TCP6"|"UNKNOWN"
   *   session.c->remote_addr session.c->local_addr
   *   session.c->remote_port, session.c->local_port "\r\n"
   */

  if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET &&
      pr_netaddr_get_family(session.c->local_addr) == AF_INET) {
    proto = "TCP4";
    src_ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
    src_port = session.c->remote_port;
    dst_ipstr = pr_netaddr_get_ipstr(session.c->local_addr);
    dst_port = session.c->local_port;

  } else {
    proto = "TCP6";
    sub_pool = make_sub_pool(p);

    if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET) {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
      src_ipstr = pstrcat(sub_pool, "::ffff:", ipstr, NULL);

    } else {
      src_ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
    }

    src_port = session.c->remote_port;

    if (pr_netaddr_get_family(session.c->local_addr) == AF_INET) {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(session.c->local_addr);
      dst_ipstr = pstrcat(sub_pool, "::ffff:", ipstr, NULL);

    } else {
      dst_ipstr = pr_netaddr_get_ipstr(session.c->local_addr);
    }

    dst_port = session.c->local_port;

    /* What should we do if the entire frontend connection is IPv6, but the
     * backend server is IPv4?  Sending "PROXY TCP6" there may not work as
     * expected, e.g. the backend server may not want to handle IPv6 addresses
     * (even though it does not have to); should that be handled using
     * "PROXY UNKNOWN"?
     */
    if (pr_netaddr_get_family(conn->remote_addr) == AF_INET) {
      proto = "UNKNOWN";

      pr_trace_msg(trace_channel, 9,
        "client address '%s' and local address '%s' are both IPv6, "
        "but backend address '%s' is IPv4, using '%s' proto", src_ipstr,
        dst_ipstr, pr_netaddr_get_ipstr(conn->remote_addr), proto);
    }
  }

  pr_trace_msg(trace_channel, 9,
    "sending proxy protocol message: 'PROXY %s %s %s %d %d' to backend",
    proto, src_ipstr, dst_ipstr, src_port, dst_port);

  res = pr_netio_printf(conn->outstrm, "PROXY %s %s %s %d %d\r\n",
    proto, src_ipstr, dst_ipstr, src_port, dst_port);

  if (sub_pool != NULL) {
    destroy_pool(sub_pool);
  }

  return res;
}
