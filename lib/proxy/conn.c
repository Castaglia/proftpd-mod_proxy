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
  const char *pconn_hostport;

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
  char hostport[512], *proto, *remote_host;
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

  memset(hostport, '\0', sizeof(hostport));
  snprintf(hostport, sizeof(hostport)-1, "%s:%u", remote_host, remote_port);

  pconn_pool = pr_pool_create_sz(p, 128); 
  pr_pool_tag(pconn_pool, "proxy connection pool");

  pconn = pcalloc(pconn_pool, sizeof(struct proxy_conn));
  pconn->pconn_pool = pconn_pool;
  pconn->pconn_hostport = pstrdup(pconn_pool, hostport);
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

const char *proxy_conn_get_hostport(struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pconn->pconn_hostport;
}

conn_t *proxy_conn_get_server_conn(pool *p, struct proxy_session *proxy_sess,
    pr_netaddr_t *remote_addr) {
  pr_netaddr_t *bind_addr, *local_addr;
  const char *remote_ipstr;
  unsigned int remote_port;
  conn_t *server_conn, *ctrl_conn;
  int res;

  if (proxy_sess->connect_timeout > 0) {
    const char *notes_key = "mod_proxy.proxy-connect-address";

    proxy_sess->connect_timerno = pr_timer_add(proxy_sess->connect_timeout,
      -1, &proxy_module, proxy_conn_connect_timeout_cb, "ProxyTimeoutConnect");

    (void) pr_table_remove(session.notes, notes_key, NULL);

    if (pr_table_add(session.notes, notes_key, remote_addr,
        sizeof(pr_netaddr_t)) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error stashing proxy connect address note: %s", strerror(errno));
    }
  }

  remote_ipstr = pr_netaddr_get_ipstr(remote_addr);
  remote_port = ntohs(pr_netaddr_get_port(remote_addr));

  /* Check the family of the retrieved address vs what we'll be using
   * to connect.  If there's a mismatch, we need to get an addr with the
   * matching family.
   */

  if (pr_netaddr_get_family(session.c->local_addr) == pr_netaddr_get_family(remote_addr)) {
    local_addr = session.c->local_addr;

  } else {
    /* In this scenario, the proxy has an IPv6 socket, but the remote/backend
     * server has an IPv4 (or IPv4-mapped IPv6) address.
     */
    local_addr = pr_netaddr_v6tov4(p, session.c->local_addr);
  }

  bind_addr = proxy_sess->src_addr;
  if (bind_addr == NULL) {
    bind_addr = local_addr;
  }

  server_conn = pr_inet_create_conn(p, -1, bind_addr, INPORT_ANY, FALSE);

  pr_trace_msg(trace_channel, 11, "connecting to backend address %s#%u from %s",
    remote_ipstr, remote_port, pr_netaddr_get_ipstr(bind_addr));

  res = pr_inet_connect_nowait(p, server_conn, remote_addr,
    ntohs(pr_netaddr_get_port(remote_addr)));
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error starting connect to %s#%u: %s", remote_ipstr, remote_port,
      strerror(xerrno));

    pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
    errno = xerrno;
    return NULL;
  }

  if (res == 0) {
    pr_netio_stream_t *nstrm;
    int nstrm_mode = PR_NETIO_IO_RD;

    if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
      /* Rather than waiting for the stream to be readable (because the
       * other end sent us something), wait for the stream to be writable
       * so that we can send something to the other end).
       */
      nstrm_mode = PR_NETIO_IO_WR;
    }

    /* Not yet connected. */
    nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, server_conn->listen_fd,
      nstrm_mode);
    if (nstrm == NULL) {
      int xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error opening stream to %s#%u: %s", remote_ipstr, remote_port,
        strerror(xerrno));

      pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
      pr_inet_close(p, server_conn);

      errno = xerrno;
      return NULL;
    }

    pr_netio_set_poll_interval(nstrm, 1);

    switch (pr_netio_poll(nstrm)) {
      case 1: {
        /* Aborted, timed out.  Note that we shouldn't reach here. */
        pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
        pr_netio_close(nstrm);
        pr_inet_close(p, server_conn);

        errno = ETIMEDOUT;
        return NULL;
      }

      case -1: {
        /* Error */
        int xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error connecting to %s#%u: %s", remote_ipstr, remote_port,
          strerror(xerrno));

        pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
        pr_netio_close(nstrm);
        pr_inet_close(p, server_conn);

        errno = xerrno;
        return NULL;
      }

      default: {
        /* Connected */
        server_conn->mode = CM_OPEN;
        pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
        pr_table_remove(session.notes, "mod_proxy.proxy-connect-addr", NULL);

        res = pr_inet_get_conn_info(server_conn, server_conn->listen_fd);
        if (res < 0) {
          int xerrno = errno;

          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error obtaining local socket info on fd %d: %s",
            server_conn->listen_fd, strerror(xerrno));

          pr_netio_close(nstrm);
          pr_inet_close(p, server_conn);

          errno = xerrno;
          return NULL;
        }

        break;
      }
    }
  }

  pr_trace_msg(trace_channel, 5,
    "successfully connected to %s#%u from %s#%d", remote_ipstr, remote_port,
    pr_netaddr_get_ipstr(server_conn->local_addr),
    ntohs(pr_netaddr_get_port(server_conn->local_addr)));

  ctrl_conn = pr_inet_openrw(p, server_conn, NULL, PR_NETIO_STRM_CTRL, -1, -1,
    -1, FALSE);
  if (ctrl_conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to open control connection to %s#%u: %s", remote_ipstr,
      remote_port, strerror(xerrno));

    pr_inet_close(p, server_conn);

    errno = xerrno;
    return NULL;
  }

  return ctrl_conn;
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
