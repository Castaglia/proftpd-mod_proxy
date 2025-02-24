/*
 * ProFTPD - mod_proxy FTP connection routines
 * Copyright (c) 2013-2025 TJ Saunders
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

#include "include/proxy/inet.h"
#include "include/proxy/netio.h"
#include "include/proxy/ftp/conn.h"

static const char *trace_channel = "proxy.ftp.conn";

static int set_conn_socket_opts(pool *p, conn_t *conn, int rcvbufsz,
    int sndbufsz, struct tcp_keepalive *keepalive, int reuse_port) {
  int res;

#if PROFTPD_VERSION_NUMBER >= 0x0001030801
  res = pr_inet_set_socket_opts2(p, conn, rcvbufsz, sndbufsz, keepalive,
    reuse_port);
#else
  res = pr_inet_set_socket_opts(p, conn, rcvbufsz, sndbufsz, keepalive);

  /* Earlier versions of ProFTPD did not support setting the SO_REUSEPORT
   * socket option via pr_inet_set_socket_opts(), so we do it ourselves.
   *
   * For active data transfers, enabling SO_REUSEPORT can be very useful,
   * since the number/range of available source ports may be small.
   */
# if defined(SO_REUSEPORT)
  if (setsockopt(conn->listen_fd, SOL_SOCKET, SO_REUSEPORT,
      (void *) &reuse_port, sizeof(reuse_port)) < 0) {
    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error setting SO_REUSEPORT on fd %d: %s", conn->listen_fd,
      strerror(errno));

  } else {
    pr_trace_msg(trace_channel, 8,
      "set socket fd %d reuseport = %d", conn->listen_fd, reuse_port);
  }
# endif /* SO_REUSEPORT */
#endif /* ProFTPD 1.3.8rc1 or later */

  return res;
}

conn_t *proxy_ftp_conn_accept(pool *p, conn_t *data_conn, conn_t *ctrl_conn,
    int frontend_data) {
  conn_t *conn;
  int reverse_dns;

  if (p == NULL ||
      data_conn == NULL ||
      ctrl_conn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  reverse_dns = pr_netaddr_set_reverse_dns(ServerUseReverseDNS);

  if (session.xfer.direction == PR_NETIO_IO_RD) {
    set_conn_socket_opts(data_conn->pool, data_conn,
      (main_server->tcp_rcvbuf_override ? main_server->tcp_rcvbuf_len : 0), 0,
      main_server->tcp_keepalive, 0);

  } else {
    set_conn_socket_opts(data_conn->pool, data_conn,
      0, (main_server->tcp_sndbuf_override ? main_server->tcp_sndbuf_len : 0),
      main_server->tcp_keepalive, 0);
  }

  if (frontend_data) {
    conn = pr_inet_accept(session.pool, data_conn, ctrl_conn, -1, -1, TRUE);

  } else {
    conn = proxy_inet_accept(session.pool, data_conn, ctrl_conn, -1, -1, TRUE);
  }

  pr_netaddr_set_reverse_dns(reverse_dns);

  if (conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error accepting backend data connection: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Check for error conditions. */
  if (conn->mode == CM_ERROR) {
    int xerrno = conn->xerrno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error accepting backend data connection: %s", strerror(xerrno));
    destroy_pool(conn->pool);

    errno = xerrno;
    return NULL;
  }

  if (frontend_data) {
    pr_pool_tag(conn->pool, "proxy frontend data accept conn pool");

  } else {
    pr_pool_tag(conn->pool, "proxy backend data accept conn pool");
  }

  pr_trace_msg(trace_channel, 9,
    "accepted connection from server '%s'", conn->remote_name);
  return conn;
}

conn_t *proxy_ftp_conn_connect(pool *p, const pr_netaddr_t *bind_addr,
    const pr_netaddr_t *remote_addr, int frontend_data) {
  conn_t *conn, *opened = NULL;
  int default_inet_family = 0, remote_family, res, reverse_dns, xerrno;

  if (p == NULL ||
      remote_addr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  remote_family = pr_netaddr_get_family(remote_addr);
  pr_trace_msg(trace_channel, 9,
    "using %s family for backend socket address %s",
    remote_family == AF_INET ? "IPv4" : "IPv6",
    pr_netaddr_get_ipstr(remote_addr));
  default_inet_family = pr_inet_set_default_family(p, remote_family);

  conn = pr_inet_create_conn(session.pool, -1, bind_addr, INPORT_ANY, TRUE);
  xerrno = errno;

  if (conn == NULL) {
    pr_inet_set_default_family(p, default_inet_family);
    errno = xerrno;
    return NULL;
  }

  reverse_dns = pr_netaddr_set_reverse_dns(ServerUseReverseDNS);

  if (session.xfer.direction == PR_NETIO_IO_RD) {
    set_conn_socket_opts(conn->pool, conn,
      (main_server->tcp_rcvbuf_override ? main_server->tcp_rcvbuf_len : 0), 0,
      main_server->tcp_keepalive, 1);

  } else {
    set_conn_socket_opts(conn->pool, conn,
      0, (main_server->tcp_sndbuf_override ? main_server->tcp_sndbuf_len : 0),
      main_server->tcp_keepalive, 1);
  }

  pr_inet_set_proto_opts(session.pool, conn,
    main_server->tcp_mss_len, 1, IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("proxy.data-connect", main_server,
    conn->local_addr, conn->listen_fd);

  pr_trace_msg(trace_channel, 9, "connecting to %s#%u from %s#%u",
    pr_netaddr_get_ipstr(remote_addr), ntohs(pr_netaddr_get_port(remote_addr)),
    pr_netaddr_get_ipstr(bind_addr), ntohs(pr_netaddr_get_port(bind_addr)));

  if (frontend_data == TRUE) {
    res = pr_inet_connect(p, conn, remote_addr,
      ntohs(pr_netaddr_get_port(remote_addr)));

  } else {
    res = proxy_inet_connect(p, conn, remote_addr,
      ntohs(pr_netaddr_get_port(remote_addr)));
  }

  if (res < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to connect to %s#%u: %s\n", pr_netaddr_get_ipstr(remote_addr),
      ntohs(pr_netaddr_get_port(remote_addr)), strerror(xerrno));

    if (frontend_data == FALSE) {
      proxy_inet_close(session.pool, conn);
    }
    pr_inet_close(session.pool, conn);

    errno = xerrno;
    return NULL;
  }

  /* XXX Will it always be STRM_DATA? */

  if (frontend_data == TRUE) {
    opened = pr_inet_openrw(session.pool, conn, NULL, PR_NETIO_STRM_DATA,
      conn->listen_fd, -1, -1, TRUE);

  } else {
    opened = proxy_inet_openrw(session.pool, conn, NULL, PR_NETIO_STRM_DATA,
      conn->listen_fd, -1, -1, TRUE);
  }

  pr_netaddr_set_reverse_dns(reverse_dns);

  if (opened == NULL) {
    xerrno = errno;

    if (frontend_data == FALSE) {
      proxy_inet_close(session.pool, conn);
    }
    pr_inet_close(session.pool, conn);

    errno = xerrno;
    return NULL;
  }

  /* The conn returned by pr_inet_openrw() is a copy of the input conn;
   * we no longer need the input conn at this point.
   */
  if (frontend_data == TRUE) {
    pr_inet_close(session.pool, conn);
    pr_pool_tag(opened->pool, "proxy frontend data connect conn pool");

  } else {
    proxy_inet_close(session.pool, conn);
    pr_inet_close(session.pool, conn);
    pr_pool_tag(opened->pool, "proxy backend data connect conn pool");
  }

  pr_inet_set_nonblock(session.pool, opened);

  pr_trace_msg(trace_channel, 9,
    "connected to server '%s'", opened->remote_name);
  return opened;
}

conn_t *proxy_ftp_conn_listen(pool *p, const pr_netaddr_t *bind_addr,
    int frontend_data) {
  int res;
  conn_t *conn = NULL;
  config_rec *c;

  if (p == NULL ||
      bind_addr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  c = find_config(main_server->conf, CONF_PARAM, "PassivePorts", FALSE);
  if (c != NULL) {
    int pasv_min_port = *((int *) c->argv[0]);
    int pasv_max_port = *((int *) c->argv[1]);

    conn = pr_inet_create_conn_portrange(session.pool, bind_addr,
      pasv_min_port, pasv_max_port);
    if (conn == NULL) {
      /* If not able to open a passive port in the given range, default to
       * normal behavior (using INPORT_ANY), and log the failure.  This
       * indicates a too-small range configuration.
       */
      pr_log_pri(PR_LOG_WARNING,
        "unable to find open port in PassivePorts range %d-%d: "
        "defaulting to INPORT_ANY (consider defining a larger PassivePorts "
        "range)", pasv_min_port, pasv_max_port);
    }
  }

  if (conn == NULL) {
    conn = pr_inet_create_conn(session.pool, -1, bind_addr, INPORT_ANY, FALSE);
  }

  if (conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error creating socket: %s", strerror(xerrno));

    errno = EINVAL;
    return NULL;
  }

  /* Make sure that necessary socket options are set on the socket prior
   * to the call to listen(2).
   */
  pr_inet_set_proto_opts(session.pool, conn, main_server->tcp_mss_len, 1,
    IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("proxy.data-listen", main_server,
    conn->local_addr, conn->listen_fd);

  pr_inet_set_block(session.pool, conn);

  if (frontend_data) {
    res = pr_inet_listen(session.pool, conn, 1, 0);

  } else {
    res = proxy_inet_listen(session.pool, conn, 1, 0);
  }

  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to listen on %s#%u: %s", pr_netaddr_get_ipstr(bind_addr),
      ntohs(pr_netaddr_get_port(bind_addr)), strerror(xerrno));

    if (!frontend_data) {
      proxy_inet_close(session.pool, conn);
    }
    pr_inet_close(session.pool, conn);

    errno = xerrno;
    return NULL;
  }

  if (frontend_data) {
    pr_pool_tag(conn->pool, "proxy frontend data listen conn pool");

    conn->instrm = pr_netio_open(session.pool, PR_NETIO_STRM_DATA,
      conn->listen_fd, PR_NETIO_IO_RD);
    conn->outstrm = pr_netio_open(session.pool, PR_NETIO_STRM_DATA,
      conn->listen_fd, PR_NETIO_IO_WR);

  } else {
    pr_pool_tag(conn->pool, "proxy backend data listen conn pool");

    conn->instrm = proxy_netio_open(session.pool, PR_NETIO_STRM_DATA,
      conn->listen_fd, PR_NETIO_IO_RD);
    conn->outstrm = proxy_netio_open(session.pool, PR_NETIO_STRM_DATA,
      conn->listen_fd, PR_NETIO_IO_WR);
  }

  return conn;
}
