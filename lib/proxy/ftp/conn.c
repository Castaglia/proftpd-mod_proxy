/*
 * ProFTPD - mod_proxy FTP connection routines
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

static const char *trace_channel = "proxy.ftp.conn";

conn_t *proxy_ftp_conn_accept(pool *p, conn_t *data_conn, conn_t *ctrl_conn) {
  conn_t *conn;

  /* XXX Other socket options need to be set -- depending on IO_RD/IO_WR
   * direction -- before calling accept(2).
   */
  conn = pr_inet_accept(session.pool, data_conn, ctrl_conn, -1, -1, TRUE);
  if (conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error accepting backend data connection: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  return conn;
}

conn_t *proxy_ftp_conn_connect(pool *p, pr_netaddr_t *local_addr,
    pr_netaddr_t *remote_addr) {
  conn_t *conn, *opened = NULL;

  conn = pr_inet_create_conn(session.pool, -1, local_addr, INPORT_ANY, TRUE);

  pr_inet_set_proto_opts(session.pool, conn,
    main_server->tcp_mss_len, 0, IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("proxy.data-connect", main_server,
    conn->local_addr, conn->listen_fd);

  pr_inet_set_nonblock(session.pool, conn);

  pr_trace_msg(trace_channel, 9, "connecting to %s#%u",
    pr_netaddr_get_ipstr(remote_addr), ntohs(pr_netaddr_get_port(remote_addr)));

  if (pr_inet_connect(p, conn, remote_addr,
      ntohs(pr_netaddr_get_port(remote_addr))) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to connect to %s#%u: %s\n", pr_netaddr_get_ipstr(remote_addr),
      ntohs(pr_netaddr_get_port(remote_addr)), strerror(xerrno));
    pr_inet_close(session.pool, conn);

    errno = xerrno;
    return NULL;
  }

  /* XXX Will it always be STRM_DATA? */
  opened = pr_inet_openrw(session.pool, conn, NULL, PR_NETIO_STRM_DATA,
    conn->listen_fd, -1, -1, TRUE);
  if (opened == NULL) {
    int xerrno = errno;

    pr_inet_close(session.pool, conn);

    errno = xerrno;
    return NULL;
  }

  return opened;
}
