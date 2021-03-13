/*
 * ProFTPD - mod_proxy Inet implementation
 * Copyright (c) 2015-2021 TJ Saunders
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

#include "proxy/netio.h"
#include "proxy/inet.h"

conn_t *proxy_inet_accept(pool *p, conn_t *data_conn, conn_t *ctrl_conn,
    int rfd, int wfd, int resolve) {
  int xerrno;
  conn_t *conn;
  pr_netio_t *curr_netio;

  curr_netio = proxy_netio_unset(PR_NETIO_STRM_DATA, "inet_accept");
  conn = pr_inet_accept(p, data_conn, ctrl_conn, rfd, wfd,
    (unsigned char) resolve);
  xerrno = errno;
  proxy_netio_set(PR_NETIO_STRM_DATA, curr_netio);

  errno = xerrno;
  return conn;
}

void proxy_inet_close(pool *p, conn_t *conn) {

  if (conn != NULL) {
    /* Note that we do our own close here, rather than relying on the
     * core Inet's close, as that one simply relies on the connection
     * cleanup callback -- and we want to use our own Proxy Netio API
     * functions for closing, too.
     */

    /* Shutdowns first, then closes. */
    if (conn->instrm != NULL) {
      proxy_netio_shutdown(conn->instrm, 0);
    }

    if (conn->outstrm != NULL) {
      proxy_netio_shutdown(conn->outstrm, 1);
    }

    if (conn->instrm != NULL) {
      proxy_netio_close(conn->instrm);
      conn->instrm = NULL;
    }

    if (conn->outstrm != NULL) {
      proxy_netio_close(conn->outstrm);
      conn->outstrm = NULL;
    }

    if (conn->listen_fd != -1) {
      (void) close(conn->listen_fd);
      conn->listen_fd = -1;
    }

    if (conn->rfd != -1) {
      (void) close(conn->rfd);
      conn->rfd = -1;
    }

    if (conn->wfd != -1) {
      (void) close(conn->wfd);
      conn->wfd = -1;
    }
  }
}

int proxy_inet_connect(pool *p, conn_t *conn, const pr_netaddr_t *addr,
    int port) {
  int instrm_type = -1, outstrm_type = -1, res, xerrno;
  pr_netio_t *in_netio = NULL, *out_netio = NULL;

  if (conn != NULL) {
    if (conn->instrm != NULL) {
      instrm_type = conn->instrm->strm_type;

      in_netio = proxy_netio_unset(instrm_type, "inet_connect");
    }

    if (conn->outstrm != NULL) {
      outstrm_type = conn->outstrm->strm_type;

      if (outstrm_type != instrm_type) {
        out_netio = proxy_netio_unset(outstrm_type, "inet_connect");
      }
    }
  }

  res = pr_inet_connect(p, conn, addr, port);
  xerrno = errno;

  if (in_netio != NULL) {
    proxy_netio_set(instrm_type, in_netio);
  }

  if (out_netio != NULL) {
    proxy_netio_set(outstrm_type, out_netio);
  }

  errno = xerrno;
  return res;
}

int proxy_inet_listen(pool *p, conn_t *conn, int backlog, int flags) {
  int instrm_type = -1, outstrm_type = -1, res, xerrno;
  pr_netio_t *in_netio = NULL, *out_netio = NULL;

  if (conn != NULL) {
    if (conn->instrm != NULL) {
      instrm_type = conn->instrm->strm_type;

      in_netio = proxy_netio_unset(instrm_type, "inet_listen");
    }

    if (conn->outstrm != NULL) {
      outstrm_type = conn->outstrm->strm_type;

      if (outstrm_type != instrm_type) {
        out_netio = proxy_netio_unset(outstrm_type, "inet_listen");
      }
    }
  }

  res = pr_inet_listen(p, conn, backlog, flags);
  xerrno = errno;

  if (in_netio != NULL) {
    proxy_netio_set(instrm_type, in_netio);
  }

  if (out_netio != NULL) {
    proxy_netio_set(outstrm_type, out_netio);
  }

  errno = xerrno;
  return res;
}

conn_t *proxy_inet_openrw(pool *p, conn_t *conn, const pr_netaddr_t *addr,
    int strm_type, int fd, int rfd, int wfd, int resolve) {
  int xerrno;
  conn_t *new_conn;
  pr_netio_t *curr_netio = NULL;

  curr_netio = proxy_netio_unset(strm_type, "inet_openrw");
  new_conn = pr_inet_openrw(p, conn, addr, strm_type, fd, rfd, wfd, resolve);
  xerrno = errno;
  proxy_netio_set(strm_type, curr_netio);

  if (new_conn != NULL) {
    /* Note: pr_inet_openrw() calls pr_inet_copy_conn(), which registers
     * a cleanup on the create object.  But we clean up our own data,
     * so that cleanup, when run, will attempt a double-free.  Thus we
     * unregister that cleanup here.
     */
    unregister_cleanup(new_conn->pool, new_conn, NULL);
  }

  errno = xerrno;
  return new_conn;
}
