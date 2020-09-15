/*
 * ProFTPD - mod_proxy FTP data conn routines
 * Copyright (c) 2012-2020 TJ Saunders
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
#include "proxy/ftp/data.h"

static const char *trace_channel = "proxy.ftp.data";

pr_buffer_t *proxy_ftp_data_recv(pool *p, conn_t *data_conn,
    int frontend_data) {
  int nread;
  pr_buffer_t *pbuf = NULL;

  if (p == NULL ||
      data_conn == NULL ||
      data_conn->instrm == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (data_conn->instrm->strm_buf != NULL) {
    pbuf = data_conn->instrm->strm_buf;

  } else {
    pbuf = pr_netio_buffer_alloc(data_conn->instrm);
  }

  pbuf->current = pbuf->buf;
  pbuf->remaining = pbuf->buflen;

  while (TRUE) {
    size_t avail_len;

    if (frontend_data) {
      nread = pr_netio_read(data_conn->instrm, pbuf->current,
        pbuf->remaining, 1);

    } else {
      nread = proxy_netio_read(data_conn->instrm, pbuf->current,
        pbuf->remaining, 1);
    }

    if (nread < 0) {
      return NULL;
    }

    if (nread == 0) {
      /* We might have had data left over in the buffer from a previous
       * iteration of the loop, thus we return it as is.
       */
      return pbuf;
    }

    pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
    pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
    pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);

    pr_trace_msg(trace_channel, 15, "received %d bytes of data", nread);

    pbuf->current += nread;
    pbuf->remaining -= nread;
    pr_event_generate("mod_proxy.data-read", pbuf);

    /* How much data is available in the buffer?  It is possible that
     * event listeners consumed that data entirely.  If there is no available
     * data left, we need to read more.
     */
    avail_len = pbuf->current - pbuf->buf;
    if (avail_len > 0) {
      break;
    }
  }

  return pbuf;
}

int proxy_ftp_data_send(pool *p, conn_t *data_conn, pr_buffer_t *pbuf,
    int frontend_data) {
  int nwrote;
  char *buf;
  size_t buflen;

  if (p == NULL ||
      data_conn == NULL ||
      data_conn->outstrm == NULL ||
      pbuf == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_event_generate("mod_proxy.data-write", pbuf);

  /* Currently, we make the conn_t nonblocking (via pr_inet_set_nonblocking),
   * BUT that does NOT set the nonblocking flag on the contained stream.
   * Thus this write is actually a BLOCKING write -- which means that we will
   * not need to worry about short writes here.
   *
   * In the future, we may want to make the streams nonblocking, but that
   * makes mod_proxy a little more sensitive to the slow producer/consumer
   * problem.
   */

  buf = pbuf->buf;
  buflen = pbuf->current - pbuf->buf;

  pr_trace_msg(trace_channel, 25, "writing %lu bytes of data to %s",
    (unsigned long) buflen,
    frontend_data ? "frontend client" : "backend server");

  if (frontend_data) {
    nwrote = pr_netio_write(data_conn->outstrm, buf, buflen);

  } else {
    nwrote = proxy_netio_write(data_conn->outstrm, buf, buflen);
  }

  while (nwrote < 0) {
    int xerrno = errno;

    if (xerrno == EAGAIN) {
      /* Since our socket is in non-blocking mode, write(2) can return
       * EAGAIN if there is not enough from for our data yet.  Handle
       * this by delaying temporarily, then trying again.
       */
      errno = EINTR;
      pr_signals_handle();

      if (frontend_data) {
        nwrote = pr_netio_write(data_conn->outstrm, buf, buflen);

      } else {
        nwrote = proxy_netio_write(data_conn->outstrm, buf, buflen);
      }

      continue;
    }

    errno = xerrno;
    return -1;
  }

  pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
  pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);

  return nwrote;
}
