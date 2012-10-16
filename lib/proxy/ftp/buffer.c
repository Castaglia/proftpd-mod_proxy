/*
 * ProFTPD - mod_proxy FTP buffer routines
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

pr_buffer_t *proxy_ftp_buffer_alloc(pr_netio_stream_t *nstrm) {
  size_t bufsz;
  pr_buffer_t *pbuf = NULL;

  pbuf = pcalloc(nstrm->strm_pool, sizeof(pr_buffer_t));

  /* Allocate a buffer. */
  bufsz = pr_config_get_server_xfer_bufsz(nstrm->strm_mode);
  pbuf->buf = pcalloc(nstrm->strm_pool, bufsz);
  pbuf->buflen = bufsz;

  /* Position the offset at the start of the buffer, and set the
   * remaining bytes value accordingly.
   */
  pbuf->current = pbuf->buf;
  pbuf->remaining = bufsz;

  /* Add this buffer to the given stream. */
  nstrm->strm_buf = pbuf;

  return pbuf;
}
