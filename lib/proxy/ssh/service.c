/*
 * ProFTPD - mod_proxy SSH service
 * Copyright (c) 2021-2022 TJ Saunders
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
#include "proxy/ssh/ssh2.h"
#include "proxy/ssh/packet.h"
#include "proxy/ssh/service.h"

#if defined(PR_USE_OPENSSL)

static const char *trace_channel = "proxy.ssh.service";

int proxy_ssh_service_handle(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  int poll_timeout_secs, res, xerrno = 0;
  unsigned int poll_attempts;
  unsigned long poll_timeout_ms;
  char msg_type;

  res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  destroy_pool(pkt->pool);
  proxy_ssh_packet_get_poll_attempts(&poll_attempts);
  proxy_ssh_packet_get_poll_timeout(&poll_timeout_secs, &poll_timeout_ms);

  proxy_ssh_packet_set_poll_attempts(3);
  proxy_ssh_packet_set_poll_timeout(0, 250);

  while (TRUE) {
    pr_signals_handle();

    pkt = proxy_ssh_packet_create(proxy_pool);
    res = proxy_ssh_packet_read(proxy_sess->backend_ctrl_conn, pkt);
    if (res < 0) {
      xerrno = errno;

      destroy_pool(pkt->pool);
      proxy_ssh_packet_set_poll_attempts(poll_attempts);
      proxy_ssh_packet_set_poll_timeout(poll_timeout_secs, poll_timeout_ms);

      errno = xerrno;
      return -1;
    }

    msg_type = proxy_ssh_packet_peek_msg_type(pkt);

    pr_trace_msg(trace_channel, 3, "received %s (%d) packet (from mod_%s.c)",
      proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type,
      pkt->m->name);

    /* Be sure to handle the messages that can come at any time as well. */
    switch (msg_type) {
      case PROXY_SSH_MSG_SERVICE_ACCEPT:
        /* Expected */
        break;

      case PROXY_SSH_MSG_DEBUG:
      case PROXY_SSH_MSG_DISCONNECT:
      case PROXY_SSH_MSG_EXT_INFO:
      case PROXY_SSH_MSG_IGNORE:
      case PROXY_SSH_MSG_UNIMPLEMENTED:
        proxy_ssh_packet_handle(pkt);
        continue;

      default:
        proxy_ssh_packet_set_poll_attempts(poll_attempts);
        proxy_ssh_packet_set_poll_timeout(poll_timeout_secs, poll_timeout_ms);
        destroy_pool(pkt->pool);

        /* Invalid protocol sequence */
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "received unexpected %s packet during SSH service setup, failing",
          proxy_ssh_packet_get_msg_type_desc(msg_type));
        errno = ENOSYS;
        return -1;
    }

    break;
  }

  proxy_ssh_packet_set_poll_attempts(poll_attempts);
  proxy_ssh_packet_set_poll_timeout(poll_timeout_secs, poll_timeout_ms);

  proxy_ssh_packet_log_cmd(pkt, FALSE);
  res = proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
  xerrno = errno;

  destroy_pool(pkt->pool);
  errno = xerrno;
  return res;
}
#endif /* PR_USE_OPENSSL */
