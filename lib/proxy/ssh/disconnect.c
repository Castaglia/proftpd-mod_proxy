/*
 * ProFTPD - mod_proxy SSH disconnects
 * Copyright (c) 2021 TJ Saunders
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
#include "proxy/ssh/msg.h"
#include "proxy/ssh/packet.h"
#include "proxy/ssh/disconnect.h"

#if defined(PR_USE_OPENSSL)

struct disconnect_reason {
  uint32_t code;
  const char *explain;
  const char *lang;
};

static struct disconnect_reason explanations[] = {
  { PROXY_SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT, "Host not allowed to connect", NULL },
  { PROXY_SSH_DISCONNECT_PROTOCOL_ERROR, "Protocol error", NULL },
  { PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Key exchange failed", NULL },
  { PROXY_SSH_DISCONNECT_MAC_ERROR, "MAC error", NULL },
  { PROXY_SSH_DISCONNECT_COMPRESSION_ERROR, "Compression error", NULL },
  { PROXY_SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "Requested service not available", NULL },
  { PROXY_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, "Protocol version not supported", NULL },
  { PROXY_SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "Host key not verifiable", NULL },
  { PROXY_SSH_DISCONNECT_CONNECTION_LOST, "Connection lost", NULL },
  { PROXY_SSH_DISCONNECT_BY_APPLICATION, "Application disconnected", NULL },
  { PROXY_SSH_DISCONNECT_TOO_MANY_CONNECTIONS, "Too many connections", NULL },
  { PROXY_SSH_DISCONNECT_AUTH_CANCELLED_BY_USER, "Authentication cancelled by user", NULL },
  { PROXY_SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "No other authentication mechanisms available", NULL },
  { PROXY_SSH_DISCONNECT_ILLEGAL_USER_NAME, "Illegal user name", NULL },
  { 0, NULL, NULL }
};

static const char *trace_channel = "proxy.ssh.disconnect";

const char *proxy_ssh_disconnect_get_text(uint32_t reason_code) {
  register unsigned int i;

  for (i = 0; explanations[i].explain; i++) {
    if (explanations[i].code == reason_code) {
      return explanations[i].explain;
    }
  }

  errno = ENOENT;
  return NULL;
}

void proxy_ssh_disconnect_send(pool *p, conn_t *conn, uint32_t reason,
    const char *explain, const char *file, int lineno, const char *func) {
  struct proxy_ssh_packet *pkt;
  const char *lang = "en-US";
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  /* Send the server a DISCONNECT mesg. */
  pkt = proxy_ssh_packet_create(p);

  buflen = bufsz = 1024;
  ptr = buf = palloc(pkt->pool, bufsz);

  if (explain == NULL) {
    register unsigned int i;

    for (i = 0; explanations[i].explain; i++) {
      if (explanations[i].code == reason) {
        explain = explanations[i].explain;
        lang = explanations[i].lang;
        if (lang == NULL) {
          lang = "en-US";
        }
        break;
      }
    }

    if (explain == NULL) {
      explain = "Unknown reason";
    }

  } else {
    lang = "en-US";
  }

  if (strlen(func) > 0) {
    pr_trace_msg(trace_channel, 9, "disconnecting (%s) [at %s:%d:%s()]",
      explain, file, lineno, func);

  } else {
    pr_trace_msg(trace_channel, 9, "disconnecting (%s) [at %s:%d]", explain,
      file, lineno);
  }

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_DISCONNECT);
  len += proxy_ssh_msg_write_int(&buf, &buflen, reason);
  len += proxy_ssh_msg_write_string(&buf, &buflen, explain);
  len += proxy_ssh_msg_write_string(&buf, &buflen, lang);

  pkt->payload = ptr;
  pkt->payload_len = len;

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "disconnecting %s (%s)", pr_netaddr_get_ipstr(conn->remote_addr), explain);

  /* Explicitly set a short poll timeout of 2 secs. */
  proxy_ssh_packet_set_poll_timeout(2, 0);

  if (proxy_ssh_packet_write(conn, pkt) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 12,
      "error writing DISCONNECT message: %s", strerror(xerrno));
  }

  destroy_pool(pkt->pool);
}

void proxy_ssh_disconnect_conn(conn_t *conn, uint32_t reason,
    const char *explain, const char *file, int lineno, const char *func) {
  proxy_ssh_disconnect_send(proxy_pool, conn, reason, explain, file, lineno,
    func);

#if defined(PR_DEVEL_COREDUMP)
  pr_session_end(PR_SESS_END_FL_NOEXIT);
  abort();
#else
  pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION, NULL);
#endif /* PR_DEVEL_COREDUMP */
}
#endif /* PR_USE_OPENSSL */
