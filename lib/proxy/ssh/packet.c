/*
 * ProFTPD - mod_proxy SSH packet IO
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
#include "proxy/ssh/msg.h"
#include "proxy/ssh/disconnect.h"
#include "proxy/ssh/cipher.h"
#include "proxy/ssh/mac.h"
#include "proxy/ssh/compress.h"
#include "proxy/ssh/kex.h"
#include "proxy/ssh/auth.h"
#include "proxy/ssh/service.h"

#if HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif

#ifndef MAX
# define MAX(x, y) (((x) > (y)) ? (x) : (y))
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#if defined(PR_USE_OPENSSL)

extern pr_response_t *resp_list, *resp_err_list;

static int (*frontend_packet_write)(int, void *) = NULL;

static uint32_t packet_client_seqno = 0;
static uint32_t packet_server_seqno = 0;

/* Maximum length of the payload data of an SSH2 packet we're willing to
 * accept.  Any packets reporting a payload length longer than this will be
 * ignored/dropped.
 */
#define PROXY_SSH_PACKET_MAX_PAYLOAD_LEN	(256 * 1024)

static int poll_timeout_secs = -1;
static unsigned long poll_timeout_ms = 0;

static const char *client_version = PROXY_SSH_ID_DEFAULT_STRING;
static const char *version_id = PROXY_SSH_ID_DEFAULT_STRING "\r\n";
static int sent_version_id = FALSE;

static void is_server_alive(conn_t *conn);

/* Count of the number of "server alive" messages sent without a response. */
static unsigned int server_alive_max = 0, server_alive_count = 0;
static unsigned int server_alive_interval = 0;

static const char *trace_channel = "proxy.ssh.packet";
static const char *timing_channel = "timing";

#define DEFAULT_POLL_ATTEMPTS		3
static unsigned long poll_attempts = DEFAULT_POLL_ATTEMPTS;

int proxy_ssh_packet_conn_mpoll(conn_t *frontend_conn, conn_t *backend_conn,
    int io) {
  fd_set rfds, wfds;
  struct timeval tv;
  int res, frontend_sockfd = -1, backend_sockfd = -1, maxfd = -1, timeout_sec,
    using_server_alive = FALSE;
  unsigned int ntimeouts = 0;
  unsigned long timeout_usec = 0;

  if (poll_timeout_secs == -1) {
    /* If we have "server alive" timeout interval configured, use that --
     * but only if we have already done the key exchange, and are not
     * rekeying.
     *
     * Otherwise, we use the default (i.e. TimeoutIdle).
     */

    if (server_alive_interval > 0 &&
        (!(proxy_sess_state & PROXY_SESS_STATE_SSH_REKEYING) && 
         (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH))) {
      timeout_sec = server_alive_interval;
      using_server_alive = TRUE;

    } else {
      timeout_sec = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
    }

    timeout_usec = 0;

  } else {
    timeout_sec = poll_timeout_secs;
    timeout_usec = (poll_timeout_ms * 1000);
  }

  tv.tv_sec = timeout_sec;
  tv.tv_usec = timeout_usec;

  if (io == PROXY_SSH_PACKET_IO_READ) {
    if (frontend_conn != NULL) {
      frontend_sockfd = frontend_conn->rfd;
    }

    if (backend_conn != NULL) {
      backend_sockfd = backend_conn->rfd;
    }

  } else {
    if (frontend_conn != NULL) {
      frontend_sockfd = frontend_conn->wfd;
    }

    if (backend_conn != NULL) {
      backend_sockfd = backend_conn->wfd;
    }
  }

  pr_trace_msg(trace_channel, 19,
    "waiting for max of %lu secs %lu ms while polling sockets %d/%d for %s "
    "using select(2)", (unsigned long) tv.tv_sec,
    (unsigned long) (tv.tv_usec / 1000), frontend_sockfd, backend_sockfd,
    io == PROXY_SSH_PACKET_IO_READ ? "reading" : "writing");

  while (TRUE) {
    pr_signals_handle();

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    switch (io) {
      case PROXY_SSH_PACKET_IO_READ: {
        if (frontend_conn != NULL) {
          FD_SET(frontend_sockfd, &rfds);
          if (frontend_sockfd > maxfd) {
            maxfd = frontend_sockfd;
          }
        }

        if (backend_conn != NULL) {
          FD_SET(backend_sockfd, &rfds);
          if (backend_sockfd > maxfd) {
            maxfd = backend_sockfd;
          }
        }

        res = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        break;
      }

      case PROXY_SSH_PACKET_IO_WRITE: {
        if (frontend_conn != NULL) {
          FD_SET(frontend_sockfd, &wfds);
          if (frontend_sockfd > maxfd) {
            maxfd = frontend_sockfd;
          }
        }

        if (backend_conn != NULL) {
          FD_SET(backend_sockfd, &wfds);
          if (backend_sockfd > maxfd) {
            maxfd = backend_sockfd;
          }
        }

        res = select(maxfd + 1, NULL, &wfds, NULL, &tv);
        break;
      }

      default:
        errno = EINVAL;
        return -1;
    }

    if (res < 0) {
      int xerrno = errno;

      if (xerrno == EINTR) {
        pr_signals_handle();
        continue;
      }

      pr_trace_msg(trace_channel, 18, "error calling select(2) on fd %d/%d: %s",
        frontend_sockfd, backend_sockfd, strerror(xerrno));

      errno = xerrno;
      return -1;

    } else if (res == 0) {
      tv.tv_sec = timeout_sec;
      tv.tv_usec = timeout_usec;

      ntimeouts++;

      if (ntimeouts > poll_attempts) {
        pr_trace_msg(trace_channel, 18,
          "polling on socket %d/%d timed out after %lu sec %lu ms "
          "(%u attempts)", frontend_sockfd, backend_sockfd,
          (unsigned long) tv.tv_sec, (unsigned long) (tv.tv_usec / 1000),
          ntimeouts);
        errno = ETIMEDOUT;
        return -1;
      }

      if (using_server_alive == TRUE) {
        if (backend_conn != NULL) {
          is_server_alive(backend_conn);
        }

      } else {
        pr_trace_msg(trace_channel, 18,
          "polling on socket %d/%d timed out after %lu sec %lu ms, "
          "trying again (timeout #%u)", frontend_sockfd, backend_sockfd,
          (unsigned long) tv.tv_sec, (unsigned long) (tv.tv_usec / 1000),
          ntimeouts);
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "polling on socket %d/%d timed out after %lu sec %lu ms, "
          "trying again (timeout #%u)", frontend_sockfd, backend_sockfd,
          (unsigned long) tv.tv_sec, (unsigned long) (tv.tv_usec / 1000),
          ntimeouts);
      }

      continue;
    }

    break;
  }

  /* Which connection has data?  Return 0 if it's the frontend connection,
   * otherwise return 1 for the backend connection.
   */

  if (frontend_conn != NULL) {
    if (io == PROXY_SSH_PACKET_IO_READ) {
      if (FD_ISSET(frontend_sockfd, &rfds)) {
        res = 0;
      }

    } else {
      if (FD_ISSET(frontend_sockfd, &wfds)) {
        res = 0;
      }
    }
  }

  if (backend_conn != NULL) {
    if (io == PROXY_SSH_PACKET_IO_READ) {
      if (FD_ISSET(backend_sockfd, &rfds)) {
        res = 1;
      }

    } else {
      if (FD_ISSET(backend_sockfd, &wfds)) {
        res = 1;
      }
    }
  }

  return res;
}

int proxy_ssh_packet_conn_poll(conn_t *conn, int io) {
  int res;

  /* This is only ever called on the backend connection. */
  res = proxy_ssh_packet_conn_mpoll(NULL, conn, io);
  if (res < 0) {
    return -1;
  }

  return 0;
}

/* The purpose of conn_read() is to loop until either we have read in the
 * requested reqlen from the socket, or the socket gives us an I/O error.
 * We want to prevent short reads from causing problems elsewhere (e.g.
 * in the decipher or MAC code).
 *
 * It is the caller's responsibility to ensure that buf is large enough to
 * hold reqlen bytes.
 */
int proxy_ssh_packet_conn_read(conn_t *conn, void *buf, size_t reqlen,
    int flags) {
  void *ptr;
  size_t remainlen;

  if (reqlen == 0) {
    return 0;
  }

  errno = 0;

  ptr = buf;
  remainlen = reqlen;

  while (remainlen > 0) {
    int res;

    if (proxy_ssh_packet_conn_poll(conn, PROXY_SSH_PACKET_IO_READ) < 0) {
      return -1;
    }

    /* The socket we accept is blocking, thus there's no need to handle
     * EAGAIN/EWOULDBLOCK errors.
     */
    res = read(conn->rfd, ptr, remainlen);
    while (res <= 0) {
      if (res < 0) {
        int xerrno = errno;

        if (xerrno == EINTR) {
          pr_signals_handle();
          res = read(conn->rfd, ptr, remainlen);
          continue;
        }

        pr_trace_msg(trace_channel, 16,
          "error reading from server (fd %d): %s", conn->rfd, strerror(xerrno));
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error reading from server (fd %d): %s", conn->rfd, strerror(xerrno));

        errno = xerrno;

        /* We explicitly disconnect the server here, rather than sending
         * a DISCONNECT message, because the errors below all indicate
         * a problem with the TCP connection, such that trying to write
         * more data on that connection would cause problems.
         */
        if (errno == ECONNRESET ||
            errno == ECONNABORTED ||
#ifdef ETIMEDOUT
            errno == ETIMEDOUT ||
#endif /* ETIMEDOUT */
#ifdef ENOTCONN
            errno == ENOTCONN ||
#endif /* ENOTCONN */
#ifdef ESHUTDOWN
            errno == ESHUTDOWN ||
#endif /* ESHUTDOWNN */
            errno == EPIPE) {
          xerrno = errno;

          pr_trace_msg(trace_channel, 16,
            "disconnecting server (%s)", strerror(xerrno));
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "disconnecting server (%s)", strerror(xerrno));
          pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_CLIENT_EOF,
            strerror(xerrno));
        }

        return -1;

      } else {
        /* If we read zero bytes here, treat it as an EOF and hang up on
         * the uncommunicative client.
         */

        pr_trace_msg(trace_channel, 16, "%s",
          "disconnecting server (received EOF)");
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "disconnecting server (received EOF)");
        pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_CLIENT_EOF,
          NULL);
      }
    }

    session.total_raw_in += reqlen;
    if ((size_t) res == remainlen) {
      break;
    }

    if (flags & PROXY_SSH_PACKET_READ_FL_PESSIMISTIC) {
      pr_trace_msg(trace_channel, 20, "read %lu bytes, expected %lu bytes; "
        "pessimistically returning", (unsigned long) res,
        (unsigned long) remainlen);
      break;
    }

    pr_trace_msg(trace_channel, 20, "read %lu bytes, expected %lu bytes; "
      "reading more", (unsigned long) res, (unsigned long) remainlen);
    ptr = ((char *) ptr + res);
    remainlen -= res;
  }

  return reqlen;
}

static const char *get_msg_cmd_desc(unsigned char msg_type) {
  const char *desc;

  desc = proxy_ssh_packet_get_msg_type_desc(msg_type);
  if (strncmp(desc, "SSH_MSG_", 8) == 0) {
    desc += 8;
  }

  return desc;
}

void proxy_ssh_packet_log_cmd(struct proxy_ssh_packet *pkt, int from_frontend) {
  cmd_rec *cmd;
  const char *pkt_cmd, *pkt_note, *pkt_note_text;

  /* Get a short version of the packet type for our cmd_rec/logging. */
  pkt_cmd = get_msg_cmd_desc(proxy_ssh_packet_peek_msg_type(pkt));

  /* XXX What to use as the cmd_rec arg?  channel ID for CHANNEL_ commands;
   * what else?  Or maybe just hardcode "-" for now?
   */

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, pkt_cmd));
  cmd->arg = pstrdup(pkt->pool, "-");
  cmd->cmd_class = CL_MISC|CL_SSH;

  /* Add a note to indicate the destination/target for this packet, be it
   * "frontend" or "backend".
   */
  pkt_note = "proxy.ssh.direction";
  pkt_note_text = from_frontend == TRUE ? "backend" : "frontend";

  if (pr_table_add_dup(cmd->notes, pkt_note, pkt_note_text, 0) < 0) {
    int xerrno = errno;

    if (xerrno != EEXIST) {
      pr_trace_msg(trace_channel, 8,
        "error setting '%s' note: %s", pkt_note, strerror(xerrno));
    }
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(cmd->pool);
}

static void handle_global_request_msg(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess, int from_frontend) {
  unsigned char *buf, *ptr;
  uint32_t buflen, len;
  char *request_name;
  int want_reply;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Skip past the message type. */
  buf += sizeof(char);
  buflen -= sizeof(char);

  len = proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &request_name);

  if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
    /* For most GLOBAL_REQUEST packets, once we have completed our kex,
     * we proxy the packet to the frontend client.
     *
     * However, some GLOBAL_REQUEST types, such as the OpenSSH hostkey rotation
     * extension, is NOT suitable for proxying to the frontend client, for
     * the frontend client is concerned with our hostkeys, not the backend
     * hostkeys.
     */

    if (strcmp(request_name, "hostkeys-00@openssh.com") != 0) {
      proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);
      return;
    }
  }

  len = proxy_ssh_msg_read_bool(pkt->pool, &buf, &buflen, &want_reply);

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "server sent GLOBAL_REQUEST for '%s', %s", request_name,
    want_reply ? "denying" : "ignoring");

  if (want_reply == TRUE) {
    struct proxy_ssh_packet *pkt2;
    uint32_t bufsz;
    int res;

    buflen = bufsz = 1024;
    ptr = buf = palloc(pkt->pool, bufsz);

    len = proxy_ssh_msg_write_byte(&buf, &buflen,
      PROXY_SSH_MSG_REQUEST_FAILURE);

    pkt2 = proxy_ssh_packet_create(pkt->pool);
    pkt2->payload = ptr;
    pkt2->payload_len = len;

    res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt2);
    if (res < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error writing REQUEST_FAILURE message: %s", strerror(errno));
    }
  }

  destroy_pool(pkt->pool);
}

static void handle_server_alive_msg(struct proxy_ssh_packet *pkt,
    char msg_type) {
  const char *msg_desc;

  msg_desc = proxy_ssh_packet_get_msg_type_desc(msg_type);

  pr_trace_msg(trace_channel, 12,
    "server sent %s message, considering server alive", msg_desc);

  server_alive_count = 0;
  destroy_pool(pkt->pool);
}

static int handle_frontend_rekey(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {

  /* Reset the mod_sftp internal machinery, such that it handles this
   * frontend-requested rekey.
   */
  pr_trace_msg("proxy.ssh", 19,
    "frontend-initiated rekeying STARTED, resetting mod_sftp packet handler");

  proxy_ssh_packet_set_frontend_packet_handle(pkt->pool, NULL);

  /* Make sure to remove our listener for mod_sftp's read-loop, until such
   * time as the frontend rekeying completes.
   */
  pr_event_unregister(&proxy_module, "mod_sftp.ssh2.read-poll", NULL);

  /* Do NOT destroy this packet's pool! */
  errno = ENOSYS;
  return -1;
}

static void is_server_alive(conn_t *conn) {
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;
  struct proxy_ssh_packet *pkt;
  pool *tmp_pool;

  if (++server_alive_count > server_alive_max) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "ProxySFTPServerAlive threshold (max %u checks, %u sec interval) "
      "reached, disconnecting client", server_alive_max, server_alive_interval);
    PROXY_SSH_DISCONNECT_CONN(conn, PROXY_SSH_DISCONNECT_BY_APPLICATION,
      "server alive threshold reached");
  }

  tmp_pool = make_sub_pool(session.pool);

  bufsz = buflen = 64;
  ptr = buf = palloc(tmp_pool, bufsz);

  pr_trace_msg(trace_channel, 9,
    "sending GLOBAL_REQUEST (keepalive@proftpd.org)");

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_GLOBAL_REQUEST);
  len += proxy_ssh_msg_write_string(&buf, &buflen, "keepalive@proftpd.org");
  len += proxy_ssh_msg_write_bool(&buf, &buflen, TRUE);

  pkt = proxy_ssh_packet_create(tmp_pool);
  pkt->payload = ptr;
  pkt->payload_len = len;

  (void) proxy_ssh_packet_write(conn, pkt);
  destroy_pool(tmp_pool);
}

/* Attempt to read in a random amount of data (up to the maximum amount of
 * SSH2 packet data we support) from the socket.  This is used to help
 * mitigate the plaintext recovery attack described by CPNI-957037.
 *
 * Technically this is only necessary if a CBC mode cipher is in use, but
 * there should be no harm in using for any cipher; we are going to
 * disconnect the client after reading this data anyway.
 */
static void read_packet_discard(conn_t *conn) {
  size_t buflen;

  buflen = PROXY_SSH_MAX_PACKET_LEN -
    ((int) (PROXY_SSH_MAX_PACKET_LEN * (rand() / (RAND_MAX + 1.0))));

  pr_trace_msg(trace_channel, 3, "reading %lu bytes of data for discarding",
    (unsigned long) buflen);

  if (buflen > 0) {
    char buf[PROXY_SSH_MAX_PACKET_LEN];
    int flags;

    /* We don't necessarily want to wait for the entire random amount of data
     * to be read in.
     */
    flags = PROXY_SSH_PACKET_READ_FL_PESSIMISTIC;
    proxy_ssh_packet_conn_read(conn, buf, buflen, flags);
  }

  return;
}

static int read_packet_len(conn_t *conn, struct proxy_ssh_packet *pkt,
    unsigned char *buf, size_t *offset, size_t *buflen, size_t bufsz,
    int etm_mac) {
  uint32_t packet_len = 0, len = 0;
  size_t readsz;
  int res;
  unsigned char *ptr = NULL;

  readsz = proxy_ssh_cipher_get_read_block_size();

  /* Since the packet length may be encrypted, we need to read in the first
   * cipher_block_size bytes from the socket, and try to decrypt them, to know
   * how many more bytes there are in the packet.
   */

  if (pkt->aad_len > 0) {
    /* If we are dealing with an authenticated encryption algorithm, or an
     * ETM mode, read enough to include the AAD.  For ETM modes, leave the
     * first block for later.
     */
    if (etm_mac == TRUE) {
      readsz = pkt->aad_len;

    } else {
      readsz += pkt->aad_len;
    }
  }

  res = proxy_ssh_packet_conn_read(conn, buf, readsz, 0);
  if (res < 0) {
    return res;
  }

  len = res;
  if (proxy_ssh_cipher_read_data(pkt, buf, readsz, &ptr, &len) < 0) {
    return -1;
  }

  memmove(&packet_len, ptr, sizeof(uint32_t));
  pkt->packet_len = ntohl(packet_len);

  ptr += sizeof(uint32_t);
  len -= sizeof(uint32_t);

  /* Copy the remaining unencrypted bytes from the block into the given
   * buffer.
   */
  if (len > 0) {
    memmove(buf, ptr, len);
    *buflen = (size_t) len;
  }

  *offset = 0;
  return 0;
}

static int read_packet_padding_len(conn_t *conn, struct proxy_ssh_packet *pkt,
    unsigned char *buf, size_t *offset, size_t *buflen, size_t bufsz) {

  if (*buflen > sizeof(char)) {
    /* XXX Assume the data in the buffer is unencrypted, and thus usable. */
    memmove(&pkt->padding_len, buf + *offset, sizeof(char));

    /* Advance the buffer past the byte we just read off. */
    *offset += sizeof(char);
    *buflen -= sizeof(char);

    return 0;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "unable to read padding len: not enough data in buffer (%u bytes)",
    (unsigned int) *buflen);
  return -1;
}

static int read_packet_payload(conn_t *conn, struct proxy_ssh_packet *pkt,
    unsigned char *buf, size_t *offset, size_t *buflen, size_t bufsz,
    int etm_mac) {
  unsigned char *ptr = NULL;
  int res;
  uint32_t payload_len = pkt->payload_len, padding_len = 0, auth_len = 0,
    data_len, len = 0;

  /* For authenticated encryption or ETM modes, we will NOT have the
   * pkt->padding_len field yet.
   *
   * For authenticated encryption, we need to read in the first block, then
   * decrypt it, to find the padding.
   *
   * For ETM, we only want to find the payload and padding AFTER we've read
   * the entire (encrypted) payload, MAC'd it, THEN decrypt it.
   */

  if (pkt->padding_len > 0) {
    padding_len = pkt->padding_len;
  }

  auth_len = proxy_ssh_cipher_get_read_auth_size();

  if (payload_len + padding_len + auth_len == 0 &&
      etm_mac == FALSE) {
    return 0;
  }

  if (payload_len > 0) {
    /* We don't want to reject the packet outright yet; but we can ignore
     * the payload data we're going to read in.  This packet will fail
     * eventually anyway.
     */
    if (payload_len > PROXY_SSH_PACKET_MAX_PAYLOAD_LEN) {
      pr_trace_msg(trace_channel, 20,
        "payload len (%lu bytes) exceeds max payload len (%lu), "
        "ignoring payload", (unsigned long) payload_len,
        (unsigned long) PROXY_SSH_PACKET_MAX_PAYLOAD_LEN);

      pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "server sent buggy/malicious packet payload length, ignoring");

      errno = EPERM;
      return -1;
    }

    pkt->payload = pcalloc(pkt->pool, payload_len);
  }

  /* If there's data in the buffer we received, it's probably already part
   * of the payload, unencrypted.  That will leave the remaining payload
   * data, if any, to be read in and decrypted.
   */
  if (*buflen > 0) {
    if (*buflen < payload_len) {
      memmove(pkt->payload, buf + *offset, *buflen);

      payload_len -= *buflen;
      *offset = 0;
      *buflen = 0;

    } else {
      /* There's enough already for the payload length.  Nice. */
      memmove(pkt->payload, buf + *offset, payload_len);

      *offset += payload_len;
      *buflen -= payload_len;
      payload_len = 0;
    }
  }

  /* The padding length is required to be greater than zero.  However, we may
   * not know the padding length yet, as for authenticated encryption or ETM
   * modes.
   */
  if (padding_len > 0) {
    pkt->padding = pcalloc(pkt->pool, padding_len);
  }

  /* If there's data in the buffer we received, it's probably already part
   * of the padding, unencrypted.  That will leave the remaining padding
   * data, if any, to be read in and decrypted.
   */
  if (*buflen > 0 &&
      padding_len > 0) {
    if (*buflen < padding_len) {
      memmove(pkt->padding, buf + *offset, *buflen);

      padding_len -= *buflen;
      *offset = 0;
      *buflen = 0;

    } else {
      /* There's enough already for the padding length.  Nice. */
      memmove(pkt->padding, buf + *offset, padding_len);

      *offset += padding_len;
      *buflen -= padding_len;
      padding_len = 0;
    }
  }

  if (etm_mac == TRUE) {
    data_len = pkt->packet_len;

  } else {
    data_len = payload_len + padding_len + auth_len;
  }

  if (data_len == 0) {
    return 0;
  }

  if (data_len > bufsz) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "remaining packet data (%lu bytes) exceeds packet buffer size (%lu "
      "bytes)", (unsigned long) data_len, (unsigned long) bufsz);
    errno = EPERM;
    return -1;
  }

  res = proxy_ssh_packet_conn_read(conn, buf + *offset, data_len, 0);
  if (res < 0) {
    return res;
  }
 
  len = res;

  /* For ETM modes, we do NOT want to decrypt the data yet; we need to read/
   * compare MACs first.
   */

  if (etm_mac == TRUE) {
    *buflen = res;

  } else {
    if (proxy_ssh_cipher_read_data(pkt, buf + *offset, data_len, &ptr,
        &len) < 0) {
      return -1;
    }

    if (payload_len > 0) {
      memmove(pkt->payload + (pkt->payload_len - payload_len), ptr,
        payload_len);
    }

    memmove(pkt->padding + (pkt->padding_len - padding_len), ptr + payload_len,
      padding_len);
  }

  return 0;
}

static int read_packet_mac(conn_t *conn, struct proxy_ssh_packet *pkt,
    unsigned char *buf) {
  int res;
  uint32_t mac_len = pkt->mac_len;

  if (mac_len == 0) {
    return 0;
  }

  res = proxy_ssh_packet_conn_read(conn, buf, mac_len, 0);
  if (res < 0) {
    return res;
  }

  pkt->mac = palloc(pkt->pool, pkt->mac_len);
  memmove(pkt->mac, buf, res);

  return 0;
}

struct proxy_ssh_packet *proxy_ssh_packet_create(pool *p) {
  pool *tmp_pool;
  struct proxy_ssh_packet *pkt;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Proxy SSH2 packet pool");

  pkt = pcalloc(tmp_pool, sizeof(struct proxy_ssh_packet));
  pkt->pool = tmp_pool;
  pkt->m = &proxy_module;
  pkt->packet_len = 0;
  pkt->payload = NULL;
  pkt->payload_len = 0;
  pkt->padding_len = 0;
  pkt->aad = NULL;
  pkt->aad_len = 0;

  return pkt;
}

char proxy_ssh_packet_get_msg_type(struct proxy_ssh_packet *pkt) {
  char msg_type;

  memmove(&msg_type, pkt->payload, sizeof(char));
  pkt->payload += sizeof(char);
  pkt->payload_len -= sizeof(char);

  return msg_type;
}

char proxy_ssh_packet_peek_msg_type(const struct proxy_ssh_packet *pkt) {
  char msg_type;

  memmove(&msg_type, pkt->payload, sizeof(char));
  return msg_type;
}

const char *proxy_ssh_packet_get_msg_type_desc(unsigned char msg_type) {
  switch (msg_type) {
    case PROXY_SSH_MSG_DISCONNECT:
      return "SSH_MSG_DISCONNECT";

    case PROXY_SSH_MSG_IGNORE:
      return "SSH_MSG_IGNORE";

    case PROXY_SSH_MSG_UNIMPLEMENTED:
      return "SSH_MSG_UNIMPLEMENTED";

    case PROXY_SSH_MSG_DEBUG:
      return "SSH_MSG_DEBUG";

    case PROXY_SSH_MSG_SERVICE_REQUEST:
      return "SSH_MSG_SERVICE_REQUEST";

    case PROXY_SSH_MSG_SERVICE_ACCEPT:
      return "SSH_MSG_SERVICE_ACCEPT";

    case PROXY_SSH_MSG_EXT_INFO:
      return "SSH_MSG_EXT_INFO";

    case PROXY_SSH_MSG_KEXINIT:
      return "SSH_MSG_KEXINIT";

    case PROXY_SSH_MSG_NEWKEYS:
      return "SSH_MSG_NEWKEYS";

    case PROXY_SSH_MSG_KEX_DH_INIT:
      return "SSH_MSG_KEX_DH_INIT";

    case PROXY_SSH_MSG_KEX_DH_REPLY:
      return "SSH_MSG_KEX_DH_REPLY";

    case PROXY_SSH_MSG_KEX_DH_GEX_INIT:
      return "SSH_MSG_KEX_DH_GEX_INIT";

    case PROXY_SSH_MSG_KEX_DH_GEX_REPLY:
      return "SSH_MSG_KEX_DH_GEX_REPLY";

    case PROXY_SSH_MSG_KEX_DH_GEX_REQUEST:
      return "SSH_MSG_KEX_DH_GEX_REQUEST";

    case PROXY_SSH_MSG_USER_AUTH_REQUEST:
      return "SSH_MSG_USERAUTH_REQUEST";

    case PROXY_SSH_MSG_USER_AUTH_FAILURE:
      return "SSH_MSG_USERAUTH_FAILURE";

    case PROXY_SSH_MSG_USER_AUTH_SUCCESS:
      return "SSH_MSG_USERAUTH_SUCCESS";

    case PROXY_SSH_MSG_USER_AUTH_BANNER:
      return "SSH_MSG_USERAUTH_BANNER";

    case PROXY_SSH_MSG_USER_AUTH_PASSWD:
      return "SSH_MSG_USERAUTH_PASSWD";

    case PROXY_SSH_MSG_USER_AUTH_INFO_RESP:
      return "SSH_MSG_USERAUTH_INFO_RESP";

    case PROXY_SSH_MSG_GLOBAL_REQUEST:
      return "SSH_MSG_GLOBAL_REQUEST";

    case PROXY_SSH_MSG_REQUEST_SUCCESS:
      return "SSH_MSG_REQUEST_SUCCESS";

    case PROXY_SSH_MSG_REQUEST_FAILURE:
      return "SSH_MSG_REQUEST_FAILURE";

    case PROXY_SSH_MSG_CHANNEL_OPEN:
      return "SSH_MSG_CHANNEL_OPEN";

    case PROXY_SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";

    case PROXY_SSH_MSG_CHANNEL_OPEN_FAILURE:
      return "SSH_MSG_CHANNEL_OPEN_FAILURE";

    case PROXY_SSH_MSG_CHANNEL_WINDOW_ADJUST:
      return "SSH_MSG_CHANNEL_WINDOW_ADJUST";

    case PROXY_SSH_MSG_CHANNEL_DATA:
      return "SSH_MSG_CHANNEL_DATA";

    case PROXY_SSH_MSG_CHANNEL_EXTENDED_DATA:
      return "SSH_MSG_CHANNEL_EXTENDED_DATA";

    case PROXY_SSH_MSG_CHANNEL_EOF:
      return "SSH_MSG_CHANNEL_EOF";

    case PROXY_SSH_MSG_CHANNEL_CLOSE:
      return "SSH_MSG_CHANNEL_CLOSE";

    case PROXY_SSH_MSG_CHANNEL_REQUEST:
      return "SSH_MSG_CHANNEL_REQUEST";

    case PROXY_SSH_MSG_CHANNEL_SUCCESS:
      return "SSH_MSG_CHANNEL_SUCCESS";

    case PROXY_SSH_MSG_CHANNEL_FAILURE:
      return "SSH_MSG_CHANNEL_FAILURE";
  }

  return "(unknown)";
}

int proxy_ssh_packet_get_poll_attempts(unsigned int *nattempts) {
  if (nattempts == NULL) {
    errno = EINVAL;
    return -1;
  }

  *nattempts = poll_attempts;
  return 0;
}

int proxy_ssh_packet_set_poll_attempts(unsigned int nattempts) {
  if (nattempts == 0) {
    poll_attempts = DEFAULT_POLL_ATTEMPTS;

  } else {
    poll_attempts = nattempts;
  }

  return 0;
}

int proxy_ssh_packet_get_poll_timeout(int *secs, unsigned long *ms) {
  if (secs == NULL ||
      ms == NULL) {
    errno = EINVAL;
    return -1;
  }

  *secs = poll_timeout_secs;
  *ms = poll_timeout_ms;
  return 0;
}

int proxy_ssh_packet_set_poll_timeout(int secs, unsigned long ms) {
  if (secs < 0) {
    poll_timeout_secs = -1;
    poll_timeout_ms = 0;

  } else {
    poll_timeout_secs = secs;
    poll_timeout_ms = ms;
  }

  return 0;
}

int proxy_ssh_packet_set_server_alive(unsigned int max, unsigned int interval) {
  server_alive_max = max;
  server_alive_interval = interval;
  return 0;
}

static void reset_timers(void) {
  int res;

  /* Handle the case where timers might be being processed at the moment. */

  res = pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
  while (res < 0) {
   if (errno == EINTR) {
      pr_signals_handle();
      res = pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
    }

    break;
  }

  res = pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
  while (res < 0) {
   if (errno == EINTR) {
      pr_signals_handle();
      res = pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
    }

    break;
  }
}

int proxy_ssh_packet_read(conn_t *conn, struct proxy_ssh_packet *pkt) {
  unsigned char buf[PROXY_SSH_MAX_PACKET_LEN];
  size_t buflen, bufsz = PROXY_SSH_MAX_PACKET_LEN, offset = 0, auth_len = 0;
  int etm_mac = FALSE;

  pr_session_set_idle();

  auth_len = proxy_ssh_cipher_get_read_auth_size();
  if (auth_len > 0) {
    /* Authenticated encryption ciphers do not encrypt the packet length,
     * and instead use it as Additional Authenticated Data (AAD).
     */
    pkt->aad_len = sizeof(uint32_t);
  }

  etm_mac = proxy_ssh_mac_is_read_etm();
  if (etm_mac == TRUE) {
    /* ETM modes do not encrypt the packet length, and instead use it as
     * Additional Authenticated Data (AAD).
     */
    pkt->aad_len = sizeof(uint32_t);
  }

  while (TRUE) {
    uint32_t encrypted_datasz, req_blocksz;

    pr_signals_handle();

    /* This is in a while loop in order to consume any debug/ignore
     * messages which the client may send.
     */

    buflen = 0;
    memset(buf, 0, sizeof(buf));

    if (read_packet_len(conn, pkt, buf, &offset, &buflen, bufsz, etm_mac) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "no data to be read from socket %d", conn->rfd);
      return -1;
    }

    pr_trace_msg(trace_channel, 20, "SSH2 packet len = %lu bytes",
      (unsigned long) pkt->packet_len);

    /* In order to mitigate the plaintext recovery attack described in
     * CPNI-957037:
     *
     *  http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt
     *
     * we do NOT check that the packet length is sane here; we have to
     * wait until the MAC check succeeds.
     */
 
    /* Note: Checking for the RFC4253-recommended minimum packet length
     * of 16 bytes causes KEX to fail (the NEWKEYS packet is 12 bytes).
     * Thus that particular check is omitted.
     */

    if (etm_mac == FALSE) {
      if (read_packet_padding_len(conn, pkt, buf, &offset, &buflen,
          bufsz) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "no data to be read from socket %d", conn->rfd);
        read_packet_discard(conn);
        return -1;
      }

      pr_trace_msg(trace_channel, 20, "SSH2 packet padding len = %u bytes",
        (unsigned int) pkt->padding_len);

      pkt->payload_len = (pkt->packet_len - pkt->padding_len - 1);
    }

    pr_trace_msg(trace_channel, 20, "SSH2 packet payload len = %lu bytes",
      (unsigned long) pkt->payload_len);

    /* Read both payload and padding, since we may need to have both before
     * decrypting the data.
     */
    if (read_packet_payload(conn, pkt, buf, &offset, &buflen, bufsz,
        etm_mac) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to read payload from socket %d", conn->rfd);
      read_packet_discard(conn);
      return -1;
    }

    pkt->mac_len = proxy_ssh_mac_get_block_size();
    pr_trace_msg(trace_channel, 20, "SSH2 packet MAC len = %lu bytes",
      (unsigned long) pkt->mac_len);

    if (etm_mac == TRUE) {
      unsigned char *buf2;
      size_t buflen2, bufsz2;

      bufsz2 = buflen2 = pkt->mac_len;
      buf2 = pcalloc(pkt->pool, bufsz2);

      /* The MAC routines assume the presence of the necessary data in
       * pkt->payload, so we temporarily put our encrypted packet data there.
       */
      pkt->payload = buf;
      pkt->payload_len = buflen;

      pkt->seqno = packet_server_seqno;

      if (read_packet_mac(conn, pkt, buf2) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to read MAC from socket %d", conn->rfd);
        read_packet_discard(conn);
        return -1;
      }

      if (proxy_ssh_mac_read_data(pkt) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to verify MAC on packet from socket %d", conn->rfd);

        /* In order to further mitigate CPNI-957037, we will read in a
         * random amount of more data from the network before closing
         * the connection.
         */
        read_packet_discard(conn);
        return -1;
      }

      /* Now we can decrypt the payload; `buf/buflen` are the encrypted
       * packet from read_packet_payload().
       */
      bufsz2 = buflen2 = PROXY_SSH_MAX_PACKET_LEN;
      buf2 = pcalloc(pkt->pool, bufsz2);

      if (proxy_ssh_cipher_read_data(pkt, buf, buflen, &buf2,
          (uint32_t *) &buflen2) < 0) {
        return -1;
      }

      offset = 0;

      if (read_packet_padding_len(conn, pkt, buf2, &offset, &buflen2,
          bufsz2) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "no data to be read from socket %d", conn->rfd);
        read_packet_discard(conn);
        return -1;
      }

      pr_trace_msg(trace_channel, 20, "SSH2 packet padding len = %u bytes",
        (unsigned int) pkt->padding_len);

      pkt->payload_len = (pkt->packet_len - pkt->padding_len - 1);
      if (pkt->payload_len > 0) {
        pkt->payload = pcalloc(pkt->pool, pkt->payload_len);
        memmove(pkt->payload, buf2 + offset, pkt->payload_len);
      }

      pkt->padding = pcalloc(pkt->pool, pkt->padding_len);
      memmove(pkt->padding, buf2 + offset + pkt->payload_len, pkt->padding_len);

    } else {
      memset(buf, 0, sizeof(buf));

      if (read_packet_mac(conn, pkt, buf) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to read MAC from socket %d", conn->rfd);
        read_packet_discard(conn);
        return -1;
      }

      pkt->seqno = packet_server_seqno;
      if (proxy_ssh_mac_read_data(pkt) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to verify MAC on packet from socket %d", conn->rfd);

        /* In order to further mitigate CPNI-957037, we will read in a
         * random amount of more data from the network before closing
         * the connection.
         */
        read_packet_discard(conn);
        return -1;
      }
    }

    /* Now that the MAC check has passed, we can do sanity checks based
     * on the fields we have read in, and trust that those fields are
     * correct.
     */

    if (pkt->packet_len < 5) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "packet length too short (%lu), less than minimum packet length (5)",
        (unsigned long) pkt->packet_len);
      read_packet_discard(conn);
      return -1;
    }

    if (pkt->packet_len > PROXY_SSH_MAX_PACKET_LEN) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "packet length too long (%lu), exceeds maximum packet length (%lu)",
        (unsigned long) pkt->packet_len,
        (unsigned long) PROXY_SSH_MAX_PACKET_LEN);
      read_packet_discard(conn);
      return -1;
    }

    /* Per Section 6 of RFC4253, the minimum padding length is 4, the
     * maximum padding length is 255.
     */

    if (pkt->padding_len < PROXY_SSH_MIN_PADDING_LEN) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "padding length too short (%u), less than minimum padding length (%u)",
        (unsigned int) pkt->padding_len,
        (unsigned int) PROXY_SSH_MIN_PADDING_LEN);
      read_packet_discard(conn);
      return -1;
    }

    if (pkt->padding_len > pkt->packet_len) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "padding length too long (%u), exceeds packet length (%lu)",
        (unsigned int) pkt->padding_len, (unsigned long) pkt->packet_len);
      read_packet_discard(conn);
      return -1;
    }

    /* From RFC4253, Section 6:
     *
     * random padding
     *   Arbitrary-length padding, such that the total length of
     *   (packet_length || padding_length || payload || random padding)
     *   is a multiple of the cipher block size or 8, whichever is
     *   larger.
     *
     * Thus packet_len + sizeof(uint32_t) (for the actual packet length field)
     * is that "(packet_length || padding_length || payload || padding)"
     * value.
     */

    req_blocksz = MAX(8, proxy_ssh_cipher_get_read_block_size());
    encrypted_datasz = pkt->packet_len + sizeof(uint32_t);

    /* If AAD bytes are present, they are not encrypted. */
    if (pkt->aad_len > 0) {
      encrypted_datasz -= pkt->aad_len;
    }

    if (encrypted_datasz % req_blocksz != 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "packet length (%lu) not a multiple of the required block size (%lu)",
        (unsigned long) encrypted_datasz, (unsigned long) req_blocksz);
      read_packet_discard(conn);
      return -1;
    }

    /* XXX I'm not so sure about this check; we SHOULD have a maximum
     * payload check, but using the max packet length check for the payload
     * length seems awkward.
     */
    if (pkt->payload_len > PROXY_SSH_MAX_PACKET_LEN) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "payload length too long (%lu), exceeds maximum payload length (%lu) "
        "(packet len %lu, padding len %u)", (unsigned long) pkt->payload_len,
        (unsigned long) PROXY_SSH_MAX_PACKET_LEN,
        (unsigned long) pkt->packet_len, (unsigned int) pkt->padding_len);
      read_packet_discard(conn);
      return -1;
    }

    /* Sanity checks passed; move on to the reading the packet payload. */
    if (proxy_ssh_compress_read_data(pkt) < 0) {
      return -1;
    }

    packet_server_seqno++;

    reset_timers();
    break;
  }

  return 0;
}

static int write_packet_padding(struct proxy_ssh_packet *pkt) {
  register unsigned int i;
  uint32_t packet_len = 0;
  size_t blocksz;

  blocksz = proxy_ssh_cipher_get_write_block_size();

  /* RFC 4253, section 6, says that the random padding is calculated
   * as follows:
   *
   *  random padding
   *     Arbitrary-length padding, such that the total length of
   *     (packet_length || padding_length || payload || random padding)
   *     is a multiple of the cipher block size or 8, whichever is
   *     larger.  There MUST be at least four bytes of padding.  The
   *     padding SHOULD consist of random bytes.  The maximum amount of
   *     padding is 255 bytes.
   *
   * This means:
   *
   *  packet len = sizeof(packet_len field) + sizeof(padding_len field) +
   *    sizeof(payload field) + sizeof(padding field)
   */

  packet_len = sizeof(uint32_t) + sizeof(char) + pkt->payload_len;
  if (pkt->aad_len > 0) {
    /* Packet length is not encrypted for encrypted authentication, or
     * Encrypt-Then-MAC modes.
     */
    packet_len -= pkt->aad_len;
  }

  pkt->padding_len = (char) (blocksz - (packet_len % blocksz));
  if (pkt->padding_len < 4) {
    /* As per RFC, there must be at least 4 bytes of padding.  So if the
     * above calculated less, then we need to add another block's worth
     * of padding.
     */
    pkt->padding_len += blocksz;
  }

  pkt->padding = palloc(pkt->pool, pkt->padding_len);

  /* Fill the padding with pseudo-random data. */
  for (i = 0; i < pkt->padding_len; i++) {
    pkt->padding[i] = (unsigned char) pr_random_next(0, UCHAR_MAX);
  }

  return 0;
}

#define PROXY_SSH_PACKET_IOVSZ		12
static struct iovec packet_iov[PROXY_SSH_PACKET_IOVSZ];
static unsigned int packet_niov = 0;

int proxy_ssh_packet_send(conn_t *conn, struct proxy_ssh_packet *pkt) {
  unsigned char buf[PROXY_SSH_MAX_PACKET_LEN * 2], msg_type;
  size_t buflen = 0, bufsz = PROXY_SSH_MAX_PACKET_LEN;
  uint32_t packet_len = 0, auth_len = 0;
  int res, write_len = 0, block_alarms = FALSE, etm_mac = FALSE;

  /* No interruptions, please.  If, for example, we are interrupted here
   * by the SFTPRekey timer, that timer will cause this same function to
   * be called -- but the packet_iov/packet_niov values will be different.
   * Which in turn leads to malformed packets, and thus badness (Bug#4216).
   */

  if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH) {
    block_alarms = TRUE;
  }

  if (block_alarms == TRUE) {
    pr_alarms_block();
  }

  auth_len = proxy_ssh_cipher_get_write_auth_size();
  if (auth_len > 0) {
    /* Authenticated encryption ciphers do not encrypt the packet length,
     * and instead use it as Additional Authenticated Data (AAD).
     */
    pkt->aad_len = sizeof(uint32_t);
    pkt->aad = NULL;
  }

  etm_mac = proxy_ssh_mac_is_write_etm();
  if (etm_mac == TRUE) {
    /* Encrypt-Then-Mac modes do not encrypt the packet length; treat it
     * as Additional Authenticated Data (AAD).
     */
    pkt->aad_len = sizeof(uint32_t);
    pkt->aad = NULL;
  }

  /* Clear the iovec array before sending the data, if possible. */
  if (packet_niov == 0) {
    memset(packet_iov, 0, sizeof(packet_iov));
  }

  msg_type = proxy_ssh_packet_peek_msg_type(pkt);

  if (proxy_ssh_compress_write_data(pkt) < 0) {
    int xerrno = errno;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }

    errno = xerrno;
    return -1;
  }

  if (write_packet_padding(pkt) < 0) {
    int xerrno = errno;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }

    errno = xerrno;
    return -1;
  }

  /* Packet length: padding len + payload + padding */
  pkt->packet_len = packet_len = sizeof(char) + pkt->payload_len +
    pkt->padding_len;

  pkt->seqno = packet_client_seqno;

  memset(buf, 0, sizeof(buf));
  buflen = bufsz;

  if (etm_mac == TRUE) {
    if (proxy_ssh_cipher_write_data(pkt, buf, &buflen) < 0) {
      int xerrno = errno;

      if (block_alarms == TRUE) {
        pr_alarms_unblock();
      }

      errno = xerrno;
      return -1;
    }

    /* Once we have the encrypted data, overwrite the plaintext packet payload
     * with it, so that the MAC is calculated from the encrypted data.
     */
    pkt->payload = buf;
    pkt->payload_len = buflen;

    if (proxy_ssh_mac_write_data(pkt) < 0) {
      int xerrno = errno;

      if (block_alarms == TRUE) {
        pr_alarms_unblock();
      }

      errno = xerrno;
      return -1;
    }

  } else {
    if (proxy_ssh_mac_write_data(pkt) < 0) {
      int xerrno = errno;

      if (block_alarms == TRUE) {
        pr_alarms_unblock();
      }

      errno = xerrno;
      return -1;
    }

    if (proxy_ssh_cipher_write_data(pkt, buf, &buflen) < 0) {
      int xerrno = errno;

      if (block_alarms == TRUE) {
        pr_alarms_unblock();
      }

      errno = xerrno;
      return -1;
    }
  }

  if (buflen > 0) {
    /* We have encrypted data, which means we don't need as many of the
     * iovec slots as for unencrypted data.
     */

    if (sent_version_id == FALSE) {
      packet_iov[packet_niov].iov_base = (void *) version_id;
      packet_iov[packet_niov].iov_len = strlen(version_id);
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }

    if (pkt->aad_len > 0) {
      pr_trace_msg(trace_channel, 20, "sending %lu bytes of packet AAD data",
        (unsigned long) pkt->aad_len);
      packet_iov[packet_niov].iov_base = (void *) pkt->aad;
      packet_iov[packet_niov].iov_len = pkt->aad_len;
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }

    pr_trace_msg(trace_channel, 20, "sending %lu bytes of packet payload data",
      (unsigned long) buflen);
    packet_iov[packet_niov].iov_base = (void *) buf;
    packet_iov[packet_niov].iov_len = buflen;
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    if (pkt->mac_len > 0) {
      pr_trace_msg(trace_channel, 20, "sending %lu bytes of packet MAC data",
        (unsigned long) pkt->mac_len);
      packet_iov[packet_niov].iov_base = (void *) pkt->mac;
      packet_iov[packet_niov].iov_len = pkt->mac_len;
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }

  } else {
    /* Don't forget to convert the packet len to network-byte order, since
     * this length is sent over the wire.
     */
    packet_len = htonl(packet_len);

    if (sent_version_id == FALSE) {
      packet_iov[packet_niov].iov_base = (void *) version_id;
      packet_iov[packet_niov].iov_len = strlen(version_id);
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }

    packet_iov[packet_niov].iov_base = (void *) &packet_len;
    packet_iov[packet_niov].iov_len = sizeof(uint32_t);
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    packet_iov[packet_niov].iov_base = (void *) &(pkt->padding_len);
    packet_iov[packet_niov].iov_len = sizeof(char);
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    packet_iov[packet_niov].iov_base = (void *) pkt->payload;
    packet_iov[packet_niov].iov_len = pkt->payload_len;
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    packet_iov[packet_niov].iov_base = (void *) pkt->padding;
    packet_iov[packet_niov].iov_len = pkt->padding_len;
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    if (pkt->mac_len > 0) {
      packet_iov[packet_niov].iov_base = (void *) pkt->mac;
      packet_iov[packet_niov].iov_len = pkt->mac_len;
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }
  }

  if (proxy_ssh_packet_conn_poll(conn, PROXY_SSH_PACKET_IO_WRITE) < 0) {
    int xerrno = errno;

    /* Socket not writable?  Clear the array, and try again. */
    memset(packet_iov, 0, sizeof(packet_iov));
    packet_niov = 0;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }

    errno = xerrno;
    return -1;
  }

  /* The socket we accept is blocking, thus there's no need to handle
   * EAGAIN/EWOULDBLOCK errors.
   */
  res = writev(conn->wfd, packet_iov, packet_niov);
  while (res < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();

      res = writev(conn->wfd, packet_iov, packet_niov);
      continue;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error writing packet (fd %d): %s", conn->wfd, strerror(xerrno));

    if (xerrno == ECONNRESET ||
        xerrno == ECONNABORTED ||
        xerrno == EPIPE) {

      if (block_alarms == TRUE) {
        pr_alarms_unblock();
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "disconnecting server (%s)", strerror(xerrno));
      pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
        strerror(xerrno));
    }

    /* Always clear the iovec array after sending the data. */
    memset(packet_iov, 0, sizeof(packet_iov));
    packet_niov = 0;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }

    errno = xerrno;
    return -1;
  }

  session.total_raw_out += res;

  /* Always clear the iovec array after sending the data. */
  memset(packet_iov, 0, sizeof(packet_iov));
  packet_niov = 0;

  if (sent_version_id == FALSE) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "sent client version '%s'", client_version);
    sent_version_id = TRUE;
  }

  packet_client_seqno++;

  pr_trace_msg(trace_channel, 3, "sent %s (%d) packet (%d bytes)",
    proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type, res);

  if (block_alarms == TRUE) {
    /* Now that we've written out the packet, we can be interrupted again. */
    pr_alarms_unblock();
  }

  reset_timers();
  return 0;
}

int proxy_ssh_packet_write(conn_t *conn, struct proxy_ssh_packet *pkt) {
  return proxy_ssh_packet_send(conn, pkt);
}

int proxy_ssh_packet_write_frontend(conn_t *conn,
    struct proxy_ssh_packet *pkt) {
  if (frontend_packet_write == NULL) {
    errno = ENOSYS;
    return -1;
  }

  /* Make sure that any backend AAD ciphers/data are not leaked through to
   * the frontend IO routines.
   */
  if (pkt->aad_len > 0) {
    pkt->aad_len = 0;
    pkt->aad = NULL;
  }

  return (frontend_packet_write)(conn->wfd, pkt);
}

void proxy_ssh_packet_handle_debug(struct proxy_ssh_packet *pkt) {
  register unsigned int i;
  int always_display;
  char *text, *lang;
  uint32_t len;

  len = proxy_ssh_msg_read_bool(pkt->pool, &pkt->payload, &pkt->payload_len,
    &always_display);
  len = proxy_ssh_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len,
    &text);

  /* Ignore the language tag. */
  (void) proxy_ssh_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len,
    &lang);

  /* Sanity-check the message for control (and other non-printable)
   * characters.
   */
  for (i = 0; i < strlen(text); i++) {
    if (PR_ISCNTRL(text[i]) ||
        !PR_ISPRINT(text[i])) {
      text[i] = '?';
    }
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "server sent SSH_MSG_DEBUG message '%s'", text);

  if (always_display == TRUE) {
    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": server sent SSH_MSG_DEBUG message '%s'", text);
  }

  destroy_pool(pkt->pool);
}

void proxy_ssh_packet_handle_disconnect(struct proxy_ssh_packet *pkt) {
  register unsigned int i;
  char *explain = NULL, *lang = NULL;
  const char *reason_text = NULL;
  uint32_t reason_code, len;

  len = proxy_ssh_msg_read_int(pkt->pool, &pkt->payload, &pkt->payload_len,
    &reason_code);
  reason_text = proxy_ssh_disconnect_get_text(reason_code);
  if (reason_text == NULL) {
    pr_trace_msg(trace_channel, 9,
      "server sent unknown disconnect reason code %lu",
      (unsigned long) reason_code);
    reason_text = "Unknown reason code";
  }

  len = proxy_ssh_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len,
    &explain);

  /* Not all clients send a language tag. */
  if (pkt->payload_len > 0) {
    len = proxy_ssh_msg_read_string(pkt->pool, &pkt->payload,
      &pkt->payload_len, &lang);
  }

  /* Sanity-check the message for control characters. */
  for (i = 0; i < strlen(explain); i++) {
    if (PR_ISCNTRL(explain[i])) {
      explain[i] = '?';
    }
  }

  /* XXX Use the language tag somehow, if provided. */
  if (lang != NULL) {
    pr_trace_msg(trace_channel, 19, "server sent DISCONNECT language tag '%s'",
      lang);
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "server at %s sent SSH_DISCONNECT message: %s (%s)",
    pr_netaddr_get_ipstr(session.c->remote_addr), explain, reason_text);
  pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_CLIENT_QUIT, explain);
}

void proxy_ssh_packet_handle_ext_info(struct proxy_ssh_packet *pkt) {
  register unsigned int i;
  unsigned char *buf;
  uint32_t buflen, ext_count = 0;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &ext_count);
  pr_trace_msg(trace_channel, 9, "server sent EXT_INFO with %lu %s",
    (unsigned long) ext_count, ext_count != 1 ? "extensions" : "extension");

  for (i = 0; i < ext_count; i++) {
    unsigned char *ext_data = NULL;
    char *ext_name = NULL;
    uint32_t ext_datalen = 0;

    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &ext_name);
    proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &ext_datalen);
    proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, ext_datalen, &ext_data);

    pr_trace_msg(trace_channel, 9,
      "server extension: %s (value %lu bytes)", ext_name,
      (unsigned long) ext_datalen);
  }

  destroy_pool(pkt->pool);
}

void proxy_ssh_packet_handle_ignore(struct proxy_ssh_packet *pkt) {
  char *text;
  size_t text_len;
  uint32_t len;

  len = proxy_ssh_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len,
    &text);
  text_len = strlen(text);

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "server sent SSH_MSG_IGNORE message (%u bytes)", (unsigned int) text_len);

  destroy_pool(pkt->pool);
}

void proxy_ssh_packet_handle_unimplemented(struct proxy_ssh_packet *pkt) {
  uint32_t seqno, len;

  len = proxy_ssh_msg_read_int(pkt->pool, &pkt->payload, &pkt->payload_len,
    &seqno);

  pr_trace_msg(trace_channel, 7, "received SSH_MSG_UNIMPLEMENTED for "
    "packet #%lu", (unsigned long) seqno);

  destroy_pool(pkt->pool);
}

int proxy_ssh_packet_proxied(const struct proxy_session *proxy_sess,
    struct proxy_ssh_packet *pkt, int from_frontend) {
  int res, xerrno = 0;
  char msg_type;

  msg_type = proxy_ssh_packet_peek_msg_type(pkt);

  if (from_frontend == TRUE) {
    /* Write the packet to the backend. */

    pr_trace_msg(trace_channel, 17,
      "proxying %s (%d) packet from frontend to backend",
       proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
    res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
    xerrno = errno;

    if (res < 0) {
      pr_trace_msg(trace_channel, 2,
        "error proxying packet from frontend to backend: %s", strerror(xerrno));
    }

  } else {
    pr_trace_msg(trace_channel, 17,
      "proxying %s (%d) packet from backend to frontend",
       proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
    res = proxy_ssh_packet_write_frontend(proxy_sess->frontend_ctrl_conn, pkt);
    xerrno = errno;

    if (res < 0) {
      if (xerrno != ENOSYS) {
        pr_trace_msg(trace_channel, 2,
          "error proxying packet from backend to frontend: %s",
          strerror(xerrno));

      } else {
        /* Ignore the case where we are told not to write packets to the
         * frontend client.
         */
        res = 0;
        xerrno = errno = 0;
      }
    }
  }

  errno = xerrno;
  return res;
}

int proxy_ssh_packet_handle(void *data) {
  const struct proxy_session *proxy_sess;
  struct proxy_ssh_packet *pkt;
  unsigned char msg_type;
  int from_frontend = FALSE;

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);

  pkt = data;

  /* We only peek at the message type here, so that we can properly proxy
   * the entire packet if needed.
   */
  msg_type = proxy_ssh_packet_peek_msg_type(pkt);

  pr_trace_msg(trace_channel, 20, "received %s (%d) packet (from mod_%s.c)",
    proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type,
    pkt->m->name);

  /* Note: Some of the SSH messages will be handled regardless of the
   * proxy_sess_state flags; this is intentional, and is the way that
   * the protocol is supposed to work.
   */

  if (pkt->m == &proxy_module) {
    from_frontend = FALSE;

  } else {
    from_frontend = TRUE;
  }

  /* Create and dispatch cmd_recs for frontend/backend SSH packets, in order to
   * support ExtendedLog logging.
   */
  proxy_ssh_packet_log_cmd(pkt, from_frontend);

  switch (msg_type) {
    case PROXY_SSH_MSG_DEBUG:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
        proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);

      } else {
        (void) proxy_ssh_packet_get_msg_type(pkt);
        proxy_ssh_packet_handle_debug(pkt);
      }
      break;

    case PROXY_SSH_MSG_DISCONNECT:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
        proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);

      } else {
        (void) proxy_ssh_packet_get_msg_type(pkt);
        proxy_ssh_packet_handle_disconnect(pkt);
      }
      break;

    case PROXY_SSH_MSG_GLOBAL_REQUEST:
      handle_global_request_msg(pkt, proxy_sess, from_frontend);
      break;

    case PROXY_SSH_MSG_REQUEST_SUCCESS:
    case PROXY_SSH_MSG_REQUEST_FAILURE:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
        proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);

      } else {
        (void) proxy_ssh_packet_get_msg_type(pkt);
        handle_server_alive_msg(pkt, msg_type);
      }
      break;

    case PROXY_SSH_MSG_IGNORE:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
        proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);

      } else {
        (void) proxy_ssh_packet_get_msg_type(pkt);
        proxy_ssh_packet_handle_ignore(pkt);
      }
      break;

    case PROXY_SSH_MSG_UNIMPLEMENTED:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
        proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);

      } else {
        (void) proxy_ssh_packet_get_msg_type(pkt);
        proxy_ssh_packet_handle_unimplemented(pkt);
      }
      break;

    case PROXY_SSH_MSG_KEXINIT: {
      uint64_t start_ms = 0;

      if (from_frontend == TRUE) {
        /* We should never see a frontend KEXINIT packet, except when the
         * frontend client has requested a rekey; we do NOT want to interact
         * with the backend anymore for this event.
         *
         * In addition, we need a way to get mod_sftp to handle this packet,
         * and the rest of the KEX.  Fun.
         */
        return handle_frontend_rekey(pkt, proxy_sess);
      }

      (void) proxy_ssh_packet_get_msg_type(pkt);

      if (pr_trace_get_level(timing_channel) > 0) {
        pr_gettimeofday_millis(&start_ms);
      }

      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
        /* The server might be initiating a rekey; watch for this.  We
         * should not be receiving frontend KEXINIT packets here.
         */
        if (from_frontend == FALSE) {
          if (proxy_sess_state & PROXY_SESS_STATE_SSH_REKEYING) {
            pr_trace_msg(trace_channel, 17,
              "rekeying already in effect, ignoring rekey request");
            break;
          }

          /* Reinitialize the KEX API for another rekeying. */
          proxy_ssh_kex_init(session.pool, NULL, NULL);
        }

      } else {
        if (pr_trace_get_level(timing_channel)) {
          unsigned long elapsed_ms;
          uint64_t finish_ms;

          pr_gettimeofday_millis(&finish_ms);
          elapsed_ms = (unsigned long) (finish_ms - session.connect_time_ms);

          pr_trace_msg(timing_channel, 4,
            "Time before first SSH key exchange: %lu ms", elapsed_ms);
        }
      }
 
      proxy_sess_state |= PROXY_SESS_STATE_SSH_REKEYING;

      /* Clear any current "have KEX" state. */
      proxy_sess_state &= ~PROXY_SESS_STATE_SSH_HAVE_KEX;

      if (proxy_ssh_kex_handle(pkt, proxy_sess) < 0) {
        PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
          PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
      }

      proxy_sess_state |= PROXY_SESS_STATE_SSH_HAVE_KEX;

      if (pr_trace_get_level(timing_channel)) {
        unsigned long elapsed_ms;
        uint64_t finish_ms;

        pr_gettimeofday_millis(&finish_ms);
        elapsed_ms = (unsigned long) (finish_ms - start_ms);

        pr_trace_msg(timing_channel, 4,
          "SSH key exchange duration: %lu ms", elapsed_ms);
      }

      if (proxy_sess_state & PROXY_SESS_STATE_SSH_REKEYING) {
        proxy_sess_state &= ~PROXY_SESS_STATE_SSH_REKEYING;
      }

      break;
    }

    case PROXY_SSH_MSG_EXT_INFO:
      /* We expect any possible EXT_INFO message after NEWKEYS, and before
       * anything else.
       */
      if ((proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) &&
          !(proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_SERVICE) &&
          !(proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_EXT_INFO)) {
        (void) proxy_ssh_packet_get_msg_type(pkt);
        proxy_ssh_packet_handle_ext_info(pkt);
        proxy_sess_state |= PROXY_SESS_STATE_SSH_HAVE_EXT_INFO;
        break;

      } else {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to handle %s (%d) message: wrong message order",
          proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
        PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
          PROXY_SSH_DISCONNECT_BY_APPLICATION, "Unsupported protocol sequence");
      }
      break;

    case PROXY_SSH_MSG_SERVICE_REQUEST:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
        if (proxy_ssh_service_handle(pkt, proxy_sess) == 0) {
          proxy_sess_state |= PROXY_SESS_STATE_SSH_HAVE_SERVICE;
        }

      } else {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to handle %s (%d) message: Key exchange required",
          proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
        PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
          PROXY_SSH_DISCONNECT_BY_APPLICATION, "Unsupported protocol sequence");
      }
      break;

    case PROXY_SSH_MSG_USER_AUTH_INFO_RESP:
    case PROXY_SSH_MSG_USER_AUTH_REQUEST:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_SERVICE) {
        /* If the client has already authenticated this connection, then
         * silently ignore this additional auth request, per recommendation
         * in RFC4252.
         */
        if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "ignoring %s (%d) message: Connection already authenticated",
            proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);

        } else {
          int ok;

          ok = proxy_ssh_auth_handle(pkt, proxy_sess);
          if (ok == 1) {
            proxy_sess_state |= PROXY_SESS_STATE_SSH_HAVE_AUTH;

          } else if (ok < 0) {
            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "error handling SSH authentication: %s", strerror(errno));
            PROXY_SSH_DISCONNECT_CONN(proxy_sess->frontend_ctrl_conn,
              PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
          }
        }

      } else {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to handle %s (%d) message: Service request required",
          proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
        PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
          PROXY_SSH_DISCONNECT_BY_APPLICATION, "Unsupported protocol sequence");
      }
      break;

    case PROXY_SSH_MSG_CHANNEL_OPEN:
    case PROXY_SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
    case PROXY_SSH_MSG_CHANNEL_OPEN_FAILURE:
    case PROXY_SSH_MSG_CHANNEL_REQUEST:
    case PROXY_SSH_MSG_CHANNEL_DATA:
    case PROXY_SSH_MSG_CHANNEL_EXTENDED_DATA:
    case PROXY_SSH_MSG_CHANNEL_EOF:
    case PROXY_SSH_MSG_CHANNEL_FAILURE:
    case PROXY_SSH_MSG_CHANNEL_SUCCESS:
    case PROXY_SSH_MSG_CHANNEL_WINDOW_ADJUST:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH) {
        (void) pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
        proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);

      } else {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to handle %s (%d) message: User authentication required",
          proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
        PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
          PROXY_SSH_DISCONNECT_BY_APPLICATION, "Unsupported protocol sequence");
      }
      break;

    case PROXY_SSH_MSG_CHANNEL_CLOSE:
      if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH) {
        proxy_ssh_packet_proxied(proxy_sess, pkt, from_frontend);

      } else {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "unable to handle %s (%d) message: User authentication required",
          proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
        PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
          PROXY_SSH_DISCONNECT_BY_APPLICATION, "Unsupported protocol sequence");
      }
      break;

    default:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unhandled %s (%d) message, disconnecting",
        proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
      PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
        PROXY_SSH_DISCONNECT_BY_APPLICATION, "Unsupported protocol sequence");
  }

  return 0;
}

int proxy_ssh_packet_process(pool *p, const struct proxy_session *proxy_sess) {
  struct proxy_ssh_packet *pkt;
  int res;

  pkt = proxy_ssh_packet_create(p);
  res = proxy_ssh_packet_read(proxy_sess->backend_ctrl_conn, pkt);
  if (res < 0) {
    /* An ETIMEDOUT error here usually means that the read poll timed out;
     * the backend host did not have any data for us, which is OK.  Right?
     */
    if (errno != ETIMEDOUT) {
      PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
        PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
    }
  }

  pr_response_clear(&resp_list);
  pr_response_clear(&resp_err_list);
  pr_response_set_pool(pkt->pool);

  proxy_ssh_packet_handle(pkt);

  pr_response_set_pool(NULL);
  return 0;
}

int proxy_ssh_packet_set_frontend_packet_handle(pool *p,
    int (*packet_handle)(void *pkt)) {
  const char *hook_symbol;
  cmdtable *sftp_cmdtab;
  cmd_rec *cmd;
  modret_t *result;

  hook_symbol = "sftp_set_packet_handler";
  sftp_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, hook_symbol, NULL, NULL,
    NULL);
  if (sftp_cmdtab == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to find SFTP hook symbol '%s'", hook_symbol);
    errno = ENOENT;
    return -1;
  }

  cmd = pr_cmd_alloc(p, 1, NULL);
  cmd->argv[0] = (void *) packet_handle;
  result = pr_module_call(sftp_cmdtab->m, sftp_cmdtab->handler, cmd);
  if (result == NULL ||
      MODRET_ISERROR(result)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error setting Proxy SSH packet handler");
    errno = EPERM;
    return -1;
  }

  return 0;
}

void proxy_ssh_packet_set_frontend_packet_write(int (*packet_write)(int, void *)) {
  frontend_packet_write = packet_write;
}

int proxy_ssh_packet_send_version(conn_t *conn) {
  if (sent_version_id == FALSE) {
    int res;
    size_t version_len;

    version_len = strlen(version_id);

    res = write(conn->wfd, version_id, version_len);
    while (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();

        res = write(conn->wfd, version_id, version_len);
        continue;
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error sending version to server wfd %d: %s", conn->wfd,
        strerror(errno));
      return res;
    }

    sent_version_id = TRUE;
    session.total_raw_out += res;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "sent client version '%s'", client_version);
  }

  return 0;
}

int proxy_ssh_packet_set_version(const char *version) {
  if (client_version == NULL) {
    errno = EINVAL;
    return -1;
  }

  client_version = version;
  version_id = pstrcat(proxy_pool, version, "\r\n", NULL);
  return 0;
}
#endif /* PR_USE_OPENSSL */
