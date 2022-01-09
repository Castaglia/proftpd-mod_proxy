/*
 * ProFTPD - mod_proxy SSH packet API
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

#ifndef MOD_PROXY_SSH_PACKET_H
#define MOD_PROXY_SSH_PACKET_H

#include "mod_proxy.h"
#include "proxy/session.h"

#if defined(PR_USE_OPENSSL)

/* From RFC 4253, Section 6 */
/* NOTE: This struct MUST be kept in sync with the struct used in mod_sftp;
 * failure to do so WILL lead to inexplicable and hard-to-diagnose errors!
 */
struct proxy_ssh_packet {
  pool *pool;

  /* Module that created this packet. */
  module *m;

  /* Length of the packet, not including mac or packet_len field itself. */
  uint32_t packet_len;

  /* Length of the padding field. */
  unsigned char padding_len;

  unsigned char *payload;
  uint32_t payload_len;

  /* Must be at least 4 bytes of padding, with a maximum of 255 bytes. */
  unsigned char *padding;

  /* Additional Authenticated Data (AAD). */
  unsigned char *aad;
  uint32_t aad_len;

  /* Message Authentication Code. */
  unsigned char *mac;
  uint32_t mac_len;

  /* Packet sequence number. */
  uint32_t seqno;
};

#define PROXY_SSH_MIN_PADDING_LEN	4
#define PROXY_SSH_MAX_PADDING_LEN	255

/* From the SFTP Draft, Section 4. */
struct proxy_sftp_packet {
  uint32_t packet_len;
  unsigned char packet_type;
  uint32_t request_id;
};

struct proxy_ssh_packet *proxy_ssh_packet_create(pool *p);
char proxy_ssh_packet_get_msg_type(struct proxy_ssh_packet *pkt);
char proxy_ssh_packet_peek_msg_type(const struct proxy_ssh_packet *pkt);
const char *proxy_ssh_packet_get_msg_type_desc(unsigned char msg_type);
void proxy_ssh_packet_log_cmd(struct proxy_ssh_packet *pkt, int from_frontend);

#define PROXY_SSH_PACKET_IO_READ	5
#define PROXY_SSH_PACKET_IO_WRITE	7

int proxy_ssh_packet_conn_poll(conn_t *conn, int io);

/* Similar to `proxy_ssh_packet_conn_poll`, but we poll multiple connections.
 * 0 is returned if the frontend connection has data, 1 is returned if the
 * backend connection has data, and -1 on error/timeout.
 */
int proxy_ssh_packet_conn_mpoll(conn_t *frontend_conn, conn_t *backend_conn,
  int io);

int proxy_ssh_packet_conn_read(conn_t *conn, void *buf, size_t reqlen,
  int flags);
int proxy_ssh_packet_read(conn_t *conn, struct proxy_ssh_packet *pkt);

/* This proxy_ssh_packet_conn_read() flag is used to tell the function to
 * read in as many of the requested length of data as it can, but to NOT
 * keep polling until that length has been acquired (i.e. to read the
 * requested length pessimistically, assuming that it will not all appear).
 */
#define PROXY_SSH_PACKET_READ_FL_PESSIMISTIC		0x001

int proxy_ssh_packet_send(conn_t *conn, struct proxy_ssh_packet *pkt);

/* Wrapper function around proxy_ssh_packet_send() which handles the sending
 * of messages and buffering of messages for network efficiency.
 */
int proxy_ssh_packet_write(conn_t *conn, struct proxy_ssh_packet *pkt);
int proxy_ssh_packet_write_frontend(conn_t *conn, struct proxy_ssh_packet *pkt);

/* Proxy the packet from frontend-to-backend, or backend-to-frontend. */
int proxy_ssh_packet_proxied(const struct proxy_session *proxy_sess,
  struct proxy_ssh_packet *pkt, int from_frontend);

/* This function reads in an SSH2 packet from the socket, and dispatches
 * the packet to various handlers.
 */
int proxy_ssh_packet_process(pool *p, const struct proxy_session *proxy_sess);

/* Handle any SSH2 packet. */
int proxy_ssh_packet_handle(void *pkt);

/* These specialized functions are for handling the additional message types
 * defined in RFC 4253, Section 11, e.g. during KEX.
 */
void proxy_ssh_packet_handle_debug(struct proxy_ssh_packet *pkt);
void proxy_ssh_packet_handle_disconnect(struct proxy_ssh_packet *pkt);
void proxy_ssh_packet_handle_ext_info(struct proxy_ssh_packet *pkt);
void proxy_ssh_packet_handle_ignore(struct proxy_ssh_packet *pkt);
void proxy_ssh_packet_handle_unimplemented(struct proxy_ssh_packet *pkt);

int proxy_ssh_packet_set_version(const char *client_version);
int proxy_ssh_packet_send_version(conn_t *conn);

int proxy_ssh_packet_get_poll_attempts(unsigned int *nattempts);
int proxy_ssh_packet_set_poll_attempts(unsigned int nattempts);

int proxy_ssh_packet_get_poll_timeout(int *secs, unsigned long *ms);
int proxy_ssh_packet_set_poll_timeout(int secs, unsigned long ms);

int proxy_ssh_packet_set_server_alive(unsigned int, unsigned int);

int proxy_ssh_packet_set_frontend_packet_handle(pool *p, int (*cb)(void *pkt));
void proxy_ssh_packet_set_frontend_packet_write(int (*cb)(int fd, void *pkt));

#endif /* PR_USE_OPENSSL */

#endif /* MOD_PROXY_SSH_PACKET_H */
