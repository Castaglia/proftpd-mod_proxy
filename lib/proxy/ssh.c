/*
 * ProFTPD - mod_proxy SSH implementation
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

#include "proxy/conn.h"
#include "proxy/netio.h"
#include "proxy/reverse.h"
#include "proxy/session.h"
#include "proxy/ssh.h"
#include "proxy/ssh/ssh2.h"
#include "proxy/ssh/msg.h"
#include "proxy/ssh/auth.h"
#include "proxy/ssh/db.h"
#include "proxy/ssh/redis.h"
#include "proxy/ssh/crypto.h"
#include "proxy/ssh/packet.h"
#include "proxy/ssh/interop.h"
#include "proxy/ssh/kex.h"
#include "proxy/ssh/keys.h"
#include "proxy/ssh/cipher.h"
#include "proxy/ssh/mac.h"
#include "proxy/ssh/utf8.h"

#if defined(PR_USE_OPENSSL)
#include <openssl/err.h>
#include <openssl/ssl.h>

static const char *ssh_tables_path = NULL;
static struct proxy_ssh_datastore ssh_ds;

static const char *ssh_client_version = PROXY_SSH_ID_DEFAULT_STRING;
static const char *ssh_server_version = NULL;

static const char *trace_channel = "proxy.ssh";

/* The number of packets to handle, while polling the backend connection, is
 * tricky.  Too many, and we risk stalling the frontend client.  Too few,
 * and we risk losing backend packets (and deadlocking the frontend client).
 *
 * This is most noticeable when most of the packets flow one way during the
 * session, as for SFTP/SCP uploads/downloads.
 *
 * With the use of packet_mpoll(), we set this number quite high; perhaps
 * this limit should be removed altogether?
 */
#define MAX_POLL_PACKETS		5000

static unsigned long ssh_opts = 0UL;

static void ssh_ssh2_read_poll_ev(const void *, void *);

static int ssh_get_server_version(pool *p,
    const struct proxy_session *proxy_sess) {
  int res;

  /* 255 is the RFC-defined maximum banner/ID string size */
  char buf[256], *banner = NULL;
  size_t buflen = 0;

  /* Read server version.  This looks ugly, reading one byte at a time.
   * It is necessary, though.  The banner sent by the server is not of any
   * guaranteed length.  The server might also send the next SSH packet in
   * the exchange, such that both messages are in the socket buffer.  If
   * we read too much of the banner, we'll read into the KEXINIT, for example,
   * and cause problems later.
   */

  while (TRUE) {
    register unsigned int i;
    int bad_proto = FALSE;

    pr_signals_handle();

    memset(buf, '\0', sizeof(buf));

    for (i = 0; i < sizeof(buf) - 1; i++) {
      res = proxy_ssh_packet_conn_read(proxy_sess->backend_ctrl_conn, &buf[i],
        1, 0);
      while (res <= 0) {
        int xerrno = errno;

        if (xerrno == EINTR) {
          pr_signals_handle();

          res = proxy_ssh_packet_conn_read(proxy_sess->backend_ctrl_conn,
            &buf[i], 1, 0);
          continue;
        }

        if (res < 0) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error reading from server rfd %d: %s",
            proxy_sess->backend_ctrl_conn->rfd, strerror(xerrno));
        }

        errno = xerrno;
        return res;
      }

      /* We continue reading until the server has sent the terminating
       * CRLF sequence.
       */
      if (buf[i] == '\r') {
        buf[i] = '\0';
        continue;
      }

      if (buf[i] == '\n') {
        buf[i] = '\0';
        break;
      }
    }

    if (i == sizeof(buf)-1) {
      bad_proto = TRUE;

    } else {
      buf[sizeof(buf)-1] = '\0';
      buflen = strlen(buf);
    }

    /* If the line does not begin with "SSH-2.0-", skip it.  RFC4253, Section
     * 4.2 does not specify what should happen if the server sends data
     * other than the proper version string initially.
     *
     * If we have been configured for compatibility with old protocol
     * implementations, check for "SSH-1.99-" as well.
     *
     * OpenSSH simply disconnects the server after saying "Protocol mismatch"
     * if the server's version string does not begin with "SSH-2.0-"
     * (or "SSH-1.99-").  Works for me.
     */
    if (bad_proto == FALSE) {
      if (strncmp(buf, "SSH-2.0-", 8) != 0) {
        bad_proto = TRUE;

        if (proxy_opts & PROXY_OPT_SSH_OLD_PROTO_COMPAT) {
          if (strncmp(buf, "SSH-1.99-", 9) == 0) {
            if (buflen == 9) {
              /* The client sent ONLY "SSH-1.99-".  OpenSSH handles this as a
               * "Protocol mismatch", so shall we.
               */
              bad_proto = TRUE;

            } else {
              banner = buf + 9;
              bad_proto = FALSE;
            }
          }
        }

      } else {
        if (buflen == 8) {
          /* The client sent ONLY "SSH-2.0-".  OpenSSH handles this as a
           * "Protocol mismatch", so shall we.
           */
          bad_proto = TRUE;

        } else {
          banner = buf + 8;
        }
      }
    }

    if (banner != NULL) {
      char *k, *v;

      k = pstrdup(session.pool, "PROXY_SSH_SERVER_BANNER");
      v = pstrdup(session.pool, banner);
      pr_env_unset(session.pool, k);
      pr_env_set(session.pool, k, v);
      (void) pr_table_add(session.notes, k, v, 0);
    }

    if (bad_proto) {
      const char *errstr = "Protocol mismatch.\n";

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "Bad protocol version '%.100s' from %s", buf,
        pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr));

      if (write(proxy_sess->backend_ctrl_conn->wfd, errstr,
          strlen(errstr)) < 0) {
        pr_trace_msg(trace_channel, 9,
          "error sending 'Protocol mismatch' message to server: %s",
          strerror(errno));
      }

      errno = EINVAL;
      return -1;
    }

    break;
  }

  ssh_server_version = pstrdup(p, buf);
  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "received server version '%s'", ssh_server_version);

  if (proxy_ssh_interop_handle_version(session.pool, proxy_sess,
      ssh_server_version) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error checking server version '%s' for interoperability: %s",
      ssh_server_version, strerror(errno));
  }

  return 0;
}

/* Event listeners
 */

static void ssh_restart_ev(const void *event_data, void *user_data) {
  /* Clear the host keys. */
  proxy_ssh_keys_free();

  /* Clear the client banner regexes. */
  proxy_ssh_interop_free();
}

static int ssh_handle_kexinit(pool *p, struct proxy_session *proxy_sess) {
  int res;

  if (proxy_opts & PROXY_OPT_SSH_PESSIMISTIC_KEXINIT) {
    /* If we are being pessimistic, we will send our version string to the
     * server now, and send our KEXINIT message later.
     */
    res = proxy_ssh_packet_send_version(proxy_sess->backend_ctrl_conn);

  } else {
    /* If we are being optimistic, we can reduce the connection latency
     * by sending our KEXINIT message now; this will have the server version
     * string automatically prepended.
     */
    res = proxy_ssh_kex_send_first_kexinit(session.pool, proxy_sess);
  }

  if (res < 0) {
    return -1;
  }

  /* Set the initial timeout for reading packets from servers.  Using
   * a value of -1 sets the default timeout value (i.e. TimeoutIdle).
   */
  proxy_ssh_packet_set_poll_timeout(-1, 0);

  res = ssh_get_server_version(proxy_pool, proxy_sess);
  if (res < 0) {
    return -1;
  }

  res = proxy_ssh_kex_init(session.pool, ssh_client_version,
    ssh_server_version);
  if (res < 0) {
    /* XXX Should we disconnect here? */
  }

  /* If we didn't send our KEXINIT earlier, send it now. */
  if (proxy_opts & PROXY_OPT_SSH_PESSIMISTIC_KEXINIT) {
    res = proxy_ssh_kex_send_first_kexinit(session.pool, proxy_sess);
    if (res < 0) {
      return -1;
    }
  }

  return 0;
}

static void ssh_handle_kex(pool *p, struct proxy_session *proxy_sess) {
  while (TRUE) {
    int res;

    pr_signals_handle();

    if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_KEX) {
      /* We're done! */
      break;
    }

    res = proxy_ssh_packet_process(proxy_pool, proxy_sess);
    if (res < 0) {
      destroy_pool(p);
      pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
        NULL);
    }
  }
}

static void ssh_ssh2_auth_completed_ev(const void *event_data,
    void *user_data) {
  int res;
  struct proxy_session *proxy_sess;
  const char *connect_data, *hook_symbol, *user;
  cmdtable *sftp_cmdtab;
  pool *tmp_pool;
  cmd_rec *cmd;
  modret_t *result;
  struct proxy_ssh_packet *pkt = NULL;
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;
  module m;

  proxy_sess = user_data;
  m.name = "mod_proxy";

  tmp_pool = make_sub_pool(session.pool);
  pr_pool_tag(tmp_pool, "Proxy SSH Auth completed pool");

  /* Look up the hook for setting the callback for writing packets to the
   * frontend client; we'll need it later.
   */

  hook_symbol = "sftp_get_packet_write";
  sftp_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, hook_symbol, NULL, NULL,
    NULL);
  if (sftp_cmdtab == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to find SFTP hook symbol '%s'", hook_symbol);
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  cmd = pr_cmd_alloc(tmp_pool, 1, NULL);
  result = pr_module_call(sftp_cmdtab->m, sftp_cmdtab->handler, cmd);
  if (result == NULL ||
      MODRET_ISERROR(result)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting SSH packet writer");
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  res = proxy_ssh_auth_set_frontend_success_handle(tmp_pool, NULL);
  if (res < 0) {
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);

  res = proxy_session_setup_env(proxy_pool, user,
    PROXY_SESSION_FL_CHECK_LOGIN_ACL);
  if (res < 0) {
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_CONFIG_ACL, NULL);
  }

  /* The "connect data" we use here depends on the sticky ConnectPolicy in
   * effect.
   */
  connect_data = user;

  if (proxy_reverse_get_connect_policy() == PROXY_REVERSE_CONNECT_POLICY_PER_GROUP) {
    connect_data = session.group;
  }

  res = proxy_reverse_connect(proxy_pool, proxy_sess, connect_data);
  if (res < 0) {
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  res = ssh_handle_kexinit(tmp_pool, proxy_sess);
  if (res < 0) {
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  proxy_ssh_auth_init(proxy_pool);

  /* Now we need to run the KEXINIT with the backend server to completion,
   * but not more than that.
   */
  ssh_handle_kex(tmp_pool, proxy_sess);

  /* We now need to run the service, auth portions to completion; for these
   * we act as if we were the frontend client sending packets.  We'll want
   * to reuse as much of our proxying machinery as possible, but we also need
   * to ensure that that machinery does not actually send packets to the
   * frontend client.  Thus we temporarily use a null packet handler here.
   */
  proxy_ssh_packet_set_frontend_packet_write(NULL);

  pkt = proxy_ssh_packet_create(tmp_pool);

  /* Note: It is important that this packet NOT come from mod_proxy. */
  pkt->m = &m;

  bufsz = buflen = 1024;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen,
    PROXY_SSH_MSG_SERVICE_REQUEST);
  len += proxy_ssh_msg_write_string(&buf, &buflen, "ssh-userauth");
  pkt->payload = ptr;
  pkt->payload_len = len;

  if (proxy_ssh_packet_handle(pkt) < 0) {
    /* Restore the callback for writing our DISCONNECT packet to the frontend
     * client.
     */
    proxy_ssh_packet_set_frontend_packet_write(result->data);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  pkt = proxy_ssh_packet_create(tmp_pool);

  /* Note: It is important that this packet NOT come from mod_proxy. */
  pkt->m = &m;

  bufsz = buflen = 4096;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen,
    PROXY_SSH_MSG_USER_AUTH_REQUEST);
  len += proxy_ssh_msg_write_string(&buf, &buflen, user);
  len += proxy_ssh_msg_write_string(&buf, &buflen, "ssh-connection");
  len += proxy_ssh_msg_write_string(&buf, &buflen, "hostbased");
  pkt->payload = ptr;
  pkt->payload_len = len;

  if (proxy_ssh_packet_handle(pkt) < 0) {
    /* Restore the callback for writing our DISCONNECT packet to the frontend
     * client.
     */
    proxy_ssh_packet_set_frontend_packet_write(result->data);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  /* Now we should be successfully authenticated to the backend server. */
  if (!(proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH)) {
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  res = proxy_ssh_packet_set_frontend_packet_handle(tmp_pool,
    proxy_ssh_packet_handle);
  if (res < 0) {
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  proxy_ssh_packet_set_frontend_packet_write(result->data);

  /* Now we register for mod_sftp's read-loop, to listen for frontend and
   * backend packets.
   */
  pr_event_register(&proxy_module, "mod_sftp.ssh2.read-poll",
    ssh_ssh2_read_poll_ev, proxy_sess);

  /* To trigger mod_proxy to restrict this session, now that we have
   * authenticated to the backend server, we generate an event as if we
   * were handling an FTP session.
   */
  pr_event_generate("mod_proxy.ctrl-read", NULL);

  destroy_pool(tmp_pool);
}

static void ssh_ssh2_kex_completed_ev(const void *event_data, void *user_data) {
  int res;
  struct proxy_session *proxy_sess;
  const char *hook_symbol;
  cmdtable *sftp_cmdtab;
  pool *tmp_pool;
  cmd_rec *cmd;
  modret_t *result;

  proxy_sess = user_data;

  tmp_pool = make_sub_pool(session.pool);
  pr_pool_tag(tmp_pool, "Proxy SSH KEX completed pool");

  res = proxy_ssh_packet_set_frontend_packet_handle(tmp_pool,
    proxy_ssh_packet_handle);
  if (res < 0) {
    destroy_pool(tmp_pool);

    /* XXX Should we disconnect here? */
    return;
  }

  /* If we have already authenticated to the backend, then this is a rekey,
   * and we do NOT want to interact with the backend anymore for this event.
   */
  if (proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH) {
    pr_trace_msg(trace_channel, 19, "frontend-initiated rekeying COMPLETED");

    /* Now we register for mod_sftp's read-loop, to listen for frontend and
     * backend packets.
     */
    pr_event_register(&proxy_module, "mod_sftp.ssh2.read-poll",
      ssh_ssh2_read_poll_ev, proxy_sess);

    destroy_pool(tmp_pool);
    return;
  }

  hook_symbol = "sftp_get_packet_write";
  sftp_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, hook_symbol, NULL, NULL,
    NULL);
  if (sftp_cmdtab == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to find SFTP hook symbol '%s'", hook_symbol);
    destroy_pool(tmp_pool);

    /* XXX Should we disconnect here? */
    return;
  }

  cmd = pr_cmd_alloc(tmp_pool, 1, NULL);
  result = pr_module_call(sftp_cmdtab->m, sftp_cmdtab->handler, cmd);
  if (result == NULL ||
      MODRET_ISERROR(result)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting SSH packet writer");

    /* XXX Should we disconnect here? */
  }

  /* Connecting to the selected backend server happened earlier (right?),
   * in proxy_reverse_sess_init().  So now we start our SSH session with
   * the selected backend host.
   */
  res = ssh_handle_kexinit(tmp_pool, proxy_sess);
  if (res < 0) {
    destroy_pool(tmp_pool);
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  proxy_ssh_auth_init(proxy_pool);

  /* Now we need to run the KEXINIT with the backend server to completion,
   * but not more than that.
   */
  ssh_handle_kex(tmp_pool, proxy_sess);

  proxy_ssh_packet_set_frontend_packet_write(result->data);

  /* Now we register for mod_sftp's read-loop, to listen for frontend and
   * backend packets.
   */
  pr_event_register(&proxy_module, "mod_sftp.ssh2.read-poll",
    ssh_ssh2_read_poll_ev, proxy_sess);

  /* To trigger mod_proxy to restrict this session, now that we have
   * authenticated to the backend server, we generate an event as if we
   * were handling an FTP session.
   */
  pr_event_generate("mod_proxy.ctrl-read", NULL);

  destroy_pool(tmp_pool);
}

static void ssh_ssh2_read_poll_ev(const void *event_data, void *user_data) {
  const struct proxy_session *proxy_sess;
  int poll_timeout_secs, res;
  unsigned long poll_timeout_ms;
  unsigned int npackets = 0, poll_attempts;
  pool *tmp_pool;

  /* We only want to do polling for, and processing of, backend packets once
   * our SSH session has reached a necessary start (SSH_HAVE_AUTH in
   * particular).
   */
  if (!(proxy_sess_state & PROXY_SESS_STATE_SSH_HAVE_AUTH)) {
    return;
  }

  proxy_sess = user_data;
  tmp_pool = make_sub_pool(session.pool);
  pr_pool_tag(tmp_pool, "Proxy SSH read-poll pool");

  proxy_ssh_packet_get_poll_attempts(&poll_attempts);
  proxy_ssh_packet_get_poll_timeout(&poll_timeout_secs, &poll_timeout_ms);

  proxy_ssh_packet_set_poll_attempts(2);
  proxy_ssh_packet_set_poll_timeout(0, 100);

  /* We try to process multiple backend packets in a loop, if we can. */

  res = proxy_ssh_packet_conn_mpoll(proxy_sess->frontend_ctrl_conn,
    proxy_sess->backend_ctrl_conn, PROXY_SSH_PACKET_IO_READ);
  pr_trace_msg(trace_channel, 10, "read-mpoll returned %d", res);

  while (res == 1 &&
         npackets < MAX_POLL_PACKETS) {
    pr_signals_handle();

    res = proxy_ssh_packet_process(tmp_pool, proxy_sess);
    if (res < 0) {
      pr_trace_msg(trace_channel, 2,
        "error processing backend packet during frontend read poll: %s",
        strerror(errno));
    }
    npackets++;

    res = proxy_ssh_packet_conn_mpoll(proxy_sess->frontend_ctrl_conn,
      proxy_sess->backend_ctrl_conn, PROXY_SSH_PACKET_IO_READ);
  }

  proxy_ssh_packet_set_poll_attempts(poll_attempts);
  proxy_ssh_packet_set_poll_timeout(poll_timeout_secs, poll_timeout_ms);
  destroy_pool(tmp_pool);
}
#endif /* PR_USE_OPENSSL */

int proxy_ssh_init(pool *p, const char *tables_path, int flags) {
#if defined(PR_USE_OPENSSL)
  int res;
  config_rec *c;

  memset(&ssh_ds, 0, sizeof(ssh_ds));

  switch (proxy_datastore) {
    case PROXY_DATASTORE_REDIS:
      res = proxy_ssh_redis_as_datastore(&ssh_ds, proxy_datastore_data,
        proxy_datastore_datasz);
      break;

    case PROXY_DATASTORE_SQLITE:
      res = proxy_ssh_db_as_datastore(&ssh_ds, proxy_datastore_data,
        proxy_datastore_datasz);
      break;

    default:
      res = -1;
      errno = EINVAL;
      break;
  }

  if (res < 0) {
    return -1;
  }

  res = (ssh_ds.init)(p, tables_path, flags);
  if (res < 0) {
    return -1;
  }

  if (pr_module_exists("mod_sftp.c") == FALSE &&
      pr_module_exists("mod_tls.c") == FALSE) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OPENSSL_config(NULL);
#endif /* prior to OpenSSL-1.1.x */
    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
  }

  ssh_tables_path = pstrdup(proxy_pool, tables_path);

  /* Initialize SSH API */
  proxy_ssh_interop_init();
  proxy_ssh_cipher_init();
  proxy_ssh_mac_init();
  proxy_ssh_utf8_init();

  pr_event_register(&proxy_module, "core.postparse", ssh_restart_ev, NULL);

  /* Note that this function is called from mod_proxy's "core.postparse" event
   * listener.  So we do, now, anything that we would have done in our own
   * postparse event listener.
   */

  c = find_config(main_server->conf, CONF_PARAM, "ProxySFTPPassPhraseProvider",
    FALSE);
  if (c != NULL) {
    proxy_ssh_keys_set_passphrase_provider(c->argv[0]);
  }

  proxy_ssh_keys_get_passphrases();
#endif /* PR_USE_OPENSSL */

  return 0;
}

int proxy_ssh_free(pool *p) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(PR_USE_OPENSSL)
  if (ssh_ds.dsh != NULL) {
    int res;

    res = (ssh_ds.close)(p, ssh_ds.dsh);
    if (res < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error closing datastore: %s", strerror(errno));
    }

    ssh_ds.dsh = NULL;
  }

  pr_event_unregister(&proxy_module, "core.restart", ssh_restart_ev);

  proxy_ssh_interop_free();
  proxy_ssh_keys_free();
  proxy_ssh_cipher_free();
  proxy_ssh_mac_free();
  proxy_ssh_utf8_free();
  proxy_ssh_crypto_free(0);

#endif /* PR_USE_OPENSSL */

  return 0;
}

int proxy_ssh_sess_init(pool *p, struct proxy_session *proxy_sess, int flags) {
#if defined(PR_USE_OPENSSL)
  int connect_policy_id = PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;
  int sftp_engine, proxy_role = 0, verify_server, xerrno = 0;
  config_rec *c;

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "SFTPEngine", FALSE);
  if (c == NULL) {
    return 0;
  }

  sftp_engine = *((int *) c->argv[0]);
  if (sftp_engine != TRUE) {
    return 0;
  }

  /* We currently only support SSH reverse proxying, not forward proxying,
   * and therefore need to check the configured ProxyRole.
   */
  c = find_config(main_server->conf, CONF_PARAM, "ProxyRole", FALSE);
  if (c != NULL) {
    proxy_role = *((int *) c->argv[0]);
  }

  /* Sadly, we cannot use the PROXY_ROLE constant here, since it is scoped
   * only to mod_proxy.c.
   */
  if (proxy_role != 1) {
    pr_trace_msg(trace_channel, 1,
      "unable to support non-reverse ProxyRole for SFTP");
    return 0;
  }

  proxy_sess->use_ftp = FALSE;
  proxy_sess->use_ssh = TRUE;
  pr_response_block(TRUE);

  c = find_config(main_server->conf, CONF_PARAM, "ServerIdent", FALSE);
  if (c != NULL) {
    if (*((unsigned char *) c->argv[0]) == FALSE) {
      /* The admin configured "ServerIdent off".  Set the version string to
       * just "mod_proxy", and that's it, no version.
       */
      ssh_client_version = pstrcat(proxy_pool, PROXY_SSH_ID_PREFIX, "mod_proxy",
        NULL);
      proxy_ssh_packet_set_version(ssh_client_version);

    } else {
      /* The admin configured "ServerIdent on", and possibly some custom
       * string.
       */
      if (c->argc > 1) {
        ssh_client_version = pstrcat(proxy_pool, PROXY_SSH_ID_PREFIX,
          c->argv[1], NULL);
        proxy_ssh_packet_set_version(ssh_client_version);
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxySFTPOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    ssh_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "ProxySFTPOptions", FALSE);
  }

  proxy_opts |= ssh_opts;

  c = find_config(main_server->conf, CONF_PARAM, "ProxySFTPHostKey", FALSE);
  while (c != NULL) {
    const char *path;

    pr_signals_handle();

    path = c->argv[0];
    if (proxy_ssh_keys_get_hostkey(p, path) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error loading hostkey '%s', skipping key", path);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ProxySFTPHostKey", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxySFTPVerifyServer",
    FALSE);
  if (c != NULL) {
    verify_server = *((int *) c->argv[0]);

  } else {
    verify_server = FALSE;
  }

  PRIVS_ROOT
  ssh_ds.dsh = (ssh_ds.open)(proxy_pool, ssh_tables_path, ssh_opts);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (ssh_ds.dsh == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error opening SSH datastore: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  proxy_ssh_kex_sess_init(p, &ssh_ds, verify_server);

  /* For PerUser/PerGroup/PerHost connection policies, we pay attention to
   * the mod_sftp events generated for successful authentication, otherwise
   * we use the successful KEX event.
   */

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseConnectPolicy",
    FALSE);
  if (c != NULL) {
    connect_policy_id = *((int *) c->argv[0]);
  }

  if (proxy_reverse_policy_is_sticky(connect_policy_id) == TRUE &&
      connect_policy_id != PROXY_REVERSE_CONNECT_POLICY_PER_HOST) {

    /* PerUser/PerGroup connect policies REQUIRE that we use "hostbased"
     * authentication to the backend server; make sure that ProxySFTPHostKeys
     * have been configured for this.
     */
    if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_UNKNOWN) != 0) {
      /* We have no configured hostkeys, thus cannot use "hostbased"
       * authentication; return FAILURE to the frontend client.
       */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to handle '%s' ProxyReverseConnectPolicy: "
        "no ProxySFTPHostKeys configured",
        proxy_reverse_policy_name(connect_policy_id));

      errno = EPERM;
      return -1;
    }

    pr_event_register(&proxy_module, "mod_sftp.ssh2.auth-hostbased",
      ssh_ssh2_auth_completed_ev, proxy_sess);
    pr_event_register(&proxy_module, "mod_sftp.ssh2.auth-kbdint",
      ssh_ssh2_auth_completed_ev, proxy_sess);
    pr_event_register(&proxy_module, "mod_sftp.ssh2.auth-password",
      ssh_ssh2_auth_completed_ev, proxy_sess);
    pr_event_register(&proxy_module, "mod_sftp.ssh2.auth-publickey",
      ssh_ssh2_auth_completed_ev, proxy_sess);

  } else {
    pr_event_register(&proxy_module, "mod_sftp.ssh2.kex.completed",
      ssh_ssh2_kex_completed_ev, proxy_sess);
  }

  proxy_ssh_auth_sess_init(p, proxy_sess);
#endif /* PR_USE_OPENSSL */
  return 0;
}

int proxy_ssh_sess_free(pool *p) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(PR_USE_OPENSSL)
  ssh_opts = 0UL;

  if (ssh_ds.dsh != NULL) {
    (void) (ssh_ds.close)(p, ssh_ds.dsh);
    ssh_ds.dsh = NULL;
  }

  proxy_ssh_kex_sess_free();

  pr_event_unregister(&proxy_module, "mod_sftp.ssh2.auth-hostbased",
    ssh_ssh2_auth_completed_ev);
  pr_event_unregister(&proxy_module, "mod_sftp.ssh2.auth-kbdint",
    ssh_ssh2_auth_completed_ev);
  pr_event_unregister(&proxy_module, "mod_sftp.ssh2.auth-password",
    ssh_ssh2_auth_completed_ev);
  pr_event_unregister(&proxy_module, "mod_sftp.ssh2.auth-publickey",
    ssh_ssh2_auth_completed_ev);
  pr_event_unregister(&proxy_module, "mod_sftp.ssh2.kex.completed",
    ssh_ssh2_kex_completed_ev);
  pr_event_unregister(&proxy_module, "mod_sftp.ssh2.read-poll",
    ssh_ssh2_read_poll_ev);
#endif /* PR_USE_OPENSSL */

  return 0;
}
