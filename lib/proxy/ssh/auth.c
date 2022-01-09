/*
 * ProFTPD - mod_proxy SSH user authentication
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
#include "proxy/ssh/packet.h"
#include "proxy/ssh/msg.h"
#include "proxy/ssh/disconnect.h"
#include "proxy/ssh/interop.h"
#include "proxy/ssh/auth.h"
#include "proxy/ssh/crypto.h"
#include "proxy/ssh/cipher.h"
#include "proxy/ssh/mac.h"
#include "proxy/ssh/compress.h"
#include "proxy/ssh/session.h"
#include "proxy/ssh/keys.h"
#include "proxy/ssh/utf8.h"

#if defined(PR_USE_OPENSSL)

/* From response.c */
extern pr_response_t *resp_list, *resp_err_list;

static pool *auth_pool = NULL;

static const char *trace_channel = "proxy.ssh.auth";

static void dispatch_cmd_err(cmd_rec *cmd) {
  pr_response_add_err(R_530, "Login incorrect.");
  pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
  pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
  pr_response_clear(&resp_err_list);
}

static int dispatch_user_cmd(pool *p, const char *orig_user,
    char **new_user) {
  cmd_rec *user_cmd;

  user_cmd = pr_cmd_alloc(p, 2, pstrdup(p, C_USER), orig_user);
  user_cmd->cmd_class = CL_AUTH|CL_SSH;
  user_cmd->arg = (char *) orig_user;

  /* Dispatch these as PRE_CMDs, so that mod_delay's tactics can be used
   * to ameliorate any timing-based attacks.
   */
  if (pr_cmd_dispatch_phase(user_cmd, PRE_CMD, 0) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "authentication request for user '%s' blocked by '%s' handler",
      orig_user, (char *) user_cmd->argv[0]);

    dispatch_cmd_err(user_cmd);
    destroy_pool(user_cmd->pool);
    return -1;
  }

  if (strcmp(orig_user, user_cmd->arg) != 0) {
    *new_user = pstrdup(p, user_cmd->arg);
  }

  pr_response_add(R_331, "Password required for %s", orig_user);
  pr_cmd_dispatch_phase(user_cmd, POST_CMD, 0);
  pr_cmd_dispatch_phase(user_cmd, LOG_CMD, 0);
  pr_response_clear(&resp_list);

  destroy_pool(user_cmd->pool);
  return 0;
}

static int dispatch_pass_cmd(pool *p, int success) {
  cmd_rec *pass_cmd;

  pass_cmd = pr_cmd_alloc(p, 1, pstrdup(p, C_PASS));
  pass_cmd->cmd_class = CL_AUTH|CL_SSH;
  pass_cmd->arg = pstrdup(pass_cmd->pool, "(hidden)");

  if (success == TRUE) {
    pr_cmd_dispatch_phase(pass_cmd, POST_CMD, 0);
    pr_cmd_dispatch_phase(pass_cmd, LOG_CMD, 0);

  } else {
    pr_cmd_dispatch_phase(pass_cmd, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(pass_cmd, LOG_CMD_ERR, 0);
  }

  pr_response_clear(&resp_list);
  destroy_pool(pass_cmd->pool);
  return 0;
}

static struct proxy_ssh_packet *read_auth_packet(pool *p,
    const struct proxy_session *proxy_sess) {
  struct proxy_ssh_packet *pkt = NULL;
  unsigned int poll_attempts;
  unsigned long poll_timeout_ms;
  int poll_timeout_secs, res, xerrno = 0;
  char msg_type;

  proxy_ssh_packet_get_poll_attempts(&poll_attempts);
  proxy_ssh_packet_get_poll_timeout(&poll_timeout_secs, &poll_timeout_ms);

  proxy_ssh_packet_set_poll_attempts(1);
  proxy_ssh_packet_set_poll_timeout(0, 50);

  pkt = proxy_ssh_packet_create(p);
  res = proxy_ssh_packet_read(proxy_sess->backend_ctrl_conn, pkt);
  if (res < 0) {
    xerrno = errno;

    proxy_ssh_packet_set_poll_attempts(poll_attempts);
    proxy_ssh_packet_set_poll_timeout(poll_timeout_secs, poll_timeout_ms);
    destroy_pool(pkt->pool);

    errno = xerrno;
    return NULL;
  }

  proxy_ssh_packet_set_poll_attempts(poll_attempts);
  proxy_ssh_packet_set_poll_timeout(poll_timeout_secs, poll_timeout_ms);

  msg_type = proxy_ssh_packet_peek_msg_type(pkt);

  pr_trace_msg(trace_channel, 3, "received %s (%d) packet (from mod_%s.c)",
    proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type,
    pkt->m->name);
  return pkt;
}

/* Returns 0 if the packet was completely processed, 1 if the caller should
 * process the packet, and -1 if the packet is invalid.
 */
static int process_auth_packet(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  char msg_type;
  int res = 0;

  msg_type = proxy_ssh_packet_peek_msg_type(pkt);

  switch (msg_type) {
    case PROXY_SSH_MSG_USER_AUTH_SUCCESS:
    case PROXY_SSH_MSG_USER_AUTH_FAILURE:
      res = 1;
      break;

    case PROXY_SSH_MSG_USER_AUTH_BANNER:
      proxy_ssh_packet_log_cmd(pkt, FALSE);
      proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
      destroy_pool(pkt->pool);
      res = 0;
      break;

    case PROXY_SSH_MSG_DEBUG:
    case PROXY_SSH_MSG_DISCONNECT:
    case PROXY_SSH_MSG_IGNORE:
    case PROXY_SSH_MSG_UNIMPLEMENTED:
      proxy_ssh_packet_handle(pkt);
      res = 0;
      break;

    default:
      errno = EINVAL;
      res = -1;
      break;
  }

  return res;
}

static int handle_userauth_none(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  int res;
  const char *methods;
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;

  /* Ideally, we would query the backend server ourselves, and synthesize the
   * full list of available methods for the frontend client.  For now, however,
   * return a response listing all implemented methods.
   */

  destroy_pool(pkt->pool);

  pkt = proxy_ssh_packet_create(auth_pool);

  bufsz = buflen = 1024;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen,
    PROXY_SSH_MSG_USER_AUTH_FAILURE);

  if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_UNKNOWN) == 0) {
    methods = "password,keyboard-interactive,publickey,hostbased";

  } else {
    /* If we have no configured ProxySFTPHostKeys, do not include the
     * "hostbased" method.
     */
    methods = "password,keyboard-interactive,publickey";
  }

  len += proxy_ssh_msg_write_string(&buf, &buflen, methods);
  len += proxy_ssh_msg_write_bool(&buf, &buflen, FALSE);

  pkt->payload = ptr;
  pkt->payload_len = len;

  res = proxy_ssh_packet_write_frontend(proxy_sess->frontend_ctrl_conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  destroy_pool(pkt->pool);
  return 0;
}

static const unsigned char *write_userauth_signed_data(pool *p,
    unsigned char *data, uint32_t datalen, size_t *sig_datalen) {
  unsigned char *buf, *ptr;
  const unsigned char *session_id;
  uint32_t bufsz, buflen, session_idlen, len = 0;

  /* XXX Is this buffer large enough?  Too large? */
  bufsz = buflen = 2048;
  ptr = buf = palloc(p, bufsz);

  /* Write the session ID. */
  session_idlen = proxy_ssh_session_get_id(&session_id);
  len += proxy_ssh_msg_write_data(&buf, &buflen, session_id, session_idlen,
    TRUE);

  /* Write the given data. */
  len += proxy_ssh_msg_write_data(&buf, &buflen, data, datalen, FALSE);

  *sig_datalen = len;
  return ptr;
}

static int write_userauth_hostbased(struct proxy_ssh_packet *pkt,
    const char *user, const char *service) {
  unsigned char *buf, *ptr;
  const unsigned char *hostkey_data, *sig_data, *signature;
  uint32_t bufsz, buflen, hostkey_datalen, len = 0;
  size_t signature_len, sig_datalen;
  const char *hostkey_algo = NULL, *hostname;
  enum proxy_ssh_key_type_e use_hostkey_type = PROXY_SSH_KEY_UNKNOWN;

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 8192;
  ptr = buf = palloc(pkt->pool, bufsz);

  /* Retrieve our hostkey.  We probe for our available hostkeys in preference
   * order:
   *
   *  Ed25519
   *  ECDSA521
   *  ECDSA384
   *  ECDSA256
   *  RSA
   *  DSA
   *
   * Note that RFC 8308 and the "server-sig-algs" EXT_INFO extension, for
   * SHA256/512 signatures using RSA keys, only applies to "publickey"
   * authentication requests, not "hostbased" -- hence why we do not probe
   * for those combinations.
   */

  len += proxy_ssh_msg_write_byte(&buf, &buflen,
    PROXY_SSH_MSG_USER_AUTH_REQUEST);
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool, user));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool, service));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool,
    "hostbased"));

  if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_ED25519) == 0) {
    use_hostkey_type = PROXY_SSH_KEY_ED25519;
    hostkey_algo = "ssh-ed25519";

  } else if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_ECDSA_521) == 0) {
    use_hostkey_type = PROXY_SSH_KEY_ECDSA_521;
    hostkey_algo = "ecdsa-sha2-nistp521";
  
  } else if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_ECDSA_384) == 0) {
    use_hostkey_type = PROXY_SSH_KEY_ECDSA_384;
    hostkey_algo = "ecdsa-sha2-nistp384";
  
  } else if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_ECDSA_256) == 0) {
    use_hostkey_type = PROXY_SSH_KEY_ECDSA_256;
    hostkey_algo = "ecdsa-sha2-nistp256";
  
  } else if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_RSA) == 0) {
    use_hostkey_type = PROXY_SSH_KEY_RSA;
    hostkey_algo = "ssh-rsa";
  
  } else if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_DSA) == 0) {
    use_hostkey_type = PROXY_SSH_KEY_DSA;
    hostkey_algo = "ssh-dss";
  }

  hostkey_data = proxy_ssh_keys_get_hostkey_data(pkt->pool,
    use_hostkey_type, &hostkey_datalen);
  if (hostkey_data == NULL) {
    return -1;
  }

  len += proxy_ssh_msg_write_string(&buf, &buflen, hostkey_algo);
  len += proxy_ssh_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen,
    TRUE);

  hostname = pr_netaddr_get_localaddr_str(pkt->pool);
  len += proxy_ssh_msg_write_string(&buf, &buflen, hostname);
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool, user));

  sig_data = write_userauth_signed_data(pkt->pool, ptr, len, &sig_datalen);
  if (sig_data == NULL) {
    return -1;
  }

  signature = proxy_ssh_keys_sign_data(pkt->pool, use_hostkey_type,
    sig_data, sig_datalen, &signature_len);
  len += proxy_ssh_msg_write_data(&buf, &buflen, signature, signature_len,
    TRUE);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int handle_userauth_hostbased(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  int res, xerrno, success = FALSE;
  unsigned char *buf;
  uint32_t buflen;
  char *orig_user, *new_user = NULL, *user, *service;
  pool *tmp_pool;

  /* We cannot send this "hostbased" USER_AUTH_REQUEST packet to the backend
   * server as-is, since the signed data involves the *frontend* session ID --
   * which the backend server will not have.
   *
   * Thus to support this, we need our own ProxySFTPHostKey.
   */

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Skip past the message type. */
  buf += sizeof(char);
  buflen -= sizeof(char);

  /* We only need to copy the user name, service name from the frontend packet;
   * we can ignore the rest.
   */
  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &orig_user);

  res = dispatch_user_cmd(pkt->pool, orig_user, &new_user);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &service);

  tmp_pool = make_sub_pool(auth_pool);
  user = pstrdup(tmp_pool, new_user != NULL ? new_user : orig_user);
  service = pstrdup(tmp_pool, service);

  destroy_pool(pkt->pool);

  (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
  if (pr_table_add_dup(session.notes, "mod_auth.orig-user", user, 0) < 0 &&
      errno != EEXIST) {
    pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
      "session.notes: %s", strerror(errno));
  }

  if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_UNKNOWN) != 0) {
    unsigned char *ptr;
    uint32_t bufsz, len = 0;
    const char *methods;

    /* We have no configured hostkeys, thus cannot use "hostbased"
     * authentication; return FAILURE to the frontend client.
     */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to handle client-requested hostbased authentication: "
      "no ProxySFTPHostKeys configured");

    pr_trace_msg(trace_channel, 9,
      "writing USER_AUTH_FAILURE message to client");
    pkt = proxy_ssh_packet_create(auth_pool);

    bufsz = buflen = 1024;
    ptr = buf = palloc(pkt->pool, bufsz);

    len += proxy_ssh_msg_write_byte(&buf, &buflen,
      PROXY_SSH_MSG_USER_AUTH_FAILURE);

    methods = "password,keyboard-interactive,publickey";
    len += proxy_ssh_msg_write_string(&buf, &buflen, methods);
    len += proxy_ssh_msg_write_bool(&buf, &buflen, FALSE);

    pkt->payload = ptr;
    pkt->payload_len = len;

    res = proxy_ssh_packet_write_frontend(proxy_sess->frontend_ctrl_conn, pkt);
    if (res < 0) {
      destroy_pool(pkt->pool);
      return -1;
    }

    return 0;
  }

  pr_trace_msg(trace_channel, 9,
    "writing USER_AUTH_REQUEST hostbased message to server");

  pkt = proxy_ssh_packet_create(auth_pool);
  res = write_userauth_hostbased(pkt, user, service);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(pkt->pool);
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(pkt->pool);
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  destroy_pool(pkt->pool);
  destroy_pool(tmp_pool);

  while (TRUE) {
    char msg_type;

    pr_signals_handle();

    pkt = read_auth_packet(auth_pool, proxy_sess);
    if (pkt == NULL) {
      return -1;
    }

    msg_type = proxy_ssh_packet_peek_msg_type(pkt);

    /* Handle the hostbased-specific message types, if any, here. */

    res = process_auth_packet(pkt, proxy_sess);
    if (res < 0) {
      destroy_pool(pkt->pool);

      /* Invalid protocol sequence */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "received unexpected %s packet during SSH authentication, failing",
        proxy_ssh_packet_get_msg_type_desc(msg_type));
      errno = ENOSYS;
      return -1;
    }

    if (res == 0) {
      continue;
    }

    /* If we reach here, it should be for USER_AUTH_SUCCESS/FAILURE packets, to
     * send to the frontend client.
     */
    proxy_ssh_packet_log_cmd(pkt, FALSE);

    if (msg_type == PROXY_SSH_MSG_USER_AUTH_SUCCESS) {
      success = TRUE;
    }

    break;
  }

  res = proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(pkt->pool);

    errno = xerrno;
    return -1;
  }

  destroy_pool(pkt->pool);
  return success;
}

static int write_userauth_kbdint(struct proxy_ssh_packet *pkt,
    const char *user, const char *service, const char *language,
    const char *submethods) {
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 8192;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen,
    PROXY_SSH_MSG_USER_AUTH_REQUEST);
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool, user));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool, service));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool,
    "keyboard-interactive"));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool,
    language));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool,
    submethods));

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int handle_userauth_kbdint(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  int res, xerrno, success = FALSE;
  unsigned char *buf;
  uint32_t buflen;
  char *orig_user, *new_user = NULL;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Skip past the message type. */
  buf += sizeof(char);
  buflen -= sizeof(char);

  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &orig_user);

  res = dispatch_user_cmd(pkt->pool, orig_user, &new_user);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  if (new_user == NULL) {
    /* No changes to the user; we can proxy the packet as is. */

    (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
    res = pr_table_add_dup(session.notes, "mod_auth.orig-user", orig_user, 0);
    if (res < 0 &&
        errno != EEXIST) {
      pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
        "session.notes: %s", strerror(errno));
    }

    res = proxy_ssh_packet_proxied(proxy_sess, pkt, TRUE);
    if (res < 0) {
      destroy_pool(pkt->pool);
      return -1;
    }

  } else {
    char *user, *service, *method, *language, *submethods;
    pool *tmp_pool;

    /* The username changed; we need to write a new packet. */

    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &service);
    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &method);
    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &language);
    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &submethods);

    tmp_pool = make_sub_pool(auth_pool);
    user = pstrdup(tmp_pool, new_user);
    service = pstrdup(tmp_pool, service);
    language = pstrdup(tmp_pool, language);
    submethods = pstrdup(tmp_pool, submethods);

    destroy_pool(pkt->pool);

    (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
    if (pr_table_add_dup(session.notes, "mod_auth.orig-user", user, 0) < 0 &&
        errno != EEXIST) {
      pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
        "session.notes: %s", strerror(errno));
    }

    pkt = proxy_ssh_packet_create(auth_pool);
    res = write_userauth_kbdint(pkt, user, service, language, submethods);
    if (res < 0) {
      xerrno = errno;

      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

    res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
    if (res < 0) {
      xerrno = errno;

      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

    destroy_pool(tmp_pool);
  }

  destroy_pool(pkt->pool);

  while (TRUE) {
    char msg_type;

    pr_signals_handle();

    pkt = read_auth_packet(auth_pool, proxy_sess);
    if (pkt == NULL) {
      return -1;
    }

    msg_type = proxy_ssh_packet_peek_msg_type(pkt);

    /* Handle the kbdint-specific message types, if any, here. */
    if (msg_type == PROXY_SSH_MSG_USER_AUTH_INFO_REQ) {
      proxy_ssh_packet_log_cmd(pkt, FALSE);
      res = proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
      destroy_pool(pkt->pool);

      if (res < 0) {
        return -1;
      }

      return 0;
    }

    res = process_auth_packet(pkt, proxy_sess);
    if (res < 0) {
      destroy_pool(pkt->pool);

      /* Invalid protocol sequence */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "received unexpected %s packet during SSH authentication, failing",
        proxy_ssh_packet_get_msg_type_desc(msg_type));
      errno = ENOSYS;
      return -1;
    }

    if (res == 0) {
      continue;
    }

    /* If we reach here, it should be for USER_AUTH_SUCCESS/FAILURE packets, to
     * send to the frontend client.
     */
    proxy_ssh_packet_log_cmd(pkt, FALSE);

    if (msg_type == PROXY_SSH_MSG_USER_AUTH_SUCCESS) {
      success = TRUE;
    }

    break;
  }

  res = proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(pkt->pool);

    errno = xerrno;
    return -1;
  }

  destroy_pool(pkt->pool);
  return success;
}

static int write_userauth_password(struct proxy_ssh_packet *pkt,
    const char *user, const char *service, const char *password) {
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 8192;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen,
    PROXY_SSH_MSG_USER_AUTH_REQUEST);
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool, user));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool, service));
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool,
    "password"));
  len += proxy_ssh_msg_write_bool(&buf, &buflen, FALSE);
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool,
    password));

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int handle_userauth_password(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  int res, xerrno, with_password, success = FALSE;
  unsigned char *buf;
  uint32_t buflen;
  char *orig_user, *new_user = NULL;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Skip past the message type. */
  buf += sizeof(char);
  buflen -= sizeof(char);

  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &orig_user);

  res = dispatch_user_cmd(pkt->pool, orig_user, &new_user);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  if (new_user == NULL) {
    /* No changes to the user; we can proxy the packet as is. */

    (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
    res = pr_table_add_dup(session.notes, "mod_auth.orig-user", orig_user, 0);
    if (res < 0 &&
        errno != EEXIST) {
      pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
        "session.notes: %s", strerror(errno));
    }

    res = proxy_ssh_packet_proxied(proxy_sess, pkt, TRUE);
    if (res < 0) {
      destroy_pool(pkt->pool);
      return -1;
    }

  } else {
    char *user, *service, *method, *password;
    pool *tmp_pool;

    /* The username changed; we need to write a new packet. */

    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &service);
    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &method);
    proxy_ssh_msg_read_bool(pkt->pool, &buf, &buflen, &with_password);
    proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &password);

    tmp_pool = make_sub_pool(auth_pool);
    user = pstrdup(tmp_pool, new_user);
    service = pstrdup(tmp_pool, service);
    password = pstrdup(tmp_pool, password);

    destroy_pool(pkt->pool);

    (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
    if (pr_table_add_dup(session.notes, "mod_auth.orig-user", user, 0) < 0 &&
        errno != EEXIST) {
      pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
        "session.notes: %s", strerror(errno));
    }

    pkt = proxy_ssh_packet_create(auth_pool);
    res = write_userauth_password(pkt, user, service, password);
    if (res < 0) {
      xerrno = errno;

      pr_memscrub(password, strlen(password));
      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

    res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
    if (res < 0) {
      xerrno = errno;

      pr_memscrub(password, strlen(password));
      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

    pr_memscrub(password, strlen(password));
    destroy_pool(tmp_pool);
  }

  destroy_pool(pkt->pool);

  while (TRUE) {
    char msg_type;

    pr_signals_handle();

    pkt = read_auth_packet(auth_pool, proxy_sess);
    if (pkt == NULL) {
      return -1;
    }

    msg_type = proxy_ssh_packet_peek_msg_type(pkt);

    /* Handle the password-specific message types here. */
    if (msg_type == PROXY_SSH_MSG_USER_AUTH_PASSWD) {
      proxy_ssh_packet_log_cmd(pkt, FALSE);
      res = proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
      destroy_pool(pkt->pool);

      if (res < 0) {
        return -1;
      }

      continue;
    }

    res = process_auth_packet(pkt, proxy_sess);
    if (res < 0) {
      destroy_pool(pkt->pool);

      /* Invalid protocol sequence */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "received unexpected %s packet during SSH authentication, failing",
        proxy_ssh_packet_get_msg_type_desc(msg_type));
      errno = ENOSYS;
      return -1;
    }

    if (res == 0) {
      continue;
    }

    /* If we reach here, it should be for USER_AUTH_SUCCESS/FAILURE packets, to
     * send to the frontend client.
     */
    proxy_ssh_packet_log_cmd(pkt, FALSE);

    if (msg_type == PROXY_SSH_MSG_USER_AUTH_SUCCESS) {
      success = TRUE;
    }

    break;
  }

  res = proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(pkt->pool);

    errno = xerrno;
    return -1;
  }

  destroy_pool(pkt->pool);
  return success;
}

static int write_pk_ok(struct proxy_ssh_packet *pkt, const char *publickey_algo,
    unsigned char *publickey_blob, uint32_t publickey_bloblen) {
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 8192;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen,
    PROXY_SSH_MSG_USER_AUTH_PK_OK);
  len += proxy_ssh_msg_write_string(&buf, &buflen, pstrdup(pkt->pool,
    publickey_algo));
  len += proxy_ssh_msg_write_data(&buf, &buflen, publickey_blob,
    publickey_bloblen, TRUE);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

/* We will use "hostbased" authentication to the backend, but we still need to
 * fulfill the "publickey" authentication protocol to the frontend client.
 */
static int handle_userauth_publickey(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  int res, xerrno, success = FALSE, with_signature = FALSE;
  unsigned char *buf, *buf2, *publickey_blob;
  uint32_t buflen, publickey_bloblen;
  char *orig_user, *new_user = NULL, *user, *service, *method, *publickey_algo;
  pool *tmp_pool;

  /* We cannot send this "publickey" USER_AUTH_REQUEST packet to the backend
   * server as-is, since the signed data involves the *frontend* session ID --
   * which the backend server will not have.
   *
   * If this publickey request contains the signature, we will send our
   * hostbased request to the backend server, and return SUCCESS.  Otherwise,
   * we will respond to the frontend client, asking them to send the
   * signature.
   */

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Skip past the message type. */
  buf += sizeof(char);
  buflen -= sizeof(char);

  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &orig_user);

  res = dispatch_user_cmd(pkt->pool, orig_user, &new_user);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &service);
  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &method);
  proxy_ssh_msg_read_bool(pkt->pool, &buf, &buflen, &with_signature);
  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &publickey_algo);
  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &publickey_bloblen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, publickey_bloblen,
    &publickey_blob);

  tmp_pool = make_sub_pool(auth_pool);
  user = pstrdup(tmp_pool, new_user != NULL ? new_user : orig_user);
  service = pstrdup(tmp_pool, service);
  publickey_algo = pstrdup(tmp_pool, publickey_algo);

  buf2 = palloc(tmp_pool, publickey_bloblen);
  memcpy(buf2, publickey_blob, publickey_bloblen);
  publickey_blob = buf2;

  destroy_pool(pkt->pool);

  (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
  if (pr_table_add_dup(session.notes, "mod_auth.orig-user", user, 0) < 0 &&
      errno != EEXIST) {
    pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
      "session.notes: %s", strerror(errno));
  }

  if (proxy_ssh_keys_have_hostkey(PROXY_SSH_KEY_UNKNOWN) != 0) {
    unsigned char *ptr;
    uint32_t bufsz, len = 0;
    const char *methods;

    /* We have no configured hostkeys, thus cannot use "hostbased"
     * authentication; return FAILURE to the frontend client.
     */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to handle client-requested publickey authentication: "
      "no ProxySFTPHostKeys configured");

    pr_trace_msg(trace_channel, 9,
      "writing USER_AUTH_FAILURE message to client");
    pkt = proxy_ssh_packet_create(auth_pool);

    bufsz = buflen = 1024;
    ptr = buf = palloc(pkt->pool, bufsz);

    len += proxy_ssh_msg_write_byte(&buf, &buflen,
      PROXY_SSH_MSG_USER_AUTH_FAILURE);

    methods = "password,keyboard-interactive,hostbased";
    len += proxy_ssh_msg_write_string(&buf, &buflen, methods);
    len += proxy_ssh_msg_write_bool(&buf, &buflen, FALSE);

    pkt->payload = ptr;
    pkt->payload_len = len;

    res = proxy_ssh_packet_write_frontend(proxy_sess->frontend_ctrl_conn, pkt);
    if (res < 0) {
      destroy_pool(pkt->pool);
      return -1;
    }

    return 0;
  }

  if (with_signature == TRUE) {
    pr_trace_msg(trace_channel, 9,
      "publickey request includes signature, writing USER_AUTH_REQUEST "
      "hostbased message to server");

    pkt = proxy_ssh_packet_create(auth_pool);
    res = write_userauth_hostbased(pkt, user, service);
    if (res < 0) {
      xerrno = errno;

      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

    res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
    if (res < 0) {
      xerrno = errno;

      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

  } else {
    pr_trace_msg(trace_channel, 9,
      "publickey request does not include signature, writing USER_AUTH_PK_OK "
      "message to client");

    pkt = proxy_ssh_packet_create(auth_pool);
    res = write_pk_ok(pkt, publickey_algo, publickey_blob, publickey_bloblen);
    if (res < 0) {
      xerrno = errno;

      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

    res = proxy_ssh_packet_write_frontend(proxy_sess->frontend_ctrl_conn, pkt);
    if (res < 0) {
      xerrno = errno;

      destroy_pool(pkt->pool);
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }

    destroy_pool(pkt->pool);
    destroy_pool(tmp_pool);
    return 0;
  }

  destroy_pool(pkt->pool);
  destroy_pool(tmp_pool);

  while (TRUE) {
    char msg_type;

    pr_signals_handle();

    pkt = read_auth_packet(auth_pool, proxy_sess);
    if (pkt == NULL) {
      return -1;
    }

    msg_type = proxy_ssh_packet_peek_msg_type(pkt);

    /* Handle the publickey-specific message types, if any, here. */

    res = process_auth_packet(pkt, proxy_sess);
    if (res < 0) {
      destroy_pool(pkt->pool);

      /* Invalid protocol sequence */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "received unexpected %s packet during SSH authentication, failing",
        proxy_ssh_packet_get_msg_type_desc(msg_type));
      errno = ENOSYS;
      return -1;
    }

    if (res == 0) {
      continue;
    }

    /* If we reach here, it should be for USER_AUTH_SUCCESS/FAILURE packets, to
     * send to the frontend client.
     */
    proxy_ssh_packet_log_cmd(pkt, FALSE);

    if (msg_type == PROXY_SSH_MSG_USER_AUTH_SUCCESS) {
      success = TRUE;
    }

    break;
  }

  res = proxy_ssh_packet_proxied(proxy_sess, pkt, FALSE);
  if (res < 0) {
    xerrno = errno;

    destroy_pool(pkt->pool);

    errno = xerrno;
    return -1;
  }

  destroy_pool(pkt->pool);
  return success;
}

int proxy_ssh_auth_handle(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  char msg_type, *user = NULL, *service = NULL, *method = NULL;
  unsigned char *buf = NULL;
  uint32_t buflen = 0;
  int success = FALSE;

  msg_type = proxy_ssh_packet_peek_msg_type(pkt);

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Skip past the message type. */
  buf += sizeof(char);
  buflen -= sizeof(char);

  if (msg_type == PROXY_SSH_MSG_USER_AUTH_REQUEST) {
    uint32_t len;

    len = proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &user);
    len = proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &service);
    len = proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &method);

    pr_trace_msg(trace_channel, 10,
      "auth requested for user '%s', service '%s', using method '%s'", user,
      service, method);

    if (strcmp(method, "none") == 0) {
      success = handle_userauth_none(pkt, proxy_sess);

    } else if (strcmp(method, "hostbased") == 0) {
      success = handle_userauth_hostbased(pkt, proxy_sess);

    } else if (strcmp(method, "keyboard-interactive") == 0) {
      success = handle_userauth_kbdint(pkt, proxy_sess);

    } else if (strcmp(method, "password") == 0) {
      success = handle_userauth_password(pkt, proxy_sess);

    } else if (strcmp(method, "publickey") == 0) {
      success = handle_userauth_publickey(pkt, proxy_sess);

    } else {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to handle SSH_MSG_USER_AUTH_REQUEST message: "
        "unknown/unsupported method '%s' requested", method);
      errno = EINVAL;
      return -1;
    }

  } else if (msg_type == PROXY_SSH_MSG_USER_AUTH_INFO_RESP) {
    pr_trace_msg(trace_channel, 17,
      "handling USER_AUTH_INFO_RESPONSE");
    success = handle_userauth_kbdint(pkt, proxy_sess);
  }

  if (success == TRUE) {
    int res;
    const char *orig_user;

    (void) pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);

    orig_user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    res = proxy_session_setup_env(proxy_pool, orig_user, 0);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }

    /* We call the compression init routines here as well, in case the
     * server selected "delayed" compression.
     */
    proxy_ssh_compress_init_read(PROXY_SSH_COMPRESS_FL_AUTHENTICATED);
    proxy_ssh_compress_init_write(PROXY_SSH_COMPRESS_FL_AUTHENTICATED);
  }

  dispatch_pass_cmd(proxy_pool, success);
  return success;
}

int proxy_ssh_auth_init(pool *p) {
  if (auth_pool == NULL) {
    auth_pool = make_sub_pool(p);
    pr_pool_tag(auth_pool, "Proxy SSH Auth Pool");
  }

  return 0;
}

int proxy_ssh_auth_sess_init(pool *p, const struct proxy_session *proxy_sess) {
  /* Currently unused. */
  (void) p;
  (void) proxy_sess;

  return 0;
}
#endif /* PR_USE_OPENSSL */
