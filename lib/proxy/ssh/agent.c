/*
 * ProFTPD - mod_proxy SSH agent support
 * Copyright (c) 2021-2023 TJ Saunders
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
#include "proxy/ssh/agent.h"
#include "proxy/ssh/msg.h"

#if defined(PR_USE_OPENSSL)

static const char *trace_channel = "proxy.ssh.agent";

/* These values from https://tools.ietf.org/html/draft-miller-ssh-agent-04
 */
#define PROXY_SSH_AGENT_FAILURE			5
#define PROXY_SSH_AGENT_SUCCESS			6

#define PROXY_SSH_AGENT_REQ_IDS			11
#define PROXY_SSH_AGENT_RESP_IDS		12

#define PROXY_SSH_AGENT_REQ_SIGN_DATA		13
#define PROXY_SSH_AGENT_RESP_SIGN_DATA		14

#define PROXY_SSH_AGENT_EXTENDED_FAILURE	30

/* Error code for ssh.com's ssh-agent2 process. */
#define PROXY_SSHCOM_AGENT_FAILURE		102

/* Size of the buffer we use to talk to the agent. */
#define AGENT_REQUEST_MSGSZ		1024

/* Max size of the agent reply that we will handle. */
#define AGENT_REPLY_MAXSZ		(256 * 1024)

/* Max number of identities/keys we're willing to handle at one time. */
#define AGENT_MAX_KEYS			1024

/* In proxy_ssh_keys_get_clientkey(), when dealing with the key data returned
 * from the agent, use get_pkey_from_data() to create the EVP_PKEY.  Keep
 * the key_data around, for signing requests to send to the agent.
 */

static int agent_failure(char resp_status) {
  int failed = FALSE;

  switch (resp_status) {
    case PROXY_SSH_AGENT_FAILURE:
    case PROXY_SSH_AGENT_EXTENDED_FAILURE:
    case PROXY_SSHCOM_AGENT_FAILURE:
      failed = TRUE;
      break;
  }

  return failed;
}

static unsigned char *agent_request(pool *p, int fd, const char *path,
    unsigned char *req, uint32_t reqlen, uint32_t *resplen) {
  unsigned char msg[AGENT_REQUEST_MSGSZ], *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;
  size_t write_len;
  int res;

  bufsz = buflen = sizeof(msg);
  buf = ptr = msg;

  len += proxy_ssh_msg_write_int(&buf, &buflen, reqlen);

  /* Send the message length to the agent. */

  write_len = len;
  res = write(fd, ptr, write_len);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error sending request length to SSH agent at '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Handle short writes. */
  if ((size_t) res != write_len) {
    pr_trace_msg(trace_channel, 3,
      "short write (%d of %lu bytes sent) when talking to SSH agent at '%s'",
      res, (unsigned long) (write_len), path);
    errno = EIO;
    return NULL;
  }

  /* Send the message payload to the agent. */

  res = write(fd, req, reqlen);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error sending request payload to SSH agent at '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Handle short writes. */
  if ((uint32_t) res != reqlen) {
    pr_trace_msg(trace_channel, 3,
      "short write (%d of %lu bytes sent) when talking to SSH agent at '%s'",
      res, (unsigned long) reqlen, path);
    errno = EIO;
    return NULL;
  }

  /* Wait for a response from the server. */
  /* XXX This needs a timeout, prevent a blocked/bad agent from stalling
   * the client.  Maybe just set an internal timer?
   */

  res = read(fd, msg, sizeof(uint32_t));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error reading response length from SSH agent at '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Sanity check the returned length; we could be dealing with a buggy
   * client (or something else is injecting data into the Unix domain socket).
   * Best be conservative: if we get a response length of more than 256KB,
   * it's too big.  (What about very long lists of keys, and/or large keys?)
   */
  if (res > AGENT_REPLY_MAXSZ) {
    pr_trace_msg(trace_channel, 1,
      "response length (%d) from SSH agent at '%s' exceeds maximum (%lu), "
      "ignoring", res, path, (unsigned long) AGENT_REPLY_MAXSZ);
    errno = EIO;
    return NULL;
  }

  buf = msg;
  buflen = res;

  len = proxy_ssh_msg_read_int(p, &buf, &buflen, resplen);
  bufsz = buflen = *resplen;

  if (bufsz == 0 ||
      bufsz > AGENT_REPLY_MAXSZ) {
    pr_trace_msg(trace_channel, 1,
      "response length (%lu) from SSH agent at '%s' exceeds maximum (%lu), "
      "ignoring", (unsigned long) bufsz, path,
      (unsigned long) AGENT_REPLY_MAXSZ);
    errno = EIO;
    return NULL;
  }

  buf = ptr = palloc(p, bufsz);

  buflen = 0;
  while (buflen != *resplen) {
    pr_signals_handle();

    res = read(fd, buf + buflen, bufsz - buflen);
    if (res < 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 3,
        "error reading %d bytes of response payload from SSH agent at '%s': %s",
        (bufsz - buflen), path, strerror(xerrno));

      errno = xerrno;
      return NULL;
    }

    /* XXX Handle short reads? */
    buflen += res;
  }

  return ptr;
}

static int agent_connect(const char *path) {
  int fd, len, res, xerrno;
  struct sockaddr_un sock;

  memset(&sock, 0, sizeof(sock));
  sock.sun_family = AF_UNIX;
  sstrncpy(sock.sun_path, path, sizeof(sock.sun_path));
  len = sizeof(sock);

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error opening Unix domain socket: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error setting CLOEXEC on fd %d for talking to SSH agent: %s",
      fd, strerror(errno));
  }

  PRIVS_ROOT
  res = connect(fd, (struct sockaddr *) &sock, len);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res < 0) {
    pr_trace_msg(trace_channel, 2, "error connecting to SSH agent at '%s': %s",
      path, strerror(xerrno));

    (void) close(fd);
    errno = xerrno;
    return -1;
  }

  return fd;
}

int proxy_ssh_agent_get_keys(pool *p, const char *agent_path,
    array_header *key_list) {
  register unsigned int i;
  int fd;
  unsigned char *buf, *req, *resp;
  uint32_t buflen, key_count, reqlen, reqsz, resplen, len = 0;
  unsigned char resp_status;

  fd = agent_connect(agent_path);
  if (fd < 0) {
    return -1;
  }

  /* Write out the request for the identities (i.e. the public keys). */

  reqsz = buflen = 64;
  req = buf = palloc(p, reqsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_AGENT_REQ_IDS);

  reqlen = len;
  resp = agent_request(p, fd, agent_path, req, reqlen, &resplen);
  if (resp == NULL) {
    int xerrno = errno;

    (void) close(fd);
    errno = xerrno;
    return -1;
  }

  (void) close(fd);

  /* Read the response from the agent. */
  len = proxy_ssh_msg_read_byte(p, &resp, &resplen, &resp_status);
  if (agent_failure(resp_status) == TRUE) {
    pr_trace_msg(trace_channel, 5,
      "SSH agent at '%s' indicated failure (%d) for identities request",
      agent_path, resp_status);
    errno = EPERM;
    return -1;
  }

  if (resp_status != PROXY_SSH_AGENT_RESP_IDS) {
    pr_trace_msg(trace_channel, 5,
      "unknown response type %d from SSH agent at '%s'", resp_status,
      agent_path);
    errno = EACCES;
    return -1;
  }

  len = proxy_ssh_msg_read_int(p, &resp, &resplen, &key_count);
  if (key_count > AGENT_MAX_KEYS) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "SSH agent at '%s' returned too many keys (%lu, max %lu)", agent_path,
      (unsigned long) key_count, (unsigned long) AGENT_MAX_KEYS);
    errno = EPERM;
    return -1;
  }

  for (i = 0; i < key_count; i++) {
    unsigned char *key_data;
    uint32_t key_datalen;
    char *key_comment;
    struct agent_key *key;

    len = proxy_ssh_msg_read_int(p, &resp, &resplen, &key_datalen);
    len = proxy_ssh_msg_read_data(p, &resp, &resplen, key_datalen, &key_data);
    len = proxy_ssh_msg_read_string(p, &resp, &resplen, &key_comment);
    if (key_comment != NULL) {
      pr_trace_msg(trace_channel, 9,
        "SSH agent at '%s' provided comment '%s' for key #%u", agent_path,
        key_comment, (i + 1));
    }

    key = pcalloc(p, sizeof(struct agent_key));

    key->key_data = key_data;
    key->key_datalen = key_datalen;
    key->agent_path = pstrdup(p, agent_path); 

    *((struct agent_key **) push_array(key_list)) = key;
  }

  pr_trace_msg(trace_channel, 9, "SSH agent at '%s' provided %lu %s",
    agent_path, (unsigned long) key_count, key_count != 1 ? "keys" : "key");
  return 0;
}

const unsigned char *proxy_ssh_agent_sign_data(pool *p, const char *agent_path,
    const unsigned char *key_data, uint32_t key_datalen,
    const unsigned char *data, uint32_t datalen, uint32_t *sig_datalen,
    int flags) {
  int fd;
  unsigned char *buf, *req, *resp, *sig_data;
  uint32_t buflen, sig_flags, reqlen, reqsz, resplen, len = 0;
  unsigned char resp_status;

  fd = agent_connect(agent_path);
  if (fd < 0) {
    return NULL;
  }

  /* XXX When to set flags to OLD_SIGNATURE? */
  sig_flags = 0;

  /* Write out the request for signing the given data. */
  reqsz = buflen = 1 + key_datalen + 4 + datalen + 4 + 4;
  req = buf = palloc(p, reqsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_AGENT_REQ_SIGN_DATA);
  len += proxy_ssh_msg_write_data(&buf, &buflen, key_data, key_datalen, TRUE);
  len += proxy_ssh_msg_write_data(&buf, &buflen, data, datalen, TRUE);
  len += proxy_ssh_msg_write_int(&buf, &buflen, sig_flags);

  reqlen = len;
  resp = agent_request(p, fd, agent_path, req, reqlen, &resplen);
  if (resp == NULL) {
    int xerrno = errno;

    (void) close(fd);
    errno = xerrno;
    return NULL;
  }

  (void) close(fd);

  /* Read the response from the agent. */
  len = proxy_ssh_msg_read_byte(p, &resp, &resplen, &resp_status);
  if (agent_failure(resp_status) == TRUE) {
    pr_trace_msg(trace_channel, 5,
      "SSH agent at '%s' indicated failure (%d) for data signing request",
      agent_path, resp_status);
    errno = EPERM;
    return NULL;
  }

  if (resp_status != PROXY_SSH_AGENT_RESP_SIGN_DATA) {
    pr_trace_msg(trace_channel, 5,
      "unknown response type %d from SSH agent at '%s'", resp_status,
      agent_path);
    errno = EACCES;
    return NULL;
  }

  len = proxy_ssh_msg_read_int(p, &resp, &resplen, sig_datalen);
  len = proxy_ssh_msg_read_data(p, &resp, &resplen, *sig_datalen, &sig_data);

  return sig_data; 
}
#endif /* PR_USE_OPENSSL */
