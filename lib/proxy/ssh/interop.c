/*
 * ProFTPD - mod_proxy SSH interoperability
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
#include "proxy/ssh/disconnect.h"
#include "proxy/ssh/interop.h"

#if defined(PR_USE_OPENSSL)

/* By default, each server is assumed to support all of the features in
 * which we are interested.
 */
static unsigned int default_flags =
  PROXY_SSH_FEAT_IGNORE_MSG |
  PROXY_SSH_FEAT_MAC_LEN |
  PROXY_SSH_FEAT_CIPHER_USE_K |
  PROXY_SSH_FEAT_REKEYING |
  PROXY_SSH_FEAT_USERAUTH_BANNER |
  PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO |
  PROXY_SSH_FEAT_SERVICE_IN_HOST_SIG |
  PROXY_SSH_FEAT_SERVICE_IN_PUBKEY_SIG |
  PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG |
  PROXY_SSH_FEAT_NO_DATA_WHILE_REKEYING |
  PROXY_SSH_FEAT_DH_NEW_GEX;

struct proxy_ssh_version_pattern {
  const char *pattern;
  int disabled_flags;
  pr_regex_t *pre;
};

static struct proxy_ssh_version_pattern known_versions[] = {
  { "^OpenSSH-2\\.0.*|"
    "^OpenSSH-2\\.1.*|"
    "^OpenSSH_2\\.1.*|"
    "^OpenSSH_2\\.2.*|"
    "^OpenSSH_2\\.3\\.0.*",	PROXY_SSH_FEAT_USERAUTH_BANNER|
				PROXY_SSH_FEAT_REKEYING|
				PROXY_SSH_FEAT_DH_NEW_GEX,		NULL },

  { "^OpenSSH_2\\.3\\..*|"
    "^OpenSSH_2\\.5\\.0p1.*|"
    "^OpenSSH_2\\.5\\.1p1.*|"
    "^OpenSSH_2\\.5\\.0.*|"
    "^OpenSSH_2\\.5\\.1.*|"
    "^OpenSSH_2\\.5\\.2.*|"
    "^OpenSSH_2\\.5\\.3.*",	PROXY_SSH_FEAT_REKEYING|
				PROXY_SSH_FEAT_DH_NEW_GEX,		NULL },

  { "^OpenSSH.*",		0,					NULL },

  { ".*J2SSH_Maverick.*",	PROXY_SSH_FEAT_REKEYING,		NULL },

  { ".*MindTerm.*",		0,					NULL },

  { "^Sun_SSH_1\\.0.*",		PROXY_SSH_FEAT_REKEYING,		NULL },

  { "^2\\.1\\.0.*|"
    "^2\\.1 .*",		PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				PROXY_SSH_FEAT_SERVICE_IN_HOST_SIG|
				PROXY_SSH_FEAT_MAC_LEN,			NULL },

  { "^2\\.0\\.13.*|"
    "^2\\.0\\.14.*|"
    "^2\\.0\\.15.*|"
    "^2\\.0\\.16.*|"
    "^2\\.0\\.17.*|"
    "^2\\.0\\.18.*|"
    "^2\\.0\\.19.*",		PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				PROXY_SSH_FEAT_SERVICE_IN_HOST_SIG|
				PROXY_SSH_FEAT_SERVICE_IN_PUBKEY_SIG|
				PROXY_SSH_FEAT_MAC_LEN,			NULL },

  { "^2\\.0\\.11.*|"
    "^2\\.0\\.12.*",		PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				PROXY_SSH_FEAT_SERVICE_IN_PUBKEY_SIG|
    				PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO|
				PROXY_SSH_FEAT_MAC_LEN,			NULL },

  { "^2\\.0\\..*",		PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				PROXY_SSH_FEAT_SERVICE_IN_PUBKEY_SIG|
    				PROXY_SSH_FEAT_HAVE_PUBKEY_ALGO|
				PROXY_SSH_FEAT_CIPHER_USE_K|
				PROXY_SSH_FEAT_MAC_LEN,			NULL },

  { "^2\\.2\\.0.*|"
    "^2\\.3\\.0.*",		PROXY_SSH_FEAT_MAC_LEN,			NULL },


  { "^1\\.2\\.18.*|"
    "^1\\.2\\.19.*|"
    "^1\\.2\\.20.*|"
    "^1\\.2\\.21.*|"
    "^1\\.2\\.22.*|"
    "^1\\.3\\.2.*|"		
    "^3\\.2\\.9.*",		PROXY_SSH_FEAT_IGNORE_MSG,		NULL },

  { ".*PuTTY.*|"
    ".*PUTTY.*|"
    ".*WinSCP.*",		PROXY_SSH_FEAT_NO_DATA_WHILE_REKEYING,	NULL },

  { NULL, 0, NULL },
};

static const char *trace_channel = "proxy.ssh.interop";

int proxy_ssh_interop_handle_version(pool *p,
    const struct proxy_session *proxy_sess, const char *server_version) {
  register unsigned int i;
  size_t version_len;
  const char *version = NULL;
  char *ptr = NULL;
  config_rec *c;

  if (server_version == NULL) {
    errno = EINVAL;
    return -1;
  }

  version_len = strlen(server_version);

  /* The version string MUST conform to the following, as per Section 4.2
   * of RFC4253:
   *
   *  SSH-protoversion-softwareversion [SP comments]
   *
   * The 'comments' field is optional.  The 'protoversion' MUST be "2.0".
   * The 'softwareversion' field MUST be printable ASCII characters and
   * cannot contain SP or the '-' character.
   */

  for (i = 0; i < version_len; i++) {
    if (!PR_ISPRINT(server_version[i]) &&
        server_version[i] != '-' &&
        server_version[i] != ' ') {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "server-sent version contains non-printable or illegal characters, "
        "disconnecting");
      PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
        PROXY_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, NULL);
    }
  }

  /* Skip past the leading "SSH-2.0-" (or "SSH-1.99-") to get the actual
   * server info.
   */
  if (strncmp(server_version, "SSH-2.0-", 8) == 0) {
    version = pstrdup(p, server_version + 8);

  } else if (strncmp(server_version, "SSH-1.99-", 9) == 0) {
    version = pstrdup(p, server_version + 9);

  } else {
    /* An illegally formatted server version.  How did it get here? */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "server-sent version (%s) is illegally formmated, disconnecting",
      server_version);
    PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
      PROXY_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, NULL);
  }

  /* Look for the optional comments field in the received server version; if
   * present, trim it out, so that we do not try to match on it.
   */
  ptr = strchr(version, ' ');
  if (ptr != NULL) {
    pr_trace_msg(trace_channel, 11, "read server version with comments: '%s'",
      version);
    *ptr = '\0';
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "handling connection to SSH2 server '%s'", version);
  pr_trace_msg(trace_channel, 5, "handling connection to SSH2 server '%s'",
    version);

  /* First matching pattern wins. */
  for (i = 0; known_versions[i].pattern != NULL; i++) {
    int res;

    pr_signals_handle();

    pr_trace_msg(trace_channel, 18,
      "checking server version '%s' against regex '%s'", version,
      known_versions[i].pattern);

    res = pr_regexp_exec(known_versions[i].pre, version, 0, NULL, 0, 0, 0);
    if (res == 0) {
      pr_trace_msg(trace_channel, 18,
        "server version '%s' matched against regex '%s'", version,
        known_versions[i].pattern);

      /* We have a match. */
      default_flags &= ~(known_versions[i].disabled_flags);
      break;

    } else {
      pr_trace_msg(trace_channel, 18,
        "server version '%s' did not match regex '%s'", version,
        known_versions[i].pattern);
    }
  }

  /* Now iterate through any ProxySFTPServerMatch rules. */

  c = find_config(main_server->conf, CONF_PARAM, "ProxySFTPServerMatch", FALSE);
  while (c != NULL) {
    int res;
    char *pattern;
    pr_regex_t *pre;

    pr_signals_handle();

    pattern = c->argv[0];
    pre = c->argv[1];

    pr_trace_msg(trace_channel, 18,
      "checking server version '%s' against ProxySFTPServerMatch regex '%s'",
      version, pattern);

    res = pr_regexp_exec(pre, version, 0, NULL, 0, 0, 0);
    if (res == 0) {
      pr_table_t *tab;
      const void *v;

      /* We have a match. */

      tab = c->argv[2];

      /* Look for the following keys:
       *  pessimisticNewkeys
       */

      v = pr_table_get(tab, "pessimisticNewkeys", NULL);
      if (v != NULL) {
        int pessimistic_newkeys;

        pessimistic_newkeys = *((int *) v);

        pr_trace_msg(trace_channel, 16,
          "setting pessimistic NEWKEYS behavior to %s, as per "
          "ProxySFTPServerMatch", pessimistic_newkeys ? "true" : "false");

        if (pessimistic_newkeys == TRUE) {
          default_flags |= PROXY_SSH_FEAT_PESSIMISTIC_NEWKEYS;
        }
      }

      /* Once we're done, we can destroy the table. */
      (void) pr_table_empty(tab);
      (void) pr_table_free(tab);
      c->argv[2] = NULL;

    } else {
      pr_trace_msg(trace_channel, 18,
        "server version '%s' did not match ProxySFTPServerMatch regex '%s'",
        version, pattern);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ProxySFTPServerMatch", FALSE);
  }

  return 0;
}

int proxy_ssh_interop_supports_feature(int feat_flag) {
  if (!(default_flags & feat_flag)) {
    return FALSE;
  }

  return TRUE;
}

int proxy_ssh_interop_init(void) {
  register unsigned int i;

  /* Compile the regexps for all of the known server versions, to save the
   * time when connecting to a server.
   */
  for (i = 0; known_versions[i].pattern != NULL; i++) {
    pr_regex_t *pre;
    int res;

    pr_signals_handle();

    pre = pr_regexp_alloc(&proxy_module);

    res = pr_regexp_compile(pre, known_versions[i].pattern,
      REG_EXTENDED|REG_NOSUB);
    if (res != 0) {
      char errmsg[256];

      memset(errmsg, '\0', sizeof(errmsg));
      pr_regexp_error(res, pre, errmsg, sizeof(errmsg));
      pr_regexp_free(NULL, pre);

      pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": error compiling regex pattern '%s' (known_versions[%u]): %s",
        known_versions[i].pattern, i, errmsg);
      continue;
    }

    known_versions[i].pre = pre;
  }

  return 0;
}

int proxy_ssh_interop_free(void) {
  register unsigned int i;

  for (i = 0; known_versions[i].pattern != NULL; i++) {
    if (known_versions[i].pre != NULL) {
      pr_regexp_free(NULL, known_versions[i].pre);
      known_versions[i].pre = NULL;
    }
  }

  return 0;
}
#endif /* PR_USE_OPENSSL */
