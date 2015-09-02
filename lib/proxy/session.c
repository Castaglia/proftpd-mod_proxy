/*
 * ProFTPD - mod_proxy session routines
 * Copyright (c) 2012-2015 TJ Saunders
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
#include "proxy/session.h"

static const char *trace_channel = "proxy.session";

struct proxy_session *proxy_session_alloc(pool *p) {
  pool *sess_pool;
  struct proxy_session *proxy_sess;

  sess_pool = make_sub_pool(p);
  pr_pool_tag(sess_pool, "Proxy Session pool");

  proxy_sess = pcalloc(sess_pool, sizeof(struct proxy_session));
  proxy_sess->pool = sess_pool;

  /* This will be configured by the ProxySourceAddress directive, if present. */
  proxy_sess->src_addr = NULL;

  /* This will be configured by the ProxyDataTransferPolicy directive, if
   * present.
   */
  proxy_sess->dataxfer_policy = PROXY_SESS_DATA_TRANSFER_POLICY_DEFAULT;

  /* Fill in the defaults for the session members. */
  proxy_sess->connect_timeout = -1;
  proxy_sess->connect_timerno = -1;

  return proxy_sess;
}

int proxy_session_check_password(pool *p, const char *user,
    const char *passwd) {
  int res;

  res = pr_auth_authenticate(p, user, passwd);
  switch (res) {
    case PR_AUTH_OK:
      break;

    case PR_AUTH_NOPWD:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "password authentication for user '%s' failed: No such user", user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): No such user found",
        user);
      return -1;

    case PR_AUTH_BADPWD:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "password authentication for user '%s' failed: Incorrect password",
        user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Incorrect password",
        user);
      return -1;

    case PR_AUTH_AGEPWD:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "password authentication for user '%s' failed: Password expired",
        user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Password expired",
        user);
      return -1;

    case PR_AUTH_DISABLEDPWD:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "password authentication for user '%s' failed: Account disabled",
        user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Account disabled",
        user);
      return -1;

    default:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unknown authentication value (%d), returning error", res);
      return -1;
  }

  return 0;
}

int proxy_session_setup_env(pool *p, const char *user, int flags) {
  struct passwd *pw;
  config_rec *c;
  int i, res = 0, xerrno = 0;
  const char *xferlog = NULL;

  session.hide_password = TRUE;

  /* Note: the given user name may not be known locally on the proxy; thus
   * having pr_auth_getpwnam() returning NULL here is not an unexpected
   * use case.
   */

  pw = pr_auth_getpwnam(p, user);
  if (pw != NULL) {
    if (pw->pw_uid == PR_ROOT_UID) {
      int root_login = FALSE;

      pr_event_generate("mod_auth.root-login", NULL);

      c = find_config(main_server->conf, CONF_PARAM, "RootLogin", FALSE);
      if (c != NULL) {
        root_login = *((int *) c->argv[0]);
      }

      if (root_login == FALSE) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "root login attempted, denied by RootLogin configuration");
        pr_log_auth(PR_LOG_NOTICE, "SECURITY VIOLATION: Root login attempted.");
        return -1;
      }

      pr_log_auth(PR_LOG_WARNING, "ROOT proxy login successful");
    }

    res = pr_auth_is_valid_shell(main_server->conf, pw->pw_shell);
    if (res == FALSE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "authentication for user '%s' failed: Invalid shell", user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Invalid shell: '%s'",
        user, pw->pw_shell);
      errno = EPERM;
      return -1;
    }

    res = pr_auth_banned_by_ftpusers(main_server->conf, pw->pw_name);
    if (res == TRUE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "authentication for user '%s' failed: User in " PR_FTPUSERS_PATH, user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): User in "
        PR_FTPUSERS_PATH, pw->pw_name);
      errno = EPERM;
      return -1;
    }
  
    session.user = pstrdup(p, pw->pw_name);
    session.group = pstrdup(p, pr_auth_gid2name(p, pw->pw_gid));

    session.login_uid = pw->pw_uid;
    session.login_gid = pw->pw_gid;

  } else {
    session.user = pstrdup(session.pool, user);

    /* XXX What should session.group, session.login_uid, session.login_gid
     * be?  Kept as is?
     */
  }
 
  if (session.gids == NULL &&
      session.groups == NULL) {
    res = pr_auth_getgroups(p, session.user, &session.gids, &session.groups);
    if (res < 1 &&
        errno != ENOENT) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "no supplemental groups found for user '%s'", session.user);
    }
  }

  if (flags & PROXY_SESSION_FL_CHECK_LOGIN_ACL) {
    int login_acl;

    login_acl = login_check_limits(main_server->conf, FALSE, TRUE, &i);
    if (!login_acl) {
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Limit configuration "
        "denies login", user);
      return -1;
    }
  }

  /* XXX Will users want wtmp logging for a proxy login? */
  session.wtmp_log = FALSE;

  PRIVS_ROOT

  c = find_config(main_server->conf, CONF_PARAM, "TransferLog", FALSE);
  if (c == NULL) {
    xferlog = PR_XFERLOG_PATH;

  } else {
    xferlog = c->argv[0];
  }

  if (strncasecmp(xferlog, "none", 5) == 0) {
    xferlog_open(NULL);

  } else {
    xferlog_open(xferlog);
  }

  res = xerrno = 0;

  if (pw != NULL) {
    res = set_groups(p, pw->pw_gid, session.gids);
    xerrno = errno;
  }

  PRIVS_RELINQUISH

  if (res < 0) {
    pr_log_pri(PR_LOG_WARNING, "unable to set process groups: %s",
      strerror(xerrno));
  }

  session.disable_id_switching = TRUE;

  session.proc_prefix = pstrdup(session.pool, session.c->remote_name);
  session.sf_flags = 0;

  pr_scoreboard_update_entry(session.pid,
    PR_SCORE_USER, session.user,
    PR_SCORE_CWD, pr_fs_getcwd(),
    NULL);

  if (session.group != NULL) {
    session.group = pstrdup(session.pool, session.group);
  }

  if (session.groups != NULL) {
    session.groups = copy_array_str(session.pool, session.groups);
  }

  proxy_sess_state |= PROXY_SESS_STATE_PROXY_AUTHENTICATED;
  pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
  return 0;
}
