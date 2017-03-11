/*
 * ProFTPD - mod_proxy reverse proxy implementation
 * Copyright (c) 2012-2017 TJ Saunders
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
#include "json.h"

#include "proxy/db.h"
#include "proxy/conn.h"
#include "proxy/netio.h"
#include "proxy/inet.h"
#include "proxy/reverse.h"
#include "proxy/reverse/db.h"
#include "proxy/reverse/redis.h"
#include "proxy/random.h"
#include "proxy/tls.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/sess.h"

#include <sqlite3.h>

extern xaset_t *server_list;

static array_header *default_backends = NULL, *reverse_backends = NULL;
static int reverse_backend_id = -1;
static int reverse_backend_updated = FALSE;
static int reverse_connect_policy = PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;
static unsigned long reverse_flags = 0UL;
static int reverse_retry_count = PROXY_DEFAULT_RETRY_COUNT;

static struct proxy_reverse_datastore reverse_ds;

/* Flag that indicates that we should select/connect to the backend server
 * at session init time, i.e. when proxy auth is not required, and we're using
 * a balancing policy.
 */
#define PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT		1

/* Flag that indicates that we should select/connect to the backend server
 * at USER time, i.e. when proxy auth is not required, and we're using a
 * sticky policy.
 */
#define PROXY_REVERSE_FL_CONNECT_AT_USER		2

/* Flag that indicates that we should select/connect to the backend server
 * at PASS time, i.e. when proxy auth IS required (balancing/sticky policy
 * doesn't really matter).
 */
#define PROXY_REVERSE_FL_CONNECT_AT_PASS		3

/* JSON handling */
#define PROXY_REVERSE_JSON_MAX_FILE_SIZE		(1024 * 1024 * 5)
#define PROXY_REVERSE_JSON_MAX_ITEMS			1000

static const char *trace_channel = "proxy.reverse";

static int reverse_policy_is_sticky(int policy_id);

static void clear_user_creds(void) {
  register unsigned int i;

  if (reverse_backends == NULL ||
      reverse_backends->nelts == 0) {
    /* Nothing to do. */
    return;
  }

  for (i = 0; i < reverse_backends->nelts; i++) {
    struct proxy_conn *pconn;

    pconn = ((struct proxy_conn **) reverse_backends->elts)[i];
    proxy_conn_clear_username(pconn);
    proxy_conn_clear_password(pconn);
  }
}

static int check_parent_dir_perms(pool *p, const char *path) {
  struct stat st;
  int res;
  char *dir_path, *ptr = NULL;

  ptr = strrchr(path, '/');
  if (ptr != path) {
    dir_path = pstrndup(p, path, ptr - path);

  } else {
    dir_path = "/";
  }

  res = stat(dir_path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to stat ProxyReverseServers %s directory '%s': %s",
      path, dir_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (!(proxy_opts & PROXY_OPT_IGNORE_CONFIG_PERMS) &&
      (st.st_mode & S_IWOTH)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use ProxyReverseServers %s from world-writable "
      "directory '%s' (perms %04o): %s", path, dir_path,
      st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int check_file_perms(pool *p, const char *path) {
  struct stat st;
  int res;
  const char *orig_path;

  orig_path = path;

  res = lstat(path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to lstat ProxyReverseServers '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (S_ISLNK(st.st_mode)) {
    char buf[PR_TUNABLE_PATH_MAX+1];

    /* Check the permissions on the parent directory; if they're world-writable,
     * then this symlink can be deleted/pointed somewhere else.
     */
    res = check_parent_dir_perms(p, path);
    if (res < 0) {
      return -1;
    }

    /* Follow the link to the target path; that path will then have its
     * parent directory checked.
     */
    memset(buf, '\0', sizeof(buf));
    res = readlink(path, buf, sizeof(buf)-1);
    if (res > 0) {
      path = pstrdup(p, buf);
    }

    res = stat(orig_path, &st);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG0, MOD_PROXY_VERSION
        ": unable to stat ProxyReverseServers '%s': %s", orig_path,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  if (S_ISDIR(st.st_mode)) {
    int xerrno = EISDIR;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use ProxyReverseServers '%s': %s", orig_path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* World-writable files are insecure, and are thus not usable/trusted. */
  if (st.st_mode & S_IWOTH) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_PROXY_VERSION
      ": unable to use world-writable ProxyReverseServers '%s' "
      "(perms %04o): %s", orig_path, st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* TODO: This will warn about files such as FIFOs, BUT will leave them
   * usable.  Good idea, or bad idea?
   */
  if (!S_ISREG(st.st_mode)) {
    pr_log_pri(PR_LOG_WARNING, MOD_PROXY_VERSION
      ": ProxyReverseServers '%s' is not a regular file", orig_path);
  }

  /* Check the parent directory of this file.  If the parent directory
   * is world-writable, that too is insecure.
   */
  res = check_parent_dir_perms(p, path);
  if (res < 0) {
    return -1;
  }

  return 0;
}

/* Shared/common routines for PerUser and PerGroup. */

static array_header *reverse_db_parse_uris(pool *p, array_header *uris) {
  array_header *pconns = NULL;
  register unsigned int i;

  pconns = make_array(p, 0, sizeof(struct proxy_conn *));

  for (i = 0; i < uris->nelts; i++) {
    char *uri;
    const struct proxy_conn *pconn;

    pr_signals_handle();
    uri = ((char **) uris->elts)[i];

    /* Skip blank/empty URIs. */
    if (*uri == '\0') {
      continue;
    }

    pconn = proxy_conn_create(p, uri);
    if (pconn == NULL) {
      pr_trace_msg(trace_channel, 9, "skipping malformed URL '%s'", uri);
      continue;
    }

    *((const struct proxy_conn **) push_array(pconns)) = pconn;
  }

  return pconns;
}

/* SQL support routines. */

static cmd_rec *reverse_db_sql_cmd_create(pool *parent_pool,
    unsigned int argc, ...) {
  pool *cmd_pool = NULL;
  cmd_rec *cmd = NULL;
  register unsigned int i = 0;
  va_list argp;

  cmd_pool = make_sub_pool(parent_pool);
  cmd = (cmd_rec *) pcalloc(cmd_pool, sizeof(cmd_rec));
  cmd->pool = cmd_pool;

  cmd->argc = argc;
  cmd->argv = pcalloc(cmd->pool, argc * sizeof(void *));

  /* Hmmm... */
  cmd->tmp_pool = cmd->pool;

  va_start(argp, argc);
  for (i = 0; i < argc; i++) {
    cmd->argv[i] = va_arg(argp, char *);
  }
  va_end(argp);

  return cmd;
}

static const char *reverse_db_sql_quote_str(pool *p, char *str) {
  size_t len;
  cmdtable *cmdtab;
  cmd_rec *cmd;
  modret_t *res;

  len = strlen(str);
  if (len == 0) {
    return str;
  }

  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_escapestr", NULL, NULL, NULL);
  if (cmdtab == NULL) {
    return str;
  }

  cmd = reverse_db_sql_cmd_create(p, 1, pr_str_strip(p, str));
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);
  if (MODRET_ISDECLINED(res) ||
      MODRET_ISERROR(res)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error executing 'sql_escapestr'");
    return str;
  }

  return res->data;
}

/* Look for any user/group-specific ProxyReverseServers and load them, either
 * from file or SQL or whatever.  Randomly choose from one of those
 * backends.  If no user/group-specific backends are found, use the existing
 * "global" list.
 */

static array_header *reverse_db_pername_sql_parse_uris(pool *p,
    cmdtable *sql_cmdtab, const char *name, int per_user,
    const char *named_query) {
  array_header *backends, *results;
  pool *tmp_pool;
  cmd_rec *cmd;
  modret_t *res;

  tmp_pool = make_sub_pool(p);
  cmd = reverse_db_sql_cmd_create(tmp_pool, 3, "sql_lookup", named_query, name);
  res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, cmd);
  if (res == NULL ||
      MODRET_ISERROR(res)) {
    destroy_pool(tmp_pool);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error processing SQLNamedQuery '%s'", named_query);
    errno = EPERM;
    return NULL;
  }

  results = res->data;
  if (results->nelts == 0) {
    destroy_pool(tmp_pool);
    pr_trace_msg(trace_channel, 10,
      "SQLNamedQuery '%s' returned zero rows for %s '%s'", named_query,
      per_user ? "user" : "group", name);
    errno = ENOENT;
    return NULL;
  }

  backends = reverse_db_parse_uris(p, results);
  destroy_pool(tmp_pool);

  if (backends != NULL) {
    if (backends->nelts == 0) {
      errno = ENOENT;
      return NULL;
    }

    pr_trace_msg(trace_channel, 10,
      "SQLNamedQuery '%s' returned %d %s for %s '%s'", named_query,
       backends->nelts, backends->nelts != 1 ? "URLs" : "URL",
       per_user ? "user" : "group", name);
  }

  return backends;
}

static array_header *reverse_db_pername_backends_by_sql(pool *p,
    const char *name, int per_user) {
  config_rec *c;
  array_header *sql_backends = NULL;
  const char *quoted_name = NULL;
  cmdtable *sql_cmdtab;

  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    /* No mod_sql backend loaded; no lookups to do. */
    pr_trace_msg(trace_channel, 18,
      "no 'sql_lookup' symbol found (mod_sql not loaded?), skipping "
      "%s SQL lookups", per_user ? "per-user" : "per-group");
    errno = EPERM;
    return NULL;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
  while (c != NULL) {
    const char *named_query, *uri;
    array_header *backends = NULL;

    pr_signals_handle();

    uri = c->argv[1];
    if (uri == NULL) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (strncmp(uri, "sql:/", 5) != 0) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    named_query = uri + 5;

    if (quoted_name == NULL) {
      quoted_name = reverse_db_sql_quote_str(p, (char *) name);
    }

    pr_trace_msg(trace_channel, 17,
      "loading %s-specific ProxyReverseServers SQLNamedQuery '%s'",
      per_user ? "user" : "group", named_query);

    backends = reverse_db_pername_sql_parse_uris(p, sql_cmdtab, quoted_name,
      per_user, named_query);
    if (backends == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error reading ProxyReverseServers SQLNamedQuery '%s': %s", named_query,
        strerror(errno));
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (backends->nelts == 0) {
      pr_trace_msg(trace_channel, 3,
        "no usable URLs found by ProxyReverseServers SQLNamedQuery '%s', "
        "ignoring", named_query);

    } else {
      if (sql_backends == NULL) {
        sql_backends = backends;

      } else {
        array_cat(sql_backends, backends);
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers", FALSE);
  }

  return sql_backends;
}

static array_header *reverse_db_pername_backends_by_json(pool *p,
    const char *name, int per_user) {
  config_rec *c;
  array_header *file_backends = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
  while (c != NULL) {
    const char *path, *uri;
    int xerrno;
    array_header *backends = NULL;

    pr_signals_handle();

    uri = c->argv[1];
    if (uri == NULL) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (per_user) {
      if (strstr(uri, "%U") == NULL) {
        c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
          FALSE);
        continue;
      }

    } else {
      if (strstr(uri, "%g") == NULL) {
        c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
          FALSE);
        continue;
      }
    }

    if (strncmp(uri, "file:", 5) != 0) {
      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (per_user) {
      path = sreplace(p, (char *) (uri + 5), "%U", name, NULL);

    } else {
      path = sreplace(p, (char *) (uri + 5), "%g", name, NULL);
    }

    pr_trace_msg(trace_channel, 17,
      "loading %s-specific ProxyReverseServers file '%s'",
      per_user ? "user" : "group", path);

    PRIVS_ROOT
    backends = proxy_reverse_json_parse_uris(p, path);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (backends == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error reading ProxyReverseServers file '%s': %s", path,
        strerror(xerrno));

      if (xerrno == ENOENT) {
        /* No file for this user?  We're done looking, then. */
        break;
      }

      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
      continue;
    }

    if (backends->nelts == 0) {
      pr_trace_msg(trace_channel, 3,
        "no usable URLs found in ProxyReverseServers file '%s', ignoring",
        path); 

    } else {
      if (file_backends == NULL) {
        file_backends = backends;

      } else {
        array_cat(file_backends, backends);
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers", FALSE);
  }

  return file_backends;
}

array_header *proxy_reverse_pername_backends(pool *p, const char *name,
    int per_user) {
  array_header *file_backends, *sql_backends, *backends = NULL;

  file_backends = reverse_db_pername_backends_by_json(p, name, per_user);
  if (file_backends != NULL) {
    backends = file_backends;
  }

  sql_backends = reverse_db_pername_backends_by_sql(p, name, per_user);
  if (sql_backends != NULL) {
    if (backends != NULL) {
      array_cat(backends, sql_backends);

    } else {
      backends = sql_backends;
    }
  }

  if (backends == NULL) {
    if (default_backends == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "no %s servers found for %s '%s', and no global "
        "ProxyReverseServers configured", per_user ? "PerUser" : "PerGroup",
        per_user ? "user" : "group", name);
      errno = ENOENT;
      return NULL;
    }

    pr_trace_msg(trace_channel, 11,
      "using global ProxyReverseServers list for %s '%s'",
      per_user ? "user" : "group", name);
    backends = default_backends;
  }

  return backends;
}

int proxy_reverse_policy_is_sticky(int policy_id) {
  int sticky = FALSE;

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      sticky = TRUE;
      break;

    default:
      break;
  }

  return sticky;
}

const char *proxy_reverse_policy_name(int policy_id) {
  const char *name;

  switch (policy_id) {
    case PROXY_REVERSE_CONNECT_POLICY_RANDOM:
      name = "Random";
      break;

    case PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN:
      name = "RoundRobin";
      break;

    case PROXY_REVERSE_CONNECT_POLICY_SHUFFLE:
      name = "Shuffle";
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_USER:
      name = "PerUser";
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_GROUP:
      name = "PerGroup";
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS:
      name = "LeastConns";
      break;

    case PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME:
      name = "LeastResponseTime";
      break;

    case PROXY_REVERSE_CONNECT_POLICY_PER_HOST:
      name = "PerHost";
      break;

    default:
      name = "unknown/unsupported";
      break;
  }

  return name;
}

static int reverse_connect_index_used(pool *p, unsigned int vhost_id,
    int idx, long connect_ms) {
  int res;

  if (reverse_backends != NULL &&
      reverse_backends->nelts == 1) {
    return 0;
  }

  res = (reverse_ds.policy_update_backend)(p, reverse_ds.dsh,
    reverse_connect_policy, vhost_id, idx, 1, connect_ms);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error updating database entry for backend ID %d: %s", idx,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  reverse_backend_updated = TRUE;

  res = (reverse_ds.policy_used_backend)(p, reverse_ds.dsh,
    reverse_connect_policy, vhost_id, idx);
  if (res < 0) {
    int xerrno = errno;

    errno = xerrno;
    return -1;
  }

  return 0;
}

static const struct proxy_conn *get_reverse_server_conn(pool *p,
    struct proxy_session *proxy_sess, int *backend_id,
    const void *policy_data) {
  const struct proxy_conn *pconn;

  pconn = (reverse_ds.policy_next_backend)(p, reverse_ds.dsh,
    reverse_connect_policy, main_server->sid, default_backends, policy_data);
  if (pconn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error selecting backend server: %s", strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "selected backend server '%s'", proxy_conn_get_uri(pconn));

  *backend_id = reverse_backend_id;
  return pconn;
}

static int reverse_try_connect(pool *p, struct proxy_session *proxy_sess,
    const void *connect_data) {
  int backend_id = -1, use_tls, xerrno = 0;
  conn_t *server_conn = NULL;
  pr_response_t *resp = NULL;
  unsigned int resp_nlines = 0;
  const struct proxy_conn *pconn;
  const pr_netaddr_t *dst_addr;
  array_header *other_addrs = NULL;
  uint64_t connecting_ms, connected_ms;

  pconn = get_reverse_server_conn(p, proxy_sess, &backend_id, connect_data);
  if (pconn == NULL) {
    return -1;
  }

  dst_addr = proxy_conn_get_addr(pconn, &other_addrs);
  proxy_sess->dst_addr = dst_addr;
  proxy_sess->dst_pconn = pconn;
  proxy_sess->other_addrs = other_addrs;

  pr_gettimeofday_millis(&connecting_ms);
  server_conn = proxy_conn_get_server_conn(p, proxy_sess, dst_addr);
  if (server_conn == NULL) {
    xerrno = errno;

    if (other_addrs != NULL) {
      register unsigned int i;

      /* Try the other IP addresses for the configured name (if any) as well. */
      for (i = 0; i < other_addrs->nelts; i++) {
        dst_addr = ((pr_netaddr_t **) other_addrs->elts)[i];

        pr_gettimeofday_millis(&connecting_ms);

        pr_trace_msg(trace_channel, 8,
          "attempting to connect to other address #%u (%s) for requested "
          "URI '%.100s'", i+1, pr_netaddr_get_ipstr(dst_addr),
          proxy_conn_get_uri(proxy_sess->dst_pconn));
        server_conn = proxy_conn_get_server_conn(p, proxy_sess, dst_addr);
        if (server_conn != NULL) {
          proxy_sess->dst_addr = dst_addr;
          break;
        }
      }
    }

    if (server_conn == NULL) {
      xerrno = errno;

      /* TODO: Under what errno values will we mark this backend/idx as
       * "unhealthy"?  When we do, how will that unhealthy flag be taken into
       * account with the existing queries?  JOIN the index on the backend table
       * to get that unhealthy flag?
       */

      if (reverse_connect_index_used(p, main_server->sid, backend_id, -1) < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error updating database for backend server index %d: %s", backend_id,
          strerror(xerrno));
      }
    }
 
    errno = xerrno;
    return -1;
  }

  if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL) {
    pr_trace_msg(trace_channel, 17,
      "sending PROXY protocol message to %s#%u",
      pr_netaddr_get_ipstr(server_conn->remote_addr),
      ntohs(pr_netaddr_get_port(server_conn->remote_addr)));

    if (proxy_conn_send_proxy(p, server_conn) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error sending PROXY message to %s#%u: %s",
        pr_netaddr_get_ipstr(server_conn->remote_addr),
        ntohs(pr_netaddr_get_port(server_conn->remote_addr)),
        strerror(errno));
    }
  }

  /* XXX Support/send a CLNT command of our own?  Configurable via e.g.
   * "UserAgent" string?
   */

  proxy_sess->frontend_ctrl_conn = session.c;
  proxy_sess->backend_ctrl_conn = server_conn;

  use_tls = proxy_tls_using_tls();

  resp = proxy_ftp_ctrl_recv_resp(p, server_conn, &resp_nlines, 0);
  if (resp == NULL) {
    xerrno = errno;

    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to read banner from server %s:%u: %s",
      pr_netaddr_get_ipstr(server_conn->remote_addr),
      ntohs(pr_netaddr_get_port(server_conn->remote_addr)), strerror(xerrno));

    errno = xerrno;
    return -1;

  } else {
    int banner_ok = TRUE;

    pr_gettimeofday_millis(&connected_ms);

    if (resp->num[0] != '2') {
      banner_ok = FALSE;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "received banner from backend %s:%u%s: %s %s",
      pr_netaddr_get_ipstr(server_conn->remote_addr),
      ntohs(pr_netaddr_get_port(server_conn->remote_addr)),
      banner_ok ? "" : ", DISCONNECTING", resp->num, resp->msg);

    if (banner_ok == FALSE) {
      pr_inet_close(p, server_conn);
      proxy_sess->backend_ctrl_conn = NULL;
      errno = EPERM;
      return -1;
    }
  }

  pr_trace_msg(trace_channel, 8,
    "connected to backend '%.100s' in %ld ms",
    proxy_conn_get_uri(proxy_sess->dst_pconn),
    (long) (connected_ms - connecting_ms));

  if (reverse_connect_index_used(p, main_server->sid, backend_id,
      (long) (connected_ms - connecting_ms)) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error updating database for backend server index %d: %s", backend_id,
      strerror(errno));
  }

  /* Get the features supported by the backend server. */
  if (proxy_ftp_sess_get_feat(p, proxy_sess) < 0) {
    if (errno != EPERM) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to determine features of backend server: %s", strerror(errno));
    }
  }

  pr_response_block(TRUE);

  if (use_tls != PROXY_TLS_ENGINE_OFF) {
    if (proxy_ftp_sess_send_auth_tls(p, proxy_sess) < 0 &&
        errno != ENOSYS) {
      xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error enabling TLS on control connection to backend server: %s",
        strerror(xerrno));
      pr_inet_close(p, server_conn);
      proxy_sess->backend_ctrl_conn = NULL;

      pr_response_block(FALSE);
      errno = xerrno;
      return -1;
    }

    use_tls = proxy_tls_using_tls();
  }

  if (proxy_netio_postopen(server_conn->instrm) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "postopen error for backend control connection input stream: %s",
      strerror(xerrno));
    proxy_inet_close(session.pool, server_conn);
    proxy_sess->backend_ctrl_conn = NULL;

    pr_response_block(FALSE);

    /* Note that we explicitly return EINVAL here, to indicate to the calling
     * code in mod_proxy that it should return e.g. "Login incorrect."
     */
    errno = EINVAL;
    return -1;
  }

  if (proxy_netio_postopen(server_conn->outstrm) < 0) {
    xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "postopen error for backend control connection output stream: %s",
      strerror(xerrno));
    proxy_inet_close(session.pool, server_conn);
    proxy_sess->backend_ctrl_conn = NULL;

    pr_response_block(FALSE);

    /* Note that we explicitly return EINVAL here, to indicate to the calling
     * code in mod_proxy that it should return e.g. "Login incorrect."
     */
    errno = EINVAL;
    return -1;
  }

  if (use_tls != PROXY_TLS_ENGINE_OFF) {
    if (proxy_sess_state & PROXY_SESS_STATE_BACKEND_HAS_CTRL_TLS) {
      /* NOTE: should this be a fatal error? */
      (void) proxy_ftp_sess_send_pbsz_prot(p, proxy_sess);
    }
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT) {
    pr_response_block(FALSE);
  }

  if (proxy_ftp_ctrl_send_resp(p, session.c, resp, resp_nlines) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to send banner to client: %s", strerror(errno));
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT) {
    pr_response_block(TRUE);
  }

  (void) proxy_ftp_sess_send_host(p, proxy_sess);

  proxy_sess_state |= PROXY_SESS_STATE_CONNECTED;
  return 0;
}

static int reverse_connect(pool *p, struct proxy_session *proxy_sess) {
  register int i;
  int res;

  for (i = 0; i < reverse_retry_count; i++) {
    pr_signals_handle();

    res = reverse_try_connect(p, proxy_sess, NULL);
    if (res == 0) {
      return 0;
    }
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "ProxyRetryCount %d reached with no successful connection, failing",
    reverse_retry_count);
  errno = EPERM;
  return -1;
}

int proxy_reverse_use_proxy_auth(void) {
  if (proxy_opts & PROXY_OPT_USE_REVERSE_PROXY_AUTH) {
    return TRUE;
  }

  return FALSE;
}

int proxy_reverse_init(pool *p, const char *tables_dir, int flags) {
  const char *ds_name = "(unknown/unsupported)";
  int res, xerrno;
  void *dsh = NULL;
  server_rec *s = NULL;

  memset(&reverse_ds, 0, sizeof(reverse_ds));
  reverse_ds.backend_id = -1;

  switch (proxy_datastore) {
    case PROXY_DATASTORE_SQLITE:
      ds_name = "SQLite";
      res = proxy_reverse_db_as_datastore(&reverse_ds, proxy_datastore_data,
        proxy_datastore_datasz);
      xerrno = errno;
      break;

    case PROXY_DATASTORE_REDIS:
      ds_name = "Redis";
      res = proxy_reverse_redis_as_datastore(&reverse_ds, proxy_datastore_data,
        proxy_datastore_datasz);
      xerrno = errno;
      break;

    default:
      res = -1;
      xerrno = errno = EINVAL;
      break;
  }

  if (res < 0) {
    return -1;
  }

  dsh = (reverse_ds.init)(p, tables_dir, flags);
  if (dsh == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": failed to initialize %s datastore: %s", ds_name, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    config_rec *c;
    array_header *backends = NULL;
    int connect_policy = reverse_connect_policy;
    unsigned long opts = 0UL;

    c = find_config(s->conf, CONF_PARAM, "ProxyReverseServers", FALSE);
    while (c != NULL) {
      const char *uri;

      pr_signals_handle();

      uri = c->argv[1];
      if (uri != NULL) {
        int defer = FALSE;

        /* Handling of sql:// URIs is done later, in the session init
         * call, assuming we've connected to a SQL server.
         */
        if (strncmp(uri, "sql:/", 5) == 0) {
          defer = TRUE;
        }

        /* Skip any %U- or %g-bearing URIs. */
        if (defer == FALSE &&
            (strstr(uri, "%U") != NULL ||
             strstr(uri, "%g") != NULL)) {
          defer = TRUE;
        }

        if (defer) {
          c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
            FALSE);
          continue;
        }
      }

      if (backends == NULL) {
        backends = c->argv[0];

      } else {
        array_cat(backends, c->argv[0]);
      }

      c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers",
        FALSE);
    }

    c = find_config(s->conf, CONF_PARAM, "ProxyReverseConnectPolicy", FALSE);
    if (c != NULL) {
      connect_policy = *((int *) c->argv[0]);
    }

    c = find_config(s->conf, CONF_PARAM, "ProxyOptions", FALSE);
    while (c != NULL) {
      unsigned long o;

      pr_signals_handle();

      o = *((unsigned long *) c->argv[0]);
      opts |= o;

      c = find_config_next(c, c->next, CONF_PARAM, "ProxyOptions", FALSE);
    }

    res = (reverse_ds.policy_init)(p, dsh, connect_policy, s->sid,
      backends, opts);
    if (res < 0) {
      xerrno = errno;
      break;
    }
  }

  (void) (reverse_ds.close)(p, dsh);

  if (res < 0) {
    errno = xerrno;
    return -1;
  }

  return 0;
}

int proxy_reverse_free(pool *p) {

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* TODO: Implement any necessary cleanup */

  if (reverse_ds.dsh != NULL) {
    (void) (reverse_ds.close)(p, reverse_ds.dsh);
    reverse_ds.dsh = NULL;
  }

  return 0;
}

int proxy_reverse_sess_exit(pool *p) {
  if (reverse_backends != NULL &&
      reverse_backend_id >= 0) {
    if (reverse_backend_updated == TRUE) {
      int res;

      res = (reverse_ds.policy_update_backend)(p, reverse_ds.dsh,
        reverse_connect_policy, main_server->sid, reverse_ds.backend_id,
        -1, -1);
      if (res < 0) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error updating backend ID %d: %s", reverse_ds.backend_id,
          strerror(errno));
      }
    }
  }

  return 0;
}

static int set_reverse_flags(void) {
  if (proxy_opts & PROXY_OPT_USE_REVERSE_PROXY_AUTH) {
    reverse_flags = PROXY_REVERSE_FL_CONNECT_AT_PASS;

  } else {
    if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_USER) {
      reverse_flags = PROXY_REVERSE_FL_CONNECT_AT_USER;

    } else if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_GROUP) {
      /* Incompatible configuration: PerGroup balancing requires that the USER
       * name be authenticated, in order to discovery the primary group name.
       */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "ReverseProxyConnectPolicy PerGroup requires the UseReverseProxyAuth ProxyOption, rejecting connection due to incompatible configuration");
      pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
        ": ReverseProxyConnectPolicy PerGroup requires the UseReverseProxyAuth ProxyOption, rejecting connection due to incompatible configuration");
      errno = EINVAL;
      return -1;

    } else {
      reverse_flags = PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT;
    }
  }

  return 0;
}

int proxy_reverse_sess_free(pool *p, struct proxy_session *proxy_sess) {
  /* Reset any state. */

  reverse_backends = NULL;
  reverse_backend_id = -1;
  reverse_connect_policy = PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;
  reverse_flags = 0UL;
  reverse_retry_count = PROXY_DEFAULT_RETRY_COUNT;

  if (reverse_ds.dsh != NULL) {
    (void) (reverse_ds.close)(p, reverse_ds.dsh);
    reverse_ds.dsh = NULL;
  }

  return 0;
}

int proxy_reverse_sess_init(pool *p, const char *tables_dir,
    struct proxy_session *proxy_sess, int flags) {
  int res;
  config_rec *c;
  void *dsh;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyRetryCount", FALSE);
  if (c != NULL) {
    reverse_retry_count = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseServers",
    FALSE);
  if (c == NULL) {
    pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "'ProxyRole reverse' in effect, but no ProxyReverseServers configured");
    pr_log_pri(PR_LOG_NOTICE, MOD_PROXY_VERSION
      ": 'ProxyRole reverse' in effect, but no ProxyReverseServers configured");
    errno = EPERM;
    return -1;
  }

  /* We need to find the ProxyReverseServers that are NOT user/group-specific.
   */
  while (c != NULL) {
    const char *uri;

    pr_signals_handle();

    uri = c->argv[1];
    if (uri == NULL) {
      if (default_backends == NULL) {
        default_backends = c->argv[0];

      } else {
        array_cat(default_backends, c->argv[0]);
      }

      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyReverseServers", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyReverseConnectPolicy",
    FALSE);
  if (c != NULL) {
    reverse_connect_policy = *((int *) c->argv[0]);
  }

  dsh = (reverse_ds.open)(p, tables_dir, default_backends);
  if (dsh == NULL) {
    return -1;
  }

  reverse_ds.dsh = dsh;

  if (set_reverse_flags() < 0) {
    return -1;
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_SESS_INIT) {
    res = reverse_connect(p, proxy_sess);
    if (res < 0) {
      return -1;
    }
  }

  return 0;
}

int proxy_reverse_have_authenticated(cmd_rec *cmd) {
  int authd = FALSE;

  /* Authenticated here means authenticated *to the proxy*, i.e. should we
   * allow more commands, or reject them because the client hasn't authenticated
   * yet.
   */

  if (proxy_sess_state & PROXY_SESS_STATE_BACKEND_AUTHENTICATED) {
    authd = TRUE;
  }

  if (authd == FALSE) {
    pr_response_send(R_530, _("Please login with USER and PASS"));
  }

  return authd;
}

static pr_json_array_t *read_json_array(pool *p, pr_fh_t *fh, off_t filesz) {
  pr_json_array_t *json = NULL;
  char *buf, *ptr;
  int res;
  off_t len;

  len = filesz;
  buf = ptr = palloc(p, len+1);
  buf[len] = '\0';

  res = pr_fsio_read(fh, buf, len);
  while (res != len) {
    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        res = pr_fsio_read(fh, buf, len);
        continue;
      }

      return NULL;
    }

    if (res == 0) {
      /* EOF, but we shouldn't reach this. */
      pr_trace_msg(trace_channel, 14,
        "unexpectedly reached EOF when reading '%s'", fh->fh_path);
      errno = EOF;
      return NULL;
    }

    /* Paranoia, paranoia...*/
    if (len > res) {
      errno = EIO;
      return NULL;
    }

    /* Short read: advance the buffer, decrement the length, and read more. */
    buf += res;
    len -= res; 

    pr_signals_handle();
    res = pr_fsio_read(fh, buf, len);
  }

  json = pr_json_array_from_text(p, ptr);
  if (json == NULL) {
    pr_trace_msg(trace_channel, 3,
      "invalid JSON format found in '%s'", fh->fh_path);
    errno = EINVAL;
    return NULL;
  }

  return json;
}

array_header *proxy_reverse_json_parse_uris(pool *p, const char *path) {
  register unsigned int i, nelts;
  int count = 0, reached_eol = TRUE, res, xerrno = 0;
  pr_fh_t *fh;
  array_header *uris = NULL;
  struct stat st;
  pool *tmp_pool;
  pr_json_array_t *json = NULL;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*path != '/') {
    /* A relative path?  Unacceptable. */
    errno = EINVAL;
    return NULL;
  }

  res = check_file_perms(p, path);
  if (res < 0) {
    return NULL;
  }

  /* Use a nonblocking open() for the path; it could be a FIFO, and we don't
   * want to block forever if the other end of the FIFO is not running.
   */
  fh = pr_fsio_open(path, O_RDONLY|O_NONBLOCK);
  if (fh == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 7,
      "error opening ProxyReverseServers file '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  pr_fsio_set_block(fh);

  /* Stat the file to find the optimal buffer size for reading. */
  res = pr_fsio_fstat(fh, &st);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "unable to fstat '%s': %s", path, strerror(xerrno));
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return NULL;
  }

  if (st.st_size == 0) {
    /* Return an empty array for this empty file. */
    pr_trace_msg(trace_channel, 15,
      "found no items in empty file '%s'", fh->fh_path);

    (void) pr_fsio_close(fh);
    uris = make_array(p, 1, sizeof(struct proxy_conn *));
    return uris;
  }

  if (st.st_size > PROXY_REVERSE_JSON_MAX_FILE_SIZE) {
    pr_trace_msg(trace_channel, 1,
      "'%s' file size (%lu bytes) exceeds max JSON file size (%lu bytes)",
      path, (unsigned long) st.st_size,
      (unsigned long) PROXY_REVERSE_JSON_MAX_FILE_SIZE);
    (void) pr_fsio_close(fh);
    errno = EPERM;
    return NULL;
  }

  fh->fh_iosz = st.st_blksize;

  tmp_pool = make_sub_pool(p);
  json = read_json_array(tmp_pool, fh, st.st_size);
  xerrno = errno;

  (void) pr_fsio_close(fh);

  if (json == NULL) {
    pr_trace_msg(trace_channel, 1,
      "unable to read JSON array from '%s': %s", path, strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  count = pr_json_array_count(json);
  if (count >= 0) {
    pr_trace_msg(trace_channel, 12,
      "found items (count %d) in JSON file '%s'", count, path);
  }

  uris = make_array(p, 1, sizeof(struct proxy_conn *));

  nelts = count;
  if (nelts > PROXY_REVERSE_JSON_MAX_ITEMS) {
    nelts = PROXY_REVERSE_JSON_MAX_ITEMS;
    reached_eol = FALSE;
  }

  for (i = 0; i < nelts; i++) {
    char *uri = NULL;
    const struct proxy_conn *pconn;

    pr_signals_handle();

    if (pr_json_array_get_string(p, json, i, &uri) == 0) {
      pconn = proxy_conn_create(p, uri);
      if (pconn == NULL) {
        pr_trace_msg(trace_channel, 9,
          "skipping malformed URL '%s' found in file '%s'", uri, path);
        continue;
      }

      *((const struct proxy_conn **) push_array(uris)) = pconn;

    } else {
      pr_trace_msg(trace_channel, 2,
        "error getting string from JSON array at index %u: %s", i,
        strerror(errno));
    }
  }

  (void) pr_json_array_free(json);
  destroy_pool(tmp_pool);

  if (reached_eol == FALSE) {
    pr_trace_msg(trace_channel, 3,
      "warning: skipped ProxyReverseServers '%s' data (only used "
      "first %u items)", path, i);
  }

  pr_trace_msg(trace_channel, 12,
    "created URIs (count %u) from JSON file '%s'", uris->nelts, path);
  return uris;
}

int proxy_reverse_connect_get_policy(const char *policy) {
  if (policy == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (strncasecmp(policy, "Random", 7) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_RANDOM;

  } else if (strncasecmp(policy, "RoundRobin", 11) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_ROUND_ROBIN;

  } else if (strncasecmp(policy, "Shuffle", 8) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_SHUFFLE;

  } else if (strncasecmp(policy, "LeastConns", 11) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_LEAST_CONNS;

  } else if (strncasecmp(policy, "PerUser", 8) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_USER;

  } else if (strncasecmp(policy, "PerGroup", 9) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_GROUP;

  } else if (strncasecmp(policy, "PerHost", 8) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_PER_HOST;

  } else if (strncasecmp(policy, "LeastResponseTime", 18) == 0) {
    return PROXY_REVERSE_CONNECT_POLICY_LEAST_RESPONSE_TIME;
  }

  errno = ENOENT;
  return -1;
}

static int send_user(struct proxy_session *proxy_sess, cmd_rec *cmd,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  char *orig_user;
  const char *uri_user;

  orig_user = cmd->arg;
  uri_user = proxy_conn_get_username(proxy_sess->dst_pconn);
  if (uri_user != NULL) {
    /* We have URI-specific USER name to use, instead of the client-provided
     * one.
     */
    pr_trace_msg(trace_channel, 18,
      "using URI-specific username '%s' instead of client-provided '%s'",
      uri_user, orig_user);
    cmd->argv[1] = cmd->arg = pstrdup(cmd->pool, uri_user);
  }

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  cmd->argv[1] = cmd->arg = orig_user;

  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines, 0);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Note that the response message may contain the per-URI user name we
   * sent; be sure to preserve the illusion, and re-write the response as
   * necessary.
   */
  if (uri_user != NULL) {
    /* TODO: handle the case where there are multiple response lines. */
    if (strstr(resp->msg, uri_user) != NULL) {
      resp->msg = sreplace(cmd->pool, resp->msg, uri_user, orig_user, NULL);
    }
  }

  if (resp->num[0] == '2' ||
      resp->num[0] == '3') {
    *successful = TRUE;

    if (strcmp(resp->num, R_232) == 0) {
      proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
      clear_user_creds();
      pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
    }
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return -1;
  }

  return 0;
}

int proxy_reverse_handle_user(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful, int *block_responses) {
  int res;

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_PASS) {
    /* If we're already connected, then proxy this USER command through to the
     * backend, otherwise we let the proftpd internals deal with it locally,
     * leading to proxy auth.
     */
    if (!(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED)) {
      *block_responses = FALSE;
      return 0;
    }
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_USER) {
    register int i;
    int connected = FALSE, xerrno = 0;

    for (i = 0; i < reverse_retry_count; i++) {
      pr_signals_handle();

      res = reverse_try_connect(proxy_pool, proxy_sess, cmd->arg);
      if (res == 0) {
        connected = TRUE;
        break;
      }

      xerrno = errno;
    }

    pr_response_block(FALSE);

    if (connected == FALSE) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "ProxyRetryCount %d reached with no successful connection, failing",
        reverse_retry_count);
      *successful = FALSE;

      if (xerrno != EINVAL) {
        errno = EPERM;
      } else {
        errno = xerrno;
      }

      return -1;
    }
  }

  res = send_user(proxy_sess, cmd, successful);
  if (res < 0) {
    return -1;
  }

  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_USER) {
    /* Restore the normal response blocking, undone for the PerUser policy. */
    pr_response_block(TRUE);
  }

  return 1;
}

static int send_pass(struct proxy_session *proxy_sess, cmd_rec *cmd,
    int *successful) {
  int res, xerrno;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  const char *uri_user, *uri_pass;
  char *orig_pass;

  if (proxy_sess == NULL ||
      proxy_sess->backend_ctrl_conn == NULL) {
    pr_trace_msg(trace_channel, 4,
      "unable to send PASS to backend server: No backend control connection");
    errno = EPERM;
    return -1;
  }

  orig_pass = cmd->arg;
  uri_user = proxy_conn_get_username(proxy_sess->dst_pconn);
  uri_pass = proxy_conn_get_password(proxy_sess->dst_pconn);
  if (uri_pass != NULL) {
    size_t uri_passlen;

    uri_passlen = strlen(uri_pass);
    if (uri_passlen > 0) {
      /* We have URI-specific password to use, instead of the client-provided
       * one.
       */
      pr_trace_msg(trace_channel, 18,
        "using URI-specific password instead of client-provided one");
      cmd->argv[1] = cmd->arg = pstrdup(cmd->pool, uri_pass);
    }
  }

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    cmd);
  cmd->argv[1] = cmd->arg = orig_pass;

  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines, 0);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    /* If we receive an EPERM here, it is probably because the backend
     * closed its control connection, yielding an EOF.  To better indicate
     * this situation, propagate the error using EPIPE.
     */
    if (xerrno == EPERM) {
      xerrno = EPIPE;
    }

    errno = xerrno;
    return -1;
  }

  /* Note that the response message may contain the per-URI user name we
   * sent; be sure to preserve the illusion, and re-write the response as
   * necessary.
   */
  if (uri_user != NULL) {
    const char *orig_user;

    orig_user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    if (orig_user != NULL) {
      /* TODO: handle the case where there are multiple response lines. */
      if (strstr(resp->msg, uri_user) != NULL) {
        resp->msg = sreplace(cmd->pool, resp->msg, uri_user, orig_user, NULL);
      }
    }
  }

  /* XXX What about other response codes for PASS? */
  if (resp->num[0] == '2') {
    *successful = TRUE;

    proxy_sess_state |= PROXY_SESS_STATE_BACKEND_AUTHENTICATED;
    clear_user_creds();
    pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE); 
  }

  res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool, proxy_sess->frontend_ctrl_conn,
    resp, resp_nlines);
  if (res < 0) {
    xerrno = errno;

    pr_response_block(TRUE);
    errno = xerrno;
    return -1;
  }

  return 0;
}

int proxy_reverse_handle_pass(cmd_rec *cmd, struct proxy_session *proxy_sess,
    int *successful, int *block_responses) {
  int res, xerrno = 0;

  /* This CONNECT_AT_PASS flag indicates that we are using proxy auth when
   * reverse proxying.
   */
  if (reverse_flags == PROXY_REVERSE_FL_CONNECT_AT_PASS) {
    if (!(proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED)) {
      const char *user = NULL;

      user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      res = proxy_session_check_password(cmd->pool, user, cmd->arg);
      if (res < 0) {
        errno = EINVAL;
        return -1;
      }

      res = proxy_session_setup_env(proxy_pool, user,
        PROXY_SESSION_FL_CHECK_LOGIN_ACL);
      if (res < 0) {
        errno = EINVAL;
        return -1;
      }

      if (session.auth_mech) {
        pr_log_debug(DEBUG2, "user '%s' authenticated by %s", user,
          session.auth_mech);
      }
    }

    if (!(proxy_sess_state & PROXY_SESS_STATE_CONNECTED)) {
      register int i;
      int connected = FALSE;
      const char *user = NULL, *connect_name = NULL;
      cmd_rec *user_cmd;

      /* If we're using a sticky policy, we need to know the USER name that was
       * sent.
       */
      if (proxy_reverse_policy_is_sticky(reverse_connect_policy) == TRUE) {
        user = connect_name = pr_table_get(session.notes, "mod_auth.orig-user",
          NULL);

        /* If the sticky policy in question is PerGroup, then we also need
         * to know the authenticated user's primary group name.
         */
        if (proxy_sess_state & PROXY_SESS_STATE_PROXY_AUTHENTICATED) {
          if (reverse_connect_policy == PROXY_REVERSE_CONNECT_POLICY_PER_GROUP) {
            connect_name = session.group;
          }
        }
      }

      for (i = 0; i < reverse_retry_count; i++) {
        pr_signals_handle();

        res = reverse_try_connect(proxy_pool, proxy_sess, connect_name);
        if (res == 0) {
          connected = TRUE;
          break;
        }

        xerrno = errno;
      }

      pr_response_block(FALSE);

      if (connected == FALSE) {
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "ProxyRetryCount %d reached with no successful connection, failing",
          reverse_retry_count);
        *successful = FALSE;

        if (xerrno != EINVAL) {
          errno = EPERM;
        } else {
          errno = xerrno;
        }

        return -1;
      }

      if (user == NULL) {
        user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      }

      user_cmd = pr_cmd_alloc(cmd->tmp_pool, 2, C_USER, user);
      user_cmd->arg = pstrdup(cmd->tmp_pool, user);

      /* Since we're replaying the USER command here, we want to make sure
       * that the USER response from the backend isn't played back to the
       * frontend client.
       */
      pr_response_block(TRUE);
      res = send_user(proxy_sess, user_cmd, successful);
      xerrno = errno;
      pr_response_block(FALSE);

      if (res < 0) {
        errno = xerrno;
        return -1;
      }
    }
  }

  res = send_pass(proxy_sess, cmd, successful);
  if (res < 0) {
    return -1;
  }

  if (reverse_flags != PROXY_REVERSE_FL_CONNECT_AT_PASS &&
      *successful == TRUE) {
    const char *user = NULL;

    /* If we're not using proxy auth, still make sure that everything is
     * set up properly.
     */

    user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    res = proxy_session_setup_env(proxy_pool, user, 0);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }
  }

  return 1;
}
