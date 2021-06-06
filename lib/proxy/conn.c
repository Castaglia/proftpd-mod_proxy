/*
 * ProFTPD - mod_proxy conn implementation
 * Copyright (c) 2012-2021 TJ Saunders
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

#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

#include "proxy/conn.h"
#include "proxy/dns.h"
#include "proxy/netio.h"
#include "proxy/inet.h"
#include "proxy/session.h"
#include "proxy/tls.h"
#include "proxy/uri.h"

struct proxy_conn {
  pool *pconn_pool;

  const char *pconn_uri;
  const char *pconn_proto;
  const char *pconn_host;
  const char *pconn_hostport;
  int pconn_port;
  int pconn_tls;

  int pconn_use_dns_srv;
  int pconn_use_dns_txt;

  /* These are only used for DNS SRV, DNS TXT URLs. */
  int pconn_dns_ttl;
  int pconn_dns_timer_id;

  /* Note that these are deliberately NOT 'const', so that they can be
   * scrubbed in the per-session memory space, once backend authentication
   * has occurred.
   */
  char *pconn_username;
  char *pconn_password;

  const pr_netaddr_t *pconn_addr;
  array_header *pconn_addrs;
};

static const char *supported_protocols[] = {
  "ftp",
  "ftp+srv",
  "ftp+txt",
  "ftps",
  "ftps+srv",
  "ftps+txt",
  "sftp",
  "sftp+srv",
  "sftp+txt",

  NULL
};

/* PROXY protocol V2 */
#define PROXY_PROTOCOL_V2_SIGLEN		12
#define PROXY_PROTOCOL_V2_HDRLEN		16
#define PROXY_PROTOCOL_V2_TRANSPORT_STREAM	0x01
#define PROXY_PROTOCOL_V2_FAMILY_INET		0x10
#define PROXY_PROTOCOL_V2_FAMILY_INET6		0x20
#define PROXY_PROTOCOL_V2_ADDRLEN_INET		(4 + 4 + 2 + 2)
#define PROXY_PROTOCOL_V2_ADDRLEN_INET6		(16 + 16 + 2 + 2)
static uint8_t proxy_protocol_v2_sig[PROXY_PROTOCOL_V2_SIGLEN] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

#define PROXY_PROTOCOL_V2_TLV_ALPN		0x01
#define PROXY_PROTOCOL_V2_TLV_AUTHORITY		0x02
#define PROXY_PROTOCOL_V2_TLV_UNIQUE_ID		0x05
#define PROXY_PROTOCOL_V2_TLV_SSL		0x20
#define PROXY_PROTOCOL_V2_TLV_SSL_VERSION	0x21
#define PROXY_PROTOCOL_V2_TLV_SSL_CIPHER	0x23

static const char *trace_channel = "proxy.conn";

static int supported_protocol(const char *proto) {
  register unsigned int i;

  for (i = 0; supported_protocols[i] != NULL; i++) {
    if (strcmp(proto, supported_protocols[i]) == 0) {
      return 0;
    }
  }

  errno = ENOENT;
  return -1;
}

int proxy_conn_connect_timeout_cb(CALLBACK_FRAME) {
  const struct proxy_session *proxy_sess;
  const pr_netaddr_t *server_addr;

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  server_addr = pr_table_get(session.notes, "mod_proxy.proxy-connect-address",
    NULL);

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "timed out connecting to %s:%d after %d %s",
    pr_netaddr_get_ipstr(server_addr), ntohs(pr_netaddr_get_port(server_addr)),
    proxy_sess->connect_timeout,
    proxy_sess->connect_timeout != 1 ? "seconds" : "second");

  pr_event_generate("mod_proxy.timeout-connect", NULL);

#if 0
  /* XXX We might not want to disconnect the frontend client here, right? */
  pr_log_pri(PR_LOG_NOTICE, "%s", "Connect timed out, disconnected");
  pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_TIMEOUT,
    "ProxyTimeoutConnect");
#endif

  /* Do not restart the timer. */
  return 0;
}

static struct proxy_conn *proxy_conn_get_addrs(pool *p, const char *uri,
    struct proxy_conn *pconn) {
  pr_netaddr_t *pconn_addr;

  pconn_addr = (pr_netaddr_t *) pr_netaddr_get_addr(pconn->pconn_pool,
    pconn->pconn_host, &(pconn->pconn_addrs));
  if (pconn_addr == NULL) {
    pr_trace_msg(trace_channel, 2, "unable to resolve '%s' from URI '%s': %s",
      pconn->pconn_host, uri, strerror(errno));
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to resolve '%s' from URI '%s'", pconn->pconn_host, uri);
    errno = EINVAL;
    return NULL;
  }

  if (pr_netaddr_set_port2(pconn_addr, pconn->pconn_port) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "unable to set port %d from URI '%s': %s", pconn->pconn_port, uri,
      strerror(xerrno));
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to set port %d from URI '%s': %s", pconn->pconn_port, uri,
      strerror(xerrno));
    errno = EINVAL;
    return NULL;
  }

  pconn->pconn_addr = pconn_addr;

  if (pconn->pconn_addrs != NULL) {
    register unsigned int i;
    pr_netaddr_t **elts;

    elts = pconn->pconn_addrs->elts;
    for (i = 0; i < pconn->pconn_addrs->nelts; i++) {
      pr_netaddr_t *elt;

      elt = elts[i];

      if (pr_netaddr_set_port2(elt, pconn->pconn_port) < 0) {
        pr_trace_msg(trace_channel, 3,
          "unable to set port %d from URI '%s': %s", pconn->pconn_port, uri,
          strerror(errno));
      }
    }
  }

  return pconn;
}

static struct proxy_conn *proxy_conn_use_dns_srv_addrs(pool *p, const char *uri,
    struct proxy_conn *pconn, unsigned int flags) {
  int res;
  const char *name;
  proxy_dns_type_e dns_type = PROXY_DNS_SRV;
  array_header *resp = NULL;
  uint32_t srv_ttl = 0;

  name = pconn->pconn_host;

  res = proxy_dns_resolve(pconn->pconn_pool, name, dns_type, &resp, &srv_ttl);
  if (res > 0) {
    pr_netaddr_t **elts, *first_addr;

    elts = resp->elts;

    /* Slightly naughty way to pop the first address of the array. */
    first_addr = elts[0];
    resp->elts = &(elts[1]);
    resp->nelts--;

    pconn->pconn_addr = first_addr;
    pconn->pconn_port = ntohs(pr_netaddr_get_port(first_addr));
    pconn->pconn_addrs = resp;

    pconn->pconn_dns_ttl = (int) srv_ttl;

    if (flags & PROXY_CONN_CREATE_FL_USE_DNS_TTL) {
      /* XXX TODO: Schedule timer for re-resolving URL on TTL.
       *
       * The existing Timer API does not provide room for custom "user data"
       * pointers; need to fix that.  In the mean time, we'll just need to track
       * things ourselves with a lookup table: timer ID -> pconn.
       *
       * This has the advantage of providing a way to iterate through the table,
       * removing all timer IDs (then destroying the table) in a session
       * process.
       *
       * What memory pool should be used for this table, that would be available
       * at startup time?  proxy_pool?
       *
       * pconn->pconn_dns_timer_id = pr_timer_add(pconn->pconn_dns_ttl, -1,
       *   &proxy_module, proxy_conn_resolve_cb, ...);
       */
    }

    return pconn;
  }

  /* Always fall back to normal name resolution. */
  return proxy_conn_get_addrs(p, uri, pconn);
}

static struct proxy_conn *proxy_conn_use_dns_txt_addrs(pool *p, const char *uri,
    struct proxy_conn *pconn, unsigned int flags) {
  int res;
  const char *name;
  proxy_dns_type_e dns_type = PROXY_DNS_TXT;
  array_header *resp = NULL;

  name = pconn->pconn_host;

  res = proxy_dns_resolve(p, name, dns_type, &resp, NULL);
  if (res > 0) {
    register unsigned int i;
    const char **elts;

    elts = resp->elts;
    for (i = 0; i < resp->nelts; i++) {
      const char *elt;
      char *scheme, *host;
      unsigned int port;
      int str_flags = PR_STR_FL_IGNORE_CASE;
      struct proxy_conn *elt_pconn;

      elt = elts[i];

      /* Many domains have multiple TXT records, for SPF, domain validation,
       * etc.  So we are only interested in any TXT records are that valid
       * (to us) URLs.
       */

      res = proxy_uri_parse(p, elt, &scheme, &host, &port, NULL, NULL);
      if (res < 0) {
        pr_trace_msg(trace_channel, 19,
          "skipping non-URL TXT record '%s' discovered for '%s'", elt, uri);
        continue;
      }

      /* If the URL found in a TXT record itself uses a DNS SRV or TXT
       * variant, skip it.  That way lies circular madness.
       */
      if (pr_strnrstr(scheme, 0, "+srv", 0, str_flags) == TRUE ||
          pr_strnrstr(scheme, 0, "+txt", 0, str_flags) == TRUE) {
        pr_trace_msg(trace_channel, 19,
          "skipping URL TXT record '%s' discovered for '%s'", elt, uri);
        continue;
      }

      elt_pconn = (struct proxy_conn *) proxy_conn_create(p, elt, 0);
      if (elt_pconn != NULL) {
        destroy_pool(pconn->pconn_pool);
        return elt_pconn;
      }
    }
  }

  /* Always fall back to normal name resolution. */
  return proxy_conn_get_addrs(p, uri, pconn);
}

const struct proxy_conn *proxy_conn_create(pool *p, const char *uri,
    unsigned int flags) {
  int res, xerrno;
  int use_dns_srv = FALSE, use_dns_txt = FALSE, use_tls = PROXY_TLS_ENGINE_AUTO;
  char *ptr = NULL;
  char hostport[512], *proto, *remote_host, *username = NULL, *password = NULL;
  unsigned int remote_port;
  struct proxy_conn *pconn, *pconn2;
  pool *pconn_pool;

  if (p == NULL ||
      uri == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = proxy_uri_parse(p, uri, &proto, &remote_host, &remote_port, &username,
    &password);
  if (res < 0) {
    return NULL;
  }

  if (supported_protocol(proto) < 0) {
    pr_trace_msg(trace_channel, 4, "unsupported protocol '%s' in URI '%.100s'",
      proto, uri);
    errno = EPERM;
    return NULL;
  }

  if (strcmp(proto, "ftps") == 0 ||
      strncmp(proto, "ftps+", 5) == 0) {
    /* If the 'ftps' scheme is used, then FTPS is REQUIRED for connections
     * to this server.
     */
    use_tls = PROXY_TLS_ENGINE_ON;

    /* We automatically (and only) use implicit FTPS for port 990.  Note that
     * we do NOT support implicit FTPS for URLs using DNS SRV, TXT.
     */
    if (strcmp(proto, "ftps") == 0 &&
        remote_port == PROXY_TLS_IMPLICIT_FTPS_PORT) {
      use_tls = PROXY_TLS_ENGINE_IMPLICIT;
    }

  } else if (strcmp(proto, "sftp") == 0 ||
             strncmp(proto, "sftp+", 5) == 0) {
    /* As might be obvious, do not try to use TLS against an SSH2/SFTP
     * server.
     */
    use_tls = PROXY_TLS_ENGINE_OFF;
  }

  if (pr_strnrstr(proto, 0, "+srv", 0, PR_STR_FL_IGNORE_CASE) == TRUE) {
    use_dns_srv = TRUE;
  }

  if (pr_strnrstr(proto, 0, "+txt", 0, PR_STR_FL_IGNORE_CASE) == TRUE) {
    use_dns_txt = TRUE;
  }

  memset(hostport, '\0', sizeof(hostport));
  snprintf(hostport, sizeof(hostport)-1, "%s:%u", remote_host, remote_port);

  pconn_pool = pr_pool_create_sz(p, 128); 
  pr_pool_tag(pconn_pool, "proxy connection pool");

  pconn = pcalloc(pconn_pool, sizeof(struct proxy_conn));
  pconn->pconn_pool = pconn_pool;
  pconn->pconn_host = pstrdup(pconn_pool, remote_host);
  pconn->pconn_port = remote_port;
  pconn->pconn_hostport = pstrdup(pconn_pool, hostport);
  pconn->pconn_uri = pstrdup(pconn_pool, uri);
  pconn->pconn_tls = use_tls;
  pconn->pconn_use_dns_srv = use_dns_srv;
  pconn->pconn_use_dns_txt = use_dns_txt;

  /* Adjust the proto (scheme, actually) to account for possible DNS SRV,
   * TXT usage.
   */
  ptr = strchr(proto, '+');
  if (ptr != NULL) {
    pconn->pconn_proto = pstrndup(pconn_pool, proto, ptr - proto);

  } else {
    pconn->pconn_proto = pstrdup(pconn_pool, proto);
  }

  if (username != NULL) {
    pconn->pconn_username = pstrdup(pconn_pool, username);
  }
  if (password != NULL) {
    pconn->pconn_password = pstrdup(pconn_pool, password);
  }

  /* Here is where we discover the addresses for this URI.  We might use
   * DNS SRV, DNS TXT, or normal DNS A/AAAA records.
   */

  if (use_dns_srv == TRUE ||
      use_dns_txt == TRUE) {
    pr_trace_msg(trace_channel, 5,
      "ignoring port %u from URI '%.100s' since port will be discovered "
      "from %s DNS records", remote_port, uri, use_dns_srv ? "SRV" : "TXT");
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "ignoring port %u from URI '%.100s' since port will be discovered "
      "from %s DNS records", remote_port, uri, use_dns_srv ? "SRV" : "TXT");
  }

  if (use_dns_srv == TRUE) {
    pconn2 = proxy_conn_use_dns_srv_addrs(p, uri, pconn, flags);
    xerrno = errno;

  } else if (use_dns_txt == TRUE) {
    pconn2 = proxy_conn_use_dns_txt_addrs(p, uri, pconn, flags);
    xerrno = errno;

  } else {
    pconn2 = proxy_conn_get_addrs(p, uri, pconn);
    xerrno = errno;
  }

  if (pconn2 == NULL) {
    destroy_pool(pconn->pconn_pool);
    errno = xerrno;
    return NULL;
  }

  return pconn2;
}

void proxy_conn_free(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    return;
  }

  destroy_pool(pconn->pconn_pool);
}

const pr_netaddr_t *proxy_conn_get_addr(const struct proxy_conn *pconn,
    array_header **addrs) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (addrs != NULL) {
    *addrs = pconn->pconn_addrs;
  }

  return pconn->pconn_addr;
}

int proxy_conn_get_dns_ttl(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* We really only care about/honor DNS TTLs for the DNS SRV. */
  if (pconn->pconn_use_dns_srv == FALSE) {
    errno = EPERM;
    return -1;
  }

  if (pconn->pconn_dns_ttl <= 0) {
    errno = ENOENT;
    return -1;
  }

  return pconn->pconn_dns_ttl;
}

const char *proxy_conn_get_host(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pconn->pconn_host;
}

const char *proxy_conn_get_hostport(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pconn->pconn_hostport;
}

int proxy_conn_get_port(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return -1;
  }

  return pconn->pconn_port;
}

void proxy_conn_clear_username(const struct proxy_conn *pconn) {
  size_t len;
  struct proxy_conn *conn;

  if (pconn == NULL) {
    return;
  }

  if (pconn->pconn_username == NULL) {
    return;
  }

  len = strlen(pconn->pconn_username);

  conn = (struct proxy_conn *) pconn;
  pr_memscrub(conn->pconn_username, len);
  conn->pconn_username = NULL;
}

const char *proxy_conn_get_username(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pconn->pconn_username;
}

void proxy_conn_clear_password(const struct proxy_conn *pconn) {
  size_t len;
  struct proxy_conn *conn;

  if (pconn == NULL) {
    return;
  }

  if (pconn->pconn_password == NULL) {
    return;
  }

  len = strlen(pconn->pconn_password);

  conn = (struct proxy_conn *) pconn;
  pr_memscrub(conn->pconn_password, len);
  conn->pconn_password = NULL;
}

const char *proxy_conn_get_password(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }
  
  return pconn->pconn_password;
}

int proxy_conn_get_tls(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return -1;
  }

  return pconn->pconn_tls;
}

int proxy_conn_use_dns_srv(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return -1;
  }

  return pconn->pconn_use_dns_srv;
}

int proxy_conn_use_dns_txt(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return -1;
  }

  return pconn->pconn_use_dns_txt;
}

conn_t *proxy_conn_get_server_conn(pool *p, struct proxy_session *proxy_sess,
    const pr_netaddr_t *remote_addr) {
  const pr_netaddr_t *bind_addr = NULL, *local_addr = NULL;
  const char *remote_ipstr = NULL;
  unsigned int remote_port;
  conn_t *server_conn, *ctrl_conn;
  int res;

  if (proxy_sess->connect_timeout > 0) {
    const char *notes_key = "mod_proxy.proxy-connect-address";

    proxy_sess->connect_timerno = pr_timer_add(proxy_sess->connect_timeout,
      -1, &proxy_module, proxy_conn_connect_timeout_cb, "ProxyTimeoutConnect");

    (void) pr_table_remove(session.notes, notes_key, NULL);

    if (pr_table_add(session.notes, notes_key, remote_addr,
        sizeof(pr_netaddr_t)) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error stashing proxy connect address note: %s", strerror(errno));
    }
  }

  remote_ipstr = pr_netaddr_get_ipstr(remote_addr);
  remote_port = ntohs(pr_netaddr_get_port(remote_addr));

  /* Check the family of the retrieved address vs what we'll be using
   * to connect.  If there's a mismatch, we need to get an addr with the
   * matching family.
   */

  if (pr_netaddr_get_family(session.c->local_addr) == pr_netaddr_get_family(remote_addr)) {
    local_addr = session.c->local_addr;

  } else {
    /* In this scenario, the proxy has an IPv6 socket, but the remote/backend
     * server has an IPv4 (or IPv4-mapped IPv6) address.  OR it's the proxy
     * which has an IPv4 socket, and the remote/backend server has an IPv6
     * address.
     */
    if (pr_netaddr_get_family(session.c->local_addr) == AF_INET) {
      char *ip_str;

      /* Convert the local address from an IPv4 to an IPv6 addr. */
      ip_str = pcalloc(p, INET6_ADDRSTRLEN + 1);
      snprintf(ip_str, INET6_ADDRSTRLEN, "::ffff:%s",
        pr_netaddr_get_ipstr(session.c->local_addr));
      local_addr = pr_netaddr_get_addr(p, ip_str, NULL);

    } else {
      local_addr = pr_netaddr_v6tov4(p, session.c->local_addr);
      if (local_addr == NULL) {
        pr_trace_msg(trace_channel, 4,
          "error converting IPv6 local address %s to IPv4 address: %s",
          pr_netaddr_get_ipstr(session.c->local_addr), strerror(errno));
      }
    }

    if (local_addr == NULL) {
      local_addr = session.c->local_addr;
    }
  }

  bind_addr = proxy_sess->src_addr;
  if (bind_addr == NULL) {
    bind_addr = local_addr;
  }

  /* Note: IF mod_proxy is running on localhost, and the connection to be
   * made is to a public IP address, then this connect(2) attempt would most
   * likely fail with ENETUNREACH, since localhost is a loopback network,
   * and of course not reachable from a public IP.  Thus we check for this
   * edge case (which happens often for development).
   */
  if (pr_netaddr_is_loopback(bind_addr) == TRUE &&
      pr_netaddr_is_loopback(remote_addr) != TRUE) {
    const char *local_name;
    const pr_netaddr_t *new_local_addr;

    local_name = pr_netaddr_get_localaddr_str(p);
    new_local_addr = pr_netaddr_get_addr(p, local_name, NULL);

    if (new_local_addr != NULL) {
      int local_family, remote_family;

      /* We need to make sure our local address family matches that
       * of the remote address.
       */
      local_family = pr_netaddr_get_family(new_local_addr);
      remote_family = pr_netaddr_get_family(remote_addr);
      if (local_family != remote_family) {
        pr_netaddr_t *new_addr = NULL;

#ifdef PR_USE_IPV6
        if (local_family == AF_INET) {
          new_addr = pr_netaddr_v4tov6(p, new_local_addr);

        } else {
          new_addr = pr_netaddr_v6tov4(p, new_local_addr);
        }
#endif /* PR_USE_IPV6 */

        if (new_addr != NULL) {
          new_local_addr = new_addr;
        }
      }

      pr_trace_msg(trace_channel, 14,
        "%s is a loopback address, and unable to reach %s; using %s instead",
        pr_netaddr_get_ipstr(bind_addr), remote_ipstr,
        pr_netaddr_get_ipstr(new_local_addr));
      bind_addr = new_local_addr;
    }
  }

  server_conn = pr_inet_create_conn(p, -1, bind_addr, INPORT_ANY, FALSE);
  if (server_conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error creating connection to %s: %s", pr_netaddr_get_ipstr(bind_addr),
      strerror(xerrno));

    pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
    errno = xerrno;
    return NULL;
  }

  pr_trace_msg(trace_channel, 12,
    "connecting to backend address %s#%u from %s#%u", remote_ipstr, remote_port,
    pr_netaddr_get_ipstr(server_conn->local_addr), server_conn->local_port);

  res = pr_inet_connect_nowait(p, server_conn, remote_addr,
    ntohs(pr_netaddr_get_port(remote_addr)));
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error starting connect to %s#%u: %s", remote_ipstr, remote_port,
      strerror(xerrno));

    pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
    errno = xerrno;
    return NULL;
  }

  if (res == 0) {
    pr_netio_stream_t *nstrm;
    int connected = FALSE, nstrm_mode = PR_NETIO_IO_RD, use_tls;

    if ((proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL_V1) ||
        (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL_V2)) {
      /* Rather than waiting for the stream to be readable (because the
       * other end sent us something), wait for the stream to be writable
       * so that we can send something to the other end).
       */
      nstrm_mode = PR_NETIO_IO_WR;
    }

    use_tls = proxy_tls_using_tls();
    if (use_tls == PROXY_TLS_ENGINE_IMPLICIT) {
      /* For implicit FTPS connections, we will be initiating the TLS
       * handshake, and thus we need to wait for the stream to be writable.
       */
      nstrm_mode = PR_NETIO_IO_WR;
    }

    /* Not yet connected. */
    nstrm = proxy_netio_open(p, PR_NETIO_STRM_OTHR, server_conn->listen_fd,
      nstrm_mode);
    if (nstrm == NULL) {
      int xerrno = errno;

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error opening stream to %s#%u: %s", remote_ipstr, remote_port,
        strerror(xerrno));

      pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
      pr_inet_close(p, server_conn);

      errno = xerrno;
      return NULL;
    }

    proxy_netio_set_poll_interval(nstrm, 1);

    while (connected == FALSE) {
      int polled;

      pr_signals_handle();

      polled = proxy_netio_poll(nstrm);
      switch (polled) {
        case 1: {
          /* Aborted, timed out.  Note that we shouldn't reach here. */
          int xerrno = ETIMEDOUT;

          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error connecting to %s#%u: %s", remote_ipstr, remote_port,
            strerror(xerrno));
          pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
          proxy_netio_close(nstrm);
          pr_inet_close(p, server_conn);

          errno = xerrno;
          return NULL;
        }

        case -1: {
          /* Error */
          int xerrno = nstrm->strm_errno;

          if (xerrno == 0) {
            xerrno = errno;
          }

          if (xerrno == EINTR) {
            /* Treat this as a timeout. */
            xerrno = ETIMEDOUT;

          } else if (xerrno == EOF) {
            xerrno = ECONNREFUSED;
          }

          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error connecting to %s#%u: %s", remote_ipstr, remote_port,
            strerror(xerrno));

          pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
          proxy_netio_close(nstrm);
          pr_inet_close(p, server_conn);

          errno = xerrno;
          return NULL;
        }

        default: {
          /* Connected */
          server_conn->mode = CM_OPEN;
          pr_timer_remove(proxy_sess->connect_timerno, &proxy_module);
          pr_table_remove(session.notes, "mod_proxy.proxy-connect-addr", NULL);

          res = pr_inet_get_conn_info(server_conn, server_conn->listen_fd);
          if (res < 0) {
            int xerrno = errno;

            (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
              "error obtaining local socket info on fd %d: %s",
              server_conn->listen_fd, strerror(xerrno));

            proxy_netio_close(nstrm);
            pr_inet_close(p, server_conn);

            errno = xerrno;
            return NULL;
          }

          proxy_netio_reset_poll_interval(nstrm);
          connected = TRUE;
          break;
        }
      }
    }
  }

  pr_trace_msg(trace_channel, 5,
    "successfully connected to %s#%u from %s#%d", remote_ipstr, remote_port,
    pr_netaddr_get_ipstr(server_conn->local_addr),
    ntohs(pr_netaddr_get_port(server_conn->local_addr)));

  ctrl_conn = proxy_inet_openrw(p, server_conn, NULL, PR_NETIO_STRM_CTRL, -1,
    -1, -1, FALSE);
  if (ctrl_conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to open control connection to %s#%u: %s", remote_ipstr,
      remote_port, strerror(xerrno));

    pr_inet_close(p, server_conn);

    errno = xerrno;
    return NULL;
  }

  /* Remember that pr_inet_openrw() makes a copy of the input connection;
   * we thus do not need server_conn now.
   */
  pr_inet_close(p, server_conn);

  pr_pool_tag(ctrl_conn->pool, "proxy backend ctrl conn pool");
  return ctrl_conn;
}

const char *proxy_conn_get_uri(const struct proxy_conn *pconn) {
  if (pconn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pconn->pconn_uri;
}

int proxy_conn_send_proxy_v1(pool *p, conn_t *conn) {
  int res, src_port, dst_port;
  const char *proto, *src_ipstr, *dst_ipstr;
  pool *sub_pool = NULL;

  if (p == NULL ||
      conn == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* "PROXY" "TCP4"|"TCP6"|"UNKNOWN"
   *   session.c->remote_addr session.c->local_addr
   *   session.c->remote_port, session.c->local_port "\r\n"
   */

  if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET &&
      pr_netaddr_get_family(session.c->local_addr) == AF_INET) {
    proto = "TCP4";
    src_ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
    src_port = session.c->remote_port;
    dst_ipstr = pr_netaddr_get_ipstr(session.c->local_addr);
    dst_port = session.c->local_port;

  } else {
    proto = "TCP6";
    sub_pool = make_sub_pool(p);

    if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET) {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
      src_ipstr = pstrcat(sub_pool, "::ffff:", ipstr, NULL);

    } else {
      src_ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
    }

    src_port = session.c->remote_port;

    if (pr_netaddr_get_family(session.c->local_addr) == AF_INET) {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(session.c->local_addr);
      dst_ipstr = pstrcat(sub_pool, "::ffff:", ipstr, NULL);

    } else {
      dst_ipstr = pr_netaddr_get_ipstr(session.c->local_addr);
    }

    dst_port = session.c->local_port;

    /* What should we do if the entire frontend connection is IPv6, but the
     * backend server is IPv4?  Sending "PROXY TCP6" there may not work as
     * expected, e.g. the backend server may not want to handle IPv6 addresses
     * (even though it does not have to); should that be handled using
     * "PROXY UNKNOWN"?
     */
    if (pr_netaddr_get_family(conn->remote_addr) == AF_INET) {
      proto = "UNKNOWN";

      pr_trace_msg(trace_channel, 9,
        "client address '%s' and local address '%s' are both IPv6, "
        "but backend address '%s' is IPv4, using '%s' proto", src_ipstr,
        dst_ipstr, pr_netaddr_get_ipstr(conn->remote_addr), proto);
    }
  }

  pr_trace_msg(trace_channel, 9,
    "sending PROXY protocol V1 message: 'PROXY %s %s %s %d %d' to backend",
    proto, src_ipstr, dst_ipstr, src_port, dst_port);

  res = proxy_netio_printf(conn->outstrm, "PROXY %s %s %s %d %d\r\n",
    proto, src_ipstr, dst_ipstr, src_port, dst_port);

  if (sub_pool != NULL) {
    destroy_pool(sub_pool);
  }

  return res;
}

static int writev_conn(conn_t *conn, const struct iovec *iov, int iov_count) {
  int res, xerrno;

  if (pr_netio_poll(conn->outstrm) < 0) {
    return -1;
  }

  res = writev(conn->wfd, iov, iov_count);
  xerrno = errno;

  while (res <= 0) {
    if (res < 0) {
      if (xerrno == EINTR) {
        pr_signals_handle();

        if (pr_netio_poll(conn->outstrm) < 0) {
          return -1;
        }

        res = writev(conn->wfd, iov, iov_count);
        xerrno = errno;

        continue;
      }

      pr_trace_msg(trace_channel, 16,
        "error writing to client (fd %d): %s", conn->wfd, strerror(xerrno));
      errno = errno;
      return -1;
    }
  }

  session.total_raw_out += res;
  return res;
}

static uint16_t add_v2_tlv_alpn(pool *p, struct iovec *v2_iov,
    unsigned int *v2_niov) {
  uint8_t *tlv_type;
  uint16_t *tlv_len, total_len;
  const char *tlv_val;
  size_t tlv_valsz = 0;
  unsigned int niov;

  tlv_type = pcalloc(p, sizeof(uint8_t));
  *tlv_type = PROXY_PROTOCOL_V2_TLV_ALPN;

  tlv_val = pstrdup(p, pr_session_get_protocol(0));
  tlv_valsz = strlen(tlv_val);

  tlv_len = pcalloc(p, sizeof(uint16_t));
  *tlv_len = htons(tlv_valsz);

  niov = *v2_niov;

  v2_iov[niov].iov_base = (void *) tlv_type;
  v2_iov[niov].iov_len = sizeof(uint8_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_len;
  v2_iov[niov].iov_len = sizeof(uint16_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_val;
  v2_iov[niov].iov_len = tlv_valsz;

  /* Make sure to increment niov one more, for the next TLV. */
  *v2_niov = niov + 1;

  total_len = sizeof(uint8_t) + sizeof(uint16_t) + tlv_valsz;
  return total_len;
}

static uint16_t add_v2_tlv_authority(pool *p, struct iovec *v2_iov,
    unsigned int *v2_niov) {
  uint8_t *tlv_type;
  uint16_t *tlv_len, total_len;
  const char *tlv_val;
  size_t tlv_valsz = 0;
  unsigned int niov;
  const void *val = NULL;

  /* Only add the Authority TLV if the client sent an FTP HOST command, or
   * used TLS SNI.
   */

  val = pr_table_get(session.notes, "mod_core.host", NULL);
  if (val == NULL) {
    val = pr_table_get(session.notes, "mod_tls.sni", NULL);
  }

  if (val == NULL) {
    return 0;
  }

  tlv_type = pcalloc(p, sizeof(uint8_t));
  *tlv_type = PROXY_PROTOCOL_V2_TLV_AUTHORITY;

  tlv_val = pstrdup(p, val);
  tlv_valsz = strlen(tlv_val);

  tlv_len = pcalloc(p, sizeof(uint16_t));
  *tlv_len = htons(tlv_valsz);

  niov = *v2_niov;

  v2_iov[niov].iov_base = (void *) tlv_type;
  v2_iov[niov].iov_len = sizeof(uint8_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_len;
  v2_iov[niov].iov_len = sizeof(uint16_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_val;
  v2_iov[niov].iov_len = tlv_valsz;

  /* Make sure to increment niov one more, for the next TLV. */
  *v2_niov = niov + 1;

  total_len = sizeof(uint8_t) + sizeof(uint16_t) + tlv_valsz;
  return total_len;
}

static uint16_t add_v2_tlv_ssl(pool *p, struct iovec *v2_iov,
    unsigned int *v2_niov) {
  uint8_t *tlv_type, client;
  uint16_t *tlv_len, total_len;
  uint32_t verify;
  void *tlv_val, *tlv_ptr;
  size_t tlv_valsz = 0, valsz = 0;
  unsigned int niov;
  const char *proto, *tls_version, *tls_cipher;

  /* Only add the SSL TLV if FTPS is in use. */
  proto = pr_session_get_protocol(0);
  if (strcmp(proto, "ftps") != 0) {
    return 0;
  }

  tlv_type = pcalloc(p, sizeof(uint8_t));
  *tlv_type = PROXY_PROTOCOL_V2_TLV_SSL;

  /* This is more complicated, due to the nested nature of SSL sub-TLVs. */

  tls_version = pr_table_get(session.notes, "TLS_PROTOCOL", NULL);
  tls_cipher = pr_table_get(session.notes, "TLS_CIPHER", NULL);

  valsz = sizeof(client) + sizeof(verify);

  if (tls_version != NULL) {
    valsz += (sizeof(uint8_t) + sizeof(uint16_t) + strlen(tls_version));
  }

  if (tls_cipher != NULL) {
    valsz += (sizeof(uint8_t) + sizeof(uint16_t) + strlen(tls_cipher));
  }

  tlv_ptr = tlv_val = pcalloc(p, valsz);
  tlv_valsz = valsz;

  /* Client field: always 0x01, until we support client certs. */
  client = 0x01;
  memcpy(tlv_ptr, &client, sizeof(client));
  tlv_ptr += sizeof(client);

  /* Verify field: always non-zero, until we support client certs. */
  verify = htonl(1);
  memcpy(tlv_ptr, &verify, sizeof(verify));
  tlv_ptr += sizeof(verify);

  if (tls_version != NULL) {
    uint8_t tlv_subtype;
    uint16_t tlv_sublen;
    size_t tlv_subvalsz;

    tlv_subtype = PROXY_PROTOCOL_V2_TLV_SSL_VERSION;
    tlv_subvalsz = strlen(tls_version);
    tlv_sublen = htons(tlv_subvalsz);

    memcpy(tlv_ptr, &tlv_subtype, sizeof(tlv_subtype));
    tlv_ptr += sizeof(tlv_subtype);

    memcpy(tlv_ptr, &tlv_sublen, sizeof(tlv_sublen));
    tlv_ptr += sizeof(tlv_sublen);

    memcpy(tlv_ptr, tls_version, tlv_subvalsz);
    tlv_ptr += tlv_subvalsz;
  }

  if (tls_cipher != NULL) {
    uint8_t tlv_subtype;
    uint16_t tlv_sublen;
    size_t tlv_subvalsz;

    tlv_subtype = PROXY_PROTOCOL_V2_TLV_SSL_CIPHER;
    tlv_subvalsz = strlen(tls_cipher);
    tlv_sublen = htons(tlv_subvalsz);

    memcpy(tlv_ptr, &tlv_subtype, sizeof(tlv_subtype));
    tlv_ptr += sizeof(tlv_subtype);

    memcpy(tlv_ptr, &tlv_sublen, sizeof(tlv_sublen));
    tlv_ptr += sizeof(tlv_sublen);

    memcpy(tlv_ptr, tls_cipher, tlv_subvalsz);
    tlv_ptr += tlv_subvalsz;
  }

  tlv_len = pcalloc(p, sizeof(uint16_t));
  *tlv_len = htons(tlv_valsz);

  niov = *v2_niov;

  v2_iov[niov].iov_base = (void *) tlv_type;
  v2_iov[niov].iov_len = sizeof(uint8_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_len;
  v2_iov[niov].iov_len = sizeof(uint16_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_val;
  v2_iov[niov].iov_len = tlv_valsz;

  /* Make sure to increment niov one more, for the next TLV. */
  *v2_niov = niov + 1;

  total_len = sizeof(uint8_t) + sizeof(uint16_t) + tlv_valsz;
  return total_len;
}

static uint16_t add_v2_tlv_unique_id(pool *p, struct iovec *v2_iov,
    unsigned int *v2_niov) {
  uint8_t *tlv_type;
  uint16_t *tlv_len, total_len;
  const char *tlv_val;
  size_t tlv_valsz = 0;
  unsigned int niov;
  const void *val = NULL;

  /* Only add the Unique ID TLV if mod_unique_id generated one. */
  val = pr_table_get(session.notes, "UNIQUE_ID", NULL);
  if (val == NULL) {
    return 0;
  }

  tlv_type = pcalloc(p, sizeof(uint8_t));
  *tlv_type = PROXY_PROTOCOL_V2_TLV_UNIQUE_ID;

  tlv_val = pstrdup(p, val);
  tlv_valsz = strlen(tlv_val);

  tlv_len = pcalloc(p, sizeof(uint16_t));
  *tlv_len = htons(tlv_valsz);

  niov = *v2_niov;

  v2_iov[niov].iov_base = (void *) tlv_type;
  v2_iov[niov].iov_len = sizeof(uint8_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_len;
  v2_iov[niov].iov_len = sizeof(uint16_t);

  niov++;
  v2_iov[niov].iov_base = (void *) tlv_val;
  v2_iov[niov].iov_len = tlv_valsz;

  /* Make sure to increment niov one more, for the next TLV. */
  *v2_niov = niov + 1;

  total_len = sizeof(uint8_t) + sizeof(uint16_t) + tlv_valsz;
  return total_len;
}

int proxy_conn_send_proxy_v2(pool *p, conn_t *conn) {
  int res, xerrno;
  uint8_t ver_cmd, trans_fam, src_ipv6[16], dst_ipv6[16];
  uint16_t v2_len, src_port, dst_port;
  uint32_t src_ipv4, dst_ipv4;
  struct iovec v2_iov[20];
  unsigned int v2_niov = 8;
  pool *sub_pool = NULL, *tlv_pool = NULL;
  char *proto;
  const pr_netaddr_t *src_addr = NULL, *dst_addr = NULL;

  if (p == NULL ||
      conn == NULL) {
    errno = EINVAL;
    return -1;
  }

  v2_iov[0].iov_base = (void *) proxy_protocol_v2_sig;
  v2_iov[0].iov_len = PROXY_PROTOCOL_V2_SIGLEN;

  /* PROXY protocol v2 + PROXY command */
  ver_cmd = (0x20|0x01);
  v2_iov[1].iov_base = (void *) &ver_cmd;
  v2_iov[1].iov_len = sizeof(ver_cmd);

  src_addr = session.c->remote_addr;
  dst_addr = session.c->local_addr;

  if (pr_netaddr_get_family(src_addr) == AF_INET &&
      pr_netaddr_get_family(dst_addr) == AF_INET) {
    struct sockaddr_in *saddr;

    proto = "TCP/IPv4";
    trans_fam = (PROXY_PROTOCOL_V2_TRANSPORT_STREAM|PROXY_PROTOCOL_V2_FAMILY_INET);
    v2_len = PROXY_PROTOCOL_V2_ADDRLEN_INET;

    saddr = (struct sockaddr_in *) pr_netaddr_get_sockaddr(src_addr);
    src_ipv4 = saddr->sin_addr.s_addr;
    v2_iov[4].iov_base = (void *) &src_ipv4;
    v2_iov[4].iov_len = sizeof(src_ipv4);

    saddr = (struct sockaddr_in *) pr_netaddr_get_sockaddr(dst_addr);
    dst_ipv4 = saddr->sin_addr.s_addr;
    v2_iov[5].iov_base = (void *) &dst_ipv4;
    v2_iov[5].iov_len = sizeof(dst_ipv4);

    /* Quell compiler warnings about unused variables. */
    (void) src_ipv6;
    (void) dst_ipv6;

  } else {
    struct sockaddr_in6 *saddr;

    proto = "TCP/IPv6";
    trans_fam = (PROXY_PROTOCOL_V2_TRANSPORT_STREAM|PROXY_PROTOCOL_V2_FAMILY_INET6);
    v2_len = PROXY_PROTOCOL_V2_ADDRLEN_INET6;

    sub_pool = make_sub_pool(p);

    if (pr_netaddr_get_family(src_addr) == AF_INET) {
      src_addr = pr_netaddr_v4tov6(sub_pool, src_addr);
    }

    saddr = (struct sockaddr_in6 *) pr_netaddr_get_sockaddr(src_addr);
    memcpy(&src_ipv6, &(saddr->sin6_addr), sizeof(src_ipv6));
    v2_iov[4].iov_base = (void *) &src_ipv6;
    v2_iov[4].iov_len = sizeof(src_ipv6);

    if (pr_netaddr_get_family(dst_addr) == AF_INET) {
      dst_addr = pr_netaddr_v4tov6(sub_pool, dst_addr);
    }

    saddr = (struct sockaddr_in6 *) pr_netaddr_get_sockaddr(dst_addr);
    memcpy(&dst_ipv6, &(saddr->sin6_addr), sizeof(dst_ipv6));
    v2_iov[5].iov_base = (void *) &dst_ipv6;
    v2_iov[5].iov_len = sizeof(dst_ipv6);

    /* Quell compiler warnings about unused variables. */
    (void) src_ipv4;
    (void) dst_ipv4;
  }

  v2_iov[2].iov_base = (void *) &trans_fam;
  v2_iov[2].iov_len = sizeof(trans_fam);

  if (proxy_opts & PROXY_OPT_USE_PROXY_PROTOCOL_V2_TLVS) {
    uint16_t tlv_len;

    tlv_pool = make_sub_pool(p);

    tlv_len = add_v2_tlv_alpn(tlv_pool, v2_iov, &v2_niov);
    if (tlv_len > 0) {
      v2_len += tlv_len;
    }

    tlv_len = add_v2_tlv_authority(tlv_pool, v2_iov, &v2_niov);
    if (tlv_len > 0) {
      v2_len += tlv_len;
    }

    tlv_len = add_v2_tlv_ssl(tlv_pool, v2_iov, &v2_niov);
    if (tlv_len > 0) {
      v2_len += tlv_len;
    }

    tlv_len = add_v2_tlv_unique_id(tlv_pool, v2_iov, &v2_niov);
    if (tlv_len > 0) {
      v2_len += tlv_len;
    }
  }

  v2_len = htons(v2_len);
  v2_iov[3].iov_base = (void *) &v2_len;
  v2_iov[3].iov_len = sizeof(v2_len);

  src_port = htons(session.c->remote_port);
  v2_iov[6].iov_base = (void *) &src_port;
  v2_iov[6].iov_len = sizeof(src_port);

  dst_port = htons(session.c->local_port);
  v2_iov[7].iov_base = (void *) &dst_port;
  v2_iov[7].iov_len = sizeof(dst_port);

  pr_trace_msg(trace_channel, 9,
    "sending PROXY protocol V2 message for %s %s#%u %s#%u to backend",
    proto, pr_netaddr_get_ipstr(src_addr), (unsigned int) ntohs(src_port),
    pr_netaddr_get_ipstr(dst_addr), (unsigned int) ntohs(dst_port));

  res = writev_conn(conn, v2_iov, v2_niov);
  xerrno = errno;

  if (sub_pool != NULL) {
    destroy_pool(sub_pool);
  }

  if (tlv_pool != NULL) {
    destroy_pool(tlv_pool);
  }

  errno = xerrno;
  return res;
}
