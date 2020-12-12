/*
 * ProFTPD - mod_proxy DNS resolution
 * Copyright (c) 2020 TJ Saunders
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
#include "proxy/dns.h"

/* The C_ANY macro is defined in ProFTPD's ftp.h file for "any" FTP command,
 * and may conflict with the DNS macros.  This API does not use ProFTPD's C_ANY
 * macro, so remove it and avoid the collision.
 */
#undef C_ANY

#include <arpa/nameser.h>
#include <resolv.h>

static const char *trace_channel = "proxy.dns";

struct srv_record {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  const char *target;
};

/* Sorting algorithm: priority first, then weight. */
static int srv_cmp(const void *left, const void *right) {
  const struct srv_record *a, *b;

  a = left;
  b = right;

  /* Lower priority wins */
  if (a->priority < b->priority) {
    return -1;
  }

  if (b->priority < a->priority) {
    return 1;
  }

  /* For equal priorities, higher weight wins.
   *
   * Yes, I know that RFC 2782 prescribes a more nuanced algorithm, with
   * weighted random selection of records with equal priorities.
   */

  if (a->weight > b->weight) {
    return -1;
  }

  if (b->weight > a->weight) {
    return 1;
  }

  return 0;
}

static int dns_query_error(const char *query_type, const char *query) {
  pr_trace_msg(trace_channel, 3, "failed to resolve %s records for '%s': %s",
    query_type, query, hstrerror(h_errno));

  /* Try to set an appropriate errno. */
  switch (h_errno) {
#if defined(HOST_NOT_FOUND)
    case HOST_NOT_FOUND:
      errno = ENOENT;
      break;
#endif /* HOST_NOT_FOUND */

#if defined(NO_DATA)
    case NO_DATA:
      errno = ENOENT;
      break;
#endif /* NO_DATA */

    default:
      errno = EPERM;
  }

  return -1;
}

static int dns_resolve_srv_a(pool *p, struct srv_record *srv, ns_rr rr,
    array_header *resp) {
  int xerrno;
  char text[INET_ADDRSTRLEN];
  const pr_netaddr_t *addr;

  pr_inet_ntop(AF_INET, ns_rr_rdata(rr), text, sizeof(text));
  addr = pr_netaddr_get_addr(p, text, NULL);
  xerrno = errno;

  if (addr == NULL) {
    pr_trace_msg(trace_channel, 3, "error resolving SRV A record '%s': %s",
      text, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  pr_netaddr_set_port2((pr_netaddr_t *) addr, srv->port);

  pr_trace_msg(trace_channel, 19, "adding SRV A record for %s#%u",
    pr_netaddr_get_ipstr(addr), ntohs(pr_netaddr_get_port(addr)));
  *((const pr_netaddr_t **) push_array(resp)) = addr;

  return 0;
}

static int dns_resolve_srv_aaaa(pool *p, struct srv_record *srv, ns_rr rr,
    array_header *resp) {
#if defined(PR_USE_IPV6)
  int xerrno;
  char text[INET6_ADDRSTRLEN];
  const pr_netaddr_t *addr;

  pr_inet_ntop(AF_INET6, ns_rr_rdata(rr), text, sizeof(text));
  addr = pr_netaddr_get_addr(p, text, NULL);
  xerrno = errno;

  if (addr == NULL) {
    pr_trace_msg(trace_channel, 3, "error resolving SRV A record '%s': %s",
      text, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  pr_netaddr_set_port2((pr_netaddr_t *) addr, srv->port);

  pr_trace_msg(trace_channel, 19, "adding SRV AAAA record for %s#%u",
    pr_netaddr_get_ipstr(addr), ntohs(pr_netaddr_get_port(addr)));
  *((const pr_netaddr_t **) push_array(resp)) = addr;

  return 0;
#endif /* PR_USE_IPV6 */

  errno = ENOSYS;
  return -1;
}

static int dns_resolve_srv_name(pool *p, struct srv_record *srv,
    array_header *resp) {
  int xerrno;
  pool *tmp_pool;
  pr_netaddr_t *addr;
  const pr_netaddr_t *res;
  array_header *addrs = NULL;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "SRV name resolution");

  res = pr_netaddr_get_addr(tmp_pool, srv->target, &addrs);
  xerrno = errno;

  if (res == NULL) {
    destroy_pool(tmp_pool);
    pr_trace_msg(trace_channel, 3, "error resolving SRV target '%s': %s",
      srv->target, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  addr = pr_netaddr_dup(p, res);
  pr_netaddr_set_port2(addr, srv->port);

  pr_trace_msg(trace_channel, 19, "adding '%s' resolved record for %s#%u",
    srv->target, pr_netaddr_get_ipstr(addr), ntohs(pr_netaddr_get_port(addr)));
  *((pr_netaddr_t **) push_array(resp)) = addr;

  if (addrs != NULL) {
    register unsigned int i;
    pr_netaddr_t **elts;

    /* Other addresses were found associated with this name. */
    elts = addrs->elts;
    for (i = 0; i < addrs->nelts; i++) {
      pr_netaddr_t *elt;

      elt = elts[i];
      addr = pr_netaddr_dup(p, elt);
      pr_netaddr_set_port2(addr, srv->port);

      pr_trace_msg(trace_channel, 19, "adding '%s' resolved record for %s#%u",
        srv->target, pr_netaddr_get_ipstr(addr),
        ntohs(pr_netaddr_get_port(addr)));
      *((pr_netaddr_t **) push_array(resp)) = addr;
    }
  }

  return 0;
}

static int dns_resolve_srv_target(pool *p, const char *query,
    struct srv_record *srv, ns_msg msgh, array_header **resp, uint32_t *ttl) {
  register unsigned int i;
  unsigned int count, found = 0;

  /* Look for A, AAAA records in the "Additional Data" (`ns_s_ar`) section.
   * These SHOULD be the records for the targets mentioned by the SRV records.
   * If no matching A, AAAA records are found, we resort to our normal
   * resolution routine, i.e. pr_netaddr_get_addr().
   *
   * If we see a CNAME record in the "Additional Data" section, ignore it; it
   * will be treated as if there are no A, AAAA records found.
   */

  count = ns_msg_count(msgh, ns_s_ar);
  pr_trace_msg(trace_channel, 17,
    "found %u %s in the '%s' SRV additional data section", count,
    count != 1 ? "records" : "record", query);

  for (i = 0; i < count; i++) {
    ns_rr record;
    uint32_t record_ttl;
    const char *record_name;

    pr_signals_handle();

    if (ns_parserr(&msgh, ns_s_ar, i, &record) < 0) {
      pr_trace_msg(trace_channel, 4,
        "error parsing DNS resource record #%u, skipping: %s", i + 1,
        strerror(errno));
      continue;
    }

    record_name = ns_rr_name(record);

    /* Remember that DNS names are case-insensitive. */
    if (strcasecmp(srv->target, record_name) != 0) {
      pr_trace_msg(trace_channel, 9, "additional resource record (#%u, %s) "
        "does not match target '%s', skipping", i + 1, record_name,
        srv->target);
      continue;
    }

    record_ttl = ns_rr_ttl(record);

    switch (ns_rr_type(record)) {
      case ns_t_a:
        if (ns_rr_rdlen(record) == 4) {
          pr_trace_msg(trace_channel, 4,
            "found additional A resource record (#%u, %s) for '%s' (TTL %lu)",
            i + 1, record_name, query, (unsigned long) record_ttl);
          if (dns_resolve_srv_a(p, srv, record, *resp) == 0) {
            if (ttl != NULL) {
              if (record_ttl < *ttl) {
                *ttl = record_ttl;
              }
            }

            found++;
          }

        } else {
          pr_trace_msg(trace_channel, 9,
            "found additional A resource record (#%u, %s) for '%s' with bad "
            "length (%d), skipping", i + 1, record_name, query,
            ns_rr_rdlen(record));
        }
        break;

      case ns_t_aaaa:
        if (ns_rr_rdlen(record) == 16) {
          pr_trace_msg(trace_channel, 4,
            "found additional AAAA resource record (#%u, %s) for '%s' "
            "(TTL %lu)", i + 1, record_name, query, (unsigned long) record_ttl);
          if (dns_resolve_srv_aaaa(p, srv, record, *resp) == 0) {
            if (ttl != NULL) {
              if (record_ttl < *ttl) {
                *ttl = record_ttl;
              }
            }

            found++;
          }

        } else {
          pr_trace_msg(trace_channel, 9,
            "found additional AAAA resource record (#%u, %s) for '%s' with bad "
            "length (%d), skipping", i + 1, record_name, query,
            ns_rr_rdlen(record));
        }
        break;

      case ns_t_cname:
        pr_trace_msg(trace_channel, 9,
          "found additional CNAME resource record (#%u, %s) for '%s' "
          "(TTL %lu), skipping", i + 1, record_name, query,
          (unsigned long) record_ttl);
        break;

      default:
        pr_trace_msg(trace_channel, 9,
          "found additional unexpected resource record (#%u, %d, %s) for '%s', "
          "skipping", i + 1, ns_rr_type(record), record_name, query);
        break;
    }
  }

  if (found == 0) {
    /* No matching addresses found in "Additional data"; resolve manually. */
    if (dns_resolve_srv_name(p, srv, *resp) < 0) {
      return -1;
    }
  }

  return 0;
}

static int dns_resolve_srv_targets(pool *p, const char *query,
    array_header *srvs, ns_msg msgh, array_header **resp, uint32_t *ttl) {
  register unsigned int i;
  struct srv_record **elts;

  *resp = make_array(p, srvs->nelts, sizeof(pr_netaddr_t *));

  elts = srvs->elts;
  for (i = 0; i < srvs->nelts; i++) {
    struct srv_record *srv;

    srv = elts[i];

    if (dns_resolve_srv_target(p, query, srv, msgh, resp, ttl) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error resolving SRV target '%s' to address: %s", srv->target,
        strerror(errno));
    }
  }

  return 0;
}

static int dns_resolve_srv(pool *p, const char *name, array_header **resp,
    uint32_t *ttl) {
  register unsigned int i;
  int answerlen, res;
  unsigned char answer[NS_PACKETSZ * 2];
  unsigned int count;
  ns_msg msgh;
  pool *srv_pool;
  array_header *srvs;

  pr_trace_msg(trace_channel, 17, "querying DNS for SRV records for '%s'",
    name);
  answerlen = res_query(name, ns_c_in, ns_t_srv, answer, sizeof(answer));
  pr_trace_msg(trace_channel, 22, "received answer (%d bytes) of SRV records "
    "for '%s'", answerlen, name);

  if (answerlen < 0) {
    return dns_query_error("SRV", name);
  }

  if (ns_initparse(answer, answerlen, &msgh) < 0) {
    pr_trace_msg(trace_channel, 2, "failed parsing SRV response for '%s'",
      name);
    errno = EINVAL;
    return -1;
  }

  count = ns_msg_count(msgh, ns_s_an);
  pr_trace_msg(trace_channel, 17, "found %u %s in the '%s' SRV answer section",
    count, count != 1 ? "records" : "record", name);

  srv_pool = make_sub_pool(p);
  pr_pool_tag(srv_pool, "SRV records");
  srvs = make_array(srv_pool, count, sizeof(struct srv_record *));

  /* Note: What does it mean, if there are more than one SRV records for a
   * given service for a domain?
   *
   * Answer: Consider the different priorities, different weights.  So yes,
   * it's quite probable.  Hopefully each of the different SRV records has
   * a different target.  Right?
   */
  for (i = 0; i < count; i++) {
    ns_rr record;
    uint16_t priority, weight, port, offset;
    uint32_t record_ttl;
    size_t target_len;
    char *target_text;
    int expanded_namelen;
    char expanded_name[NS_MAXDNAME];
    struct srv_record *srv;

    pr_signals_handle();

    if (ns_parserr(&msgh, ns_s_an, i, &record) < 0) {
      pr_trace_msg(trace_channel, 4,
        "error parsing DNS resource record #%u, skipping: %s", i + 1,
        strerror(errno));
      continue;
    }

    if (ns_rr_type(record) != ns_t_srv) {
      pr_trace_msg(trace_channel, 4,
        "found non-SRV DNS resource record #%u, skipping", i + 1);
      continue;
    }

    record_ttl = ns_rr_ttl(record);

    offset = 0;
    priority = ns_get16(ns_rr_rdata(record) + offset);

    offset += NS_INT16SZ;
    weight = ns_get16(ns_rr_rdata(record) + offset);

    /* TODO: Watch out for port 0 values! */
    offset += NS_INT16SZ;
    port = ns_get16(ns_rr_rdata(record) + offset);

    offset += NS_INT16SZ;

    /* Ideally, we would assume proper RFC 2782 implementations, and would NOT
     * attempt to decompress the target names.  For related issues, see:
     *
     * systemd should not compress target names in SRV records:
     *   https://github.com/systemd/systemd/issues/9793
     *
     * net: target domain names in SRV records should not be decompressed
     *   https://github.com/golang/go/issues/10622
     *
     * However, we opportunistically attempt to uncompress the target name,
     * for now.  Behavior subject to change without notice.
     */

    expanded_namelen = ns_name_uncompress(ns_msg_base(msgh), ns_msg_end(msgh),
      ns_rr_rdata(record) + offset, expanded_name, sizeof(expanded_name));
    if (expanded_namelen < 0) {
      /* Assume the target name was properly NOT compressed. */
      target_len = ns_rr_rdlen(record) - offset;
      target_text = pcalloc(srv_pool, target_len + 1);
      memcpy(target_text, (unsigned char *) ns_rr_rdata(record) + offset,
        target_len);

    } else {
      target_len = expanded_namelen;
      target_text = pcalloc(srv_pool, target_len + 1);
      memcpy(target_text, expanded_name, expanded_namelen);
    }

    pr_trace_msg(trace_channel, 17, "resolved '%s' to SRV record #%u "
      "(TTL %lu): priority = %u, weight = %u, port = %u, target = '%s'",
      name, i + 1, (unsigned long) record_ttl, priority, weight, port,
      target_text);

    /* If target is ".", abort (per RFC 2782); this means that this service
     * is decidedly not offered for this host/domain.
     */
    if (strcmp(target_text, ".") == 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "SRV records for '%s' indicate that the service is explicitly "
        "not available", name);
      *resp = NULL;
      errno = ENOENT;
      return -1;
    }

    srv = palloc(srv_pool, sizeof(struct srv_record));
    srv->priority = priority;
    srv->weight = weight;
    srv->port = port;
    srv->target = target_text;

    *((struct srv_record **) push_array(srvs)) = srv;
  }

  /* Sort our SRV records to get the ordered list of target names/ports. */
  qsort(srvs->elts, srvs->nelts, sizeof(struct srv_record *), srv_cmp);

  res = dns_resolve_srv_targets(p, name, srvs, msgh, resp, ttl);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error resolving SRV targets to addresses: %s", strerror(errno));
  }

  destroy_pool(srv_pool);
  return (*resp)->nelts;
}

static int dns_resolve_txt(pool *p, const char *name, array_header **resp,
    uint32_t *ttl) {
  register unsigned int i;
  int answerlen;
  unsigned char answer[NS_PACKETSZ * 2];
  unsigned int count;
  ns_msg msgh;

  pr_trace_msg(trace_channel, 17, "querying DNS for TXT records for '%s'",
    name);
  answerlen = res_query(name, ns_c_in, ns_t_txt, answer, sizeof(answer));
  pr_trace_msg(trace_channel, 22, "received answer (%d bytes) of TXT records "
    "for '%s'", answerlen, name);

  if (answerlen < 0) {
    return dns_query_error("TXT", name);
  }

  if (ns_initparse(answer, answerlen, &msgh) < 0) {
    pr_trace_msg(trace_channel, 2, "failed parsing TXT response for '%s'",
      name);
    errno = EINVAL;
    return -1;
  }

  count = ns_msg_count(msgh, ns_s_an);
  pr_trace_msg(trace_channel, 17, "found %u %s in the '%s' TXT answer section",
    count, count != 1 ? "records" : "record", name);
  *resp = make_array(p, count, sizeof(char *));

  for (i = 0; i < count; i++) {
    ns_rr record;
    uint32_t record_ttl;
    size_t record_len;
    char *record_text;

    pr_signals_handle();

    if (ns_parserr(&msgh, ns_s_an, i, &record) < 0) {
      pr_trace_msg(trace_channel, 4,
        "error parsing DNS resource record #%u, skipping: %s", i + 1,
        strerror(errno));
      continue;
    }

    if (ns_rr_type(record) != ns_t_txt) {
      pr_trace_msg(trace_channel, 4,
        "found non-TXT DNS resource record #%u, skipping", i + 1);
      continue;
    }

    record_ttl = ns_rr_ttl(record);

    record_len = ns_rr_rdlen(record) - 1;
    record_text = pcalloc(p, record_len + 1);
    memcpy(record_text, (unsigned char *) ns_rr_rdata(record) + 1, record_len);

    pr_trace_msg(trace_channel, 17,
      "resolved '%s' to TXT record #%u: '%s' (TTL %lu)", name, i + 1,
      record_text, (unsigned long) record_ttl);

    /* It is up to the caller to filter through these TXT records, looking for
     * what they want (e.g. URLs).
     */
    *((char **) push_array(*resp)) = record_text;

    if (ttl != NULL) {
      if (record_ttl < *ttl) {
        *ttl = record_ttl;
      }
    }
  }

  return (*resp)->nelts;
}

/* Note that this is mostly used for resolving SRV, TXT records. */
int proxy_dns_resolve(pool *p, const char *name, proxy_dns_type_e dns_type,
    array_header **resp, uint32_t *ttl) {
  int res;

  if (p == NULL ||
      name == NULL ||
      resp == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (dns_type) {
    case PROXY_DNS_A:
      /* Currently not implemented. */
      errno = ENOSYS;
      res = -1;
      break;

#if defined(PR_USE_IPV6)
    case PROXY_DNS_AAAA:
      /* Currently not implemented. */
      errno = ENOSYS;
      res = -1;
      break;
#endif /* PR_USE_IPV6 */

    case PROXY_DNS_SRV:
      res = dns_resolve_srv(p, name, resp, ttl);
      break;

    case PROXY_DNS_TXT:
      res = dns_resolve_txt(p, name, resp, ttl);
      break;

    case PROXY_DNS_UNKNOWN:
    default:
      errno = EPERM;
      res = -1;
  }

  return res;
}
