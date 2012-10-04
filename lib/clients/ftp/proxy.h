
#ifdef MOD_PROXY_CLIENT_H
#define MOD_PROXY_CLIENT_H

#include "conf.h"

struct proxy_ftp_client {
  pool *client_pool;

  const char *protocol;

  pr_netaddr_t *remote_addr;
  unsigned int remote_port;

  /* This will be non-NULL in cases where we need to connect through
   * a proxy, e.g. a SOCKS proxy or another FTP proxy.
   */
  struct proxy_client *proxy;

  /* FTP-specific stuff */
  conn_t *ctrl_conn;
  conn_t *data_conn;
};

#endif /* MOD_PROXY_CLIENT_H */
