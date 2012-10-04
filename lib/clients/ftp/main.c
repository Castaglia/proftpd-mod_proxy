/*
 * ProFTPD - mod_proxy FTP client library
 * Copyright (c) 2012 TJ Saunders <tj@castaglia.org>
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

#include "ftp.h"

static int connect_timeout_reached = FALSE;
static pr_netio_stream_t *connect_timeout_strm = NULL;

static int connect_timeout_cb(CALLBACK_FRAME) {
  connect_timeout_reached = TRUE;

  if (connect_timeout_strm != NULL) {
    /* Abort the stream. */
    pr_netio_abort(connect_timeout_strm);
    connect_timeout_strm->strm_errno = ETIMEDOUT;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  pool *p;
  const char *remote_name;
  pr_netaddr_t *remote_addr;
  conn_t *client_conn, *ctrl_conn, *data_conn;
  unsigned int connect_timeout, remote_port;
  struct proxy_ftp_client *ftp;
  int res, timerno;
  char buf[1024];

  /* Seed the random number generator. */
  /* XXX Use random(3) in the future? */
  srand((unsigned int) (time(NULL) * getpid()));

  init_pools();
  init_privs();
  init_log();
  init_regexp();
  init_inet();
  init_netio();
  init_netaddr();
  init_fs();
  init_class();
  init_config();
  init_stash();

  pr_log_setdebuglevel(10);
  log_stderr(TRUE);
  pr_trace_use_stderr(TRUE);
  pr_trace_set_levels("DEFAULT", 1, 20);

  p = make_sub_pool(permanent_pool);
  pr_pool_tag(p, "FTP Client Pool");

  remote_name = "ftp.proftpd.org";

  remote_addr = pr_netaddr_get_addr(p, remote_name, NULL);
  if (remote_addr == NULL) {
    fprintf(stderr, "Failed to get addr for '%s': %s\n", remote_name,
      strerror(errno));
    destroy_pool(p);
    return 1;
  } 

  fprintf(stdout, "Resolved name '%s' to IP address '%s'\n", remote_name,
    pr_netaddr_get_ipstr(remote_addr));

  remote_port = 21;
  connect_timeout = 5;
  ftp = proxy_ftp_connect(p, remote_addr, remote_port, connect_timeout, NULL);
  if (ftp == NULL) {
    fprintf(stderr, "Error connecting to FTP server: %s\n", strerror(errno));
    destroy_pool(p);
    return 1;
  }

  fprintf(stdout, "Successfully connected to %s:%d from %s:%d\n", remote_name,
    remote_port, pr_netaddr_get_ipstr(client_conn->local_addr),
    ntohs(pr_netaddr_get_port(client_conn->local_addr)));

  res = proxy_ftp_disconnect(ftp);
  if (res < 0) {
    fprintf(stderr, "Error disconnecting from FTP server: %s\n",
      strerror(errno));
    destroy_pool(p);
    return 1;
  }

  ctrl_conn = pr_inet_openrw(p, client_conn, NULL, PR_NETIO_STRM_OTHR,
    -1, -1, -1, FALSE);
  if (ctrl_conn == NULL) {
    fprintf(stderr, "Error opening control connection: %s\n", strerror(errno));

    pr_inet_close(p, client_conn);
    destroy_pool(p);
    return 1;
  }

  fprintf(stdout, "Reading response from %s:%d\n", remote_name, remote_port);

  /* Read the response */
  memset(buf, '\0', sizeof(buf));

  /* XXX We need to write our own version of netio_telnet_gets(), with
   * the buffering to handle reassembly of a full FTP response out of
   * multiple TCP packets.  Not sure why the existing netio_telnet_gets()
   * is not sufficient.  But we don't need the handling of Telnet codes
   * in our reading.  But DO generate the 'core.ctrl-read' event, so that
   * any event listeners get a chance to process the data we've received.
   * (Or maybe use 'mod_proxy.server-read', and differentiate between
   * client and server reads/writes?)
   */
  if (pr_netio_read(ctrl_conn->instrm, buf, sizeof(buf)-1, 5) < 0) {
    fprintf(stderr, "Error reading response from server: %s\n",
      strerror(errno));

  } else {
    fprintf(stdout, "Response: \"%s\"\n", buf);
  }

  /* Disconnect */
  res = pr_netio_printf(ctrl_conn->outstrm, "%s\r\n", C_QUIT);
  if (res < 0) {
    fprintf(stderr, "Error writing command to server: %s", strerror(errno));
  }

  pr_inet_close(p, ctrl_conn);
  pr_inet_close(p, client_conn);
  destroy_pool(p);
  return 0;
}
