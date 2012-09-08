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

unsigned char is_master = TRUE;
pid_t mpid = 0;
session_t session;
module *static_modules[] = { NULL };
module *loaded_modules = NULL;

volatile unsigned int recvd_signal_flags = 0;

static int connect_timeout_reached = FALSE;
static conn_t *connect_timeout_conn = NULL;

static int connect_timeout_cb(CALLBACK_FRAME) {
  connect_timeout_reached = TRUE;

fprintf(stderr, "connect_timeout_cb: fired\n");

  if (connect_timeout_conn != NULL) {
fprintf(stderr, "connect_timeout_cb: fired, setting the ERROR flag on the conn\n");
    connect_timeout_conn->mode = CM_ERROR;
    connect_timeout_conn->xerrno = ETIMEDOUT;
  }

  return 0;
}

void pr_signals_handle(void) {
  table_handling_signal(TRUE);

  if (errno == EINTR &&
      PR_TUNABLE_EINTR_RETRY_INTERVAL > 0) {
    struct timeval tv;
    unsigned long interval_usecs = PR_TUNABLE_EINTR_RETRY_INTERVAL * 1000000;

    tv.tv_sec = (interval_usecs / 1000000);
    tv.tv_usec = (interval_usecs - (tv.tv_sec * 1000000));

    pr_timer_usleep(interval_usecs);
  }

  while (recvd_signal_flags & RECEIVED_SIG_ALRM) {
    if (recvd_signal_flags & RECEIVED_SIG_ALRM) {
      recvd_signal_flags &= ~RECEIVED_SIG_ALRM;
      pr_trace_msg("signal", 9, "handling SIGALRM (signal %d)", SIGALRM);
      handle_alarm();
    }
  }

  table_handling_signal(FALSE);
}

int main(int argc, char *argv[]) {
  pool *p;
  const char *remote_name;
  pr_netaddr_t *remote_addr;
  conn_t *client_conn, *ctrl_conn, *data_conn;
  int remote_port, res, timerno;
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

  pr_netaddr_disable_ipv6();

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

  remote_port = 23;
 
  fprintf(stdout, "Resolved name '%s' to IP address '%s'\n", remote_name,
    pr_netaddr_get_ipstr(remote_addr));

  timerno = pr_timer_add(5, -1, NULL, connect_timeout_cb,
    "FTP client connect timeout");
  if (timerno <= 0) {
    fprintf(stderr, "Error register connect timer: %s\n", strerror(errno));
    destroy_pool(p);
    return 1;
  }

  /* Connect to the addr */
  client_conn = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  if (client_conn == NULL) {
    fprintf(stderr, "Error creating connection: %s\n", strerror(errno));

    pr_timer_remove(timerno, NULL);
    destroy_pool(p);
    return 1;
  }

  /* XXX And now I have an easy way to reproduce Bug#3802! */

  connect_timeout_conn = client_conn;
  res = pr_inet_connect(p, client_conn, remote_addr, remote_port);
  if (res < 0) {
    fprintf(stderr, "Error connecting to %s:%d: %s\n", remote_name,
      remote_port, strerror(errno));

    pr_timer_remove(timerno, NULL);
    pr_inet_close(p, client_conn);
    destroy_pool(p);
    return 1;
  }

  /* XXX Need to test what happens when connect to same machine */

  fprintf(stdout, "Successfully connected to %s:%d from %s:%d\n", remote_name,
    remote_port, pr_netaddr_get_ipstr(client_conn->local_addr),
    ntohs(pr_netaddr_get_port(client_conn->local_addr)));

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
