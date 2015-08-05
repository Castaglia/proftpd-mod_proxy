/*
 * ProFTPD - mod_proxy API testsuite
 * Copyright (c) 2012-2015 TJ Saunders <tj@castaglia.org>
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

#include "tests.h"

/* Stubs */

session_t session;
server_rec *main_server = NULL;
pid_t mpid = 1;
unsigned char is_master = TRUE;
unsigned int recvd_signal_flags = 0;
module *static_modules[] = { NULL };
module *loaded_modules = NULL;
xaset_t *server_list = NULL;

int proxy_logfd = -1;
module proxy_module;
pool *proxy_pool = NULL;
unsigned long proxy_opts = 0UL;
unsigned int proxy_sess_state = 0;

int login_check_limits(xaset_t *set, int recurse, int and, int *found) {
  return TRUE;
}

int xferlog_open(const char *path) {
  return 0;
}

int pr_config_get_server_xfer_bufsz(int direction) {
  return 0;
}

void pr_log_auth(int priority, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "AUTH: ");

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

void pr_log_debug(int level, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "DEBUG%d: ", level);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

void pr_log_pri(int prio, const char *fmt, ...) {
}

int pr_log_writefile(int fd, const char *name, const char *fmt, ...) {
  return 0;
}

conn_t *pr_inet_accept(pool *p, conn_t *data_conn, conn_t *ctrl_conn, int rfd,
    int wfd, unsigned char resolve) {
  errno = ENOSYS;
  return NULL;
}

void pr_inet_close(pool *p, conn_t *conn) {
}

int pr_inet_connect(pool *p, conn_t *conn, pr_netaddr_t *addr, int port) {
  errno = ENOSYS;
  return -1;
}

int pr_inet_connect_nowait(pool *p, conn_t *conn, pr_netaddr_t *addr,
    int port) {
  errno = ENOSYS;
  return -1;
}

conn_t *pr_inet_create_conn(pool *p, int fd, pr_netaddr_t *bind_addr,
    int port, int retry_bind) {
  errno = ENOSYS;
  return NULL;
}

int pr_inet_get_conn_info(conn_t *conn, int fd) {
  errno = ENOSYS;
  return -1;
}

int pr_inet_getservport(pool *p, const char *serv, const char *proto) {
  errno = ENOSYS;
  return -1;
}

int pr_inet_listen(pool *p, conn_t *conn, int backlog, int flags) {
  return 0;
}

conn_t *pr_inet_openrw(pool *p, conn_t *conn, pr_netaddr_t *addr, int strm_type,
    int fd, int rfd, int wfd, int resolve) {
  errno = ENOSYS;
  return NULL;
}

pr_netio_t *pr_get_netio(int strm_type) {
  errno = ENOSYS;
  return NULL;
}

int pr_register_netio(pr_netio_t *netio, int strm_types) {
  return 0;
}

int pr_unregister_netio(int strm_types) {
  return 0;
}

int pr_netio_close(pr_netio_stream_t *strm) {
  return 0;
}

int pr_netio_lingering_abort(pr_netio_stream_t *strm, long linger) {
  return 0;
}

int pr_netio_lingering_close(pr_netio_stream_t *strm, long linger) {
  return 0;
}

pr_netio_stream_t *pr_netio_open(pool *p, int strm_type, int fd, int mode) {
  errno = ENOSYS;
  return NULL;
}

int pr_netio_poll(pr_netio_stream_t *nstrm) {
  return 0;
}

int pr_netio_postopen(pr_netio_stream_t *nstrm) {
  return 0;
}

int pr_netio_printf(pr_netio_stream_t *nstrm, const char *fmt, ...) {
  return 0;
}

int pr_netio_printf_async(pr_netio_stream_t *nstrm, char *fmt, ...) {
  return 0;
}

int pr_netio_read(pr_netio_stream_t *nstrm, char *buf, size_t bufsz,
    int bufmin) {
  return 0;
}

void pr_netio_set_poll_interval(pr_netio_stream_t *nstrm, unsigned int secs) {
}

int pr_netio_shutdown(pr_netio_stream_t *nstrm, int how) {
  return 0;
}

int pr_netio_vprintf(pr_netio_stream_t *nstrm, const char *fmt, va_list msg) {
  return 0;
}

int pr_netio_write(pr_netio_stream_t *nstrm, char *buf, size_t bufsz) {
  return bufsz;
}

int pr_response_block(int block) {
  return 0;
}

void pr_response_send(const char *resp_code, const char *fmt, ...) {
}

int pr_scoreboard_entry_update(pid_t pid, ...) {
  return 0;
}

void pr_session_disconnect(module *m, int reason_code, const char *details) {
}

void pr_signals_handle(void) {
}

int pr_trace_get_level(const char *channel) {
  return 0;
}

int pr_trace_msg(const char *channel, int level, const char *fmt, ...) {
  va_list msg;

  if (getenv("TEST_VERBOSE") != NULL) {
    fprintf(stderr, "<%s:%d>: ", channel, level);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }

  return 0;
}

/* Module-specific stubs */

cmd_rec *proxy_ftp_ctrl_recv_cmd(pool *p, conn_t *conn) {
  errno = ENOSYS;
  return NULL;
}

pr_response_t *proxy_ftp_ctrl_recv_resp(pool *p, conn_t *conn,
    unsigned int *resp_nlines) {
  errno = ENOSYS;
  return NULL;
}

int proxy_ftp_ctrl_send_cmd(pool *p, conn_t *conn, cmd_rec *cmd) {
  return 0;
}

int proxy_ftp_ctrl_send_resp(pool *p, conn_t *conn, pr_response_t *resp,
    unsigned int resp_nlines) {
  return 0;
}

int proxy_ftp_sess_get_feat(pool *p, struct proxy_session *proxy_sess) {
  return 0;
}

int proxy_ftp_sess_send_auth_tls(pool *p, struct proxy_session *proxy_sess) {
  return 0;
}

int proxy_ftp_sess_send_host(pool *p, struct proxy_session *proxy_sess) {
  return 0;
}

int proxy_ftp_sess_send_pbsz_prot(pool *p, struct proxy_session *proxy_sess) {
  return 0;
}
