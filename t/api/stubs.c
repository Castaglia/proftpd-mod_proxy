/*
 * ProFTPD - mod_proxy API testsuite
 * Copyright (c) 2012-2013 TJ Saunders <tj@castaglia.org>
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
unsigned char is_master = TRUE;
unsigned int recvd_signal_flags = 0;
xaset_t *server_list = NULL;

int proxy_logfd = -1;
module proxy_module;
unsigned long proxy_opts = 0UL;
unsigned int proxy_sess_state = 0;

config_rec *find_config(xaset_t *set, int type, const char *name, int recurse) {
  return NULL;
}

void *get_param_ptr(xaset_t *set, const char *name, int recurse) {
  errno = ENOENT;
  return NULL;
}

void pr_log_debug(int level, const char *fmt, ...) {
}

void pr_log_pri(int prio, const char *fmt, ...) {
}

int pr_log_writefile(int fd, const char *name, const char *fmt, ...) {
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

int pr_netio_printf(pr_netio_stream_t *nstrm, const char *fmt, ...) {
  return 0;
}

void pr_netio_set_poll_interval(pr_netio_stream_t *nstrm, unsigned int secs) {
}

int pr_response_block(int block) {
  return 0;
}

void pr_session_disconnect(module *m, int reason_code, const char *details) {
}

void pr_signals_block(void) {
}

void pr_signals_unblock(void) {
}

void pr_signals_handle(void) {
}

int pr_trace_get_level(const char *channel) {
  return 0;
}

int pr_trace_msg(const char *channel, int level, const char *fmt, ...) {
  va_list msg;

  fprintf(stderr, "<%s:%d>: ", channel, level);

  va_start(msg, fmt);
  vfprintf(stderr, fmt, msg);
  va_end(msg);

  fprintf(stderr, "\n");
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

int proxy_ftp_feat_get(pool *p, struct proxy_session *proxy_sess) {
  return 0;
}
