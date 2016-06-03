/*
 * ProFTPD - mod_proxy API testsuite
 * Copyright (c) 2012-2016 TJ Saunders <tj@castaglia.org>
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

int pr_response_block(int block) {
  return 0;
}

void pr_response_send(const char *resp_code, const char *fmt, ...) {
}

void pr_response_send_async(const char *resp_code, const char *fmt, ...) {
}

int pr_scoreboard_entry_update(pid_t pid, ...) {
  return 0;
}

void pr_session_disconnect(module *m, int reason_code, const char *details) {
}

void pr_signals_handle(void) {
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
