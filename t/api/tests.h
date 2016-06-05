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

/* Testsuite management */

#ifndef MOD_PROXY_TESTS_H
#define MOD_PROXY_TESTS_H

#include "mod_proxy.h"

#include "proxy/random.h"
#include "proxy/db.h"
#include "proxy/conn.h"
#include "proxy/netio.h"
#include "proxy/inet.h"
#include "proxy/uri.h"
#include "proxy/tls.h"
#include "proxy/session.h"
#include "proxy/reverse.h"
#include "proxy/forward.h"
#include "proxy/ftp/msg.h"
#include "proxy/ftp/conn.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/ftp/data.h"
#include "proxy/ftp/sess.h"
#include "proxy/ftp/xfer.h"

#ifdef HAVE_CHECK_H
# include <check.h>
#else
# error "Missing Check installation; necessary for ProFTPD testsuite"
#endif

int tests_rmpath(pool *p, const char *path);
int tests_stubs_set_next_cmd(cmd_rec *cmd);

Suite *tests_get_conn_suite(void);
Suite *tests_get_db_suite(void);
Suite *tests_get_inet_suite(void);
Suite *tests_get_netio_suite(void);
Suite *tests_get_random_suite(void);
Suite *tests_get_reverse_suite(void);
Suite *tests_get_forward_suite(void);
Suite *tests_get_tls_suite(void);
Suite *tests_get_uri_suite(void);
Suite *tests_get_session_suite(void);

Suite *tests_get_ftp_msg_suite(void);
Suite *tests_get_ftp_conn_suite(void);
Suite *tests_get_ftp_ctrl_suite(void);
Suite *tests_get_ftp_data_suite(void);
Suite *tests_get_ftp_sess_suite(void);
Suite *tests_get_ftp_xfer_suite(void);

unsigned int recvd_signal_flags;
extern pid_t mpid;
extern server_rec *main_server;

#endif /* MOD_PROXY_TESTS_H */
