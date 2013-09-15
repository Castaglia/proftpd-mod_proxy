/*
 * ProFTPD - mod_proxy FTP FEAT routines
 * Copyright (c) 2013 TJ Saunders
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
#include "proxy/ftp/feat.h"
#include "proxy/ftp/ctrl.h"

static const char *feat_crlf = "\r\n";

static const char *trace_channel = "proxy.ftp.feat";

int proxy_ftp_feat_get(pool *p, struct proxy_session *proxy_sess) {
  pool *tmp_pool;
  int res, xerrno = 0;
  cmd_rec *cmd;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  char *feats, *token;
  size_t token_len = 0;

  tmp_pool = make_sub_pool(p);

  cmd = pr_cmd_alloc(tmp_pool, 1, C_FEAT);
  res = proxy_ftp_ctrl_send_cmd(tmp_pool, proxy_sess->backend_ctrl_conn, cmd);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error sending %s to backend: %s", cmd->argv[0], strerror(xerrno));
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines);
  if (resp == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4,
      "error receiving %s from backend: %s", cmd->argv[0], strerror(xerrno));
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  if (resp->num[0] != '2') {
    pr_trace_msg(trace_channel, 4,
      "received unexpected %s response code %s from backend", cmd->argv[0],
      resp->num);
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  proxy_sess->backend_feats = pr_table_nalloc(p, 0, 4);

  feats = resp->msg;
  token = pr_str_get_token2(&feats, (char *) feat_crlf, &token_len);
  while (token != NULL) {
    pr_signals_handle();

    if (token_len > 0) {
      /* The FEAT response lines in which we are interested all start with
       * a single space, per RFC spec.  Ignore any other lines.
       */
      if (token[0] == ' ') {
        char *key, *val, *ptr;

        /* Find the next space in the string, to delimit our key/value pairs. */
        ptr = strchr(token + 1, ' ');
        if (ptr != NULL) {
          key = pstrndup(p, token + 1, ptr - token - 1);
          val = pstrdup(p, ptr + 1);

        } else {
          key = pstrdup(p, token + 1);
          val = pstrdup(p, "");
        }

        pr_table_add(proxy_sess->backend_feats, key, val, 0);
      }
    }

    feats = token + token_len + 1;
    token = pr_str_get_token2(&feats, (char *) feat_crlf, &token_len);
  }

  destroy_pool(tmp_pool);
  return 0;
}
