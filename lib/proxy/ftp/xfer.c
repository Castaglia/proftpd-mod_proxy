/*
 * ProFTPD - mod_proxy FTP data transfer routines
 * Copyright (c) 2013-2016 TJ Saunders
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

#include "include/proxy/inet.h"
#include "include/proxy/ftp/conn.h"
#include "include/proxy/ftp/ctrl.h"
#include "include/proxy/ftp/msg.h"
#include "include/proxy/ftp/xfer.h"

/* From response.c */
extern pr_response_t *resp_list, *resp_err_list;

static const char *trace_channel = "proxy.ftp.xfer";

int proxy_ftp_xfer_prepare_active(int policy_id, cmd_rec *cmd,
    const char *error_code, struct proxy_session *proxy_sess, int flags) {
  int backend_family, bind_family, res, xerrno = 0;
  cmd_rec *actv_cmd;
  const pr_netaddr_t *bind_addr = NULL;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  conn_t *data_conn = NULL;
  char *active_cmd;
  const char *resp_msg = NULL;

  switch (policy_id) {
    case PR_CMD_PORT_ID:
      active_cmd = C_PORT;
      break;

    case PR_CMD_EPRT_ID:
      /* If the remote host does not mention EPRT in its features, fall back
       * to using PORT.
       */
      active_cmd = C_EPRT;
      if (pr_table_get(proxy_sess->backend_features, C_EPRT, NULL) == NULL) {
        pr_trace_msg(trace_channel, 19,
          "EPRT not supported by backend server (via FEAT), using PORT");
        if (proxy_sess->dataxfer_policy == PR_CMD_EPRT_ID) {
          proxy_sess->dataxfer_policy = PR_CMD_PORT_ID;
        }

        active_cmd = C_PORT;
        policy_id = PR_CMD_PORT_ID;
      }
      break;

    default:
      /* In this case, the cmd we were given is the one we should send to
       * the backend server.
       */
      active_cmd = cmd->argv[0];

      if (pr_cmd_cmp(cmd, PR_CMD_EPRT_ID) == 0) {
        /* If the remote host does not mention EPRT in its features, fall back
         * to using PORT.
         */
        if (pr_table_get(proxy_sess->backend_features, C_EPRT, NULL) == NULL) {
          pr_trace_msg(trace_channel, 19,
            "EPRT not supported by backend server (via FEAT), using PORT");
          if (proxy_sess->dataxfer_policy == PR_CMD_EPRT_ID) {
            proxy_sess->dataxfer_policy = PR_CMD_PORT_ID;
          }

          active_cmd = C_PORT;
          policy_id = PR_CMD_PORT_ID;
        }
      }

      break;
  }

  bind_addr = proxy_sess->src_addr;
  if (bind_addr == NULL) {
    bind_addr = session.c->local_addr;
  }

  if (pr_netaddr_is_loopback(bind_addr) == TRUE &&
      pr_netaddr_is_loopback(proxy_sess->backend_ctrl_conn->remote_addr) != TRUE) {
    const char *local_name;
    const pr_netaddr_t *local_addr;

    local_name = pr_netaddr_get_localaddr_str(cmd->pool);
    local_addr = pr_netaddr_get_addr(cmd->pool, local_name, NULL);

    if (local_addr != NULL) {
      pr_trace_msg(trace_channel, 14,
        "%s is a loopback address, using %s instead",
        pr_netaddr_get_ipstr(bind_addr), pr_netaddr_get_ipstr(local_addr));
      bind_addr = local_addr;
    }
  }

  /* Need to check the family of the bind addr against the family of the
   * backend server.
   */
  backend_family = pr_netaddr_get_family(proxy_sess->backend_ctrl_conn->remote_addr);
  bind_family = pr_netaddr_get_family(bind_addr);
  if (bind_family == backend_family) {
#ifdef PR_USE_IPV6
    if (pr_netaddr_use_ipv6()) {
      /* Make sure that the family is NOT IPv6, even though the local and
       * remote families match.  The PORT command cannot be used for IPv6
       * addresses -- but EPRT CAN be used for IPv6 addresses.
       */
      if (bind_family == AF_INET6 &&
          policy_id == PR_CMD_PORT_ID) {
        pr_netaddr_t *mapped_addr;

        mapped_addr = pr_netaddr_v6tov4(cmd->pool, bind_addr);
        if (mapped_addr != NULL) {
          pr_trace_msg(trace_channel, 9,
            "converting local IPv6 address '%s' to IPv4 address '%s' for "
            "active transfer using PORT", pr_netaddr_get_ipstr(bind_addr),
            pr_netaddr_get_ipstr(mapped_addr));
          bind_addr = mapped_addr;
        }
      }
    }
#endif /* PR_USE_IPV6 */
  } else {
    if (backend_family == AF_INET) {
      pr_netaddr_t *mapped_addr;

      /* In this scenario, the remote peer is an IPv4 (or IPv4-mapped IPv6)
       * peer, so make sure we use an IPv4 local address.
       */
      mapped_addr = pr_netaddr_v6tov4(cmd->pool, bind_addr);
      if (mapped_addr != NULL) {
        pr_trace_msg(trace_channel, 9,
          "converting local IPv6 address '%s' to IPv4 address '%s' for "
          "active transfer with IPv4 peer", pr_netaddr_get_ipstr(bind_addr),
          pr_netaddr_get_ipstr(mapped_addr));
        bind_addr = mapped_addr;
      }
    }
  }

  if (proxy_sess->backend_data_conn != NULL) {
    /* Make sure that we only have one backend data connection. */
    proxy_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;
  }

  data_conn = proxy_ftp_conn_listen(cmd->tmp_pool, bind_addr, FALSE);
  if (data_conn == NULL) {
    xerrno = errno;

    pr_response_add_err(error_code,
      _("Unable to build data connection: Internal error"));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return -1;
  }

  proxy_sess->backend_data_conn = data_conn;

  switch (pr_cmd_get_id(active_cmd)) {
    case PR_CMD_PORT_ID:
      resp_msg = proxy_ftp_msg_fmt_addr(cmd->tmp_pool, data_conn->local_addr,
        data_conn->local_port, FALSE);
      break;

    case PR_CMD_EPRT_ID:
      resp_msg = proxy_ftp_msg_fmt_ext_addr(cmd->tmp_pool,
        data_conn->local_addr, data_conn->local_port, PR_CMD_EPRT_ID, FALSE);
      break;
  }

  actv_cmd = pr_cmd_alloc(cmd->tmp_pool, 2, active_cmd, resp_msg);
  actv_cmd->arg = (char *) resp_msg;

  pr_cmd_clear_cache(actv_cmd);

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    actv_cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) actv_cmd->argv[0],
      strerror(xerrno));

    proxy_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_response_add_err(error_code, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return -1;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines, flags);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s",
      (char *) actv_cmd->argv[0], strerror(xerrno));

    proxy_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    pr_response_add_err(error_code, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return -1;
  }

  if (resp->num[0] != '2') {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "received non-2xx response from backend for %s: %s %s",
      (char *) actv_cmd->argv[0], resp->num, resp->msg);

    proxy_inet_close(session.pool, proxy_sess->backend_data_conn);
    proxy_sess->backend_data_conn = NULL;

    if (policy_id == PR_CMD_EPRT_ID) {
      /* If using EPRT failed, try again using PORT, and switch the
       * DataTransferPolicy (if EPRT) to be PORT, for future attempts.
       */

      if (proxy_sess->dataxfer_policy == PR_CMD_EPRT_ID) {
        pr_trace_msg(trace_channel, 15,
          "falling back from EPRT to PORT DataTransferPolicy");
        proxy_sess->dataxfer_policy = PR_CMD_PORT_ID;
      }

      return proxy_ftp_xfer_prepare_active(PR_CMD_PORT_ID, cmd,
        error_code, proxy_sess, flags);
    }

    pr_response_add_err(error_code, "%s", resp->msg);
    pr_response_flush(&resp_err_list);

    errno = EINVAL;
    return -1;
  }

  return 0;
}

const pr_netaddr_t *proxy_ftp_xfer_prepare_passive(int policy_id, cmd_rec *cmd,
    const char *error_code, struct proxy_session *proxy_sess, int flags) {
  int res, xerrno = 0;
  cmd_rec *pasv_cmd;
  const pr_netaddr_t *remote_addr = NULL;
  pr_response_t *resp;
  unsigned int resp_nlines = 0;
  unsigned short remote_port;
  char *passive_cmd, *passive_respcode = NULL;

  /* Whether we send a PASV (and expect 227) or an EPSV (and expect 229)
   * need to depend on the policy_id.
   */
  switch (policy_id) {
    case PR_CMD_PASV_ID:
      passive_cmd = C_PASV;
      break;

    case PR_CMD_EPSV_ID:
      /* If the remote host does not mention EPSV in its features, fall back
       * to using PASV.
       */
      passive_cmd = C_EPSV;
      if (pr_table_get(proxy_sess->backend_features, C_EPSV, NULL) == NULL) {
        pr_trace_msg(trace_channel, 19,
          "EPSV not supported by backend server (via FEAT), using PASV");
        if (proxy_sess->dataxfer_policy == PR_CMD_EPSV_ID) {
          proxy_sess->dataxfer_policy = PR_CMD_PASV_ID;
        }

        passive_cmd = C_PASV;
        policy_id = PR_CMD_PASV_ID;
      }
      break;

    default:
      /* In this case, the cmd we were given is the one we should send to
       * the backend server.
       */
      passive_cmd = cmd->argv[0];

      if (pr_cmd_cmp(cmd, PR_CMD_EPSV_ID) == 0) {
        /* If the remote host does not mention EPSV in its features, fall back
         * to using PASV.
         */
        if (pr_table_get(proxy_sess->backend_features, C_EPSV, NULL) == NULL) {
          pr_trace_msg(trace_channel, 19,
            "EPSV not supported by backend server (via FEAT), using PASV");
          if (proxy_sess->dataxfer_policy == PR_CMD_EPSV_ID) {
            proxy_sess->dataxfer_policy = PR_CMD_PASV_ID;
          }

          passive_cmd = C_PASV;
          policy_id = PR_CMD_PASV_ID;
        }
      }

      break;
  }

  pasv_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, passive_cmd);

  switch (pr_cmd_get_id(pasv_cmd->argv[0])) {
    case PR_CMD_PASV_ID:
      passive_respcode = R_227;
      break;

    case PR_CMD_EPSV_ID:
      passive_respcode = R_229;
      break;
  } 

  res = proxy_ftp_ctrl_send_cmd(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    pasv_cmd);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error sending %s to backend: %s", (char *) pasv_cmd->argv[0],
      strerror(xerrno));

    pr_response_add_err(error_code, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return NULL;
  }

  resp = proxy_ftp_ctrl_recv_resp(cmd->tmp_pool, proxy_sess->backend_ctrl_conn,
    &resp_nlines, flags);
  if (resp == NULL) {
    xerrno = errno;
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error receiving %s response from backend: %s",
      (char *) pasv_cmd->argv[0], strerror(xerrno));

    pr_response_add_err(error_code, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return NULL;
  }

  /* We specifically expect a 227 or 229 response code here; anything else is
   * an error.  Right?
   */
  if (strncmp(resp->num, passive_respcode, 4) != 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "received response code %s, but expected %s for %s command", resp->num,
      passive_respcode, (char *) pasv_cmd->argv[0]);

    if (policy_id == PR_CMD_EPSV_ID) {
      /* If using EPSV failed, try again using PASV, and switch the
       * DataTransferPolicy (if EPSV) to be PASV, for future attempts.
       */

      if (proxy_sess->dataxfer_policy == PR_CMD_EPSV_ID) {
        pr_trace_msg(trace_channel, 15,
          "falling back from EPSV to PASV DataTransferPolicy");
        proxy_sess->dataxfer_policy = PR_CMD_PASV_ID;
      }

      return proxy_ftp_xfer_prepare_passive(PR_CMD_PASV_ID, cmd,
        error_code, proxy_sess, flags);
    }

    res = proxy_ftp_ctrl_send_resp(cmd->tmp_pool,
      proxy_sess->frontend_ctrl_conn, resp, resp_nlines);

    errno = EPERM;
    return NULL;
  }

  switch (pr_cmd_get_id(pasv_cmd->argv[0])) {
    case PR_CMD_PASV_ID:
      remote_addr = proxy_ftp_msg_parse_addr(cmd->tmp_pool, resp->msg,
        pr_netaddr_get_family(session.c->local_addr));
      break;

    case PR_CMD_EPSV_ID:
      remote_addr = proxy_ftp_msg_parse_ext_addr(cmd->tmp_pool, resp->msg,
        session.c->remote_addr, PR_CMD_EPSV_ID, NULL);
      break;
  }

  if (remote_addr == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 2, "error parsing %s response '%s': %s",
      (char *) pasv_cmd->argv[0], resp->msg, strerror(xerrno));

    xerrno = EPERM;
    pr_response_add_err(error_code, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return NULL;
  }

  remote_port = ntohs(pr_netaddr_get_port(remote_addr));

  /* Make sure that the given address matches the address to which we
   * originally connected.
   */

  if (pr_netaddr_cmp(remote_addr,
      proxy_sess->backend_ctrl_conn->remote_addr) != 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "Refused %s address %s (address mismatch with %s)",
      (char *) pasv_cmd->argv[0], pr_netaddr_get_ipstr(remote_addr),
      pr_netaddr_get_ipstr(proxy_sess->backend_ctrl_conn->remote_addr));
    xerrno = EPERM;

    pr_response_add_err(error_code, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return NULL;
  }

  if (remote_port < 1024) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "Refused %s port %hu (below 1024)",
      (char *) pasv_cmd->argv[0], remote_port);
    xerrno = EPERM;

    pr_response_add_err(error_code, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));
    pr_response_flush(&resp_err_list);

    errno = xerrno;
    return NULL;
  }

  return remote_addr;
}
