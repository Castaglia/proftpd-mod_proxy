/*
 * ProFTPD - mod_proxy FTP control conn routines
 * Copyright (c) 2012-2023 TJ Saunders
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

#include "proxy/netio.h"
#include "proxy/ftp/ctrl.h"
#include "proxy/tls.h"

static const char *trace_channel = "proxy.ftp.ctrl";

static char *ftp_telnet_gets(char *buf, size_t buflen,
    pr_netio_stream_t *nstrm, conn_t *conn) {
  char *buf_ptr = buf;
  unsigned char cp;
  int nread, saw_newline = FALSE;
  pr_buffer_t *pbuf = NULL;

  if (buflen == 0 ||
      nstrm == NULL ||
      conn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  buflen--;

  if (nstrm->strm_buf != NULL) {
    pbuf = nstrm->strm_buf;

  } else {
    pbuf = pr_netio_buffer_alloc(nstrm);
  }

  while (buflen > 0) {
    /* Is the buffer empty? */
    if (pbuf->current == NULL ||
        pbuf->remaining == pbuf->buflen) {

      nread = proxy_netio_read(nstrm, pbuf->buf,
        (buflen < pbuf->buflen ? buflen : pbuf->buflen), 4);
      if (nread <= 0) {
        if (buf_ptr != buf) {
          *buf_ptr = '\0';
          return buf;
        }

        if (nread == 0) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "read EOF from %s", conn->remote_name);
          errno = EPERM;
        }

        return NULL;
      }

      pbuf->remaining = pbuf->buflen - nread;
      pbuf->current = pbuf->buf;

      pr_event_generate("mod_proxy.ctrl-read", pbuf);
    }

    nread = pbuf->buflen - pbuf->remaining;

    /* Expensive copying of bytes while we look for the trailing LF. */
    while (buflen > 0 &&
           nread > 0 &&
           *pbuf->current != '\n' &&
           nread--) {
      pr_signals_handle();

      cp = *pbuf->current++;
      pbuf->remaining++;
      *buf_ptr++ = cp;
      buflen--;
    }

    if (buflen > 0 &&
        nread > 0 &&
        *pbuf->current == '\n') {
      buflen--;
      nread--;
      *buf_ptr++ = *pbuf->current++;
      pbuf->remaining++;

      saw_newline = TRUE;
      break;
    }

    if (nread == 0) {
      pbuf->current = NULL;
    }
  }

  if (saw_newline == FALSE) {
    /* If we haven't seen a newline, then assume the server is deliberately
     * sending a too-long response, trying to exploit buffer sizes and make
     * the proxy make some possibly bad assumptions.
     */

    errno = E2BIG;
    return NULL;
  }

  *buf_ptr = '\0';
  return buf;
}

pr_response_t *proxy_ftp_ctrl_recv_resp(pool *p, conn_t *ctrl_conn,
    unsigned int *nlines, int flags) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  pr_response_t *resp = NULL;
  int multi_line = FALSE;
  unsigned int count = 0;

  if (p == NULL ||
      ctrl_conn == NULL ||
      nlines == NULL) {
    errno = EINVAL;
    return NULL;
  }

  while (TRUE) {
    char c, *ptr;
    int resp_code;
    size_t buflen;

    pr_signals_handle();

    memset(buf, '\0', sizeof(buf));
    if (ftp_telnet_gets(buf, sizeof(buf)-1, ctrl_conn->instrm,
        ctrl_conn) == NULL) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "error reading telnet data: %s", strerror(xerrno));

      errno = xerrno;
      return NULL;
    }

    buflen = strlen(buf);

    /* TODO: What if the given buffer does not end in a CR/LF?  What if the
     * backend server is spewing response lines longer than our buffer?
     */

    /* Remove any trailing CRs, LFs. */
    while (buflen > 0 &&
           (buf[buflen-1] == '\r' || buf[buflen-1] == '\n')) {
      pr_signals_handle();

      buf[buflen-1] = '\0';
      buflen--;
    }

    if (buflen == 0 &&
        (flags & PROXY_FTP_CTRL_FL_IGNORE_BLANK_RESP)) {
      pr_trace_msg(trace_channel, 19, "%s",
        "skipping blank response line from backend server");
      continue;
    }

    /* If we are the first line of the response, the first three characters
     * MUST be numeric, followed by a hypen.  Anything else is nonconformant
     * with RFC 959.
     *
     * If we are NOT the first line of the response, then we are probably
     * handling a multi-line response. If the first character is a space, then
     * this is a continuation line.  Otherwise, the first three characters
     * MUST be numeric, AND MUST match the numeric code from the first line.
     * This indicates the last line in the multi-line response -- and the
     * character after the numerics MUST be a space.
     *
     * Unfortunately, some FTP servers (IIS, for instance) will use multi-line
     * responses whose continuation lines do NOT start with the mandated
     * space (as for a multi-line STAT response on a file, for example).  Sigh.
     */
    if (resp == NULL) {
      /* First line of a possibly multi-line response (or just the only
       * line).
       */
      if (buflen < 4) {
        pr_trace_msg(trace_channel, 12,
          "read %lu characters of response, needed at least %d",
          (unsigned long) buflen, 4);
        errno = EINVAL;
        return NULL;
      }

      if (!PR_ISDIGIT((int) buf[0]) ||
          !PR_ISDIGIT((int) buf[1]) ||
          !PR_ISDIGIT((int) buf[2])) {
        pr_trace_msg(trace_channel, 1,
          "non-numeric characters in start of response data: '%c%c%c'",
          buf[0], buf[1], buf[2]);
        errno = EINVAL;
        return NULL;
      }

      /* If this is a space, then we have a single line response.  If it
       * is a hyphen, then this is the first line of a multi-line response.
       */
      if (buf[3] != ' ' &&
          buf[3] != '-') {
        pr_trace_msg(trace_channel, 1,
          "unexpected character '%c' following numeric response code", buf[3]);
        errno = EINVAL;
        return NULL;
      }

      if (buf[3] == '-') {
        multi_line = TRUE;
      }

      count++;
      resp = (pr_response_t *) pcalloc(p, sizeof(pr_response_t));

    } else {
      if (buflen >= 1) {

        /* TODO: We should have a limit for how large of a buffered response
         * we will tolerate.  Consider a malicious/buggy backend server whose
         * multi-line response is in the GB?
         *
         * One way to avoid the buffering would be to relay each individual
         * response line, as we read them, to the frontend client.  But if
         * we do so, then we will not be properly acting as an FTP protocol
         * sanitizer, either.  Hrm.
         */

        if (buf[0] == ' ') {
          /* Continuation line; append it the existing response. */
          if (buflen > 1) {
            resp->msg = pstrcat(p, resp->msg, "\r\n", buf, NULL);
          }
          count++;
          continue;

        } else {
          /* Possible ending line of multi-line response. */
          if (buflen < 4) {
            errno = EINVAL;
            return NULL;
          }

          if (!PR_ISDIGIT((int) buf[0]) ||
              !PR_ISDIGIT((int) buf[1]) ||
              !PR_ISDIGIT((int) buf[2])) {
            pr_trace_msg(trace_channel, 1,
              "non-numeric characters in end of response data: '%c%c%c'",
              buf[0], buf[1], buf[2]);

            /* NOTE: We could/should be strict here, and require conformant
             * responses only.  For now, though, we'll proxy through the
             * backend's response to the frontend client, to let it decide
             * how it wants to handle this response data.
             */
            resp->msg = pstrcat(p, resp->msg, "\r\n", buf, NULL);
            count++;
            continue;
          }

          if (buf[3] != ' ') {
            /* NOTE: We could/should be strict here, and require conformant
             * responses only.  For now, though, we'll proxy through the
             * backend's response to the frontend client, to let it decide
             * how it wants to handle this response data.
             */
            resp->msg = pstrcat(p, resp->msg, "\r\n", buf, NULL);
            count++;
            continue;
          }

          count++;
        }
      }
    }

    ptr = &(buf[3]);
    c = *ptr;
    *ptr = '\0';
    resp_code = atoi(buf);
    if (resp_code < 100 ||
        resp_code >= 700) {
      /* Outside of the expected/defined FTP response code range. */
      pr_trace_msg(trace_channel, 1,
        "invalid FTP response code %d received", resp_code);
      errno = EINVAL;
      return NULL;
    }

    if (resp->num == NULL) {
      resp->num = pstrdup(p, buf);

    } else {
      /* Make sure the last line of the multi-line response uses the same
       * response code.
       */
      if (strncmp(resp->num, buf, 3) != 0) {
        pr_trace_msg(trace_channel, 1,
          "invalid multi-line FTP response: mismatched starting response "
          "code (%s) and ending response code (%s)", resp->num, buf);
        errno = EINVAL;
        return NULL;
      }
    }

    if (resp->msg == NULL) {
      if (buflen > 4) {
        if (multi_line == TRUE) {
          *ptr = c;
          resp->msg = pstrdup(p, ptr);
          *ptr = '\0';

        } else {
          resp->msg = pstrdup(p, ptr + 1);
        }

      } else {
        resp->msg = "";
      }

      /* If the character after the response code was a space, then this is
       * a single line response; we can be done now.
       */
      if (c == ' ') {
        break;
      }

    } else {
      if (buflen > 4) {
        if (multi_line == TRUE) {
          *ptr = c;

          /* This the last line of a multi-line response, which means we
           * need the ENTIRE line, including the response code.
           */
          resp->msg = pstrcat(p, resp->msg, "\r\n", buf, NULL);

        } else {
          resp->msg = pstrcat(p, resp->msg, "\r\n", ptr + 1, NULL);
        }
      }

      break;
    }
  }

  *nlines = count;

  pr_trace_msg(trace_channel, 9,
    "received '%s%s%s' response from backend to frontend",
    resp->num, multi_line ? "-" : " ", resp->msg);
  return resp;
}

#ifndef TELNET_DM
# define TELNET_DM	242
#endif /* TELNET_DM */

#ifndef TELNET_IAC
# define TELNET_IAC	255
#endif /* TELNET_IAC */

#ifndef TELNET_IP
# define TELNET_IP	244
#endif /* TELNET_IP */

int proxy_ftp_ctrl_send_abort(pool *p, conn_t *ctrl_conn, cmd_rec *cmd) {
  int fd, res, use_tls, xerrno;
  unsigned char buf[7];

  if (p == NULL ||
      ctrl_conn == NULL ||
      cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* If we are proxying the ABOR command, preface it with the Telnet "Sync"
   * mechanism, using OOB data.  If the receiving server supports this, it can
   * generate a signal to interrupt any IO occurring on the backend server
   * (such as when sendfile(2) is used).
   *
   * Note that such Telnet codes can only be used if we are NOT using TLS
   * on the backend control connection.
   */
  use_tls = proxy_tls_using_tls();
  if (use_tls != PROXY_TLS_ENGINE_OFF) {
    return proxy_ftp_ctrl_send_cmd(p, ctrl_conn, cmd);
  }

  fd = PR_NETIO_FD(ctrl_conn->outstrm);

  buf[0] = TELNET_IAC;
  buf[1] = TELNET_IP;
  buf[2] = TELNET_IAC;

  pr_trace_msg(trace_channel, 9,
    "sending Telnet abort code out-of-band to backend");
  res = send(fd, &buf, 3, MSG_OOB);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "error sending Telnet abort code out-of-band to backend: %s",
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  buf[0] = TELNET_DM;
  buf[1] = 'A';
  buf[2] = 'B';
  buf[3] = 'O';
  buf[4] = 'R';
  buf[5] = '\r';
  buf[6] = '\n';

  pr_trace_msg(trace_channel, 9,
    "proxied %s command from frontend to backend", (char *) cmd->argv[0]);
  res = send(fd, &buf, 7, 0);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "error sending Telnet DM code to backend: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  return 0;
}

int proxy_ftp_ctrl_send_cmd(pool *p, conn_t *ctrl_conn, cmd_rec *cmd) {
  int res;

  if (p == NULL ||
      ctrl_conn == NULL ||
      cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (cmd->argc > 1) {
    const char *display_str;
    size_t display_len = 0;

    display_str = pr_cmd_get_displayable_str(cmd, &display_len);

    pr_trace_msg(trace_channel, 9,
      "proxied command '%s' from frontend to backend", display_str);
    res = proxy_netio_printf(ctrl_conn->outstrm, "%s %s\r\n",
      (char *) cmd->argv[0], cmd->arg);

  } else {
    pr_trace_msg(trace_channel, 9,
      "proxied %s command from frontend to backend", (char *) cmd->argv[0]);
    res = proxy_netio_printf(ctrl_conn->outstrm, "%s\r\n",
      (char *) cmd->argv[0]);
  }

  return res;
}

int proxy_ftp_ctrl_send_resp(pool *p, conn_t *ctrl_conn, pr_response_t *resp,
    unsigned int resp_nlines) {
  pool *curr_pool;

  (void) ctrl_conn;

  if (p == NULL ||
      resp == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "backend->frontend response: %s%s%s", resp->num,
    resp_nlines <= 1 ? " " : "", resp->msg);

  curr_pool = pr_response_get_pool();
  if (curr_pool == NULL) {
    pr_response_set_pool(p);
  }

  if (resp_nlines > 1) {
    pr_response_send_raw("%s-%s", resp->num, resp->msg);

  } else {
    pr_response_send(resp->num, "%s", resp->msg);
  }

  pr_response_set_pool(curr_pool);
  return 0;
}

int proxy_ftp_ctrl_handle_async(pool *p, conn_t *backend_conn,
    conn_t *frontend_conn, int flags) {

  if (p == NULL ||
      backend_conn == NULL ||
      backend_conn->instrm == NULL ||
      frontend_conn == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (!(proxy_sess_state & PROXY_SESS_STATE_CONNECTED)) {
    /* Nothing to do if we're not yet connected to the backend server. */
    return 0;
  }

  while (TRUE) {
    fd_set rfds;
    struct timeval tv;
    int ctrlfd, res, xerrno = 0;

    /* By using a timeout of zero, we effect a poll on the fd. */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    pr_signals_handle();

    FD_ZERO(&rfds);

    ctrlfd = PR_NETIO_FD(backend_conn->instrm);
    FD_SET(ctrlfd, &rfds);

    res = select(ctrlfd + 1, &rfds, NULL, NULL, &tv);
    if (res < 0) {
      xerrno = errno;

      if (xerrno == EINTR) {
        pr_signals_handle();
        continue;
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error calling select(2) on backend control connection (fd %d): %s",
        ctrlfd, strerror(xerrno));
      return 0;
    }

    if (res == 0) {
      /* Nothing there. */
      break;
    }

    pr_trace_msg(trace_channel, 19,
      "select(2) reported %d for backend %s (fd %d)", res,
      backend_conn->remote_name, ctrlfd);

    if (FD_ISSET(ctrlfd, &rfds)) {
      unsigned int resp_nlines = 0;
      pr_response_t *resp;

      pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);

      pr_trace_msg(trace_channel, 9, "reading async response from backend %s",
        backend_conn->remote_name);

      resp = proxy_ftp_ctrl_recv_resp(p, backend_conn, &resp_nlines, flags);
      if (resp == NULL) {
        xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error receiving response from backend control connection: %s",
          strerror(xerrno));

        errno = xerrno;
        return -1;
      }

      res = proxy_ftp_ctrl_send_resp(p, frontend_conn, resp, resp_nlines);
      if (res < 0) {
        xerrno = errno;

        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "error sending response to frontend control connection: %s",
          strerror(xerrno));

        errno = xerrno;
        return -1;
      }
    }

    break;
  }

  return 0;
}
