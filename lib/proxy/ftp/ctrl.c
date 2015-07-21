/*
 * ProFTPD - mod_proxy FTP control conn routines
 * Copyright (c) 2012-2015 TJ Saunders
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

static const char *trace_channel = "proxy.ftp.ctrl";

static char *ftp_telnet_gets(char *buf, size_t buflen,
    pr_netio_stream_t *nstrm) {
  char *buf_ptr = buf;
  unsigned char cp;
  int nread, saw_newline = FALSE;
  pr_buffer_t *pbuf = NULL;

  if (buflen == 0) {
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

cmd_rec *proxy_ftp_ctrl_recv_cmd(pool *p, conn_t *ctrl_conn) {
  cmd_rec *cmd = NULL;

  while (TRUE) {
    int res;

    pr_signals_handle();

    res = pr_cmd_read(&cmd);
    if (res < 0) {
      if (PR_NETIO_ERRNO(session.c->instrm) == EINTR) {
        continue;
      }
    }

    /* EOF */
    pr_session_disconnect(&proxy_module, PR_SESS_DISCONNECT_CLIENT_EOF, NULL);
  }

  return cmd;
}

pr_response_t *proxy_ftp_ctrl_recv_resp(pool *p, conn_t *ctrl_conn,
    unsigned int *nlines) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  pr_response_t *resp = NULL;
  int multiline = FALSE;
  unsigned int count = 0;

  while (TRUE) {
    char c, *ptr;
    int resp_code;
    size_t buflen;

    pr_signals_handle();

    memset(buf, '\0', sizeof(buf));
    if (ftp_telnet_gets(buf, sizeof(buf)-1, ctrl_conn->instrm) == NULL) {
      return NULL;
    }

    buflen = strlen(buf);

    /* Remove any trailing CRs, LFs. */
    while (buflen > 0 &&
           (buf[buflen-1] == '\r' || buf[buflen-1] == '\n')) {
      pr_signals_handle();

      buf[buflen-1] = '\0';
      buflen--;
    }

    /* If we are the first line of the response, the first three characters
     * MUST be numeric, followed by a hypen.  Anything else is nonconformant
     * with RFC 959.
     *
     * If we are NOT the first line of the response, then we are probably
     * handling a multiline response. If the first character is a space, then
     * this is a continuation line.  Otherwise, the first three characters
     * MUST be numeric, AND MUST match the numeric code from the first line.
     * This indicates the last line in the multiline response -- and the
     * character after the numerics MUST be a space.
     *
     */
    if (resp == NULL) {
      /* First line of a possibly multiline response (or just the only line). */
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
       * is a hyphen, then this is the first line of a multiline response.
       */
      if (buf[3] != ' ' &&
          buf[3] != '-') {
        pr_trace_msg(trace_channel, 1,
          "unexpected character '%c' following numeric response code", buf[3]);
        errno = EINVAL;
        return NULL;
      }

      if (buf[3] == '-') {
        multiline = TRUE;
      }
 
      count++;
      resp = (pr_response_t *) pcalloc(p, sizeof(pr_response_t));

    } else {
      if (buflen >= 1) {
        if (buf[0] == ' ') {
          /* Continuation line; append it the existing response. */
          if (buflen > 1) {
            resp->msg = pstrcat(p, resp->msg, "\r\n", buf, NULL);
          }
          count++;
          continue;

        } else {
          /* Possible ending line of multiline response. */
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
            errno = EINVAL;
            return NULL;
          }

          if (buf[3] != ' ') {
            errno = EINVAL;
            return NULL;
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
      /* Make sure the last line of the multiline response uses the same
       * response code.
       */
      if (strncmp(resp->num, buf, 3) != 0) {
        pr_trace_msg(trace_channel, 1,
          "invalid multiline FTP response: mismatched starting response "
          "code (%s) and ending response code (%s)", resp->num, buf);
        errno = EINVAL;
        return NULL;
      }
    }

    if (resp->msg == NULL) {
      if (buflen > 4) {
        if (multiline) {
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
        if (multiline) {
          *ptr = c;

          /* This the last line of a multiline response, which means we
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
    "received '%s%s%s' response from backend to frontend", resp->num,
    multiline ? "" : " ", resp->msg);
  return resp;
}

int proxy_ftp_ctrl_send_cmd(pool *p, conn_t *ctrl_conn, cmd_rec *cmd) {
  int res;

  if (cmd->argc > 1) {
    char *display_str;
    size_t display_len = 0;

    display_str = pr_cmd_get_displayable_str(cmd, &display_len);

    pr_trace_msg(trace_channel, 9,
      "proxied command '%s' from frontend to backend", display_str);
    res = proxy_netio_printf(ctrl_conn->outstrm, "%s %s\r\n", cmd->argv[0],
      cmd->arg);

  } else {
    pr_trace_msg(trace_channel, 9,
      "proxied %s command from frontend to backend", cmd->argv[0]);
    res = proxy_netio_printf(ctrl_conn->outstrm, "%s\r\n", cmd->argv[0]);
  }

  return res;
}

int proxy_ftp_ctrl_send_resp(pool *p, conn_t *ctrl_conn, pr_response_t *resp,
    unsigned int resp_nlines) {
  pool *curr_pool;

  (void) ctrl_conn;

  pr_trace_msg(trace_channel, 9,
    "backend->frontend response: %s%s%s", resp->num,
    resp_nlines == 1 ? " " : "", resp->msg);

  curr_pool = pr_response_get_pool();
  if (curr_pool == NULL) {
    pr_response_set_pool(p);
  }

  if (resp_nlines > 1) {
    pr_response_send_raw("%s%s", resp->num, resp->msg);

  } else {
    pr_response_send(resp->num, "%s", resp->msg);
  }

  pr_response_set_pool(curr_pool);
  return 0;
}

