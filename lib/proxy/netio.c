/*
 * ProFTPD - mod_proxy NetIO implementation
 * Copyright (c) 2015-2021 TJ Saunders
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

static const char *trace_channel = "proxy.netio";

static pr_netio_t *ctrl_netio = NULL;
static pr_netio_t *data_netio = NULL;

static const char *netio_strm_typestr(int strm_type) {
  const char *typestr = "(unknown)";

  switch (strm_type) {
    case PR_NETIO_STRM_CTRL:
      typestr = "ctrl";
      break;

    case PR_NETIO_STRM_DATA:
      typestr = "data";
      break;

    case PR_NETIO_STRM_OTHR:
      typestr = "othr";
      break;

    default:
      break;
  }

  return typestr;
}

int proxy_netio_use(int strm_type, pr_netio_t *netio) {
  int res;

  switch (strm_type) {
    case PR_NETIO_STRM_CTRL:
      ctrl_netio = netio;
      res = 0;
      break;

    case PR_NETIO_STRM_DATA:
      data_netio = netio;
      res = 0;
      break;

    default:
      errno = ENOSYS;
      res = -1;
  }

  return res;
}

int proxy_netio_using(int strm_type, pr_netio_t **netio) {
  int res;

  if (netio == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (strm_type) {
    case PR_NETIO_STRM_CTRL:
      *netio = ctrl_netio;
      res = 0;
      break;

    case PR_NETIO_STRM_DATA:
      *netio = data_netio;
      res = 0;
      break;

    default:
      errno = ENOENT;
      res = -1;
  }

  return res;
}

pr_netio_t *proxy_netio_unset(int strm_type, const char *fn) {
  pr_netio_t *netio = NULL;

  if (fn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  netio = pr_get_netio(strm_type);
  if (netio != NULL) {
    const char *owner_name = "core", *typestr;

    if (netio->owner_name != NULL) {
      owner_name = netio->owner_name;
    }
    typestr = netio_strm_typestr(strm_type);

    pr_trace_msg(trace_channel, 18, "(%s) found %s %s NetIO", fn, owner_name,
      typestr);
    if (pr_unregister_netio(strm_type) < 0) {
      pr_trace_msg(trace_channel, 3,
        "(%s) error unregistering %s NetIO: %s", fn, typestr, strerror(errno));
    }
  }

  /* Regardless of whether we found a previously registered NetIO, make
   * sure to use our own NetIO, if any.
   */
  switch (strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        if (pr_register_netio(ctrl_netio, strm_type) < 0) {
          pr_trace_msg(trace_channel, 3,
            "(%s) error registering proxy %s NetIO: %s", fn,
            netio_strm_typestr(strm_type), strerror(errno));

        } else {
          pr_trace_msg(trace_channel, 19,
            "(%s) using proxy %s NetIO", fn, netio_strm_typestr(strm_type));
        }
      }
      break;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        if (pr_register_netio(data_netio, strm_type) < 0) {
          pr_trace_msg(trace_channel, 3,
            "(%s) error registering proxy %s NetIO: %s", fn,
            netio_strm_typestr(strm_type), strerror(errno));

        } else {
          pr_trace_msg(trace_channel, 19,
            "(%s) using proxy %s NetIO", fn, netio_strm_typestr(strm_type));
        }
      }
      break;

    default:
      break;
  }
 
  return netio;
}

int proxy_netio_set(int strm_type, pr_netio_t *netio) {
  /* Note: we DO want to unregister the registered stream type, assuming we
   * have a NetIO of our own to use for that type.
   */
  switch (strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        (void) pr_unregister_netio(strm_type);
      }
      break;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        (void) pr_unregister_netio(strm_type);
      }
      break;

    default:
      break;
  }

  if (netio != NULL) {
    if (pr_register_netio(netio, strm_type) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error registering previous %s NetIO: %s",
        netio_strm_typestr(strm_type), strerror(errno));
    }
  }

  return 0;
}

int proxy_netio_close(pr_netio_stream_t *nstrm) {
  int strm_type = -1, res, xerrno;
  pr_netio_t *curr_netio = NULL;

  if (nstrm != NULL) {
    strm_type = nstrm->strm_type;
    curr_netio = proxy_netio_unset(strm_type, "netio_close");
  }

  res = pr_netio_close(nstrm);
  xerrno = errno;

  if (strm_type != -1) {
    proxy_netio_set(strm_type, curr_netio);
  }

  errno = xerrno;
  return res;
}

pr_netio_stream_t *proxy_netio_open(pool *p, int strm_type, int fd, int mode) {
  int xerrno;
  pr_netio_stream_t *nstrm = NULL;
  pr_netio_t *curr_netio;

  curr_netio = proxy_netio_unset(strm_type, "netio_open");
  nstrm = pr_netio_open(p, strm_type, fd, mode);
  xerrno = errno;
  proxy_netio_set(strm_type, curr_netio);

  errno = xerrno;
  return nstrm;
}

int proxy_netio_poll(pr_netio_stream_t *nstrm) {
  int res, xerrno;
  pr_netio_t *curr_netio;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_poll");
  res = pr_netio_poll(nstrm);
  xerrno = errno;
  proxy_netio_set(nstrm->strm_type, curr_netio);

  errno = xerrno;
  return res;
}

int proxy_netio_postopen(pr_netio_stream_t *nstrm) {
  int res = 0, xerrno;
  pr_netio_t *curr_netio = NULL;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_postpopen");
  res = pr_netio_postopen(nstrm);
  xerrno = errno;
  proxy_netio_set(nstrm->strm_type, curr_netio);
 
  errno = xerrno;
  return res;
}

int proxy_netio_printf(pr_netio_stream_t *nstrm, const char *fmt, ...) {
  int res, xerrno;
  va_list msg;
  pr_netio_t *curr_netio = NULL;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_printf");
  va_start(msg, fmt);
  res = pr_netio_vprintf(nstrm, fmt, msg);
  xerrno = errno;
  va_end(msg);
  proxy_netio_set(nstrm->strm_type, curr_netio);

  errno = xerrno;
  return res;
}

int proxy_netio_read(pr_netio_stream_t *nstrm, char *buf, size_t bufsz,
    int bufmin) {
  int res, xerrno;
  pr_netio_t *curr_netio = NULL;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_read");
  res = pr_netio_read(nstrm, buf, bufsz, bufmin);
  xerrno = errno;
  proxy_netio_set(nstrm->strm_type, curr_netio);

  errno = xerrno;
  return res;
}

void proxy_netio_reset_poll_interval(pr_netio_stream_t *nstrm) {
  pr_netio_t *curr_netio = NULL;

  if (nstrm == NULL) {
    return;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_reset_poll_interval");
  pr_netio_reset_poll_interval(nstrm);
  proxy_netio_set(nstrm->strm_type, curr_netio);
}

void proxy_netio_set_poll_interval(pr_netio_stream_t *nstrm,
    unsigned int secs) {
  pr_netio_t *curr_netio = NULL;

  if (nstrm == NULL) {
    return;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_set_poll_interval");
  pr_netio_set_poll_interval(nstrm, secs);
  proxy_netio_set(nstrm->strm_type, curr_netio);
}

int proxy_netio_shutdown(pr_netio_stream_t *nstrm, int how) {
  int res, xerrno;
  pr_netio_t *curr_netio = NULL;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_shutdown");
  res = pr_netio_shutdown(nstrm, how);
  xerrno = errno;
  proxy_netio_set(nstrm->strm_type, curr_netio);

  errno = xerrno;
  return res;
}

int proxy_netio_write(pr_netio_stream_t *nstrm, char *buf, size_t bufsz) {
  int res, xerrno;
  pr_netio_t *curr_netio = NULL;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  curr_netio = proxy_netio_unset(nstrm->strm_type, "netio_write");
  res = pr_netio_write(nstrm, buf, bufsz);
  xerrno = errno;
  proxy_netio_set(nstrm->strm_type, curr_netio);

  errno = xerrno;
  return res;
}
