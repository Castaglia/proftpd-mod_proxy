/*
 * ProFTPD - mod_proxy FTP dirlist routines
 * Copyright (c) 2020-2025 TJ Saunders
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

#include "proxy/str.h"
#include "proxy/ftp/dirlist.h"
#include "proxy/ftp/facts.h"

static unsigned long facts_opts = 0UL;

/* Tracks all of the state/context for parsing a single directory listing. */
struct dirlist_ctx {
  pool *pool;
  unsigned long opts;

  /* Style/format of directory listing: Unix, Windows/DOS, etc. */
  int list_style;

  /* Skip the "total NNN" leadling line in some listings? */
  unsigned char skip_total;

  /* Accumulated unprocessed input data. In theory, this should never be
   * more than a single line of text, minus the terminating LF.
   */
  char *input_ptr, *input_text;
  size_t input_textsz, input_textlen;

  /* Accumulated output data. */
  char *output_ptr, *output_text;
  size_t output_textsz, output_textlen;
};

#define DIRLIST_LIST_STYLE_UNKNOWN	0
#define DIRLIST_LIST_STYLE_UNIX		1
#define DIRLIST_LIST_STYLE_WINDOWS	2

static const char *trace_channel = "proxy.ftp.dirlist";

int proxy_ftp_dirlist_init(pool *p, struct proxy_session *proxy_sess) {
  struct dirlist_ctx *ctx;
  pool *ctx_pool;

  if (p == NULL ||
      proxy_sess == NULL) {
    errno = EINVAL;
    return -1;
  }

  facts_opts = proxy_ftp_facts_get_opts();

  ctx_pool = make_sub_pool(p);
  pr_pool_tag(ctx_pool, "Proxy Dirlist Context Pool");

  ctx = pcalloc(ctx_pool, sizeof(struct dirlist_ctx));
  ctx->pool = ctx_pool;
  ctx->opts = proxy_sess->dirlist_opts;
  ctx->list_style = DIRLIST_LIST_STYLE_UNKNOWN;
  ctx->skip_total = TRUE;

  /* This is the maximum size of one line, per mod_ls.  Be aware, however, that
   * we may be talking to non-ProFTPD servers, whose behaviors will be different.
   */
  ctx->input_textsz = (PR_TUNABLE_PATH_MAX * 2) + 256;
  ctx->input_ptr = ctx->input_text = palloc(ctx_pool, ctx->input_textsz);

  ctx->output_textsz = (pr_config_get_server_xfer_bufsz(PR_NETIO_IO_WR) * 64);
  ctx->output_ptr = ctx->output_text = palloc(ctx_pool, ctx->output_textsz);

  proxy_sess->dirlist_ctx = (void *) ctx;
  return 0;
}

int proxy_ftp_dirlist_finish(struct proxy_session *proxy_sess) {
  if (proxy_sess == NULL) {
    errno = EINVAL;
    return -1;
  }

  facts_opts = 0UL;

  if (proxy_sess->dirlist_ctx != NULL) {
    struct dirlist_ctx *ctx;

    ctx = proxy_sess->dirlist_ctx;

    destroy_pool(ctx->pool);
    proxy_sess->dirlist_ctx = NULL;
  }

  return 0;
}

struct proxy_dirlist_fileinfo *proxy_ftp_dirlist_fileinfo_from_dos(pool *p,
    const char *text, size_t textlen, unsigned long opts) {
  struct proxy_dirlist_fileinfo *pdf;
  char *buf, *ptr;
  size_t buflen, windows_ts_fmtlen = 17;
  const char *windows_ts_fmt = "%m-%d-%y  %I:%M%p";

  if (p == NULL ||
      text == NULL ||
      textlen == 0) {
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 19, "parsing Windows text: '%.*s'",
    (int) textlen, text);

  /* 24 is the minimum length of a well-formatted Windows directory listing
   * line.
   */
  if (textlen < 24) {
    pr_trace_msg(trace_channel, 3,
      "error parsing Windows text (too short, need at least 24 bytes): '%.*s'",
        (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  pdf = pcalloc(p, sizeof(struct proxy_dirlist_fileinfo));

  ptr = (char *) text;
  buflen = 8;
  buf = pstrndup(p, ptr, buflen);

  if (strpbrk(buf, "0123456789-") == NULL) {
    pr_trace_msg(trace_channel, 3,
      "unexpected Windows date format: '%.*s'", (int) buflen, buf);
    errno = EINVAL;
    return NULL;
  }

  ptr += buflen;
  if (strncmp(ptr, "  ", 2) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Windows text (expected 2 spaces after date): '%.*s'",
      (int) textlen, text); errno = EINVAL;
    return NULL;
  }

  ptr += 2;

  buflen = 7;
  buf = pstrndup(p, ptr, buflen);

  if (strpbrk(buf, "AMP0123456789:") == NULL) {
    pr_trace_msg(trace_channel, 3, "unexpected Windows time format: '%.*s'",
      (int) buflen, buf);
    errno = EINVAL;
    return NULL;
  }

  /* Some servers might mistakenly omit the AM/PM markers; try to handle these
   * cases gracefully.
   */
  if (strpbrk(buf, "AMP") == NULL) {
    pr_trace_msg(trace_channel, 3,
      "Windows time format lacks AM/PM marker, adjusting expectations");
    windows_ts_fmt = "%m-%d-%y  %I:%M";
    windows_ts_fmtlen = 15;
  }

  pdf->tm = pcalloc(p, sizeof(struct tm));

  buflen = windows_ts_fmtlen;
  buf = pstrndup(p, text, buflen);

  pr_trace_msg(trace_channel, 19,
    "parsing Windows-style timestamp: '%.*s'", (int) buflen, buf);
  if (strptime(buf, windows_ts_fmt, pdf->tm) == NULL) {
    pr_trace_msg(trace_channel, 3,
      "unexpected Windows timestamp format: '%.*s'", (int) buflen, buf);
    errno = EINVAL;
    return NULL;
  }

  ptr = (char *) text + buflen;

  /* We now expect at least 7 spaces. */
  if (strncmp(ptr, "       ", 7) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Windows text (expected 7 spaces after timestamp): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  ptr += 7;
  pdf->st = pcalloc(p, sizeof(struct stat));

  if (strncmp(ptr, "<DIR>", 5) == 0) {
    pdf->st->st_mode |= S_IFDIR;
    pdf->type = pstrdup(p, "dir");

    /* For a directory, we expect the next 10 characters to be spaces. */
    ptr += 5;

    if (strncmp(ptr, "          ", 10) != 0) {
      pr_trace_msg(trace_channel, 3,
        "malformed Windows text (expected 10 spaces after dir): '%.*s'",
        (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    ptr += 10;

  } else if (strncmp(ptr, "     ", 5) == 0) {
    char *size_ptr;
    off_t filesz;

    pdf->st->st_mode |= S_IFREG;
    pdf->type = pstrdup(p, "file");

    /* For a file, we expect to see the file size within 9 characters or
     * less.
     */
    ptr += 5;

    buflen = 9;
    buf = pstrndup(p, ptr, buflen);

    if (strpbrk(buf, "0123456789 ") == NULL) {
      pr_trace_msg(trace_channel, 3,
        "malformed Windows text (expected filesize with '%.*s'): '%.*s'",
        (int) buflen, buf, (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    size_ptr = strpbrk(buf, "0123456789");
    if (size_ptr == NULL) {
      pr_trace_msg(trace_channel, 3,
        "malformed Windows text (expected filesize not found): '%.*s'",
        (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    pr_trace_msg(trace_channel, 19,
      "parsing Windows-style filesize from '%s'", size_ptr);

    if (pr_str_get_nbytes(size_ptr, NULL, &filesz) < 0) {
      pr_trace_msg(trace_channel, 3,
        "malformed Windows text (unable to parse filesize: %s): '%.*s'",
        strerror(errno), (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    pdf->st->st_size = filesz;
    ptr += 9;

    if (strncmp(ptr, " ", 1) != 0) {
      pr_trace_msg(trace_channel, 3,
        "malformed Windows text (missing space after filesize): '%.*s'",
        (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    ptr += 1;

  } else {
    pr_trace_msg(trace_channel, 3,
      "malformed Windows text (unexpected spaces after timestamp): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  pdf->path = pstrdup(p, ptr);
  return pdf;
}

static mode_t get_unix_mode(const char *text) {
  mode_t perms = 0;

  /* User permissions */
  switch (text[0]) {
    /* S_IRUSR only */
    case 'r':
      perms |= S_IRUSR;
      break;

    case '-':
      break;
  }

  switch (text[1]) {
    /* S_IWUSR only */
    case 'w':
      perms |= S_IWUSR;
      break;

    case '-':
      break;
  }

  switch (text[2]) {
    case 'S':
#if defined(S_ISUID)
      perms |= S_ISUID;
#endif /* S_ISUID */
      break;

    /* S_ISUID + S_IXUSR */
    case 's':
#if defined(S_ISUID)
      perms |= S_ISUID;
      perms |= S_IXUSR;
#endif /* S_ISUID */
      break;

    /* S_IXUSR only */
    case 'x':
      perms |= S_IXUSR;
      break;

    case '-':
      break;
  }

  /* Group permissions */
  switch (text[3]) {
    case 'r':
      perms |= S_IRGRP;
      break;

    case '-':
      break;
  }

  switch (text[4]) {
    case 'w':
      perms |= S_IWGRP;
      break;

    case '-':
      break;
  }

  switch (text[5]) {
    case 'S':
#if defined(S_ISGID)
      perms |= S_ISGID;
#endif /* S_ISGID */
      break;

    /* S_ISGID + S_IXGRP */
    case 's':
#if defined(S_ISGID)
      perms |= S_ISGID;
      perms |= S_IXGRP;
#endif /* S_ISGID */
      break;

    /* S_IXGRP only */
    case 'x':
      perms |= S_IXGRP;
      break;

    case '-':
      break;
  }

  /* World/other permissions */
  switch (text[6]) {
    case 'r':
      perms |= S_IROTH;
      break;

    case '-':
      break;
  }

  switch (text[7]) {
    case 'w':
      perms |= S_IWOTH;
      break;

    case '-':
      break;
  }

  switch (text[8]) {
    /* S_ISVTX only */
    case 'T':
#if defined(S_ISVTX)
      perms |= S_ISVTX;
#endif /* S_ISVTX */
      break;

    /* S_ISVTX + S_IXOTH */
    case 't':
#if defined(S_ISVTX)
      perms |= S_ISVTX;
      perms |= S_IXOTH;
#endif /* S_ISVTX */
      break;

    /* S_IXOTH only */
    case 'x':
      perms |= S_IXOTH;
      break;

    case '-':
      break;
  }

  return perms;
}

/* See RFC 3659, Section 7.5.5: "The perm Fact" */
static char *get_perm_fact(pool *p, mode_t mode) {
  char *perm = "";

  if (!S_ISDIR(mode)) {
    if (mode & (S_IWUSR|S_IWGRP|S_IWOTH)) {
      perm = pstrcat(p, perm, "a", NULL);
    }

    perm = pstrcat(p, perm, "d", NULL);

    if (mode & (S_IWUSR|S_IWGRP|S_IWOTH)) {
      perm = pstrcat(p, perm, "f", NULL);
    }

    if (mode & (S_IRUSR|S_IRGRP|S_IROTH)) {
      perm = pstrcat(p, perm, "r", NULL);
    }

    if (mode & (S_IWUSR|S_IWGRP|S_IWOTH)) {
      perm = pstrcat(p, perm, "w", NULL);
    }

  } else if (S_ISDIR(mode)) {
    if (mode & (S_IWUSR|S_IWGRP|S_IWOTH)) {
      perm = pstrcat(p, perm, "c", NULL);
    }

    perm = pstrcat(p, perm, "d", NULL);

    if (mode & (S_IXUSR|S_IXGRP|S_IXOTH)) {
      perm = pstrcat(p, perm, "e", NULL);
    }

    if (mode & (S_IWUSR|S_IWGRP|S_IWOTH)) {
      perm = pstrcat(p, perm, "f", NULL);
    }

    if (mode & (S_IXUSR|S_IXGRP|S_IXOTH)) {
      perm = pstrcat(p, perm, "l", NULL);
    }

    if (mode & (S_IWUSR|S_IWGRP|S_IWOTH)) {
      perm = pstrcat(p, perm, "mp", NULL);
    }
  }

  return perm;
}

static int get_unix_nlink(pool *p, char *buf, size_t buflen, struct stat *st) {
  char *nlinks_ptr;

  if (strpbrk(buf, "0123456789 ") == NULL) {
    errno = EINVAL;
    return -1;
  }

  nlinks_ptr = strpbrk(buf, "0123456789");
  if (nlinks_ptr == NULL) {
    errno = EINVAL;
    return -1;
  }

  st->st_nlink = atoi(nlinks_ptr);
  return 0;
}

static int get_unix_user(pool *p, char *buf, size_t buflen,
    struct proxy_dirlist_fileinfo *pdf) {
  int res;
  char user[32];
  uid_t uid;

  memset(user, '\0', sizeof(user));

  while (PR_ISSPACE(*buf) &&
         *buf) {
    buf += 1;
    buflen -= 1;
  }

  res = sscanf(buf, "%s", user);
  if (res != 1) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (unable to parse user): '%.*s'", (int) buflen, buf);
    errno = EINVAL;
    return -1;
  }

  if (pr_str2uid(user, &uid) == 0) {
    pdf->st->st_uid = uid;
    pdf->have_uid = TRUE;

  } else {
    pdf->user = pstrdup(p, user);
  }

  return 0;
}

static int get_unix_group(pool *p, char *buf, size_t buflen,
    struct proxy_dirlist_fileinfo *pdf) {
  int res;
  char group[32];
  gid_t gid;

  memset(group, '\0', sizeof(group));

  while (PR_ISSPACE(*buf) &&
         *buf) {
    buf += 1;
    buflen -= 1;
  }

  res = sscanf(buf, "%s", group);
  if (res != 1) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (unable to parse group): '%.*s'", (int) buflen, buf);
    errno = EINVAL;
    return -1;
  }

  if (pr_str2gid(group, &gid) == 0) {
    pdf->st->st_gid = gid;
    pdf->have_gid = TRUE;

  } else {
    pdf->group = pstrdup(p, group);
  }

  return 0;
}

static int get_unix_filesize(pool *p, char *buf, size_t buflen,
    struct stat *st) {
  off_t filesz;

  if (pr_str_get_nbytes(buf, NULL, &filesz) < 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (unable to parse filesize: %s): '%.*s'",
      strerror(errno), (int) buflen, buf);
    errno = EINVAL;
    return -1;
  }

  st->st_size = filesz;
  return 0;
}

static const char *months[13] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  NULL
};

/* Either:
 *
 *  "Jul 21 04:53"
 *  "Apr  9  2015"
 */
static int get_unix_timestamp(pool *p, char *buf, size_t buflen,
    struct tm *tm, int current_year) {
  register unsigned int i;
  int found_month = FALSE, mday, year, hour, min, res;

  for (i = 0; months[i]; i++) {
    if (strncmp(buf, months[i], 3) == 0) {
      tm->tm_mon = (int) i;
      found_month = TRUE;
      break;
    }
  }

  if (found_month == FALSE) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (unable to month in '%.*s')", (int) buflen, buf);
    errno = EINVAL;
    return -1;
  }

  buf += 3;
  buflen -= 3;

  if (strncmp(buf, " ", 1) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after month): '%.*s'",
      (int) buflen, buf);
    errno = EINVAL;
    return -1;
  }

  buf += 1;
  buflen -= 1;

  res = sscanf(buf, "%2d", &mday);
  if (res != 1) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected mday after month): '%.*s'",
      (int) buflen, buf);
    errno = EINVAL;
    return -1;
  }

  tm->tm_mday = mday;
  buf += 2;
  buflen -= 2;

  res = sscanf(buf, "%02d:%02d", &hour, &min);
  if (res == 2) {
    tm->tm_year = current_year;
    tm->tm_hour = hour;
    tm->tm_min = min;

  } else {
    /* We have text of 5 characters, but years are only 4 characters.
     * Advance past the space character.
     */
    buf += 1;
    buflen -= 1;

    res = sscanf(buf, "%4d", &year);
    if (res == 1) {
      tm->tm_year = year;
      if (tm->tm_year > 1900) {
        tm->tm_year -= 1900;
      }

    } else {
      pr_trace_msg(trace_channel, 3,
        "malformed Unix text (expected year/hour/min after mday): '%.*s'",
        (int) buflen, buf);
      errno = EINVAL;
      return -1;
    }
  }

  return 0;
}

struct proxy_dirlist_fileinfo *proxy_ftp_dirlist_fileinfo_from_unix(pool *p,
    const char *text, size_t textlen, struct tm *tm, unsigned long opts) {
  struct proxy_dirlist_fileinfo *pdf;
  char *buf, *perm, *ptr, *ptr2;
  size_t buflen;
  mode_t mode;

  if (p == NULL ||
      text == NULL ||
      textlen == 0 ||
      tm == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 19, "parsing Unix text: '%.*s'",
    (int) textlen, text);

  /* 43 is the minimum length of a well-formatted Unix directory listing
   * line.
   */
  if (textlen < 43) {
    pr_trace_msg(trace_channel, 3,
      "error parsing Unix text (too short, need at least 43 bytes): '%.*s'",
        (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  pdf = pcalloc(p, sizeof(struct proxy_dirlist_fileinfo));
  pdf->st = pcalloc(p, sizeof(struct stat));

  switch (text[0]) {
    case '-':
      pdf->st->st_mode |= S_IFREG;
      pdf->type = pstrdup(p, "file");
      break;

    case 'd':
      pdf->st->st_mode |= S_IFDIR;
      pdf->type = pstrdup(p, "dir");
      break;

    case 'l':
#if defined(S_IFLNK)
      pdf->st->st_mode |= S_IFLNK;
#endif /* S_IFLNK */
      /* If the USE_SLINK option is set, then pdf->type will be filled in
       * later, once we know the symlink target.
       */
      if (!(opts & PROXY_FTP_DIRLIST_OPT_USE_SLINK)) {
        pdf->type = pstrdup(p, "OS.unix=symlink");
      }
      break;

    case 'p':
#if defined(S_IFIFO)
      pdf->st->st_mode |= S_IFIFO;
#else
      pdf->st->st_mode |= S_IFREG;
#endif /* S_IFIFO */
      pdf->type = pstrdup(p, "OS.unix=pipe");
      break;

    case 's':
#if defined(S_IFSOCK)
      pdf->st->st_mode |= S_IFSOCK;
#else
      pdf->st->st_mode |= S_IFREG;
#endif /* S_IFSOCK */
      pdf->type = pstrdup(p, "OS.unix=socket");
      break;

    case 'c':
#if defined(S_IFCHR)
      pdf->st->st_mode |= S_IFCHR;
#else
      pdf->st->st_mode |= S_IFREG;
#endif /* S_IFCHR */
      pdf->type = pstrdup(p, "OS.unix=chardev");
      break;

    case 'b':
#if defined(S_IFBLK)
      pdf->st->st_mode |= S_IFBLK;
#else
      pdf->st->st_mode |= S_IFREG;
#endif /* S_IFBLK */
      pdf->type = pstrdup(p, "OS.unix=blockdev");
      break;

    case 'D':
#if defined(S_IFIFO)
      pdf->st->st_mode |= S_IFIFO;
#else
      pdf->st->st_mode |= S_IFREG;
#endif /* S_IFIFO */
      pdf->type = pstrdup(p, "OS.solaris=door");
      break;

    default:
      pr_trace_msg(trace_channel, 3, "unknown Unix file type: '%.*s'", 1, text);
      errno = EINVAL;
      return NULL;
  }

  ptr = (char *) text + 1;
  buflen = 9;
  buf = pstrndup(p, ptr, buflen);

  if (strpbrk(buf, "rwx-tTsS") == NULL) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected permissions): '%.*s'", (int) buflen, buf);
    errno = EINVAL;
    return NULL;
  }

  mode = get_unix_mode(buf);
  pdf->st->st_mode |= mode;

  perm = get_perm_fact(p, pdf->st->st_mode);
  pdf->perm = perm;

  ptr += buflen;
  if (strncmp(ptr, " ", 1) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after permissions): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  ptr += 1;

  if (*ptr == ' ') {
    buflen = 3;

  } else {
    ptr2 = strchr(ptr, ' ');
    if (ptr2 == NULL) {
      pr_trace_msg(trace_channel, 3,
        "malformed Unix text (expected space after nlink): '%.*s'",
        (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    buflen = ptr2 - ptr;
  }

  buf = pstrndup(p, ptr, buflen);
  if (get_unix_nlink(p, buf, buflen, pdf->st) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected nlink with '%.*s'): '%.*s'", (int) buflen,
      buf, (int) textlen, text);

    errno = xerrno;
    return NULL;
  }

  ptr += buflen;
  if (strncmp(ptr, " ", 1) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after nlink): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  ptr += 1;

  buflen = 8;
  buf = pstrndup(p, ptr, buflen);
  if (get_unix_user(p, buf, buflen, pdf) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected user with '%.*s'): '%.*s'", (int) buflen,
      buf, (int) textlen, text);

    errno = xerrno;
    return NULL;
  }

  ptr += buflen;
  if (strncmp(ptr, " ", 1) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after user): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  ptr += 1;

  buflen = 8;
  buf = pstrndup(p, ptr, buflen);
  if (get_unix_group(p, buf, buflen, pdf) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected group with '%.*s'): '%.*s'", (int) buflen,
      buf, (int) textlen, text);

    errno = xerrno;
    return NULL;
  }

  ptr += buflen;
  if (strncmp(ptr, " ", 1) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after group): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  ptr += 1;

  while (PR_ISSPACE(*ptr) &&
         *ptr) {
    pr_signals_handle();
    ptr++;
  }

  ptr2 = strchr(ptr, ' ');
  if (ptr2 == NULL) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after filesize): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  buflen = ptr2 - ptr;
  buf = pstrndup(p, ptr, buflen);
  if (get_unix_filesize(p, buf, buflen, pdf->st) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected filesize with '%.*s'): '%.*s'",
      (int) buflen, buf, (int) textlen, text);

    errno = xerrno;
    return NULL;
  }

  ptr += buflen;
  if (strncmp(ptr, " ", 1) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after filesize): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  ptr += 1;

  pdf->tm = pcalloc(p, sizeof(struct tm));
  buflen = 12;
  buf = pstrndup(p, ptr, buflen);
  if (get_unix_timestamp(p, buf, buflen, pdf->tm, tm->tm_year) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected timestamp with '%.*s'): '%.*s'",
      (int) buflen, buf, (int) textlen, text);

    errno = xerrno;
    return NULL;
  }

  ptr += buflen;
  if (strncmp(ptr, " ", 1) != 0) {
    pr_trace_msg(trace_channel, 3,
      "malformed Unix text (expected space after timestamp): '%.*s'",
      (int) textlen, text);
    errno = EINVAL;
    return NULL;
  }

  ptr += 1;

  if (S_ISLNK(pdf->st->st_mode)) {
    ptr2 = strchr(ptr, ' ');
    if (ptr2 == NULL) {
      pr_trace_msg(trace_channel, 3,
        "malformed Unix text (expected space after symlink source): '%.*s'",
        (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    buflen = ptr2 - ptr;
    pdf->path = pstrndup(p, ptr, buflen);

    ptr = ptr2 + 1;
    if (strncmp(ptr, "-> ", 3) != 0) {
      pr_trace_msg(trace_channel, 3,
        "malformed Unix text (expected arrow after symlink source): '%.*s'",
        (int) textlen, text);
      errno = EINVAL;
      return NULL;
    }

    ptr += 3;

    if (opts & PROXY_FTP_DIRLIST_OPT_USE_SLINK) {
      char *target_path;

      target_path = pstrdup(p, ptr);
      pdf->type = pstrcat(p, "OS.unix=slink:", target_path, NULL);
    }

  } else {
    pdf->path = pstrdup(p, ptr);
  }

  if (strcmp(pdf->path, ".") == 0) {
    pdf->type = pstrdup(p, "cdir");

  } else if (strcmp(pdf->path, "..") == 0) {
    pdf->type = pstrdup(p, "pdir");
  }

  return pdf;
}

struct proxy_dirlist_fileinfo *proxy_ftp_dirlist_fileinfo_from_text(pool *p,
    const char *text, size_t textlen, struct tm *tm, void *user_data,
    unsigned long opts) {
  struct proxy_session *proxy_sess;
  struct dirlist_ctx *ctx;
  struct proxy_dirlist_fileinfo *pdf = NULL;

  if (p == NULL ||
      text == NULL ||
      textlen == 0 ||
      user_data == NULL) {
    errno = EINVAL;
    return NULL;
  }

  proxy_sess = user_data;
  if (proxy_sess->dirlist_ctx == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ctx = proxy_sess->dirlist_ctx;

  if (ctx->list_style == DIRLIST_LIST_STYLE_UNKNOWN) {
    /* We don't know yet what style of listing we have, so we use some
     * heuristics to guess.
     *
     * A Windows-style listing always starts with a timestamp, e.g.:
     *
     *   01-29-97 11:32PM <DIR> prog
     *
     * Thus if the first character is '0' or '1', we treat it as Windows,
     * otherwise Unix.
     */

    if (text[0] == '0' ||
        text[1] == '1') {
      ctx->list_style = DIRLIST_LIST_STYLE_WINDOWS;
      pr_trace_msg(trace_channel, 19,
        "assuming Windows-style directory listing data");

    } else {
      ctx->list_style = DIRLIST_LIST_STYLE_UNIX;
      pr_trace_msg(trace_channel, 19,
        "assuming Unix-style directory listing data");
    }
  }

  switch (ctx->list_style) {
    case DIRLIST_LIST_STYLE_UNIX:
      pdf = proxy_ftp_dirlist_fileinfo_from_unix(p, text, textlen, tm, opts);
      break;

    case DIRLIST_LIST_STYLE_WINDOWS:
      pdf = proxy_ftp_dirlist_fileinfo_from_dos(p, text, textlen, opts);
      break;

    default:
      pr_trace_msg(trace_channel, 3,
        "unable to determine directory listing style");
      errno = EPERM;
      pdf = NULL;
      break;
  }

  return pdf;
}

static size_t facts_fmt(const struct proxy_dirlist_fileinfo *pdf, char *buf,
    size_t bufsz) {
  int len;
  char *ptr;
  size_t buflen = 0;

  memset(buf, '\0', bufsz);
  ptr = buf;

  if (pdf->tm != NULL &&
      (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_MODIFY)) {
    len = pr_snprintf(ptr, bufsz, "modify=%04d%02d%02d%02d%02d%02d;",
      pdf->tm->tm_year+1900, pdf->tm->tm_mon+1, pdf->tm->tm_mday,
      pdf->tm->tm_hour, pdf->tm->tm_min, pdf->tm->tm_sec);
    buflen += len;
    ptr = buf + buflen;
  }

  if (pdf->perm != NULL &&
      (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_PERM)) {
    len = pr_snprintf(ptr, bufsz - buflen, "perm=%s;", pdf->perm);
    buflen += len;
    ptr = buf + buflen;
  }

  if (pdf->st != NULL &&
      !S_ISDIR(pdf->st->st_mode) &&
      (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_SIZE)) {
    len = pr_snprintf(ptr, bufsz - buflen, "size=%" PR_LU ";",
      (pr_off_t) pdf->st->st_size);
    buflen += len;
    ptr = buf + buflen;
  }

  if (pdf->type != NULL &&
      (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_TYPE)) {
    len = pr_snprintf(ptr, bufsz - buflen, "type=%s;", pdf->type);
    buflen += len;
    ptr = buf + buflen;
  }

  if (pdf->st != NULL) {
    if (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_UNIQUE) {
      len = pr_snprintf(ptr, bufsz - buflen, "unique=%lXU%lX;",
        (unsigned long) pdf->st->st_dev, (unsigned long) pdf->st->st_ino);
      buflen += len;
      ptr = buf + buflen;
    }

    if (pdf->have_gid == TRUE &&
        (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP)) {
      len = pr_snprintf(ptr, bufsz - buflen, "UNIX.group=%s;",
        pr_gid2str(NULL, pdf->st->st_gid));
      buflen += len;
      ptr = buf + buflen;
    }
  }

  if (pdf->group != NULL &&
      (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP_NAME)) {
    len = pr_snprintf(ptr, bufsz - buflen, "UNIX.groupname=%s;", pdf->group);
    buflen += len;
    ptr = buf + buflen;
  }

  if (pdf->st != NULL) {
    if (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_UNIX_MODE) {
      len = pr_snprintf(ptr, bufsz - buflen, "UNIX.mode=0%o;",
        (unsigned int) pdf->st->st_mode & 07777);
      buflen += len;
      ptr = buf + buflen;
    }

    if (pdf->have_uid == TRUE &&
        (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER)) {
      len = pr_snprintf(ptr, bufsz - buflen, "UNIX.owner=%s;",
        pr_uid2str(NULL, pdf->st->st_uid));
      buflen += len;
      ptr = buf + buflen;
    }
  }

  if (pdf->user != NULL &&
      (facts_opts & PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER_NAME)) {
    len = pr_snprintf(ptr, bufsz - buflen, "UNIX.ownername=%s;", pdf->user);
    buflen += len;
    ptr = buf + buflen;
  }

  /* Make sure we terminate each line with CRLF; this text will be sent to
   * the requesting client as is.
   */
  len = pr_snprintf(ptr, bufsz - buflen, " %s\r\n", pdf->path);

  buf[bufsz-1] = '\0';
  buflen += len;

  return buflen;
}

const char *proxy_ftp_dirlist_fileinfo_to_facts(pool *p,
    const struct proxy_dirlist_fileinfo *pdf, size_t *textlen) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  size_t buflen;

  if (p == NULL ||
      pdf == NULL ||
      textlen == NULL) {
    errno = EINVAL;
    return NULL;
  }

  buflen = facts_fmt(pdf, buf, sizeof(buf));
  *textlen = buflen;

  return pstrndup(p, buf, buflen);
}

static array_header *text_to_lines(pool *p, const char *text, size_t textlen) {
  char *ptr;
  array_header *text_lines;

  text_lines = make_array(p, 1, sizeof(char *));

  ptr = proxy_strnstr(text, "\r\n", textlen);
  while (ptr != NULL) {
    size_t linelen;

    pr_signals_handle();

    linelen = ptr - text;
    if (linelen > 0) {
      char *line;

      line = palloc(p, linelen + 1);
      memcpy(line, text, linelen);
      line[linelen] = '\0';
      *((char **) push_array(text_lines)) = line;
    }

    text = ptr + 2;
    textlen = textlen - linelen - 2;
    if (textlen == 0) {
      break;
    }

    ptr = proxy_strnstr(text, "\r\n", textlen);
  }

  if (textlen > 0) {
    *((char **) push_array(text_lines)) = pstrdup(p, text);
  }

  return text_lines;
}

int proxy_ftp_dirlist_to_text(pool *p, char *buf, size_t buflen,
    size_t max_textsz, char **output_text, size_t *output_textlen,
    void *user_data) {
  register unsigned int i;
  pool *tmp_pool;
  struct proxy_session *proxy_sess;
  struct dirlist_ctx *ctx;
  char *text, **lines;
  size_t textlen;
  array_header *text_lines;
  unsigned long current_facts_opts;
  time_t now;
  struct tm *tm;

  if (p == NULL ||
      buf == NULL ||
      buflen == 0 ||
      max_textsz == 0 ||
      output_text == NULL ||
      output_textlen == NULL ||
      user_data == NULL) {
    errno = EINVAL;
    return -1;
  }

  proxy_sess = user_data;
  if (proxy_sess->dirlist_ctx == NULL) {
    errno = EINVAL;
    return -1;
  }

  ctx = proxy_sess->dirlist_ctx;
  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Proxy Dirlist Text Pool");

  /* Our text to process is comprised of any previous buffered input text,
   * and our given input buffer.
   */
  if (ctx->input_textlen == 0) {
    text = buf;
    textlen = buflen;

  } else {
    /* We cannot use pstrcat() here because the buffers are not
     * NUL-terminated.
     */
    textlen = ctx->input_textlen + buflen;
    text = palloc(tmp_pool, textlen + 1);
    memcpy(text, ctx->input_ptr, ctx->input_textlen);
    memcpy(text + ctx->input_textlen, buf, buflen);
    text[textlen] = '\0';

    ctx->input_text = ctx->input_ptr;
    ctx->input_textlen = 0;
  }

  if (textlen < 3) {
    /* Not enough; keep accumulating. */
    memcpy(ctx->input_text, text, textlen);
    ctx->input_text += textlen;
    ctx->input_textlen += textlen;

    return 0;
  }

  /* Check for a terminating CRLF.  If present, we can process the entire
   * text.  Otherwise, trim off the unterminated line, and save it for the
   * next pass.
   */
  if (text[textlen-2] != '\r' ||
      text[textlen-1] != '\n') {
    char *ptr = NULL;
    size_t len = 0;

    /* Too bad there is no `memrchr(3)` library function. */
    for (i = textlen-1; i != 0; i--) {
      if (text[i] == '\n') {
        ptr = &(text[i]);
        break;
      }
    }

    if (ptr == NULL) {
      memcpy(ctx->input_text, text, textlen);
      ctx->input_text += textlen;
      ctx->input_textlen += textlen;

      return 0;
    }

    ptr++;

    len = textlen - (ptr - text);
    if (len > ctx->input_textsz) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unterminated directory list data length (%lu bytes) exceeds "
        "capacity (%lu bytes), rejecting", (unsigned long) len,
        (unsigned long) ctx->input_textsz);
      errno = EPERM;
      return -1;
    }

    memcpy(ctx->input_text, ptr, len);
    ctx->input_text += len;
    ctx->input_textlen += len;

    pr_trace_msg(trace_channel, 25,
      "given text (%lu bytes) is not CRLF-terminated, "
      "trimming %lu bytes for later", (unsigned long) textlen,
      (unsigned long) len);
    textlen -= len;
  }

  text_lines = text_to_lines(tmp_pool, text, textlen);

  current_facts_opts = facts_opts;

  /* We get the current time, for filling in defaults. */
  now = time(NULL);
  tm = pr_gmtime(tmp_pool, &now);

  lines = text_lines->elts;
  for (i = 0; i < text_lines->nelts; i++) {
    const char *input_line, *output_line;
    size_t input_linelen, output_linelen = 0;
    struct proxy_dirlist_fileinfo *pdf;

    pr_signals_handle();

    input_line = lines[i];
    input_linelen = strlen(input_line);

    /* Skip any possible "total NNN" lines, as from /bin/ls. */
    if (ctx->skip_total == TRUE) {
      ctx->skip_total = FALSE;

      if (strncmp(input_line, "total ", 6) == 0) {
        continue;
      }
    }

    pdf = proxy_ftp_dirlist_fileinfo_from_text(tmp_pool, input_line,
      input_linelen, tm, user_data, proxy_sess->dirlist_opts);
    if (pdf == NULL) {
      pr_trace_msg(trace_channel, 3, "error parsing text '%.*s': %s",
        (int) input_linelen, input_line, strerror(errno));
      continue;
    }

    if (ctx->list_style == DIRLIST_LIST_STYLE_WINDOWS) {
      /* Once we know that we are parsing a Windows-style directory listing,
       * we can toggle off the RFC 3649 facts that we KNOW will not be provided
       * by the listing data.
       */
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_PERM;
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_UNIQUE;
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_UNIX_MODE;
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP;
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP_NAME;
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER;
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER_NAME;

    } else {
      /* Once we know that we are parsing a Unix-style directory listing,
       * we can toggle off the RFC 3649 facts that we KNOW will not be provided
       * by the listing data.
       */
      facts_opts &= ~PROXY_FTP_FACTS_OPT_SHOW_UNIQUE;
    }

    output_line = proxy_ftp_dirlist_fileinfo_to_facts(tmp_pool, pdf,
      &output_linelen);

    pr_trace_msg(trace_channel, 19, "emitting line: '%.*s'",
      (int) output_linelen, output_line);

    /* XXX What to do if this will exceed capacity of output buffer? */
    /* TODO: Watch for output_linelen > (ctx->output_textsz - ctx->output_textlen),
     * and rejigger this function to handle the case of "no more input to
     * accumulate, but have unprocess input".
     */

    sstrcat(ctx->output_text, output_line,
      ctx->output_textsz - ctx->output_textlen);
    ctx->output_text += output_linelen;
    ctx->output_textlen += output_linelen;
  }

  facts_opts = current_facts_opts;

  *output_textlen = ctx->output_textlen;
  if (*output_textlen > max_textsz) {
    *output_textlen = max_textsz;
  }

  pr_trace_msg(trace_channel, 29,
    "emitting %lu bytes of output text (max %lu), for %lu bytes of input text",
    (unsigned long) *output_textlen, (unsigned long) max_textsz, textlen);

  *output_text = palloc(p, *output_textlen);
  memcpy(*output_text, ctx->output_ptr, *output_textlen);

  memmove(ctx->output_ptr, ctx->output_ptr + *output_textlen,
    ctx->output_textsz - *output_textlen);
  ctx->output_text = ctx->output_ptr;
  ctx->output_textlen -= *output_textlen;

  destroy_pool(tmp_pool);
  return 0;
}
