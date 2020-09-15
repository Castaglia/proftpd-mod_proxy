/*
 * ProFTPD - mod_proxy FTP Facts routines
 * Copyright (c) 2020 TJ Saunders
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

#include "proxy/ftp/facts.h"

/* Similar to those of mod_facts. */

/* NOTE: We only want to parse/handle any OPTS MLST commands from the frontend
 * client IFF the DirectoryListPolicy is "LIST".  Otherwise, let the backend
 * handle them.  But...what if the backend doesn't support OPTS MLST?  Do
 * we watch for that error, and handle it ourselves (e.g. show our defaults)?
 */

static unsigned long facts_opts = PROXY_FTP_FACTS_OPT_SHOW_MODIFY|
  PROXY_FTP_FACTS_OPT_SHOW_PERM|
  PROXY_FTP_FACTS_OPT_SHOW_SIZE|
  PROXY_FTP_FACTS_OPT_SHOW_TYPE|
  PROXY_FTP_FACTS_OPT_SHOW_UNIQUE|
  PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP|
  PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP_NAME|
  PROXY_FTP_FACTS_OPT_SHOW_UNIX_MODE|
  PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER|
  PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER_NAME;

static const char *trace_channel = "proxy.ftp.facts";

unsigned long proxy_ftp_facts_get_opts(void) {
  return facts_opts;
}

void proxy_ftp_facts_parse_opts(char *facts) {
  unsigned long opts = 0UL;
  char *ptr;

  if (facts == NULL) {
    return;
  }

  ptr = strchr(facts, ';');
  while (ptr != NULL) {
    pr_signals_handle();

    *ptr = '\0';

    if (strcasecmp(facts, "modify") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_MODIFY;

    } else if (strcasecmp(facts, "perm") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_PERM;

    } else if (strcasecmp(facts, "size") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_SIZE;

    } else if (strcasecmp(facts, "type") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_TYPE;

    } else if (strcasecmp(facts, "unique") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_UNIQUE;

    } else if (strcasecmp(facts, "UNIX.group") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP;

    } else if (strcasecmp(facts, "UNIX.groupname") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_UNIX_GROUP_NAME;

    } else if (strcasecmp(facts, "UNIX.mode") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_UNIX_MODE;

    } else if (strcasecmp(facts, "UNIX.owner") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER;

    } else if (strcasecmp(facts, "UNIX.ownername") == 0) {
      opts |= PROXY_FTP_FACTS_OPT_SHOW_UNIX_OWNER_NAME;

    } else {
      pr_trace_msg(trace_channel, 7,
        "client requested unsupported fact '%s'", facts);
    }

    *ptr = ';';
    facts = ptr + 1;
    ptr = strchr(facts, ';');
  }

  facts_opts = opts;
}
