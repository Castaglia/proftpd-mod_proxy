/* -----------------------------------------------------------------------
 * 
 * umac.h -- C Implementation UMAC Message Authentication
 *
 * Version 0.93a of rfc4418.txt -- 2006 July 14
 *
 * For a full description of UMAC message authentication see the UMAC
 * world-wide-web page at http://www.cs.ucdavis.edu/~rogaway/umac
 * Please report bugs and suggestions to the UMAC webpage.
 *
 * Copyright (c) 1999-2004 Ted Krovetz
 *                                                                 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and with or without fee, is hereby
 * granted provided that the above copyright notice appears in all copies
 * and in supporting documentation, and that the name of the copyright
 * holder not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior permission.
 *
 * Comments should be directed to Ted Krovetz (tdk@acm.org)
 *                                                                   
 * ---------------------------------------------------------------------- */
 
#ifndef MOD_PROXY_SSH_UMAC_H
#define MOD_PROXY_SSH_UMAC_H

struct umac_ctx *proxy_ssh_umac_alloc(void);
struct umac_ctx *proxy_ssh_umac_new(const unsigned char key[]);
void proxy_ssh_umac_init(struct umac_ctx *ctx, const unsigned char key[]);
int proxy_ssh_umac_reset(struct umac_ctx *ctx);
int proxy_ssh_umac_update(struct umac_ctx *ctx, const unsigned char *input,
  long len);
int proxy_ssh_umac_final(struct umac_ctx *ctx, unsigned char tag[],
  const unsigned char nonce[8]);
int proxy_ssh_umac_delete(struct umac_ctx *ctx);

struct umac_ctx *proxy_ssh_umac128_alloc(void);
struct umac_ctx *proxy_ssh_umac128_new(const unsigned char key[]);
void proxy_ssh_umac128_init(struct umac_ctx *ctx, const unsigned char key[]);
int proxy_ssh_umac128_reset(struct umac_ctx *ctx);
int proxy_ssh_umac128_update(struct umac_ctx *ctx, const unsigned char *input,
  long len);
int proxy_ssh_umac128_final(struct umac_ctx *ctx, unsigned char tag[],
  const unsigned char nonce[8]);
int proxy_ssh_umac128_delete(struct umac_ctx *ctx);

#endif /* MOD_PROXY_SSH_UMAC_H */
