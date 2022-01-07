/*
 * ProFTPD - mod_proxy SSH ciphers
 * Copyright (c) 2021 TJ Saunders
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

#include "proxy/ssh/packet.h"
#include "proxy/ssh/msg.h"
#include "proxy/ssh/crypto.h"
#include "proxy/ssh/cipher.h"
#include "proxy/ssh/session.h"
#include "proxy/ssh/interop.h"

#if defined(PR_USE_OPENSSL)
#include <openssl/evp.h>

struct proxy_ssh_cipher {
  pool *pool;
  const char *algo;
  const EVP_CIPHER *cipher;

  unsigned char *iv;
  uint32_t iv_len;

  unsigned char *key;
  uint32_t key_len;

  size_t discard_len;
};

/* We need to keep the old ciphers around, so that we can handle N
 * arbitrary packets to/from the client using the old keys, as during rekeying.
 * Thus we have two read cipher contexts, two write cipher contexts.
 * The cipher idx variable indicates which of the ciphers is currently in use.
 */

static struct proxy_ssh_cipher read_ciphers[2] = {
  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0 },
  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0 }
};
static EVP_CIPHER_CTX *read_ctxs[2];

static struct proxy_ssh_cipher write_ciphers[2] = {
  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0 },
  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0 }
};
static EVP_CIPHER_CTX *write_ctxs[2];

#define PROXY_SSH_CIPHER_DEFAULT_BLOCK_SZ		8

static size_t cipher_blockszs[2] = {
  PROXY_SSH_CIPHER_DEFAULT_BLOCK_SZ,
  PROXY_SSH_CIPHER_DEFAULT_BLOCK_SZ,
};

static unsigned int read_cipher_idx = 0;
static unsigned int write_cipher_idx = 0;

static const char *trace_channel = "proxy.ssh.cipher";

static void clear_cipher(struct proxy_ssh_cipher *);

static unsigned int get_next_read_index(void) {
  if (read_cipher_idx == 1) {
    return 0;
  }

  return 1;
}

static unsigned int get_next_write_index(void) {
  if (write_cipher_idx == 1) {
    return 0;
  }

  return 1;
}

static void switch_read_cipher(void) {
  /* First, clear the context of the existing read cipher, if any. */
  if (read_ciphers[read_cipher_idx].key) {
    clear_cipher(&(read_ciphers[read_cipher_idx]));

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
    if (EVP_CIPHER_CTX_cleanup(read_ctxs[read_cipher_idx]) != 1) {
#else
    if (EVP_CIPHER_CTX_reset(read_ctxs[read_cipher_idx]) != 1) {
#endif /* OpenSSL-1.1.x and later */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error clearing cipher context: %s", proxy_ssh_crypto_get_errors());
    }
 
    cipher_blockszs[read_cipher_idx] = PROXY_SSH_CIPHER_DEFAULT_BLOCK_SZ; 

    /* Now we can switch the index. */
    if (read_cipher_idx == 1) {
      read_cipher_idx = 0;
      return;
    }

    read_cipher_idx = 1;
  }
}

static void switch_write_cipher(void) {
  /* First, clear the context of the existing read cipher, if any. */
  if (write_ciphers[write_cipher_idx].key) {
    clear_cipher(&(write_ciphers[write_cipher_idx]));

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
    if (EVP_CIPHER_CTX_cleanup(write_ctxs[write_cipher_idx]) != 1) {
#else
    if (EVP_CIPHER_CTX_reset(write_ctxs[write_cipher_idx]) != 1) {
#endif /* OpenSSL-1.1.x and later */
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error clearing cipher context: %s", proxy_ssh_crypto_get_errors());
    }

    cipher_blockszs[write_cipher_idx] = PROXY_SSH_CIPHER_DEFAULT_BLOCK_SZ;

    /* Now we can switch the index. */
    if (write_cipher_idx == 1) {
      write_cipher_idx = 0;
      return;
    }

    write_cipher_idx = 1;
  }
}

static void clear_cipher(struct proxy_ssh_cipher *cipher) {
  if (cipher->iv != NULL) {
    pr_memscrub(cipher->iv, cipher->iv_len);
    free(cipher->iv);
    cipher->iv = NULL;
    cipher->iv_len = 0;
  }

  if (cipher->key != NULL) {
    pr_memscrub(cipher->key, cipher->key_len);
    free(cipher->key);
    cipher->key = NULL;
    cipher->key_len = 0;
  }

  cipher->cipher = NULL;
  cipher->algo = NULL;
}

static int set_cipher_iv(struct proxy_ssh_cipher *cipher, const EVP_MD *md,
    const unsigned char *k, uint32_t klen, const char *h, uint32_t hlen,
    char letter, const unsigned char *id, uint32_t id_len) {
  EVP_MD_CTX *ctx;
  unsigned char *iv = NULL;
  size_t cipher_iv_len = 0, iv_sz = 0;
  uint32_t iv_len = 0;

  if (strcmp(cipher->algo, "none") == 0) {
    cipher->iv = iv;
    cipher->iv_len = iv_len;

    return 0;
  }

   /* Some ciphers do not use IVs; handle this case. */
  cipher_iv_len = EVP_CIPHER_iv_length(cipher->cipher);
  if (cipher_iv_len != 0) {
    iv_sz = proxy_ssh_crypto_get_size(cipher_iv_len, EVP_MD_size(md));

  } else {
    iv_sz = EVP_MD_size(md);
  }

  if (iv_sz == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to determine IV length for cipher '%s'", cipher->algo);
     errno = EINVAL;
    return -1;
  }

  iv = malloc(iv_sz);
  if (iv == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_PROXY_VERSION ": Out of memory!");
    _exit(1);
  }

  ctx = EVP_MD_CTX_create();
  EVP_DigestInit(ctx, md);
  if (proxy_ssh_interop_supports_feature(PROXY_SSH_FEAT_CIPHER_USE_K)) {
    EVP_DigestUpdate(ctx, k, klen);
  }
  EVP_DigestUpdate(ctx, h, hlen);
  EVP_DigestUpdate(ctx, &letter, sizeof(letter));
  EVP_DigestUpdate(ctx, (char *) id, id_len);
  EVP_DigestFinal(ctx, iv, &iv_len);
  EVP_MD_CTX_destroy(ctx);

  /* If we need more, keep hashing, as per RFC, until we have enough
   * material.
   */
  while (iv_sz > iv_len) {
    uint32_t len = iv_len;

    pr_signals_handle();

    ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, md);
    if (proxy_ssh_interop_supports_feature(PROXY_SSH_FEAT_CIPHER_USE_K)) {
      EVP_DigestUpdate(ctx, k, klen);
    }
    EVP_DigestUpdate(ctx, h, hlen);
    EVP_DigestUpdate(ctx, iv, len);
    EVP_DigestFinal(ctx, iv + len, &len);
    EVP_MD_CTX_destroy(ctx);

    iv_len += len;
  }

  cipher->iv = iv;
  cipher->iv_len = iv_len;

  return 0;
}

static int set_cipher_key(struct proxy_ssh_cipher *cipher, const EVP_MD *md,
    const unsigned char *k, uint32_t klen, const char *h, uint32_t hlen,
    char letter, const unsigned char *id, uint32_t id_len) {
  EVP_MD_CTX *ctx;
  unsigned char *key = NULL;
  size_t key_sz = 0;
  uint32_t key_len = 0;

  if (strcmp(cipher->algo, "none") == 0) {
    cipher->key = key;
    cipher->key_len = key_len;

    return 0;
  }

  key_sz = proxy_ssh_crypto_get_size(cipher->key_len > 0 ?
      cipher->key_len : (size_t) EVP_CIPHER_key_length(cipher->cipher),
    EVP_MD_size(md));
  if (key_sz == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to determine key length for cipher '%s'", cipher->algo);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 19, "setting key (%lu bytes) for cipher %s",
    (unsigned long) key_sz, cipher->algo);

  key = malloc(key_sz);
  if (key == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_PROXY_VERSION ": Out of memory!");
    _exit(1);
  }

  ctx = EVP_MD_CTX_create();
  EVP_DigestInit(ctx, md);
  EVP_DigestUpdate(ctx, k, klen);
  EVP_DigestUpdate(ctx, h, hlen);
  EVP_DigestUpdate(ctx, &letter, sizeof(letter));
  EVP_DigestUpdate(ctx, (char *) id, id_len);
  EVP_DigestFinal(ctx, key, &key_len);
  EVP_MD_CTX_destroy(ctx);

  pr_trace_msg(trace_channel, 19, "hashed data to produce key (%lu bytes)",
    (unsigned long) key_len);

  /* If we need more, keep hashing, as per RFC, until we have enough
   * material.
   */
  while (key_sz > key_len) {
    uint32_t len = key_len;

    pr_signals_handle();

    ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, k, klen);
    EVP_DigestUpdate(ctx, h, hlen);
    EVP_DigestUpdate(ctx, key, len);
    EVP_DigestFinal(ctx, key + len, &len);
    EVP_MD_CTX_destroy(ctx);

    key_len += len;
  }

  cipher->key = key;
  return 0;
}

/* If the chosen cipher requires that we discard some of the initial bytes of
 * the cipher stream, then do so.  (This is mostly for any RC4 ciphers.)
 */
static int set_cipher_discarded(struct proxy_ssh_cipher *cipher,
    EVP_CIPHER_CTX *pctx) {
  unsigned char *garbage_in, *garbage_out;

  if (cipher->discard_len == 0) {
    return 0;
  }

  garbage_in = malloc(cipher->discard_len);
  if (garbage_in == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_PROXY_VERSION ": Out of memory!");
    _exit(1);
  }

  garbage_out = malloc(cipher->discard_len);
  if (garbage_out == NULL) {
    free(garbage_in);
    pr_log_pri(PR_LOG_ALERT, MOD_PROXY_VERSION ": Out of memory!");
    _exit(1);
  }

  if (EVP_Cipher(pctx, garbage_out, garbage_in,
      cipher->discard_len) != 1) {
    free(garbage_in);
    pr_memscrub(garbage_out, cipher->discard_len);
    free(garbage_out);
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error ciphering discard data: %s", proxy_ssh_crypto_get_errors());

    return -1;
  }

  pr_trace_msg(trace_channel, 19, "discarded %lu bytes of cipher data",
    (unsigned long) cipher->discard_len);
  free(garbage_in);
  pr_memscrub(garbage_out, cipher->discard_len);
  free(garbage_out);

  return 0;
}

size_t proxy_ssh_cipher_get_block_size(void) {
  return cipher_blockszs[read_cipher_idx];
}

void proxy_ssh_cipher_set_block_size(size_t blocksz) {
  if (blocksz > cipher_blockszs[read_cipher_idx]) {
    cipher_blockszs[read_cipher_idx] = blocksz;
  }
}

const char *proxy_ssh_cipher_get_read_algo(void) {
  if (read_ciphers[read_cipher_idx].key != NULL ||
      strcmp(read_ciphers[read_cipher_idx].algo, "none") == 0) {
    return read_ciphers[read_cipher_idx].algo;
  }

  return NULL;
}

int proxy_ssh_cipher_set_read_algo(pool *p, const char *algo) {
  unsigned int idx = read_cipher_idx;
  size_t key_len = 0, discard_len = 0;

  if (read_ciphers[idx].key != NULL) {
    /* If we have an existing key, it means that we are currently rekeying. */
    idx = get_next_read_index();
  }

  read_ciphers[idx].cipher = proxy_ssh_crypto_get_cipher(algo, &key_len,
    &discard_len);
  if (read_ciphers[idx].cipher == NULL) {
    return -1;
  }

  if (key_len > 0) {
    pr_trace_msg(trace_channel, 19,
      "setting read key for cipher %s: key len = %lu", algo,
      (unsigned long) key_len);
  }

  if (discard_len > 0) {
    pr_trace_msg(trace_channel, 19,
      "setting read key for cipher %s: discard len = %lu", algo,
      (unsigned long) discard_len);
  }

  /* Note that we use a new pool, each time the algorithm is set (which
   * happens during key exchange) to prevent undue memory growth for
   * long-lived sessions with many rekeys.
   */
  if (read_ciphers[idx].pool != NULL) {
    destroy_pool(read_ciphers[idx].pool);
  }

  read_ciphers[idx].pool = make_sub_pool(p);
  pr_pool_tag(read_ciphers[idx].pool, "Proxy SFTP cipher read pool");
  read_ciphers[idx].algo = pstrdup(read_ciphers[idx].pool, algo);

  read_ciphers[idx].key_len = (uint32_t) key_len;
  read_ciphers[idx].discard_len = discard_len;
  return 0;
}

int proxy_ssh_cipher_set_read_key(pool *p, const EVP_MD *md,
    const unsigned char *k, uint32_t klen, const char *h, uint32_t hlen,
    int role) {
  const unsigned char *id = NULL;
  char letter;
  uint32_t id_len;
  int key_len;
  struct proxy_ssh_cipher *cipher;
  EVP_CIPHER_CTX *pctx;

  /* Currently unused. */
  (void) p;

  switch_read_cipher();

  cipher = &(read_ciphers[read_cipher_idx]);
  pctx = read_ctxs[read_cipher_idx];

  id_len = proxy_ssh_session_get_id(&id);

  /* The letters used depend on the role; see:
   *  https://tools.ietf.org/html/rfc4253#section-7.2
   *
   * If we are the CLIENT, then we use the letters for the "server to client"
   * flows, since we are READING from the server.
   */

  /* client-to-server IV: HASH(K || H || "A" || session_id)
   * server-to-client IV: HASH(K || H || "B" || session_id)
   */
  letter = (role == PROXY_SSH_ROLE_CLIENT ? 'B' : 'A');
  if (set_cipher_iv(cipher, md, k, klen, h, hlen, letter, id, id_len) < 0) {
    return -1;
  }

  /* client-to-server key: HASH(K || H || "C" || session_id)
   * server-to-client key: HASH(K || H || "D" || session_id)
   */
  letter = (role == PROXY_SSH_ROLE_CLIENT ? 'D' : 'C');
  if (set_cipher_key(cipher, md, k, klen, h, hlen, letter, id, id_len) < 0) {
    return -1;
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_CIPHER_CTX_init(pctx);
#else
  EVP_CIPHER_CTX_reset(pctx);
#endif /* prior to OpenSSL-1.1.0 */

#if defined(PR_USE_OPENSSL_EVP_CIPHERINIT_EX)
  if (EVP_CipherInit_ex(pctx, cipher->cipher, NULL, NULL,
    cipher->iv, 0) != 1) {
#else
  if (EVP_CipherInit(pctx, cipher->cipher, NULL, cipher->iv, 0) != 1) {
#endif /* PR_USE_OPENSSL_EVP_CIPHERINIT_EX */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error initializing %s cipher for decryption: %s", cipher->algo,
      proxy_ssh_crypto_get_errors());
    return -1;
  }

  /* Next, set the key length. */
  key_len = (int) cipher->key_len;
  if (key_len > 0) {
    if (EVP_CIPHER_CTX_set_key_length(pctx, key_len) != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error setting key length (%d bytes) for %s cipher for decryption: %s",
        key_len, cipher->algo, proxy_ssh_crypto_get_errors());
      return -1;
    }

    pr_trace_msg(trace_channel, 19,
      "set key length (%d) for %s cipher for decryption", key_len,
      cipher->algo);
  }

#if defined(PR_USE_OPENSSL_EVP_CIPHERINIT_EX)
  if (EVP_CipherInit_ex(pctx, NULL, NULL, cipher->key, NULL, -1) != 1) {
#else
  if (EVP_CipherInit(pctx, NULL, cipher->key, NULL, -1) != 1) {
#endif /* PR_USE_OPENSSL_EVP_CIPHERINIT_EX */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error re-initializing %s cipher for decryption: %s", cipher->algo,
      proxy_ssh_crypto_get_errors());
    return -1;
  }

  if (set_cipher_discarded(cipher, pctx) < 0) {
    return -1;
  }

  proxy_ssh_cipher_set_block_size(EVP_CIPHER_block_size(cipher->cipher));
  return 0;
}

int proxy_ssh_cipher_read_data(pool *p, unsigned char *data, uint32_t data_len,
    unsigned char **buf, uint32_t *buflen) {
  struct proxy_ssh_cipher *cipher;
  EVP_CIPHER_CTX *pctx;
  size_t cipher_blocksz;

  cipher = &(read_ciphers[read_cipher_idx]);
  pctx = read_ctxs[read_cipher_idx];
  cipher_blocksz = cipher_blockszs[read_cipher_idx];

  if (cipher->key != NULL) {
    int res;
    unsigned char *ptr = NULL;

    if (*buflen % cipher_blocksz != 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "bad input length for decryption (%u bytes, %u block size)", *buflen,
        (unsigned int) cipher_blocksz);
      return -1;
    }

    if (*buf == NULL) {
      size_t bufsz;

      /* Allocate a buffer that's large enough. */
      bufsz = (data_len + cipher_blocksz - 1);
      ptr = palloc(p, bufsz);

    } else {
      ptr = *buf;
    }

    res = EVP_Cipher(pctx, ptr, data, data_len);
    if (res != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error decrypting %s data from client: %s", cipher->algo,
        proxy_ssh_crypto_get_errors());
      return -1;
    }

    *buflen = data_len;
    *buf = ptr;

    return 0;
  }

  *buf = data;
  *buflen = data_len;
  return 0;
}

const char *proxy_ssh_cipher_get_write_algo(void) {
  if (write_ciphers[write_cipher_idx].key != NULL ||
      strcmp(write_ciphers[write_cipher_idx].algo, "none") == 0) {
    return write_ciphers[write_cipher_idx].algo;
  }

  return NULL;
}

int proxy_ssh_cipher_set_write_algo(pool *p, const char *algo) {
  unsigned int idx = write_cipher_idx;
  size_t key_len = 0, discard_len = 0;

  if (write_ciphers[idx].key != NULL) {
    /* If we have an existing key, it means that we are currently rekeying. */
    idx = get_next_write_index();
  }

  write_ciphers[idx].cipher = proxy_ssh_crypto_get_cipher(algo, &key_len,
    &discard_len);
  if (write_ciphers[idx].cipher == NULL) {
    return -1;
  }

  if (key_len > 0) {
    pr_trace_msg(trace_channel, 19,
      "setting write key for cipher %s: key len = %lu", algo,
      (unsigned long) key_len);
  }

  if (discard_len > 0) {
    pr_trace_msg(trace_channel, 19,
      "setting write key for cipher %s: discard len = %lu", algo,
      (unsigned long) discard_len);
  }

  /* Note that we use a new pool, each time the algorithm is set (which
   * happens during key exchange) to prevent undue memory growth for
   * long-lived sessions with many rekeys.
   */
  if (write_ciphers[idx].pool != NULL) {
    destroy_pool(write_ciphers[idx].pool);
  }

  write_ciphers[idx].pool = make_sub_pool(p);
  pr_pool_tag(write_ciphers[idx].pool, "Proxy SFTP cipher write pool");
  write_ciphers[idx].algo = pstrdup(write_ciphers[idx].pool, algo);

  write_ciphers[idx].key_len = (uint32_t) key_len;
  write_ciphers[idx].discard_len = discard_len;
  return 0;
}

int proxy_ssh_cipher_set_write_key(pool *p, const EVP_MD *md,
    const unsigned char *k, uint32_t klen, const char *h, uint32_t hlen,
    int role) {
  const unsigned char *id = NULL;
  char letter;
  uint32_t id_len;
  int key_len;
  struct proxy_ssh_cipher *cipher;
  EVP_CIPHER_CTX *pctx;

  /* Currently unused. */
  (void) p;

  switch_write_cipher();

  cipher = &(write_ciphers[write_cipher_idx]);
  pctx = write_ctxs[write_cipher_idx];

  id_len = proxy_ssh_session_get_id(&id);

  /* The letters used depend on the role; see:
   *  https://tools.ietf.org/html/rfc4253#section-7.2
   *
   * If we are the CLIENT, then we use the letters for the "client to server"
   * flows, since we are WRITING to the server.
   */

  /* client-to-server IV: HASH(K || H || "A" || session_id)
   * server-to-client IV: HASH(K || H || "B" || session_id)
   */
  letter = (role == PROXY_SSH_ROLE_CLIENT ? 'A' : 'B');
  if (set_cipher_iv(cipher, md, k, klen, h, hlen, letter, id, id_len) < 0) {
    return -1;
  }

  /* client-to-server key: HASH(K || H || "C" || session_id)
   * server-to-client key: HASH(K || H || "D" || session_id)
   */
  letter = (role == PROXY_SSH_ROLE_CLIENT ? 'C' : 'D');
  if (set_cipher_key(cipher, md, k, klen, h, hlen, letter, id, id_len) < 0) {
    return -1;
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_CIPHER_CTX_init(pctx);
#else
  EVP_CIPHER_CTX_reset(pctx);
#endif

#if defined(PR_USE_OPENSSL_EVP_CIPHERINIT_EX)
  if (EVP_CipherInit_ex(pctx, cipher->cipher, NULL, NULL,
    cipher->iv, 1) != 1) {
#else
  if (EVP_CipherInit(pctx, cipher->cipher, NULL, cipher->iv, 1) != 1) {
#endif /* PR_USE_OPENSSL_EVP_CIPHERINIT_EX */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error initializing %s cipher for encryption: %s", cipher->algo,
      proxy_ssh_crypto_get_errors());
    return -1;
  }

  /* Next, set the key length. */
  key_len = (int) cipher->key_len;
  if (key_len > 0) {
    if (EVP_CIPHER_CTX_set_key_length(pctx, key_len) != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error setting key length (%d bytes) for %s cipher for decryption: %s",
        key_len, cipher->algo, proxy_ssh_crypto_get_errors());
      return -1;
    }

    pr_trace_msg(trace_channel, 19,
      "set key length (%d) for %s cipher for encryption", key_len,
      cipher->algo);
  }

#if defined(PR_USE_OPENSSL_EVP_CIPHERINIT_EX)
  if (EVP_CipherInit_ex(pctx, NULL, NULL, cipher->key, NULL, -1) != 1) {
#else
  if (EVP_CipherInit(pctx, NULL, cipher->key, NULL, -1) != 1) {
#endif /* PR_USE_OPENSSL_EVP_CIPHERINIT_EX */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error re-initializing %s cipher for encryption: %s", cipher->algo,
      proxy_ssh_crypto_get_errors());
    return -1;
  }

  if (set_cipher_discarded(cipher, pctx) < 0) {
    return -1;
  }

  return 0;
}

int proxy_ssh_cipher_write_data(struct proxy_ssh_packet *pkt,
    unsigned char *buf, size_t *buflen) {
  struct proxy_ssh_cipher *cipher;
  EVP_CIPHER_CTX *pctx;

  cipher = &(write_ciphers[write_cipher_idx]);
  pctx = write_ctxs[write_cipher_idx];

  if (cipher->key != NULL) {
    int res;
    unsigned char *data, *ptr;
    uint32_t datalen, datasz, len = 0;

    /* Always leave a little extra room in the buffer. */
    datasz = sizeof(uint32_t) + pkt->packet_len + 64;

    datalen = datasz;
    ptr = data = palloc(pkt->pool, datasz);

    len += proxy_ssh_msg_write_int(&data, &datalen, pkt->packet_len);
    len += proxy_ssh_msg_write_byte(&data, &datalen, pkt->padding_len);
    len += proxy_ssh_msg_write_data(&data, &datalen, pkt->payload,
      pkt->payload_len, FALSE);
    len += proxy_ssh_msg_write_data(&data, &datalen, pkt->padding,
      pkt->padding_len, FALSE);

    res = EVP_Cipher(pctx, buf, ptr, len);
    if (res != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error encrypting %s data for server: %s", cipher->algo,
        proxy_ssh_crypto_get_errors());
      errno = EIO;
      return -1;
    }

    *buflen = len;

#ifdef SFTP_DEBUG_PACKET
{
  unsigned int i;

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "encrypted packet data (len %lu):", (unsigned long) *buflen);
  for (i = 0; i < *buflen;) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "  %02x%02x %02x%02x %02x%02x %02x%02x",
      ((unsigned char *) buf)[i], ((unsigned char *) buf)[i+1],
      ((unsigned char *) buf)[i+2], ((unsigned char *) buf)[i+3],
      ((unsigned char *) buf)[i+4], ((unsigned char *) buf)[i+5],
      ((unsigned char *) buf)[i+6], ((unsigned char *) buf)[i+7]);
    i += 8;
  }
}
#endif

    return 0;
  }

  *buflen = 0;
  return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x1000000fL
/* In older versions of OpenSSL, there was not a way to dynamically allocate
 * an EVP_CIPHER_CTX object.  Thus we have these static objects for those
 * older versions.
 */
static EVP_CIPHER_CTX read_ctx1, read_ctx2;
static EVP_CIPHER_CTX write_ctx1, write_ctx2;
#endif /* prior to OpenSSL-1.0.0 */

int proxy_ssh_cipher_init(void) {
#if OPENSSL_VERSION_NUMBER < 0x1000000fL
  read_ctxs[0] = &read_ctx1;
  read_ctxs[1] = &read_ctx2;
  write_ctxs[0] = &write_ctx1;
  write_ctxs[1] = &write_ctx2;
#else
  read_ctxs[0] = EVP_CIPHER_CTX_new();
  read_ctxs[1] = EVP_CIPHER_CTX_new();
  write_ctxs[0] = EVP_CIPHER_CTX_new();
  write_ctxs[1] = EVP_CIPHER_CTX_new();
#endif /* OpenSSL-1.0.0 and later */

  return 0;
}

int proxy_ssh_cipher_free(void) {
#if OPENSSL_VERSION_NUMBER >= 0x1000000fL
  EVP_CIPHER_CTX_free(read_ctxs[0]);
  EVP_CIPHER_CTX_free(read_ctxs[1]);
  EVP_CIPHER_CTX_free(write_ctxs[0]);
  EVP_CIPHER_CTX_free(write_ctxs[1]);
#endif /* OpenSSL-1.0.0 and later */

  return 0;
}
#endif /* PR_USE_OPENSSL */
