/*
 * ProFTPD - mod_proxy SSH key exchange (kex)
 * Copyright (c) 2021-2022 TJ Saunders
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
#include "proxy/conn.h"
#include "proxy/ssh.h"
#include "proxy/ssh/ssh2.h"
#include "proxy/ssh/msg.h"
#include "proxy/ssh/packet.h"
#include "proxy/ssh/session.h"
#include "proxy/ssh/cipher.h"
#include "proxy/ssh/mac.h"
#include "proxy/ssh/compress.h"
#include "proxy/ssh/kex.h"
#include "proxy/ssh/keys.h"
#include "proxy/ssh/crypto.h"
#include "proxy/ssh/disconnect.h"
#include "proxy/ssh/interop.h"
#include "proxy/ssh/misc.h"

#if defined(PR_USE_OPENSSL)
# include <openssl/bn.h>
# include <openssl/dh.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/rsa.h>

# if defined(PR_USE_OPENSSL_ECC)
#  include <openssl/ec.h>
#  include <openssl/ecdh.h>
# endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM)
# include <sodium.h>
# define CURVE25519_SIZE	32
#endif /* PR_USE_SODIUM */

#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
# define CURVE448_SIZE          56
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */

/* This needs to align/match with the SFTP_ROLE_CLIENT macro from mod_sftp.h,
 * for now.
 */
#define PROXY_SSH_ROLE_CLIENT	2

/* Define the min/preferred/max DH group lengths we request; see RFC 4419. */
#define PROXY_SSH_DH_MIN_LEN			2048
#define PROXY_SSH_DH_MAX_LEN			8192

extern pr_response_t *resp_list, *resp_err_list;

/* For managing the kexinit process */
static pool *kex_pool = NULL;

/* For hostkey verification. */
static struct proxy_ssh_datastore *kex_ds = NULL;
static int kex_verify_hostkeys = FALSE;

struct proxy_ssh_kex_names {
  const char *kex_algo;
  const char *server_hostkey_algo;
  const char *c2s_encrypt_algo;
  const char *s2c_encrypt_algo;
  const char *c2s_mac_algo;
  const char *s2c_mac_algo;
  const char *c2s_comp_algo;
  const char *s2c_comp_algo;
  const char *c2s_lang;
  const char *s2c_lang;
};

struct proxy_ssh_kex {
  pool *pool;

  /* Versions */
  const char *client_version;
  const char *server_version;

  /* KEXINIT lists from client */
  struct proxy_ssh_kex_names *client_names;

  /* KEXINIT lists from server. */
  struct proxy_ssh_kex_names *server_names;

  /* Session algorithms */
  struct proxy_ssh_kex_names *session_names;

  /* For constructing the session ID/hash */
  unsigned char *client_kexinit_payload;
  size_t client_kexinit_payload_len;

  unsigned char *server_kexinit_payload;
  size_t server_kexinit_payload_len;

  int first_kex_follows;

  /* Server-preferred hostkey type, based on algorithm:
   *
   *  "ssh-dss"      --> PROXY_SSH_KEY_DSA
   *  "ssh-rsa"      --> PROXY_SSH_KEY_RSA
   *  "ecdsa-sha2-*" --> PROXY_SSH_KEY_ECDSA_*
   *  "ssh-ed25519"  --> PROXY_SSH_KEY_ED25519
   *  "ssh-ed448"    --> PROXY_SSH_KEY_ED448
   *  "rsa-sha2-256" --> PROXY_SSH_KEY_RSA_SHA256
   *  "rsa-sha2-512" --> PROXY_SSH_KEY_RSA_SHA512
   */
  enum proxy_ssh_key_type_e use_hostkey_type;

  /* Using DH group-exchange? */
  int use_gex;

  /* Using RSA key exchange? */
  int use_kexrsa;

  /* Using ECDH? */
  int use_ecdh;

  /* Using Curve25519? */
  int use_curve25519;

  /* Using Curve448? */
  int use_curve448;

  /* Using extension negotiations? */
  int use_ext_info;

  /* For generating the session ID */
  DH *dh;
  const BIGNUM *e;
  const EVP_MD *hash;

  const BIGNUM *k;
  const char *h;
  uint32_t hlen;

  uint32_t dh_gex_min;
  uint32_t dh_gex_pref;
  uint32_t dh_gex_max;

  RSA *rsa;
  unsigned char *rsa_encrypted;
  uint32_t rsa_encrypted_len;

#if defined(PR_USE_OPENSSL_ECC)
  EC_KEY *ec;
  EC_POINT *server_point;
#endif /* PR_USE_OPENSSL_ECC */
#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
  unsigned char *client_curve25519_priv_key;
  unsigned char *client_curve25519_pub_key;
  unsigned char *server_curve25519_pub_key;
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */
#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
  unsigned char *client_curve448_priv_key;
  unsigned char *client_curve448_pub_key;
  unsigned char *server_curve448_pub_key;
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */
};

static struct proxy_ssh_kex *kex_first_kex = NULL;
static struct proxy_ssh_kex *kex_rekey_kex = NULL;
static int kex_sent_kexinit = FALSE;

/* Diffie-Hellman group moduli */

static const char *dh_group1_str =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

static const char *dh_group14_str = 
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
  "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

static const char *dh_group16_str =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
  "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
  "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
  "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
  "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
  "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
  "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
  "FFFFFFFFFFFFFFFF";

static const char *dh_group18_str =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
  "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
  "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
  "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
  "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
  "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
  "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
  "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
  "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
  "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
  "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
  "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
  "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
  "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
  "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
  "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
  "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
  "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
  "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
  "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
  "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
  "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
  "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
  "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
  "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
  "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
  "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
  "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
  "60C980DD98EDD3DFFFFFFFFFFFFFFFFF";

#define PROXY_SSH_DH_GROUP1_SHA1		1
#define PROXY_SSH_DH_GROUP14_SHA1		2
#define PROXY_SSH_DH_GEX_SHA1			3
#define PROXY_SSH_DH_GEX_SHA256			4
#define PROXY_SSH_KEXRSA_SHA1			5
#define PROXY_SSH_KEXRSA_SHA256			6
#define PROXY_SSH_ECDH_SHA256			7
#define PROXY_SSH_ECDH_SHA384			8
#define PROXY_SSH_ECDH_SHA512			9
#define PROXY_SSH_DH_GROUP14_SHA256		10
#define PROXY_SSH_DH_GROUP16_SHA512		11
#define PROXY_SSH_DH_GROUP18_SHA512		12

#define PROXY_SSH_KEXRSA_SHA1_SIZE		2048
#define PROXY_SSH_KEXRSA_SHA256_SIZE		3072

static const char *kex_client_version = NULL;
static const char *kex_server_version = NULL;
static unsigned char kex_digest_buf[EVP_MAX_MD_SIZE];

/* Necessary prototypes. */
static struct proxy_ssh_packet *read_kex_packet(pool *, struct proxy_ssh_kex *,
  conn_t *, int, char *, unsigned int, ...);

static const char *trace_channel = "proxy.ssh.kex";

static int digest_data(struct proxy_ssh_kex *kex, unsigned char *buf,
    uint32_t len, uint32_t *hlen) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  pctx = EVP_MD_CTX_new();
#else
  pctx = &ctx;
#endif /* OpenSSL-1.1.0 and later */

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(pctx, kex->hash) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error initializing message digest: %s", proxy_ssh_crypto_get_errors());
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestInit(pctx, kex->hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, buf, len) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error updating message digest: %s", proxy_ssh_crypto_get_errors());
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestUpdate(pctx, buf, len);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(pctx, kex_digest_buf, hlen) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error finalizing message digest: %s", proxy_ssh_crypto_get_errors());
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestFinal(pctx, kex_digest_buf, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  EVP_MD_CTX_free(pctx);
#endif /* OpenSSL-1.1.0 and later */

  return 0;
}

static const unsigned char *calculate_h(pool *p, struct proxy_ssh_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *server_pub_key, const BIGNUM *k, uint32_t *hlen) {
  const BIGNUM *dh_pub_key;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  bufsz = buflen = 8192;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = palloc(p, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it. */

  /* First, the version strings */
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->client_version);
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->client_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->server_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Server hostkey data */
  len += proxy_ssh_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen,
    TRUE);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */

  /* Client's key */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, dh_pub_key);

  /* Server's key */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, server_pub_key);

  /* Shared secret */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, k);

  if (digest_data(kex, ptr, len, hlen) < 0) {
    pr_memscrub(ptr, bufsz);
    return NULL;
  }

  pr_memscrub(ptr, bufsz);
  return kex_digest_buf;
}

static int verify_h(pool *p, struct proxy_ssh_kex *kex,
    const unsigned char *key_data, uint32_t key_datalen,
    const unsigned char *sig_data, uint32_t sig_datalen,
    const unsigned char *h, uint32_t hlen) {
  int res, xerrno;
  const char *pubkey_algo = NULL;

  switch (kex->use_hostkey_type) {
    case PROXY_SSH_KEY_DSA:
      pubkey_algo = "ssh-dss";
      break;

    case PROXY_SSH_KEY_RSA:
      pubkey_algo = "ssh-rsa";
      break;

#if defined(HAVE_SHA256_OPENSSL)
    case PROXY_SSH_KEY_RSA_SHA256:
      pubkey_algo = "rsa-sha2-256";
      break;
#endif /* HAVE_SHA256_OPENSSL */

#if defined(HAVE_SHA512_OPENSSL)
    case PROXY_SSH_KEY_RSA_SHA512:
      pubkey_algo = "rsa-sha2-512";
      break;
#endif /* HAVE_SHA512_OPENSSL */

#if defined(PR_USE_OPENSSL_ECC)
    case PROXY_SSH_KEY_ECDSA_256:
      pubkey_algo = "ecdsa-sha2-nistp256";
      break;

    case PROXY_SSH_KEY_ECDSA_384:
      pubkey_algo = "ecdsa-sha2-nistp384";
      break;

    case PROXY_SSH_KEY_ECDSA_521:
      pubkey_algo = "ecdsa-sha2-nistp521";
      break;
#endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM)
    case PROXY_SSH_KEY_ED25519:
      pubkey_algo = "ssh-ed25519";
      break;
#endif /* PR_USE_SODIUM */

#if defined(HAVE_X448_OPENSSL)
    case PROXY_SSH_KEY_ED448:
      pubkey_algo = "ssh-ed448";
      break;
#endif /* HAVE_X448_OPENSSL */

    default:
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to verify signed data: Unknown public key algorithm");
      errno = EINVAL;
      return -1;
  }

  res = proxy_ssh_keys_verify_signed_data(p, pubkey_algo,
    (unsigned char *) key_data, key_datalen,
    (unsigned char *) sig_data, sig_datalen,
    (unsigned char *) h, hlen);
  xerrno = errno;

  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to verify server signature on H: %s", strerror(xerrno));
    errno = xerrno;
  }

  return res;
}

static const unsigned char *calculate_gex_h(pool *p, struct proxy_ssh_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *server_pub_key, const BIGNUM *k, uint32_t *hlen) {
  const BIGNUM *dh_p, *dh_g, *dh_pub_key;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 8192;
  ptr = buf = palloc(p, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it.
   * The ordering of these fields is described in RFC4419.
   */

  /* First, the version strings */
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->client_version);
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->client_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->server_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  len += proxy_ssh_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen,
    TRUE);

  if (kex->dh_gex_min == 0 ||
      kex->dh_gex_max == 0) {
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_pref);

  } else {
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_min);
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_pref);
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_max);
  }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);
#else
  dh_p = kex->dh->p;
  dh_g = kex->dh->g;
#endif /* prior to OpenSSL-1.1.0 */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, dh_p);
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, dh_g);

  /* Client's key */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else 
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, dh_pub_key);

  /* Server's key */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, server_pub_key);

  /* Shared secret */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, k);

  if (digest_data(kex, ptr, len, hlen) < 0) {
    pr_memscrub(ptr, bufsz);
    return NULL;
  }

  pr_memscrub(ptr, bufsz);
  return kex_digest_buf;
}

static const unsigned char *calculate_kexrsa_h(pool *p,
    struct proxy_ssh_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, uint32_t *hlen) {
  const BIGNUM *rsa_e = NULL, *rsa_n = NULL;
  unsigned char *buf, *ptr, *rsa_key, *rsa_data;
  uint32_t buflen, bufsz, len = 0, rsa_datalen, rsa_keysz, rsa_keylen = 0;

  /* XXX Is this buffer large enough?  Too large? */
  rsa_keysz = rsa_datalen = 4096;
  rsa_key = rsa_data = palloc(p, rsa_keysz);

  /* Write the transient RSA public key into its own buffer, to then be
   * written in its entirety as an SSH2 string.
   */
  rsa_keylen += proxy_ssh_msg_write_string(&rsa_data, &rsa_datalen, "ssh-rsa");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  RSA_get0_key(kex->rsa, &rsa_n, &rsa_e, NULL);
#else
  rsa_e = kex->rsa->e;
  rsa_n = kex->rsa->n;
#endif /* prior to OpenSSL-1.1.0 */

  rsa_keylen += proxy_ssh_msg_write_mpint(&rsa_data, &rsa_datalen, rsa_e);
  rsa_keylen += proxy_ssh_msg_write_mpint(&rsa_data, &rsa_datalen, rsa_n);

  bufsz = buflen = 4096;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = palloc(p, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it. */

  /* First, the version strings */
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->client_version);
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->client_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->server_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  len += proxy_ssh_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen,
    TRUE);

  /* Transient RSA public key */
  len += proxy_ssh_msg_write_data(&buf, &buflen, rsa_key, rsa_keylen, TRUE);

  /* RSA-encrypted secret */
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->rsa_encrypted,
    kex->rsa_encrypted_len, TRUE);

  /* Shared secret. */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, k);

  if (digest_data(kex, ptr, len, hlen) < 0) {
    pr_memscrub(ptr, bufsz);
    return NULL;
  }

  pr_memscrub(rsa_key, rsa_keysz);
  pr_memscrub(ptr, bufsz);

  return kex_digest_buf;
}

#if defined(PR_USE_OPENSSL_ECC)
static const unsigned char *calculate_ecdh_h(pool *p, struct proxy_ssh_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, uint32_t *hlen) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  bufsz = buflen = 4096;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = palloc(p, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it.
   * The ordering of these fields is described in RFC5656.
   */

  /* First, the version strings */
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->client_version);
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->client_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->server_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  len += proxy_ssh_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen,
    TRUE);

  /* Client public key */
  len += proxy_ssh_msg_write_ecpoint(&buf, &buflen, EC_KEY_get0_group(kex->ec),
    EC_KEY_get0_public_key(kex->ec));

  /* Server public key */
  len += proxy_ssh_msg_write_ecpoint(&buf, &buflen, EC_KEY_get0_group(kex->ec),
    kex->server_point);

  /* Shared secret */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, k);

  if (digest_data(kex, ptr, len, hlen) < 0) {
    pr_memscrub(ptr, bufsz);
    return NULL;
  }

  pr_memscrub(ptr, bufsz);
  return kex_digest_buf;
}
#endif /* PR_USE_OPENSSL_ECC */

/* Make sure that the DH key we're generating is good enough. */
static int have_good_dh(DH *dh, const BIGNUM *pub_key) {
  register int i;
  unsigned int nbits = 0;
  const BIGNUM *dh_p = NULL;
  BIGNUM *tmp;

  if (dh == NULL ||
      pub_key == NULL) {
    errno = EINVAL;
    return -1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x0090801fL
  if (BN_is_negative(pub_key)) {
    pr_trace_msg(trace_channel, 10,
      "DH public keys cannot have negative numbers");
    errno = EINVAL;
    return -1;
  }
#endif /* OpenSSL-0.9.8a or later */

  if (BN_cmp(pub_key, BN_value_one()) != 1) {
    pr_trace_msg(trace_channel, 10, "bad DH public key exponent (<= 1)");
    errno = EINVAL;
    return -1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_pqg(dh, &dh_p, NULL, NULL);
#else
  dh_p = dh->p;
#endif /* prior to OpenSSL-1.1.0 */

  tmp = BN_new();
  if (!BN_sub(tmp, dh_p, BN_value_one()) ||
      BN_cmp(pub_key, tmp) != -1) {
    BN_clear_free(tmp);
    pr_trace_msg(trace_channel, 10, "bad DH public key (>= p-1)");
    errno = EINVAL;
    return -1;
  }

  BN_clear_free(tmp);

  for (i = 0; i <= BN_num_bits(pub_key); i++) {
    if (BN_is_bit_set(pub_key, i)) {
      nbits++;
    }
  }

  /* The number of bits set in the public key must be greater than one.
   * Otherwise, the public key will not hold up under scrutiny, not for
   * our needs.  (The OpenSSH client is picky about the DH public keys it
   * will accept as well, so this is necessary to pass OpenSSH's requirements).
   */
  if (nbits <= 1) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 10, "good DH public key: %u bits set", nbits);
  return 0;
}

static int get_dh_nbits(struct proxy_ssh_kex *kex) {
  int dh_nbits = 0, dh_size = 0;
  const char *algo;
  const EVP_CIPHER *cipher;
  const EVP_MD *digest;

  algo = kex->session_names->c2s_encrypt_algo;
  cipher = proxy_ssh_crypto_get_cipher(algo, NULL, NULL, NULL);
  if (cipher != NULL) {
    int block_size, key_len;

    key_len = EVP_CIPHER_key_length(cipher);
    if (strcmp(algo, "none") == 0 &&
        key_len < 32) {
      key_len = 32;
    }

    if (dh_size < key_len) {
      dh_size = key_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching client-to-server '%s' cipher "
        "key length", dh_size, algo);
    }

    block_size = EVP_CIPHER_block_size(cipher);
    if (dh_size < block_size) {
      dh_size = block_size;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching client-to-server '%s' cipher "
        "block size", dh_size, algo);
    }
  }

  algo = kex->session_names->s2c_encrypt_algo;
  cipher = proxy_ssh_crypto_get_cipher(algo, NULL, NULL, NULL);
  if (cipher != NULL) {
    int block_size, key_len;

    key_len = EVP_CIPHER_key_length(cipher);
    if (strcmp(algo, "none") == 0 &&
        key_len < 32) {
      key_len = 32;
    }

    if (dh_size < key_len) {
      dh_size = key_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching server-to-client '%s' cipher "
        "key length", dh_size, algo);
    }

    block_size = EVP_CIPHER_block_size(cipher);
    if (dh_size < block_size) {
      dh_size = block_size;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching server-to-client '%s' cipher "
        "block size", dh_size, algo);
    }
  }

  algo = kex->session_names->c2s_mac_algo;
  digest = proxy_ssh_crypto_get_digest(algo, NULL);
  if (digest != NULL) {
    int mac_len;

    mac_len = EVP_MD_size(digest);
    if (dh_size < mac_len) {
      dh_size = mac_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching client-to-server '%s' digest size",
        dh_size, algo);
    }
  }

  algo = kex->session_names->s2c_mac_algo;
  digest = proxy_ssh_crypto_get_digest(algo, NULL);
  if (digest != NULL) {
    int mac_len;

    mac_len = EVP_MD_size(digest);
    if (dh_size < mac_len) {
      dh_size = mac_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching server-to-client '%s' digest size",
        dh_size, algo);
    }
  }

  /* We want to return bits, not bytes. */
  dh_nbits = dh_size * 8;

  pr_trace_msg(trace_channel, 8, "requesting DH size of %d bits", dh_nbits);
  return dh_nbits;
}

static int create_dh(struct proxy_ssh_kex *kex, int type) {
  unsigned int attempts = 0;
  int dh_nbits;
  DH *dh;

  if (type != PROXY_SSH_DH_GROUP1_SHA1 &&
      type != PROXY_SSH_DH_GROUP14_SHA1 &&
      type != PROXY_SSH_DH_GROUP14_SHA256 &&
      type != PROXY_SSH_DH_GROUP16_SHA512 &&
      type != PROXY_SSH_DH_GROUP18_SHA512) {
    errno = EINVAL;
    return -1;
  }

  if (kex->dh != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (kex->dh->p != NULL) {
      BN_clear_free(kex->dh->p);
      kex->dh->p = NULL;
    }

    if (kex->dh->g != NULL) {
      BN_clear_free(kex->dh->g);
      kex->dh->g = NULL;
    }

    if (kex->dh->priv_key != NULL) {
      BN_clear_free(kex->dh->priv_key);
      kex->dh->priv_key = NULL;
    }

    if (kex->dh->pub_key != NULL) {
      BN_clear_free(kex->dh->pub_key);
      kex->dh->pub_key = NULL;
    }
#endif /* prior to OpenSSL-1.1.0 */

    DH_free(kex->dh);
    kex->dh = NULL;
  }

  dh_nbits = get_dh_nbits(kex);

  /* We have 10 attempts to make a DH key which passes muster. */
  while (attempts <= 10) {
    const BIGNUM *dh_p, *dh_g, *dh_pub_key = NULL, *dh_priv_key = NULL;

    pr_signals_handle();

    attempts++;
    pr_trace_msg(trace_channel, 9, "attempt #%u to create a good DH key",
      attempts);

    dh = DH_new();
    if (dh == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error creating DH: %s", proxy_ssh_crypto_get_errors());
      return -1;
    }

    dh_p = BN_new();

    switch (type) {
      case PROXY_SSH_DH_GROUP18_SHA512:
        if (BN_hex2bn((BIGNUM **) &dh_p, dh_group18_str) == 0) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error setting DH (group18) P: %s", proxy_ssh_crypto_get_errors());
          BN_clear_free((BIGNUM *) dh_p);
          DH_free(dh);
          return -1;
        }
        break;

      case PROXY_SSH_DH_GROUP16_SHA512:
        if (BN_hex2bn((BIGNUM **) &dh_p, dh_group16_str) == 0) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error setting DH (group16) P: %s", proxy_ssh_crypto_get_errors());
          BN_clear_free((BIGNUM *) dh_p);
          DH_free(dh);
          return -1;
        }
        break;

      case PROXY_SSH_DH_GROUP14_SHA1:
      case PROXY_SSH_DH_GROUP14_SHA256:
        if (BN_hex2bn((BIGNUM **) &dh_p, dh_group14_str) == 0) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error setting DH (group14) P: %s", proxy_ssh_crypto_get_errors());
          BN_clear_free((BIGNUM *) dh_p);
          DH_free(dh);
          return -1;
        }
        break;

      default:
        if (BN_hex2bn((BIGNUM **) &dh_p, dh_group1_str) == 0) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error setting DH (group1) P: %s", proxy_ssh_crypto_get_errors());
          BN_clear_free((BIGNUM *) dh_p);
          DH_free(dh);
          return -1;
        }
        break;
    }

    dh_g = BN_new();

    if (BN_hex2bn((BIGNUM **) &dh_g, "2") == 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error setting DH G: %s", proxy_ssh_crypto_get_errors());
      BN_clear_free((BIGNUM *) dh_p);
      BN_clear_free((BIGNUM *) dh_g);
      DH_free(dh);
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_pqg(dh, (BIGNUM *) dh_p, NULL, (BIGNUM *) dh_g);
#else
    dh->p = dh_p;
    dh->g = dh_g;
#endif /* prior to OpenSSL-1.1.0 */

    dh_priv_key = BN_new();

    /* Generate a random private exponent of the desired size, in bits. */
    if (!BN_rand((BIGNUM *) dh_priv_key, dh_nbits, 0, 0)) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error generating DH random key (%d bits): %s", dh_nbits,
        proxy_ssh_crypto_get_errors());
      BN_clear_free((BIGNUM *) dh_priv_key);
      DH_free(dh);
      return -1;
    }

    dh_pub_key = BN_new();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_key(dh, (BIGNUM *) dh_pub_key, (BIGNUM *) dh_priv_key);
#else
    dh->pub_key = dh_pub_key;
    dh->priv_key = dh_priv_key;
#endif /* prior to OpenSSL-1.1.0 */

    pr_trace_msg(trace_channel, 12, "generating DH key");
    if (DH_generate_key(dh) != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error generating DH key: %s", proxy_ssh_crypto_get_errors());
      DH_free(dh);
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_get0_key(dh, &dh_pub_key, NULL);
#else
    dh_pub_key = dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */

    if (have_good_dh(dh, dh_pub_key) < 0) {
      DH_free(dh);
      continue;
    }

    kex->dh = dh;

    switch (type) {
#if defined(HAVE_SHA512_OPENSSL)
      case PROXY_SSH_DH_GROUP16_SHA512:
      case PROXY_SSH_DH_GROUP18_SHA512:
        kex->hash = EVP_sha512();
        break;
#endif /* HAVE_SHA512_OPENSSL */

#if defined(HAVE_SHA256_OPENSSL)
      case PROXY_SSH_DH_GROUP14_SHA256:
        kex->hash = EVP_sha256();
        break;
#endif /* HAVE_SHA256_OPENSSL */

      default:
        kex->hash = EVP_sha1();
    }

    return 0;
  }

  errno = EPERM;
  return -1;
}

static int prepare_dh(struct proxy_ssh_kex *kex, int type) {
  DH *dh;

  if (type != PROXY_SSH_DH_GEX_SHA1 &&
      type != PROXY_SSH_DH_GEX_SHA256) {
    errno = EINVAL;
    return -1;
  }

  if (kex->dh != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (kex->dh->p != NULL) {
      BN_clear_free(kex->dh->p);
      kex->dh->p = NULL;
    }

    if (kex->dh->g != NULL) {
      BN_clear_free(kex->dh->g);
      kex->dh->g = NULL;
    }

    if (kex->dh->priv_key != NULL) {
      BN_clear_free(kex->dh->priv_key);
      kex->dh->priv_key = NULL;
    }

    if (kex->dh->pub_key != NULL) {
      BN_clear_free(kex->dh->pub_key);
      kex->dh->pub_key = NULL;
    }
#endif /* prior to OpenSSL-1.1.0 */

    DH_free(kex->dh);
    kex->dh = NULL;
  }

  dh = DH_new();
  if (dh == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error creating DH: %s", proxy_ssh_crypto_get_errors());
    return -1;
  }

  kex->dh = dh;

  if (type == PROXY_SSH_DH_GEX_SHA1) {
    kex->hash = EVP_sha1();

#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  } else if (type == PROXY_SSH_DH_GEX_SHA256) {
    kex->hash = EVP_sha256();
#endif
  }

  return 0;
}

static int create_kexrsa(struct proxy_ssh_kex *kex, int type) {
  if (type != PROXY_SSH_KEXRSA_SHA1 &&
      type != PROXY_SSH_KEXRSA_SHA256) {
    errno = EINVAL;
    return -1;
  }

  if (kex->rsa != NULL) {
    RSA_free(kex->rsa);
    kex->rsa = NULL;
  }

  if (kex->rsa_encrypted != NULL) {
    pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
    kex->rsa_encrypted = NULL;
    kex->rsa_encrypted_len = 0;
  }

  if (type == PROXY_SSH_KEXRSA_SHA1) {
    kex->hash = EVP_sha1();

#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  } else if (type == PROXY_SSH_KEXRSA_SHA256) {
    kex->hash = EVP_sha256();
#endif
  }

  return 0;
}

#if defined(PR_USE_OPENSSL_ECC)
static int create_ecdh(struct proxy_ssh_kex *kex, int type) {
  EC_KEY *ec;
  int curve_nid = -1;
  char *curve_name = NULL;

  switch (type) {
    case PROXY_SSH_ECDH_SHA256:
      curve_name = "NID_X9_62_prime256v1";
# if defined(HAVE_SHA256_OPENSSL)
      curve_nid = NID_X9_62_prime256v1;
      kex->hash = EVP_sha256();
# else
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to generate EC key using '%s': OpenSSL lacks SHA256 support",
        curve_name);
      errno = ENOSYS;
      return -1;
# endif /* HAVE_SHA256_OPENSSL */
      break;

    case PROXY_SSH_ECDH_SHA384:
      curve_name = "NID_secp384r1";
# if defined(HAVE_SHA256_OPENSSL)
      curve_nid = NID_secp384r1;
      kex->hash = EVP_sha384();
# else
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to generate EC key using '%s': OpenSSL lacks SHA256 support",
        curve_name);
      errno = ENOSYS;
      return -1;
# endif /* HAVE_SHA256_OPENSSL */
      break;

    case PROXY_SSH_ECDH_SHA512:
      curve_name = "NID_secp521r1";
# if defined(HAVE_SHA512_OPENSSL)
      curve_nid = NID_secp521r1;
      kex->hash = EVP_sha512();
# else
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "unable to generate EC key using '%s': OpenSSL lacks SHA512 support",
        curve_name);
      errno = ENOSYS;
      return -1;
# endif /* HAVE_SHA512_OPENSSL */
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  ec = EC_KEY_new_by_curve_name(curve_nid);
  if (ec == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error generating new EC key using '%s': %s", curve_name,
      proxy_ssh_crypto_get_errors());
    return -1;
  }

  if (EC_KEY_generate_key(ec) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error generating new EC key: %s", proxy_ssh_crypto_get_errors());
    EC_KEY_free(ec);
    return -1;
  }

  kex->ec = ec;
  return 0;
}
#endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
static int generate_curve25519_keys(unsigned char *priv_key,
    unsigned char *pub_key) {
  static const unsigned char basepoint[CURVE25519_SIZE] = {9};
  unsigned char zero_curve25519[CURVE25519_SIZE];
  int res;

  randombytes_buf(priv_key, CURVE25519_SIZE);
  res = crypto_scalarmult_curve25519(pub_key, priv_key, basepoint);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error performing Curve25519 scalar multiplication");
    errno = EINVAL;
    return -1;
  }

  /* Check for all-zero public keys. */
  sodium_memzero(zero_curve25519, CURVE25519_SIZE);
  if (sodium_memcmp(pub_key, zero_curve25519, CURVE25519_SIZE) == 0) {
    pr_trace_msg(trace_channel, 12,
      "generated all-zero Curve25519 public key, trying again");
    return generate_curve25519_keys(priv_key, pub_key);
  }

  return 0;
}

static int get_curve25519_shared_key(unsigned char *shared_key,
    unsigned char *pub_key, unsigned char *priv_key) {
  int res;

  res = crypto_scalarmult_curve25519(shared_key, priv_key, pub_key);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error performing Curve25519 scalar multiplication");
    errno = EINVAL;
    return -1;
  }

  return CURVE25519_SIZE;
}

static const unsigned char *calculate_curve25519_h(pool *p,
    struct proxy_ssh_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, uint32_t *hlen) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  bufsz = buflen = 4096;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = palloc(p, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it.
   * The ordering of these fields is described in RFC5656.
   */

  /* First, the version strings */
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->client_version);
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->client_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->server_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  len += proxy_ssh_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen,
    TRUE);

  /* Client's key */
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_curve25519_pub_key,
    CURVE25519_SIZE, TRUE);

  /* Server's key */
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_curve25519_pub_key,
    CURVE25519_SIZE, TRUE);

  /* Shared secret */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, k);

  if (digest_data(kex, ptr, len, hlen) < 0) {
    pr_memscrub(ptr, bufsz);
    return NULL;
  }

  pr_memscrub(ptr, bufsz);
  return kex_digest_buf;
}

static int create_curve25519(struct proxy_ssh_kex *kex) {
  kex->client_curve25519_priv_key = palloc(kex_pool, CURVE25519_SIZE);
  kex->client_curve25519_pub_key = palloc(kex_pool, CURVE25519_SIZE);

  return generate_curve25519_keys(kex->client_curve25519_priv_key,
    kex->client_curve25519_pub_key);
}
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */

#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
static int generate_curve448_keys(unsigned char *priv_key,
    unsigned char *pub_key) {
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *pkey = NULL;
  size_t key_len = 0;

  pctx = EVP_PKEY_CTX_new_id(NID_X448, NULL);
  if (pctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error initializing context for Curve448 key: %s",
      proxy_ssh_crypto_get_errors());
    return -1;
  }

  if (EVP_PKEY_keygen_init(pctx) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error preparing to generate Curve448 key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_CTX_free(pctx);
    return -1;
  }

  if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error generating Curve448 shared key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_CTX_free(pctx);
    return -1;
  }

  key_len = CURVE448_SIZE;
  if (EVP_PKEY_get_raw_private_key(pkey, priv_key, &key_len) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error obtaining Curve448 private key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return -1;
  }

  key_len = CURVE448_SIZE;
  if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &key_len) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error obtaining Curve448 public key: %s", proxy_ssh_crypto_get_errors());
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(pkey);
  return 0;
}

static int get_curve448_shared_key(unsigned char *shared_key,
    unsigned char *pub_key, unsigned char *priv_key) {
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *client_pkey = NULL, *server_pkey = NULL;
  size_t shared_keylen = 0;

  server_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, priv_key,
    CURVE448_SIZE);
  if (server_pkey == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error initializing Curve448 server key: %s",
      proxy_ssh_crypto_get_errors());
    return -1;
  }

  client_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, pub_key,
    CURVE448_SIZE);
  if (client_pkey == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error initializing Curve448 client key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_free(server_pkey);
    return -1;
  }

  pctx = EVP_PKEY_CTX_new(server_pkey, NULL);
  if (pctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error initializing context for Curve448 shared key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(client_pkey);
    return -1;
  }

  if (EVP_PKEY_derive_init(pctx) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error preparing for Curve448 shared key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(client_pkey);
    return -1;
  }

  if (EVP_PKEY_derive_set_peer(pctx, client_pkey) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error setting peer for Curve448 shared key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(client_pkey);
    return -1;
  }

  shared_keylen = CURVE448_SIZE;
  if (EVP_PKEY_derive(pctx, shared_key, &shared_keylen) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error generating Curve448 shared key: %s",
      proxy_ssh_crypto_get_errors());
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(client_pkey);
    return -1;
  }

  if (shared_keylen != CURVE448_SIZE) {
    pr_trace_msg(trace_channel, 1,
      "generated Curve448 shared key length (%lu bytes) is not as expected "
      "(%lu bytes)", (unsigned long) shared_keylen,
      (unsigned long) CURVE448_SIZE);
  }

  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(server_pkey);
  EVP_PKEY_free(client_pkey);

  return CURVE448_SIZE;
}

static const unsigned char *calculate_curve448_h(pool *p,
    struct proxy_ssh_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, uint32_t *hlen) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  bufsz = buflen = 4096;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = palloc(p, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it.
   * The ordering of these fields is described in RFC5656.
   */

  /* First, the version strings */
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->client_version);
  len += proxy_ssh_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->client_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  len += proxy_ssh_msg_write_int(&buf, &buflen,
    kex->server_kexinit_payload_len + 1);
  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  len += proxy_ssh_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen,
    TRUE);

  /* Client's key */
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_curve448_pub_key,
    CURVE448_SIZE, TRUE);

  /* Server's key */
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->server_curve448_pub_key,
    CURVE448_SIZE, TRUE);

  /* Shared secret */
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, k);

  if (digest_data(kex, ptr, len, hlen) < 0) {
    pr_memscrub(ptr, bufsz);
    return NULL;
  }

  pr_memscrub(ptr, bufsz);
  return kex_digest_buf;
}

static int create_curve448(struct proxy_ssh_kex *kex) {
  kex->client_curve448_priv_key = palloc(kex_pool, CURVE448_SIZE);
  kex->client_curve448_pub_key = palloc(kex_pool, CURVE448_SIZE);

  return generate_curve448_keys(kex->client_curve448_priv_key,
    kex->client_curve448_pub_key);
}
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */

/* Given a name-list, return the first (i.e. preferred) name in the list. */
static const char *get_preferred_name(pool *p, const char *names) {
  register unsigned int i;

  /* Advance to the first comma, or NUL. */
  for (i = 0; names[i] && names[i] != ','; i++);
  
  if (names[i] == ',' ||
      names[i] == '\0') {
    char *pref;

    pref = pcalloc(p, i + 1);
    memcpy(pref, names, i);

    return pref;
  }

  /* This should never happen. */
  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "unable to find preferred name in '%s'", names);
  return NULL;
}

/* Note that in this default list of key exchange algorithms, one of the
 * REQUIRED algorithms is conspicuously absent:
 *
 *   diffie-hellman-group1-sha1
 *
 * This exchange has a weak hardcoded DH group, and will thus only be used
 * if explicitly requested via ProxySFTPKeyExchanges, or if the AllowWeakDH
 * SFTPOption is used.
 */
static const char *kex_exchanges[] = {
#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
  "curve448-sha512",
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */
#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */
#if defined(PR_USE_OPENSSL_ECC)
  "ecdh-sha2-nistp521",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp256",
#endif /* PR_USE_OPENSSL_ECC */

#if (OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
    (OPENSSL_VERSION_NUMBER > 0x000908000L)
# if defined(HAVE_SHA512_OPENSSL)
  "diffie-hellman-group18-sha512",
  "diffie-hellman-group16-sha512",
# endif /* HAVE_SHA512_OPENSSL */
# if defined(HAVE_SHA256_OPENSSL)
  "diffie-hellman-group14-sha256",
  "diffie-hellman-group-exchange-sha256",
# endif /* HAVE_SHA256_OPENSSL */
#endif
  "diffie-hellman-group-exchange-sha1",
  "diffie-hellman-group14-sha1",

#if 0
/* We cannot currently support rsa2048-sha256, since it requires support
 * for PKCS#1 v2.1 (RFC3447).  OpenSSL only supports PKCS#1 v2.0 (RFC2437)
 * at present, which only allows EME-OAEP using SHA1.  v2.1 allows for
 * using other message digests, e.g. SHA256, for EME-OAEP.
 */
#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  "rsa2048-sha256",
#endif
#endif

  "rsa1024-sha1",
  NULL,
};

static const char *get_kexinit_exchange_list(pool *p) {
  char *res = "";
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "ProxySFTPKeyExchanges",
    FALSE);
  if (c != NULL) {
    res = pstrdup(p, c->argv[0]);

  } else {
    register unsigned int i;

    for (i = 0; kex_exchanges[i]; i++) {
      res = pstrcat(p, res, *res ? "," : "", pstrdup(p, kex_exchanges[i]),
        NULL);
    }

    if (proxy_opts & PROXY_OPT_SSH_ALLOW_WEAK_DH) {
      /* The hardcoded group for this exchange is rather weak in the face of
       * the "Logjam" vulnerability (see https://weakdh.org).  Thus it is
       * only appended to the end of the default exchanges if the AllowWeakDH
       * SFTPOption is in effect.
       */
      res = pstrcat(p, res, ",", pstrdup(p, "diffie-hellman-group1-sha1"),
        NULL);
    }
  }

  if (!(proxy_opts & PROXY_OPT_SSH_NO_EXT_INFO)) {
    /* Indicate support for RFC 8308's extension negotiation mechanism. */
    res = pstrcat(p, res, *res ? "," : "", pstrdup(p, "ext-info-c"), NULL);
  }

  return res;
}

static const char *get_kexinit_hostkey_algo_list(pool *p) {
  char *list = "";

  /* Our list of supported hostkey algorithms depends on the hostkeys
   * that have been configured.  Show a preference for RSA over DSA,
   * and ECDSA over both RSA and DSA, and ED25519/ED448 over all.
   *
   * XXX Should this be configurable later?
   */

#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
  list = pstrcat(p, list, *list ? "," : "", "ssh-ed448", NULL);
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */

#if defined(PR_USE_SODIUM)
  list = pstrcat(p, list, *list ? "," : "", "ssh-ed25519", NULL);
#endif /* PR_USE_SODIUM */

#if defined(PR_USE_OPENSSL_ECC)
  list = pstrcat(p, list, *list ? "," : "", "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521", NULL);
#endif /* PR_USE_OPENSSL_ECC */

#if defined(HAVE_SHA512_OPENSSL)
  list = pstrcat(p, list, *list ? "," : "", "rsa-sha2-512", NULL);
#endif /* HAVE_SHA512_OPENSSL */

#if defined(HAVE_SHA256_OPENSSL)
  list = pstrcat(p, list, *list ? "," : "", "rsa-sha2-256", NULL);
#endif /* HAVE_SHA256_OPENSSL */

  list = pstrcat(p, list, *list ? "," : "", "ssh-rsa", NULL);

#if !defined(OPENSSL_NO_DSA)
  list = pstrcat(p, list, *list ? "," : "", "ssh-dss", NULL);
#endif /* OPENSSL_NO_DSA */

  return list;
}

static struct proxy_ssh_kex *create_kex(pool *p) {
  struct proxy_ssh_kex *kex;
  const char *list;
  config_rec *c;
  pool *tmp_pool;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Kex KEXINIT Pool");

  kex = pcalloc(tmp_pool, sizeof(struct proxy_ssh_kex));
  kex->pool = tmp_pool;
  kex->client_version = kex_client_version;
  kex->server_version = kex_server_version;
  kex->client_names = pcalloc(kex->pool, sizeof(struct proxy_ssh_kex_names));
  kex->server_names = pcalloc(kex->pool, sizeof(struct proxy_ssh_kex_names));
  kex->session_names = pcalloc(kex->pool, sizeof(struct proxy_ssh_kex_names));
  kex->use_hostkey_type = PROXY_SSH_KEY_UNKNOWN;
  kex->dh = NULL;
  kex->e = NULL;
  kex->hash = NULL;
  kex->k = NULL;
  kex->h = NULL;
  kex->hlen = 0;
  kex->dh_gex_min = kex->dh_gex_pref = kex->dh_gex_max = 0;
  kex->rsa = NULL;
  kex->rsa_encrypted = NULL;
  kex->rsa_encrypted_len = 0;

  list = get_kexinit_exchange_list(kex->pool);
  kex->client_names->kex_algo = list;

  list = get_kexinit_hostkey_algo_list(kex->pool);
  kex->client_names->server_hostkey_algo = list;

  list = proxy_ssh_crypto_get_kexinit_cipher_list(kex->pool);
  kex->client_names->c2s_encrypt_algo = list;
  kex->client_names->s2c_encrypt_algo = list;

  list = proxy_ssh_crypto_get_kexinit_digest_list(kex->pool);
  kex->client_names->c2s_mac_algo = list;
  kex->client_names->s2c_mac_algo = list;

  c = find_config(main_server->conf, CONF_PARAM, "ProxySFTPCompression", FALSE);
  if (c != NULL) {
    int comp_mode;

    comp_mode = *((int *) c->argv[0]);

    switch (comp_mode) {
      case 2:
        /* Advertise that we support OpenSSH's "delayed" compression mode. */
        kex->client_names->c2s_comp_algo = "zlib@openssh.com,zlib,none";
        kex->client_names->s2c_comp_algo = "zlib@openssh.com,zlib,none";
        break;

      case 1:
        kex->client_names->c2s_comp_algo = "zlib,none";
        kex->client_names->s2c_comp_algo = "zlib,none";
        break;

      default:
        kex->client_names->c2s_comp_algo = "none";
        kex->client_names->s2c_comp_algo = "none";
        break;
    }

  } else {
    kex->client_names->c2s_comp_algo = "none";
    kex->client_names->s2c_comp_algo = "none";
  }

  kex->client_names->c2s_lang = "";
  kex->client_names->s2c_lang = "";

  return kex;
}

static void destroy_kex(struct proxy_ssh_kex *kex) {
  if (kex != NULL) {
    if (kex->dh != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      if (kex->dh->p != NULL) {
        BN_clear_free(kex->dh->p);
        kex->dh->p = NULL;
      }

      if (kex->dh->g != NULL) {
        BN_clear_free(kex->dh->g);
        kex->dh->g = NULL;
      }
#endif /* prior to OpenSSL-1.1.0 */

      DH_free(kex->dh);
      kex->dh = NULL;
    }

    if (kex->rsa != NULL) {
      RSA_free(kex->rsa);
      kex->rsa = NULL;
    }

    if (kex->rsa_encrypted != NULL) {
      pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
      kex->rsa_encrypted = NULL;
      kex->rsa_encrypted_len = 0;
    }

    if (kex->e != NULL) {
      BN_clear_free((BIGNUM *) kex->e);
      kex->e = NULL;
    }

    if (kex->k != NULL) {
      BN_clear_free((BIGNUM *) kex->k);
      kex->k = NULL;
    }

    if (kex->hlen > 0) {
      pr_memscrub((char *) kex->h, kex->hlen);
      kex->hlen = 0;
    }

#if defined(PR_USE_OPENSSL_ECC)
    if (kex->ec != NULL) {
      EC_KEY_free(kex->ec);
      kex->ec = NULL;
    }

    if (kex->server_point != NULL) {
      EC_POINT_free(kex->server_point);
      kex->server_point = NULL;
    }
#endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
    if (kex->client_curve25519_priv_key != NULL) {
      pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
      kex->client_curve25519_priv_key = NULL;
    }

    if (kex->client_curve25519_pub_key != NULL) {
      pr_memscrub(kex->client_curve25519_pub_key, CURVE25519_SIZE);
      kex->client_curve25519_pub_key = NULL;
    }

    if (kex->server_curve25519_pub_key != NULL) {
      pr_memscrub(kex->server_curve25519_pub_key, CURVE25519_SIZE);
      kex->server_curve25519_pub_key = NULL;
    }
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */

#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
    if (kex->client_curve448_priv_key != NULL) {
      pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);
      kex->client_curve448_priv_key = NULL;
    }

    if (kex->client_curve448_pub_key != NULL) {
      pr_memscrub(kex->client_curve448_pub_key, CURVE448_SIZE);
      kex->client_curve448_pub_key = NULL;
    }

    if (kex->server_curve448_pub_key != NULL) {
      pr_memscrub(kex->server_curve448_pub_key, CURVE448_SIZE);
      kex->server_curve448_pub_key = NULL;
    }
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */

    if (kex->pool != NULL) {
      destroy_pool(kex->pool);
      kex->pool = NULL;
    }
  }

  kex_first_kex = kex_rekey_kex = NULL;
}

static int setup_kex_algo(struct proxy_ssh_kex *kex, const char *algo) {
  if (strcmp(algo, "diffie-hellman-group1-sha1") == 0) {
    if (create_dh(kex, PROXY_SSH_DH_GROUP1_SHA1) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;
  }

  if (strcmp(algo, "diffie-hellman-group14-sha1") == 0) {
    if (create_dh(kex, PROXY_SSH_DH_GROUP14_SHA1) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;
  }

  if (strcmp(algo, "diffie-hellman-group14-sha256") == 0) {
    if (create_dh(kex, PROXY_SSH_DH_GROUP14_SHA256) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;
  }

  if (strcmp(algo, "diffie-hellman-group16-sha512") == 0) {
    if (create_dh(kex, PROXY_SSH_DH_GROUP16_SHA512) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;
  }

  if (strcmp(algo, "diffie-hellman-group18-sha512") == 0) {
    if (create_dh(kex, PROXY_SSH_DH_GROUP18_SHA512) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;
  }

  if (strcmp(algo, "diffie-hellman-group-exchange-sha1") == 0) {
    if (prepare_dh(kex, PROXY_SSH_DH_GEX_SHA1) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_gex = TRUE;
    return 0;
  }

  if (strcmp(algo, "rsa1024-sha1") == 0) {
    if (create_kexrsa(kex, PROXY_SSH_KEXRSA_SHA1) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_kexrsa = TRUE;
    return 0;
  }

#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  if (strcmp(algo, "diffie-hellman-group-exchange-sha256") == 0) {
    if (prepare_dh(kex, PROXY_SSH_DH_GEX_SHA256) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_gex = TRUE;
    return 0;
  }

  if (strcmp(algo, "rsa2048-sha256") == 0) {
    if (create_kexrsa(kex, PROXY_SSH_KEXRSA_SHA256) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_kexrsa = TRUE;
    return 0;
  }
#endif

#if defined(PR_USE_OPENSSL_ECC)
  if (strcmp(algo, "ecdh-sha2-nistp256") == 0) {
    if (create_ecdh(kex, PROXY_SSH_ECDH_SHA256) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_ecdh = TRUE;
    return 0;
  }

  if (strcmp(algo, "ecdh-sha2-nistp384") == 0) {
    if (create_ecdh(kex, PROXY_SSH_ECDH_SHA384) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_ecdh = TRUE;
    return 0;
  }

  if (strcmp(algo, "ecdh-sha2-nistp521") == 0) {
    if (create_ecdh(kex, PROXY_SSH_ECDH_SHA512) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_ecdh = TRUE;
    return 0;
  }
#endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
  if (strcmp(algo, "curve25519-sha256") == 0 ||
      strcmp(algo, "curve25519-sha256@libssh.org") == 0) {
    if (create_curve25519(kex) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->hash = EVP_sha256();
    kex->session_names->kex_algo = algo;
    kex->use_curve25519 = TRUE;
    return 0;
  }
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */

#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
  if (strcmp(algo, "curve448-sha512") == 0) {
    if (create_curve448(kex) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->hash = EVP_sha512();
    kex->session_names->kex_algo = algo;
    kex->use_curve448 = TRUE;
    return 0;
  }
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */

  if (strcmp(algo, "ext-info-c") == 0 ||
      strcmp(algo, "ext-info-s") == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unable to use extension negotiation algorithm '%s' for key exchange",
      algo);
    errno = EINVAL;
    return -1;
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "unsupported key exchange algorithm '%s'", algo);
  errno = EINVAL;
  return -1;
}

static int setup_hostkey_algo(struct proxy_ssh_kex *kex, const char *algo) {
  kex->session_names->server_hostkey_algo = (char *) algo;

  if (strcmp(algo, "ssh-dss") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_DSA;
    return 0;
  }

  if (strcmp(algo, "ssh-rsa") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_RSA;
    return 0;
  }

#if defined(HAVE_SHA256_OPENSSL)
  if (strcmp(algo, "rsa-sha2-256") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_RSA_SHA256;
    return 0;
  }
#endif /* HAVE_SHA256_OPENSSL */

#if defined(HAVE_SHA512_OPENSSL)
  if (strcmp(algo, "rsa-sha2-512") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_RSA_SHA512;
    return 0;
  }
#endif /* HAVE_SHA512_OPENSSL */

#if defined(PR_USE_OPENSSL_ECC)
  if (strcmp(algo, "ecdsa-sha2-nistp256") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_ECDSA_256;
    return 0;
  }

  if (strcmp(algo, "ecdsa-sha2-nistp384") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_ECDSA_384;
    return 0;
  }

  if (strcmp(algo, "ecdsa-sha2-nistp521") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_ECDSA_521;
    return 0;
  }
#endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM)
  if (strcmp(algo, "ssh-ed25519") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_ED25519;
    return 0;
  }
#endif /* PR_USE_SODIUM */

#if defined(HAVE_X448_OPENSSL)
  if (strcmp(algo, "ssh-ed448") == 0) {
    kex->use_hostkey_type = PROXY_SSH_KEY_ED448;
    return 0;
  }
#endif /* HAVE_X448_OPENSSL */

  errno = EINVAL;
  return -1;
}

static int setup_c2s_encrypt_algo(struct proxy_ssh_kex *kex, const char *algo) {
  if (proxy_ssh_cipher_set_read_algo(kex_pool, algo) < 0) {
    return -1;
  }

  kex->session_names->c2s_encrypt_algo = algo;
  return 0;
}

static int setup_s2c_encrypt_algo(struct proxy_ssh_kex *kex, const char *algo) {
  if (proxy_ssh_cipher_set_write_algo(kex_pool, algo) < 0) {
    return -1;
  }

  kex->session_names->s2c_encrypt_algo = algo;
  return 0;
}

static int setup_c2s_mac_algo(struct proxy_ssh_kex *kex, const char *algo) {
  if (proxy_ssh_mac_set_read_algo(kex_pool, algo) < 0) {
    return -1;
  }

  kex->session_names->c2s_mac_algo = algo;
  return 0;
}

static int setup_s2c_mac_algo(struct proxy_ssh_kex *kex, const char *algo) {
  if (proxy_ssh_mac_set_write_algo(kex_pool, algo) < 0) {
    return -1;
  }

  kex->session_names->s2c_mac_algo = algo;
  return 0;
}

static int setup_c2s_comp_algo(struct proxy_ssh_kex *kex, const char *algo) {
  if (proxy_ssh_compress_set_read_algo(kex_pool, algo) < 0) {
    return -1;
  }

  kex->session_names->c2s_comp_algo = algo;
  return 0;
}

static int setup_s2c_comp_algo(struct proxy_ssh_kex *kex, const char *algo) {
  if (proxy_ssh_compress_set_write_algo(kex_pool, algo) < 0) {
    return -1;
  }

  kex->session_names->s2c_comp_algo = algo;
  return 0;
}

static int setup_c2s_lang(struct proxy_ssh_kex *kex, const char *lang) {
  /* XXX Need to implement the functionality here. */
  kex->session_names->c2s_lang = lang;
  return 0;
}

static int setup_s2c_lang(struct proxy_ssh_kex *kex, const char *lang) {
  /* XXX Need to implement the functionality here. */
  kex->session_names->s2c_lang = lang;
  return 0;
}

static int get_session_names(struct proxy_ssh_kex *kex, int *correct_guess) {
  const char *kex_algo, *shared, *client_list, *server_list;
  const char *client_pref, *server_pref;
  pool *tmp_pool;

  tmp_pool = make_sub_pool(kex->pool);
  pr_pool_tag(tmp_pool, "Proxy SSH session shared name pool");

  client_list = kex->client_names->kex_algo;
  server_list = kex->server_names->kex_algo;

  pr_trace_msg(trace_channel, 8, "client-sent key exchange algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent key exchange algorithms: %s",
    server_list);

  client_pref = get_preferred_name(tmp_pool, client_list);
  server_pref = get_preferred_name(tmp_pool, server_list);

  /* Did the client correctly guess at the key exchange algorithm that
   * we would list first in our server list, if it says it sent
   * a guess KEX packet?
   */

  if (kex->first_kex_follows == TRUE &&
      *correct_guess == TRUE &&
      client_pref != NULL &&
      server_pref != NULL) {

    if (strcmp(client_pref, server_pref) != 0) {
      *correct_guess = FALSE;

      pr_trace_msg(trace_channel, 7,
        "client incorrectly guessed key exchange algorithm '%s'", client_pref);

    } else {
      pr_trace_msg(trace_channel, 7,
        "client correctly guessed key exchange algorithm '%s'", server_pref);
    }
  }

  kex_algo = proxy_ssh_misc_namelist_shared(kex->pool, client_list,
    server_list);
  if (kex_algo != NULL) {
    /* Unlike the following algorithms, we wait to setup the chosen kex algo
     * until the end.  Why?  The kex algo setup may require knowledge of the
     * ciphers chosen for encryption, MAC, etc (Bug#4097).
     */
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session key exchange: %s", kex_algo);
    pr_trace_msg(trace_channel, 20, "session key exchange algorithm: %s",
      kex_algo);

    /* Did the server indicate EXT_INFO support */
    kex->use_ext_info = proxy_ssh_misc_namelist_contains(kex->pool, server_list,
      "ext-info-s");
    pr_trace_msg(trace_channel, 20, "server %s EXT_INFO support",
      kex->use_ext_info ? "signaled" : "did not signal" );

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "no shared key exchange algorithm found (client sent '%s', server sent "
      "'%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->server_hostkey_algo;
  server_list = kex->server_names->server_hostkey_algo;

  pr_trace_msg(trace_channel, 8,
    "client-sent host key algorithms: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent host key algorithms: %s", server_list);

  shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared != NULL) {
    if (setup_hostkey_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session server hostkey: %s", shared);
    pr_trace_msg(trace_channel, 20, "session server hostkey algorithm: %s",
      shared);

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "no shared server hostkey algorithm found (client sent '%s', server sent "
      "'%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->c2s_encrypt_algo;
  server_list = kex->server_names->c2s_encrypt_algo;

  pr_trace_msg(trace_channel, 8, "client-sent client encryption algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent client encryption algorithms: %s",
    server_list);

  shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared != NULL) {
    if (setup_c2s_encrypt_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session client-to-server encryption: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server encryption algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "no shared client-to-server encryption algorithm found (client sent '%s',"
      " server sent '%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->s2c_encrypt_algo;
  server_list = kex->server_names->s2c_encrypt_algo;

  pr_trace_msg(trace_channel, 8, "client-sent server encryption algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent server encryption algorithms: %s",
    server_list);

  shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared != NULL) {
    if (setup_s2c_encrypt_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session server-to-client encryption: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client encryption algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "no shared server-to-client encryption algorithm found (client sent '%s',"
      " server sent '%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->c2s_mac_algo;
  server_list = kex->server_names->c2s_mac_algo;

  pr_trace_msg(trace_channel, 8, "client-sent client MAC algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent client MAC algorithms: %s",
    server_list);

  /* Ignore MAC/digests when authenticated encryption algorithms are used. */
  if (proxy_ssh_cipher_get_read_auth_size2() == 0) {
    shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list,
      server_list);
    if (shared != NULL) {
      if (setup_c2s_mac_algo(kex, shared) < 0) {
        destroy_pool(tmp_pool);
        return -1;
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        " + Session client-to-server MAC: %s", shared);
      pr_trace_msg(trace_channel, 20,
        "session client-to-server MAC algorithm: %s", shared);

    } else {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "no shared client-to-server MAC algorithm found (client sent '%s', "
        "server sent '%s')", client_list, server_list);
      destroy_pool(tmp_pool);
      return -1;
    }

  } else {
    pr_trace_msg(trace_channel, 8, "ignoring MAC algorithms due to use of "
      "client-to-server authenticated cipher algorithm '%s'",
      kex->session_names->c2s_encrypt_algo);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server MAC algorithm: <implicit>");
  }

  client_list = kex->client_names->s2c_mac_algo;
  server_list = kex->server_names->s2c_mac_algo;

  pr_trace_msg(trace_channel, 8, "client-sent server MAC algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent server MAC algorithms: %s",
    server_list);

  /* Ignore MAC/digests when authenticated encryption algorithms are used. */
  if (proxy_ssh_cipher_get_write_auth_size2() == 0) {
    shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list,
      server_list);
    if (shared != NULL) {
      if (setup_s2c_mac_algo(kex, shared) < 0) {
        destroy_pool(tmp_pool);
        return -1;
      }

      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        " + Session server-to-client MAC: %s", shared);
      pr_trace_msg(trace_channel, 20,
        "session server-to-client MAC algorithm: %s", shared);

    } else {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "no shared server-to-client MAC algorithm found (client sent '%s', "
        "server sent '%s')", client_list, server_list);
      destroy_pool(tmp_pool);
      return -1;
    }

  } else {
    pr_trace_msg(trace_channel, 8, "ignoring MAC algorithms due to use of "
      "server-to-client authenticated cipher algorithm '%s'",
      kex->session_names->s2c_encrypt_algo);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client MAC algorithm: <implicit>");
  }

  client_list = kex->client_names->c2s_comp_algo;
  server_list = kex->server_names->c2s_comp_algo;

  pr_trace_msg(trace_channel, 8,
    "client-sent client compression algorithms: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent client compression algorithms: %s", server_list);

  shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared != NULL) {
    if (setup_c2s_comp_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session client-to-server compression: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server compression algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "no shared client-to-server compression algorithm found (client sent "
      "'%s', server sent '%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->s2c_comp_algo;
  server_list = kex->server_names->s2c_comp_algo;

  pr_trace_msg(trace_channel, 8,
    "client-sent server compression algorithms: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent server compression algorithms: %s", server_list);

  shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared != NULL) {
    if (setup_s2c_comp_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session server-to-client compression: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client compression algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "no shared server-to-client compression algorithm found (client sent "
      "'%s', server sent '%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->c2s_lang;
  server_list = kex->server_names->c2s_lang;

  pr_trace_msg(trace_channel, 8,
    "client-sent client languages: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent client languages: %s", client_list);

  shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared != NULL) {
    if (setup_c2s_lang(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session client-to-server language: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server language: %s", shared);

    /* Currently ignore any lack of shared languages. */
  }

  client_list = kex->client_names->s2c_lang;
  server_list = kex->server_names->s2c_lang;

  pr_trace_msg(trace_channel, 8,
    "client-sent server languages: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent server languages: %s", client_list);

  shared = proxy_ssh_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared != NULL) {
    if (setup_s2c_lang(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      " + Session server-to-client language: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client language: %s", shared);

    /* Currently ignore any lack of shared languages. */
  }

  /* Now that we've finished setting up the other bits, we can set up the
   * kex algo.
   */
  if (setup_kex_algo(kex, kex_algo) < 0) {
    destroy_pool(tmp_pool);
    return -1;
  }

  destroy_pool(tmp_pool);
  return 0;
}

static int read_kexinit(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf;
  unsigned char *cookie;
  char *list;
  uint32_t buflen, reserved;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Make a copy of the payload for later. */
  kex->server_kexinit_payload = palloc(kex->pool, pkt->payload_len);
  kex->server_kexinit_payload_len = pkt->payload_len;
  memcpy(kex->server_kexinit_payload, pkt->payload, pkt->payload_len);

  /* Read the cookie, which is a mandated length of 16 bytes. */
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, 16, &cookie);

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->kex_algo = list;

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->server_hostkey_algo = list;

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->c2s_encrypt_algo = list;

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->s2c_encrypt_algo = list;

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->c2s_mac_algo = list;

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->s2c_mac_algo = list;

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->c2s_comp_algo = list;

  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->s2c_comp_algo = list;

  /* Client-to-server languages */
  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->c2s_lang = list;

  /* Server-to-client languages */
  proxy_ssh_msg_read_string(kex->pool, &buf, &buflen, &list);
  kex->server_names->s2c_lang = list;

  /* Read the "first kex packet follows" byte */
  proxy_ssh_msg_read_bool(pkt->pool, &buf, &buflen, &(kex->first_kex_follows));

  pr_trace_msg(trace_channel, 3, "first kex packet follows = %s",
    kex->first_kex_follows ? "true" : "false");

  /* Reserved flags */
  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &reserved);

  return 0;
}

static int write_kexinit(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char cookie[16];
  unsigned char *buf, *ptr;
  const char *list;
  uint32_t bufsz, buflen, len = 0;

  /* XXX Always have empty language lists; we really don't care. */
  const char *langs = "";

  bufsz = buflen = sizeof(char) +
    sizeof(cookie) +
    sizeof(uint32_t) + strlen(kex->client_names->kex_algo) +
    sizeof(uint32_t) + strlen(kex->client_names->server_hostkey_algo) +
    sizeof(uint32_t) + strlen(kex->client_names->c2s_encrypt_algo) +
    sizeof(uint32_t) + strlen(kex->client_names->s2c_encrypt_algo) +
    sizeof(uint32_t) + strlen(kex->client_names->c2s_mac_algo) +
    sizeof(uint32_t) + strlen(kex->client_names->s2c_mac_algo) +
    sizeof(uint32_t) + strlen(kex->client_names->c2s_comp_algo) +
    sizeof(uint32_t) + strlen(kex->client_names->s2c_comp_algo) +
    sizeof(uint32_t) + strlen(langs) +
    sizeof(uint32_t) + strlen(langs) +
    sizeof(char) +
    sizeof(uint32_t);

  ptr = buf = pcalloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXINIT);

  /* Try first to use cryptographically secure bytes for the cookie.
   * If that fails (e.g. if the PRNG hasn't been seeded well), use
   * pseudo-cryptographically secure bytes.
   */
  memset(cookie, 0, sizeof(cookie));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  RAND_bytes(cookie, sizeof(cookie));
#else
  if (RAND_bytes(cookie, sizeof(cookie)) != 1) {
    RAND_pseudo_bytes(cookie, sizeof(cookie));
  }
#endif /* prior to OpenSSL-1.1.0 */

  len += proxy_ssh_msg_write_data(&buf, &buflen, cookie, sizeof(cookie), FALSE);

  list = kex->client_names->kex_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  list = kex->client_names->server_hostkey_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  list = kex->client_names->c2s_encrypt_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  list = kex->client_names->s2c_encrypt_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  list = kex->client_names->c2s_mac_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  list = kex->client_names->s2c_mac_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  list = kex->client_names->c2s_comp_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  list = kex->client_names->s2c_comp_algo;
  len += proxy_ssh_msg_write_string(&buf, &buflen, list);

  /* XXX Need to support langs here. */
  len += proxy_ssh_msg_write_string(&buf, &buflen, langs);
  len += proxy_ssh_msg_write_string(&buf, &buflen, langs);

  /* We don't try to optimistically guess what algorithms the client would
   * use and send a preemptive kex packet.
   */
  len += proxy_ssh_msg_write_bool(&buf, &buflen, FALSE);
  len += proxy_ssh_msg_write_int(&buf, &buflen, 0);

  pkt->payload = ptr;
  pkt->payload_len = len;

  /* Make a copy of the payload for later. Skip past the first byte, which
   * is the KEXINIT identifier.
   */
  kex->client_kexinit_payload_len = pkt->payload_len - 1;
  kex->client_kexinit_payload = palloc(kex->pool, pkt->payload_len - 1);
  memcpy(kex->client_kexinit_payload, pkt->payload + 1, pkt->payload_len - 1);

  return 0;
}

/* Only set the given environment variable/value IFF it is not already
 * present.
 */
static void set_env_var(pool *p, const char *k, const char *v) {
  const char *val;
  int have_val = FALSE;

  val = pr_env_get(p, k);
  if (val != NULL) {
    if (strcmp(val, v) == 0) {
      have_val = TRUE;
    }
  }

  if (have_val == FALSE) {
    k = pstrdup(p, k);
    v = pstrdup(p, v);
    pr_env_unset(p, k);
    pr_env_set(p, k, v);
  }
}

static int set_session_keys(struct proxy_ssh_kex *kex) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, klen;
  int comp_read_flags, comp_write_flags;

  /* To date, the kex algo that has generated the largest K that I have
   * seen so far is "diffie-hellman-group18-sha512".
   */
  bufsz = buflen = 2048;
  ptr = buf = palloc(kex_pool, bufsz);

  /* Need to use SSH2-style format of K for the key. */
  klen = proxy_ssh_msg_write_mpint(&buf, &buflen, kex->k);

  if (proxy_ssh_cipher_set_read_key(kex_pool, kex->hash, ptr, klen, kex->h,
      kex->hlen, PROXY_SSH_ROLE_CLIENT) < 0) {
    pr_memscrub(ptr, bufsz);
    return -1;
  }

  if (proxy_ssh_cipher_set_write_key(kex_pool, kex->hash, ptr, klen, kex->h,
      kex->hlen, PROXY_SSH_ROLE_CLIENT) < 0) {
    pr_memscrub(ptr, bufsz);
    return -1;
  }

  if (proxy_ssh_mac_set_read_key(kex_pool, kex->hash, ptr, klen, kex->h,
      kex->hlen, PROXY_SSH_ROLE_CLIENT) < 0) {
    pr_memscrub(ptr, bufsz);
    return -1;
  }

  if (proxy_ssh_mac_set_write_key(kex_pool, kex->hash, ptr, klen, kex->h,
      kex->hlen, PROXY_SSH_ROLE_CLIENT) < 0) {
    pr_memscrub(ptr, bufsz);
    return -1;
  }

  comp_read_flags = comp_write_flags = PROXY_SSH_COMPRESS_FL_NEW_KEY;

  /* If we are rekeying, AND the existing compression is "delayed", then
   * we need to use slightly different compression flags.
   */
  if (kex_rekey_kex != NULL) {
    const char *algo;

    algo = proxy_ssh_compress_get_read_algo();
    if (strcmp(algo, "zlib@openssh.com") == 0) {
      comp_read_flags = PROXY_SSH_COMPRESS_FL_AUTHENTICATED;
    }

    algo = proxy_ssh_compress_get_write_algo();
    if (strcmp(algo, "zlib@openssh.com") == 0) {
      comp_write_flags = PROXY_SSH_COMPRESS_FL_AUTHENTICATED;
    }
  }

  if (proxy_ssh_compress_init_read(comp_read_flags) < 0) {
    pr_memscrub(ptr, bufsz);
    return -1;
  }

  if (proxy_ssh_compress_init_write(comp_write_flags) < 0) {
    pr_memscrub(ptr, bufsz);
    return -1;
  }

  pr_memscrub(ptr, bufsz);

  set_env_var(session.pool, "PROXY_SSH_CLIENT_CIPHER_ALGO",
    proxy_ssh_cipher_get_write_algo());
  set_env_var(session.pool, "PROXY_SSH_SERVER_CIPHER_ALGO",
    proxy_ssh_cipher_get_read_algo());

  if (proxy_ssh_cipher_get_read_auth_size2() == 0) {
    set_env_var(session.pool, "PROXY_SSH_CLIENT_MAC_ALGO",
      proxy_ssh_mac_get_write_algo());

  } else {
    set_env_var(session.pool, "PROXY_SSH_CLIENT_MAC_ALGO", "implicit");
  }

  if (proxy_ssh_cipher_get_write_auth_size2() == 0) {
    set_env_var(session.pool, "PROXY_SSH_SERVER_MAC_ALGO",
      proxy_ssh_mac_get_read_algo());

  } else {
    set_env_var(session.pool, "PROXY_SSH_SERVER_MAC_ALGO", "implicit");
  }

  set_env_var(session.pool, "PROXY_SSH_CLIENT_COMPRESSION_ALGO",
    proxy_ssh_compress_get_write_algo());
  set_env_var(session.pool, "PROXY_SSH_SERVER_COMPRESSION_ALGO",
    proxy_ssh_compress_get_read_algo());
  set_env_var(session.pool, "PROXY_SSH_KEX_ALGO",
    kex->session_names->kex_algo);

  if (kex_rekey_kex != NULL) {
    pr_trace_msg(trace_channel, 3, "rekey KEX completed");
    kex_rekey_kex = NULL;
  }

  return 0;
}

static int write_newkeys_reply(struct proxy_ssh_packet *pkt) {
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, len = 0;

  /* Write out the NEWKEYS message. */
  bufsz = buflen = 1;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_NEWKEYS);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int handle_server_hostkey(pool *p,
    enum proxy_ssh_key_type_e hostkey_type, unsigned char *hostkey_data,
    uint32_t hostkey_datalen) {
  unsigned int vhost_id;
  const struct proxy_session *proxy_sess;
  const char *backend_uri, *hostkey_algo, *stored_hostkey_algo = NULL;
  const unsigned char *stored_hostkey_data = NULL;
  uint32_t stored_hostkey_datalen = 0;

  proxy_sess = pr_table_get(session.notes, "mod_proxy.proxy-session", NULL);
  backend_uri = proxy_conn_get_uri(proxy_sess->dst_pconn);
  vhost_id = main_server->sid;

  hostkey_algo = proxy_ssh_keys_get_key_type_desc(hostkey_type);

  stored_hostkey_data = (kex_ds->hostkey_get)(p, kex_ds->dsh, vhost_id,
    backend_uri, &stored_hostkey_algo, &stored_hostkey_datalen);
  if (stored_hostkey_data == NULL) {
    if (errno != ENOENT) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error retrieving stored hostkey for vhost ID %u, URI '%s': %s",
        vhost_id, backend_uri, strerror(errno));
      return 0;
    }

    pr_trace_msg(trace_channel, 18,
      "no existing hostkey stored for vhost ID %u, URI '%s', "
      "storing '%s' hostkey (%lu bytes)", vhost_id, backend_uri, hostkey_algo,
      (unsigned long) hostkey_datalen);

    if ((kex_ds->hostkey_add)(p, kex_ds->dsh, vhost_id, backend_uri,
        hostkey_algo, hostkey_data, hostkey_datalen) < 0) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error adding '%s' hostkey for vhost ID %u, URI '%s': %s",
        hostkey_algo, vhost_id, backend_uri, strerror(errno));
    }

  } else {
    int verified = TRUE;

    pr_trace_msg(trace_channel, 12,
      "found stored '%s' hostkey (%lu bytes) for vhost ID %u, URI '%s'",
      stored_hostkey_algo, (unsigned long) stored_hostkey_datalen, vhost_id,
      backend_uri);

    if (strcmp(hostkey_algo, stored_hostkey_algo) != 0) {
      pr_trace_msg(trace_channel, 1,
        "stored hostkey for vhost ID %u, URI '%s' uses different algorithm: "
        "'%s' (stored), '%s' (current)", vhost_id, backend_uri,
        stored_hostkey_algo, hostkey_algo);
      verified = FALSE;
    }

    if (verified == TRUE &&
        hostkey_datalen != stored_hostkey_datalen) {
      pr_trace_msg(trace_channel, 1,
        "stored hostkey for vhost ID %u, URI '%s' has different length: "
        "%lu bytes (stored), %lu bytes (current)", vhost_id, backend_uri,
        (unsigned long) stored_hostkey_datalen,
        (unsigned long) hostkey_datalen);
      verified = FALSE;
    }

    if (verified == TRUE &&
        memcmp(hostkey_data, stored_hostkey_data, hostkey_datalen) != 0) {
      pr_trace_msg(trace_channel, 1,
        "stored hostkey for vhost ID %u, URI '%s' does not match current key",
        vhost_id, backend_uri);
      verified = FALSE;
    }

    if (verified == TRUE) {
      pr_trace_msg(trace_channel, 18,
        "stored hostkey matches current hostkey for vhost ID %u, URI '%s'",
        vhost_id, backend_uri);

    } else {
      if (kex_verify_hostkeys == TRUE) {
        /* TODO: This is where we would implement functionality similar to
         * OpenSSH's UpdateHostKeys, via hostkey rotation extensions, where
         * available.
         */

        /* TODO: If we fail the KEX here, what recourse does the admin have?
         * We currently are not providing a way to update/remove the offending
         * stored hostkey in the SQLite database.
         *
         * For now, just loudly log the mismatch.
         */
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "stored hostkey does not match current hostkey "
          "(vhost ID %u, URI '%s') and ProxySFTPVerifyServer is enabled",
          vhost_id, backend_uri);

      } else {
        /* Replace the stored hostkey. */
        pr_trace_msg(trace_channel, 10, "stored hostkey does not match current "
          "hostkey (vhost ID %u, URI '%s') and ProxySFTPVerifyServer is "
          "disabled, updating stored hostkey", vhost_id, backend_uri);
        if ((kex_ds->hostkey_update)(p, kex_ds->dsh, vhost_id, backend_uri,
             hostkey_algo, hostkey_data, hostkey_datalen) < 0) {
          (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
            "error updating '%s' hostkey for vhost ID %u, URI '%s': %s",
            hostkey_algo, vhost_id, backend_uri, strerror(errno));
        }
      }
    }
  }

  return 0;
}

static struct proxy_ssh_packet *read_kex_packet(pool *p,
    struct proxy_ssh_kex *kex, conn_t *conn, int disconn_code,
    char *found_msg_type, unsigned int ntypes, ...) {
  register unsigned int i;
  va_list ap;
  struct proxy_ssh_packet *pkt = NULL;
  array_header *allowed_types;

  pr_trace_msg(trace_channel, 9, "waiting for a message of %d %s from server",
    ntypes, ntypes != 1 ? "types" : "type");

  allowed_types = make_array(p, 1, sizeof(char));
 
  va_start(ap, ntypes);  

  while (ntypes-- > 0) {
    *((char *) push_array(allowed_types)) = va_arg(ap, int);
  }

  va_end(ap);

  /* Keep looping until we get the desired message, or we time out (hopefully
   * via TimeoutLogin or somesuch).
   */
  while (pkt == NULL) {
    int found = FALSE, res;
    char msg_type;

    pr_signals_handle();

    pkt = proxy_ssh_packet_create(p);
    res = proxy_ssh_packet_read(conn, pkt);
    if (res < 0) {
      int xerrno = errno;

      destroy_kex(kex);
      destroy_pool(pkt->pool);

      errno = xerrno;
      return NULL;
    }

    pr_response_clear(&resp_list);
    pr_response_clear(&resp_err_list);
    pr_response_set_pool(pkt->pool);

    /* Per RFC 4253, Section 11, DEBUG, DISCONNECT, IGNORE, and UNIMPLEMENTED
     * messages can occur at any time, even during KEX.  We have to be prepared
     * for this, and Do The Right Thing(tm).
     */

    msg_type = proxy_ssh_packet_get_msg_type(pkt);

    for (i = 0; i < allowed_types->nelts; i++) {
      if (msg_type == ((unsigned char *) allowed_types->elts)[i]) {
        /* Exactly what we were looking for.  Excellent. */
        pr_trace_msg(trace_channel, 13,
          "received expected %s message",
          proxy_ssh_packet_get_msg_type_desc(msg_type));

        if (found_msg_type != NULL) {
          /* The caller wants to know the type of message we're returning;
           * packet_get_msg_type() performs a destructive read.
           */
          *found_msg_type = msg_type;
        }

        found = TRUE;
        break;
      }
    }

    if (found == TRUE) {
      break;
    }

    switch (msg_type) {
      case PROXY_SSH_MSG_DEBUG:
        proxy_ssh_packet_handle_debug(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      case PROXY_SSH_MSG_DISCONNECT:
        proxy_ssh_packet_handle_disconnect(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      case PROXY_SSH_MSG_IGNORE:
        proxy_ssh_packet_handle_ignore(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      case PROXY_SSH_MSG_UNIMPLEMENTED:
        proxy_ssh_packet_handle_unimplemented(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      default:
        /* For any other message type, it's considered a protocol error. */
        (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
          "received %s (%d) unexpectedly, disconnecting",
          proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);
        pr_response_set_pool(NULL);
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        PROXY_SSH_DISCONNECT_CONN(conn, disconn_code, NULL);
    }
  }

  return pkt;
}

static int write_dh_init(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;
  const BIGNUM *dh_pub_key;

  /* In our DH_INIT, send 'e', our client DH public key. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */

  bufsz = buflen = 2048;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEX_DH_INIT);
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, dh_pub_key);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int read_dh_reply(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  const unsigned char *h;
  unsigned char *buf, *buf2, *server_hostkey_data = NULL, *sig = NULL;
  uint32_t buflen, server_hostkey_datalen = 0, siglen = 0, hlen = 0;
  const BIGNUM *server_pub_key = NULL, *k = NULL;
  size_t dh_len = 0;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* See RFC 4253, Section 8 "Diffie-Hellman Key Exchange" */

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &server_hostkey_datalen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, server_hostkey_datalen,
    &server_hostkey_data);

  res = handle_server_hostkey(pkt->pool, kex->use_hostkey_type,
    server_hostkey_data, server_hostkey_datalen);
  if (res < 0) {
    int xerrno;

    xerrno = errno;
    DH_free(kex->dh);
    kex->dh = NULL;
   
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error handling server host key: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  proxy_ssh_msg_read_mpint(pkt->pool, &buf, &buflen, &server_pub_key);

  if (have_good_dh(kex->dh, server_pub_key) < 0) {
    DH_free(kex->dh);
    kex->dh = NULL;
   
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "invalid server public DH key");
    return -1;
  }

  /* Compute the shared secret. */
  dh_len = DH_size(kex->dh);
  buf2 = palloc(pkt->pool, dh_len);

  pr_trace_msg(trace_channel, 12, "computing DH key");
  res = DH_compute_key(buf2, server_pub_key, kex->dh);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error computing DH shared secret: %s", proxy_ssh_crypto_get_errors());

    DH_free(kex->dh);
    kex->dh = NULL;
    return -1;
  }

  k = BN_new();
  if (BN_bin2bn(buf2, res, (BIGNUM *) k) == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error converting DH shared secret to BN: %s",
      proxy_ssh_crypto_get_errors());

    DH_free(kex->dh);
    kex->dh = NULL;
    return -1;
  }

  kex->k = k;

  /* Calculate H */
  h = calculate_h(pkt->pool, kex, server_hostkey_data, server_hostkey_datalen,
    server_pub_key, k, &hlen);
  if (h == NULL) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    DH_free(kex->dh);
    kex->dh = NULL;

    return -1;
  }

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &siglen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, siglen, &sig);

  /* Verify H */
  res = verify_h(pkt->pool, kex, server_hostkey_data, server_hostkey_datalen,
    sig, siglen, h, hlen);
  if (res < 0) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    DH_free(kex->dh);
    kex->dh = NULL;

    return -1;
  }

  kex->h = palloc(kex_pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID. */
  proxy_ssh_session_set_id(session.pool, h, hlen);

  return 0;
}

static int handle_kex_dh(struct proxy_ssh_kex *kex, conn_t *conn) {
  int res;
  struct proxy_ssh_packet *pkt;

  pr_trace_msg(trace_channel, 9, "writing DH_INIT message to server");
  pkt = proxy_ssh_packet_create(kex_pool);
  res = write_dh_init(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = proxy_ssh_packet_write(conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "reading DH_REPLY message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEX_DH_REPLY);

  res = read_dh_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}

/* Values from NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 (rev 3) limited by the recommended maximum value from
 * RFC 4419 section 3.
 */
static uint32_t estimate_dh(int nbits) {
  if (nbits <= 112) {
    return PROXY_SSH_DH_MIN_LEN;
  }

  if (nbits <= 128) {
    return 3072;
  }

  if (nbits <= 192) {
    return 7680;
  }

  return PROXY_SSH_DH_MAX_LEN;
}

static int write_dh_gex_request(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;
  int dh_nbits = 0;

  /* Estimate our desired DH size based on our negotiated ciphers. */
  dh_nbits = get_dh_nbits(kex);

  kex->dh_gex_pref = estimate_dh(dh_nbits);

  if (kex->dh_gex_pref < PROXY_SSH_DH_MIN_LEN) {
    kex->dh_gex_pref = PROXY_SSH_DH_MIN_LEN;
  }

  if (kex->dh_gex_pref > PROXY_SSH_DH_MAX_LEN) {
    kex->dh_gex_pref = PROXY_SSH_DH_MAX_LEN;
  }

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 2048;
  ptr = buf = palloc(pkt->pool, bufsz);

  if (proxy_ssh_interop_supports_feature(PROXY_SSH_FEAT_DH_NEW_GEX) == TRUE) {
    kex->dh_gex_min = PROXY_SSH_DH_MIN_LEN;
    kex->dh_gex_max = PROXY_SSH_DH_MAX_LEN;

    len += proxy_ssh_msg_write_byte(&buf, &buflen,
      PROXY_SSH_MSG_KEX_DH_GEX_REQUEST);
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_min);
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_pref);
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_max);

  } else {
    len += proxy_ssh_msg_write_byte(&buf, &buflen,
      PROXY_SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
    len += proxy_ssh_msg_write_int(&buf, &buflen, kex->dh_gex_pref);
  }

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int create_gex_dh(struct proxy_ssh_kex *kex, const BIGNUM *dh_p,
    const BIGNUM *dh_g) {
  unsigned int attempts = 0;
  int dh_nbits;
  DH *dh;

  if (kex->dh != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (kex->dh->p != NULL) {
      BN_clear_free(kex->dh->p);
      kex->dh->p = NULL;
    }

    if (kex->dh->g != NULL) {
      BN_clear_free(kex->dh->g);
      kex->dh->g = NULL;
    }

    if (kex->dh->priv_key != NULL) {
      BN_clear_free(kex->dh->priv_key);
      kex->dh->priv_key = NULL;
    }

    if (kex->dh->pub_key != NULL) {
      BN_clear_free(kex->dh->pub_key);
      kex->dh->pub_key = NULL;
    }
#endif /* prior to OpenSSL-1.1.0 */

    DH_free(kex->dh);
    kex->dh = NULL;
  }

  dh_nbits = get_dh_nbits(kex);

  /* We have 10 attempts to make a DH key which passes muster. */
  while (attempts <= 10) {
    const BIGNUM *dh_pub_key = NULL, *dh_priv_key = NULL;

    pr_signals_handle();

    attempts++;
    pr_trace_msg(trace_channel, 9, "attempt #%u to create a good DH key",
      attempts);

    dh = DH_new();
    if (dh == NULL) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error creating DH: %s", proxy_ssh_crypto_get_errors());
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_pqg(dh, (BIGNUM *) dh_p, NULL, (BIGNUM *) dh_g);
#else
    dh->p = dh_p;
    dh->g = dh_g;
#endif /* prior to OpenSSL-1.1.0 */

    dh_priv_key = BN_new();

    /* Generate a random private exponent of the desired size, in bits. */
    if (!BN_rand((BIGNUM *) dh_priv_key, dh_nbits, 0, 0)) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error generating DH random key (%d bits): %s", dh_nbits,
        proxy_ssh_crypto_get_errors());
      BN_clear_free((BIGNUM *) dh_priv_key);
      DH_free(dh);
      return -1;
    }

    dh_pub_key = BN_new();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_key(dh, (BIGNUM *) dh_pub_key, (BIGNUM *) dh_priv_key);
#else
    dh->pub_key = dh_pub_key;
    dh->priv_key = dh_priv_key;
#endif /* prior to OpenSSL-1.1.0 */

    pr_trace_msg(trace_channel, 12, "generating DH key");
    if (DH_generate_key(dh) != 1) {
      (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
        "error generating DH key: %s", proxy_ssh_crypto_get_errors());
      DH_free(dh);
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_get0_key(dh, &dh_pub_key, NULL);
#else
    dh_pub_key = dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */
    if (have_good_dh(dh, dh_pub_key) < 0) {
      DH_free(dh);
      continue;
    }

    kex->dh = dh;
    return 0;
  }

  errno = EPERM;
  return -1;
}

static int read_dh_gex_group(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf = NULL;
  uint32_t buflen = 0;
  const BIGNUM *dh_p, *dh_g;
  int dh_nbits;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  proxy_ssh_msg_read_mpint(pkt->pool, &buf, &buflen, &dh_p);
  proxy_ssh_msg_read_mpint(pkt->pool, &buf, &buflen, &dh_g);

  dh_nbits = BN_num_bits(dh_p);
  if (kex->dh_gex_min > (uint32_t) dh_nbits ||
      kex->dh_gex_max < (uint32_t) dh_nbits) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "server provided out-of-range DH size %d (requested %lu<%lu<%lu)",
      dh_nbits, (unsigned long) kex->dh_gex_min,
      (unsigned long) kex->dh_gex_pref, (unsigned long) kex->dh_gex_max);
    return -1;
  }

  if (create_gex_dh(kex, dh_p, dh_g) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error generating group-exchange DH: %s", strerror(errno));
    return -1;
  }

  return 0;
}

static int write_dh_gex_init(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;
  const BIGNUM *dh_pub_key;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 2048;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEX_DH_GEX_INIT);
  len += proxy_ssh_msg_write_mpint(&buf, &buflen, dh_pub_key);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int read_dh_gex_reply(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  const unsigned char *h;
  unsigned char *buf, *buf2, *server_hostkey_data = NULL, *sig = NULL;
  uint32_t buflen, server_hostkey_datalen = 0, siglen = 0, hlen = 0;
  const BIGNUM *server_pub_key = NULL, *k = NULL;
  size_t dh_len = 0;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* See RFC 4419, Section 3 "Diffie-Hellman Group and Key Exchange" */

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &server_hostkey_datalen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, server_hostkey_datalen,
    &server_hostkey_data);

  res = handle_server_hostkey(pkt->pool, kex->use_hostkey_type,
    server_hostkey_data, server_hostkey_datalen);
  if (res < 0) {
    int xerrno;

    xerrno = errno;
    DH_free(kex->dh);
    kex->dh = NULL;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error handling server host key: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  proxy_ssh_msg_read_mpint(pkt->pool, &buf, &buflen, &server_pub_key);

  if (have_good_dh(kex->dh, server_pub_key) < 0) {
    DH_free(kex->dh);
    kex->dh = NULL;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "invalid server public DH key");
    return -1;
  }

  /* Compute the shared secret. */
  dh_len = DH_size(kex->dh);
  buf2 = palloc(pkt->pool, dh_len);

  pr_trace_msg(trace_channel, 12, "computing DH key");
  res = DH_compute_key(buf2, server_pub_key, kex->dh);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error computing DH shared secret: %s", proxy_ssh_crypto_get_errors());

    DH_free(kex->dh);
    kex->dh = NULL;
    return -1;
  }

  k = BN_new();
  if (BN_bin2bn(buf2, res, (BIGNUM *) k) == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error converting DH shared secret to BN: %s",
      proxy_ssh_crypto_get_errors());

    DH_free(kex->dh);
    kex->dh = NULL;
    return -1;
  }

  kex->k = k;

  /* Calculate H */
  h = calculate_gex_h(pkt->pool, kex, server_hostkey_data,
    server_hostkey_datalen, server_pub_key, k, &hlen);
  if (h == NULL) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    DH_free(kex->dh);
    kex->dh = NULL;

    return -1;
  }

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &siglen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, siglen, &sig);

  /* Verify H */
  res = verify_h(pkt->pool, kex, server_hostkey_data, server_hostkey_datalen,
    sig, siglen, h, hlen);
  if (res < 0) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    DH_free(kex->dh);
    kex->dh = NULL;

    return -1;
  }

  kex->h = palloc(kex_pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID. */
  proxy_ssh_session_set_id(session.pool, h, hlen);

  return 0;
}

static int handle_kex_dh_gex(struct proxy_ssh_kex *kex, conn_t *conn) {
  int res;
  struct proxy_ssh_packet *pkt;

  pr_trace_msg(trace_channel, 9, "writing DH_GEX_REQUEST message to server");
  pkt = proxy_ssh_packet_create(kex_pool);
  res = write_dh_gex_request(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = proxy_ssh_packet_write(conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "reading DH_GEX_GROUP message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEX_DH_GEX_GROUP);

  res = read_dh_gex_group(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "writing DH_GEX_INIT message to server");
  pkt = proxy_ssh_packet_create(kex_pool);
  res = write_dh_gex_init(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = proxy_ssh_packet_write(conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "reading DH_GEX_REPLY message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEX_DH_GEX_REPLY);

  res = read_dh_gex_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}

#if defined(PR_USE_OPENSSL_ECC)
static int write_ecdh_init(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  /* In our ECDH_INIT, send 'e', our client curve public key. */

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 2048;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEX_ECDH_INIT);
  len += proxy_ssh_msg_write_ecpoint(&buf, &buflen,
    EC_KEY_get0_group(kex->ec), EC_KEY_get0_public_key(kex->ec));

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

/* This is used to validate the ECDSA parameters we might receive e.g. from
 * a server.  These checks come from Section 3.2.2.1 of 'Standards for
 * Efficient Cryptography Group, "Elliptic Curve Cryptography", SEC 1,
 * May 2009:
 *
 *  http://www.secg.org/download/aid-780/sec1-v2.pdf
 *
 * as per RFC 5656 recommendation.
 */
static int validate_ecdsa_params(const EC_GROUP *group, const EC_POINT *point) {
  BN_CTX *bn_ctx;
  BIGNUM *ec_order, *x_coord, *y_coord, *bn_tmp;
  int coord_nbits, ec_order_nbits;
  EC_POINT *subgroup_order = NULL;

  if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) != NID_X9_62_prime_field) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "ECDSA group is not a prime field, rejecting");
    errno = EACCES;
    return -1;
  }

  /* A Q of infinity is unacceptable. */
  if (EC_POINT_is_at_infinity(group, point) != 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "ECDSA EC point has infinite value, rejecting");
    errno = EACCES;
    return -1;
  }

  /* A BN_CTX is like our pools; we allocate one, use it to get any
   * number of BIGNUM variables, and only have free up the BN_CTX when
   * we're done, rather than all of the individual BIGNUMs.
   */

  bn_ctx = BN_CTX_new();
  if (bn_ctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating BN_CTX: %s", proxy_ssh_crypto_get_errors());
    return -1;
  }

  BN_CTX_start(bn_ctx);

  ec_order = BN_CTX_get(bn_ctx);
  if (ec_order == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting new BIGNUM from BN_CTX: %s",
      proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  if (EC_GROUP_get_order(group, ec_order, bn_ctx) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting EC group order: %s", proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  x_coord = BN_CTX_get(bn_ctx);
  if (x_coord == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting new BIGNUM from BN_CTX: %s",
      proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  y_coord = BN_CTX_get(bn_ctx);
  if (y_coord == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting new BIGNUM from BN_CTX: %s",
      proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  if (EC_POINT_get_affine_coordinates_GFp(group, point, x_coord, y_coord,
      bn_ctx) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting EC point affine coordinates: %s",
      proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  /* Ensure that the following are both true:
   *
   *  log2(X coord) > log2(EC order)/2
   *  log2(Y coord) > log2(EC order)/2
   */

  coord_nbits = BN_num_bits(x_coord);
  ec_order_nbits = BN_num_bits(ec_order);
  if (coord_nbits <= (ec_order_nbits / 2)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "EC public key X coordinate (%d bits) too small (<= %d bits), rejecting",
      coord_nbits, (ec_order_nbits / 2));
    BN_CTX_free(bn_ctx);
    errno = EACCES;
    return -1;
  }

  coord_nbits = BN_num_bits(y_coord);
  if (coord_nbits <= (ec_order_nbits / 2)) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "EC public key Y coordinate (%d bits) too small (<= %d bits), rejecting",
      coord_nbits, (ec_order_nbits / 2));
    BN_CTX_free(bn_ctx);
    errno = EACCES;
    return -1;
  }

  /* Ensure that the following is true:
   *
   *  subgroup order == infinity
   */

  subgroup_order = EC_POINT_new(group);
  if (subgroup_order == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new EC_POINT: %s", proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  if (EC_POINT_mul(group, subgroup_order, NULL, point, ec_order, bn_ctx) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error doing EC point multiplication: %s", proxy_ssh_crypto_get_errors());
    EC_POINT_free(subgroup_order);
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  if (EC_POINT_is_at_infinity(group, subgroup_order) != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "EC public key has finite subgroup order, rejecting");
    EC_POINT_free(subgroup_order);
    BN_CTX_free(bn_ctx);
    errno = EACCES;
    return -1;
  }

  EC_POINT_free(subgroup_order);

  /*  Ensure that the following are both true:
   *
   *  X < order - 1
   *  Y < order - 1
   */

  bn_tmp = BN_CTX_get(bn_ctx);
  if (bn_tmp == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error getting new BIGNUM from BN_CTX: %s",
      proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  if (BN_sub(bn_tmp, ec_order, BN_value_one()) == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error subtracting one from EC group order: %s",
      proxy_ssh_crypto_get_errors());
    BN_CTX_free(bn_ctx);
    errno = EPERM;
    return -1;
  }

  if (BN_cmp(x_coord, bn_tmp) >= 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "EC public key X coordinate too large (>= EC group order - 1), "
      "rejecting");
    BN_CTX_free(bn_ctx);
    errno = EACCES;
    return -1;
  }

  if (BN_cmp(y_coord, bn_tmp) >= 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "EC public key Y coordinate too large (>= EC group order - 1), "
      "rejecting");
    BN_CTX_free(bn_ctx);
    errno = EACCES;
    return -1;
  }

  BN_CTX_free(bn_ctx);
  return 0;
}

static int read_ecdh_reply(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  const unsigned char *h;
  unsigned char *buf, *buf2, *server_hostkey_data = NULL, *sig = NULL;
  uint32_t buflen, server_hostkey_datalen = 0, siglen = 0, hlen = 0;
  const BIGNUM *k = NULL;
  const EC_GROUP *curve = NULL;
  EC_POINT *server_point = NULL;
  size_t ecdh_len = 0;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* See RFC 5656, Section 4 "ECDH Key Exchange" */

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &server_hostkey_datalen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, server_hostkey_datalen,
    &server_hostkey_data);

  res = handle_server_hostkey(pkt->pool, kex->use_hostkey_type,
    server_hostkey_data, server_hostkey_datalen);
  if (res < 0) {
    int xerrno;

    xerrno = errno;
    EC_KEY_free(kex->ec);
    kex->ec = NULL;
  
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error handling server host key: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  curve = EC_KEY_get0_group(kex->ec);

  server_point = EC_POINT_new(curve);
  if (server_point == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating EC_POINT: %s", proxy_ssh_crypto_get_errors());
    EC_KEY_free(kex->ec);
    kex->ec = NULL;

    return -1;
  }

  proxy_ssh_msg_read_ecpoint(pkt->pool, &buf, &buflen, curve, &server_point);
  if (server_point == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error reading ECDH_REPLY: %s", strerror(errno));
    EC_KEY_free(kex->ec);
    kex->ec = NULL;

    return -1;
  }
  kex->server_point = server_point;

  if (validate_ecdsa_params(curve, kex->server_point) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "invalid server ECDH public key (EC point): %s", strerror(errno));
    EC_POINT_clear_free(kex->server_point);
    kex->server_point = NULL;

    return -1;
  }

  /* Compute the shared secret */
  ecdh_len = ((EC_GROUP_get_degree(EC_KEY_get0_group(kex->ec)) + 7) / 8);
  buf2 = palloc(kex_pool, ecdh_len);

  pr_trace_msg(trace_channel, 12, "computing ECDH key");
  res = ECDH_compute_key((unsigned char *) buf2, ecdh_len, kex->server_point,
    kex->ec, NULL);
  if (res <= 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error computing ECDH shared secret: %s", proxy_ssh_crypto_get_errors());
    pr_memscrub(buf2, ecdh_len);
    return -1;
  }

  if ((size_t) res != ecdh_len) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "computed ECDH shared secret length (%d) does not match needed length "
      "(%lu), rejecting", res, (unsigned long) ecdh_len);
    pr_memscrub(buf2, ecdh_len);
    return -1;
  }

  k = BN_new();
  if (k == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BIGNUM: %s", proxy_ssh_crypto_get_errors());
    pr_memscrub(buf2, ecdh_len);
    return -1;
  }

  if (BN_bin2bn(buf2, res, (BIGNUM *) k) == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error converting ECDH shared secret to BN: %s",
      proxy_ssh_crypto_get_errors());
    EC_KEY_free(kex->ec);
    kex->ec = NULL;
    pr_memscrub(buf2, ecdh_len);
    return -1;
  }

  kex->k = k;
  pr_memscrub(buf2, ecdh_len);

  /* Calculate H */
  h = calculate_ecdh_h(pkt->pool, kex, server_hostkey_data,
    server_hostkey_datalen, k, &hlen);
  if (h == NULL) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    EC_KEY_free(kex->ec);
    kex->ec = NULL;

    return -1;
  }

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &siglen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, siglen, &sig);

  /* Verify H */
  res = verify_h(pkt->pool, kex, server_hostkey_data, server_hostkey_datalen,
    sig, siglen, h, hlen);
  if (res < 0) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    EC_KEY_free(kex->ec);
    kex->ec = NULL;

    return -1;
  }

  kex->h = palloc(kex_pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID. */
  proxy_ssh_session_set_id(session.pool, h, hlen);

  return 0;
}

static int handle_kex_ecdh(struct proxy_ssh_kex *kex, conn_t *conn) {
  int res;
  struct proxy_ssh_packet *pkt;

  pr_trace_msg(trace_channel, 9, "writing ECDH_INIT message to server");
  pkt = proxy_ssh_packet_create(kex_pool);
  res = write_ecdh_init(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = proxy_ssh_packet_write(conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "reading ECDH_REPLY message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEX_ECDH_REPLY);

  res = read_ecdh_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}
#endif /* PR_USE_OPENSSL_ECC */

static int read_kexrsa_pubkey(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex, pool *hostkey_pool,
    unsigned char **hostkey_data, uint32_t *hostkey_datalen) {
  char *key_type = NULL;
  unsigned char *buf, *server_hostkey_data = NULL, *rsa_pubkey_data = NULL;
  uint32_t buflen, server_hostkey_datalen = 0, rsa_pubkey_datalen = 0;
  const BIGNUM *rsa_n = NULL, *rsa_e = NULL;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* See RFC 4432 "SSH RSA Key Exchange" */

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &server_hostkey_datalen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, server_hostkey_datalen,
    &server_hostkey_data);

  res = handle_server_hostkey(pkt->pool, kex->use_hostkey_type,
    server_hostkey_data, server_hostkey_datalen);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error handling server host key: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  *hostkey_datalen = server_hostkey_datalen;
  *hostkey_data = palloc(hostkey_pool, server_hostkey_datalen);
  memcpy(*hostkey_data, server_hostkey_data, server_hostkey_datalen);

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &rsa_pubkey_datalen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, rsa_pubkey_datalen,
    &rsa_pubkey_data);

  kex->rsa = RSA_new();
  if (kex->rsa == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new RSA: %s", proxy_ssh_crypto_get_errors());
    pr_memscrub(rsa_pubkey_data, rsa_pubkey_datalen);
    return -1;
  }

  buf = rsa_pubkey_data;
  buflen = rsa_pubkey_datalen;

  proxy_ssh_msg_read_string(pkt->pool, &buf, &buflen, &key_type);
  if (key_type == NULL ||
      strcmp(key_type, "ssh-rsa") != 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "unsupported key type received: %s",
      key_type != NULL ? key_type : "(nil)");
    return -1;
  } 

  proxy_ssh_msg_read_mpint(pkt->pool, &buf, &buflen, &rsa_e);
  proxy_ssh_msg_read_mpint(pkt->pool, &buf, &buflen, &rsa_n);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  RSA_set0_key(kex->rsa, (BIGNUM *) rsa_n, (BIGNUM *) rsa_e, NULL);
#else
  kex->rsa->e = rsa_e;
  kex->rsa->n = rsa_n;
#endif /* prior to OpenSSL-1.1.0 */

  return 0;
}

static int write_kexrsa_secret(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  BN_CTX *ctx;
  BIGNUM *k = NULL, *range = NULL, *two = NULL, *bits = NULL;
  int res, klen = 0, hlen = 0, nbits = 0, plaintext_len = 0, encrypted_len = 0;
  unsigned char *buf, *ptr, *plaintext = NULL, *encrypted = NULL;
  uint32_t bufsz, buflen, len = 0;

  klen = RSA_size(kex->rsa) * 8;
  hlen = EVP_MD_size(kex->hash) * 8;
  nbits = klen - (2 * hlen) - 49;

  two = BN_new();
  if (two == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BIGNUM: %s", proxy_ssh_crypto_get_errors());
    return -1;
  }

  res = BN_set_word(two, (BN_ULONG) 2);
  if (res != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating setting BIGNUM value: %s",
      proxy_ssh_crypto_get_errors());
    BN_free(two);
    return -1;
  }

  bits = BN_new();
  if (bits == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BIGNUM: %s", proxy_ssh_crypto_get_errors());
    BN_free(two);
    return -1;
  }

  res = BN_set_word(bits, (BN_ULONG) nbits);
  if (res != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating setting BIGNUM value: %s",
      proxy_ssh_crypto_get_errors());
    BN_free(two);
    BN_free(bits);
    return -1;
  }

  range = BN_new();
  if (range == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BIGNUM: %s", proxy_ssh_crypto_get_errors());
    BN_free(two);
    BN_free(bits);
    return -1;
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BN_CTX: %s", proxy_ssh_crypto_get_errors());
    BN_free(two);
    BN_free(bits);
    BN_free(range);
    return -1;
  }

  res = BN_exp(range, two, bits, ctx);
  if (res != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error expontentiating BIGNUM: %s", proxy_ssh_crypto_get_errors());
    BN_free(two);
    BN_free(bits);
    BN_free(range);
    BN_CTX_free(ctx);
    return -1;
  }

  k = BN_new();
  if (k == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BIGNUM: %s", proxy_ssh_crypto_get_errors());
    BN_free(two);
    BN_free(bits);
    BN_free(range);
    BN_CTX_free(ctx);
    return -1;
  }

  res = BN_rand_range(k, range);
  if (res != 1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error generating random BIGNUM: %s", proxy_ssh_crypto_get_errors());
    BN_free(k);
    BN_free(two);
    BN_free(bits);
    BN_free(range);
    BN_CTX_free(ctx);
    return -1;
  }

  BN_free(two);
  BN_free(bits);
  BN_free(range);
  BN_CTX_free(ctx);

  kex->k = k;

  plaintext_len = BN_bn2mpi(kex->k, NULL);
  plaintext = palloc(pkt->pool, plaintext_len);
  res = BN_bn2mpi(kex->k, plaintext);
  if (res != plaintext_len) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error converting RSA shared secret from BN: %s",
      proxy_ssh_crypto_get_errors());
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    return -1;
  }

  pr_trace_msg(trace_channel, 12, "encrypting RSA shared secret");

  encrypted_len = RSA_size(kex->rsa);
  encrypted = palloc(pkt->pool, encrypted_len);

  res = RSA_public_encrypt(plaintext_len, plaintext, encrypted, kex->rsa,
    RSA_PKCS1_OAEP_PADDING);
  if (res == -1) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error encrypting RSA shared secret: %s", proxy_ssh_crypto_get_errors());
    pr_memscrub(plaintext, plaintext_len);
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    return -1;
  }

  pr_memscrub(plaintext, plaintext_len);

  /* Store the encrypted RSA for calculating H later. */
  kex->rsa_encrypted_len = encrypted_len;
  kex->rsa_encrypted = palloc(kex_pool, encrypted_len);
  memcpy(kex->rsa_encrypted, encrypted, encrypted_len);

  bufsz = buflen = 2048;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEXRSA_SECRET);
  len += proxy_ssh_msg_write_data(&buf, &buflen, encrypted, encrypted_len,
    TRUE);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int read_kexrsa_done(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex, unsigned char *server_hostkey_data,
    uint32_t server_hostkey_datalen) {
  const unsigned char *h;
  unsigned char *buf, *sig = NULL;
  uint32_t buflen, siglen = 0, hlen = 0;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &siglen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, siglen, &sig);

  /* Calculate H */
  h = calculate_kexrsa_h(pkt->pool, kex, server_hostkey_data,
    server_hostkey_datalen, kex->k, &hlen);
  if (h == NULL) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;

    return -1;
  }

  /* Verify H */
  res = verify_h(pkt->pool, kex, server_hostkey_data, server_hostkey_datalen,
    sig, siglen, h, hlen);
  if (res < 0) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;

    return -1;
  }

  kex->h = palloc(kex_pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID. */
  proxy_ssh_session_set_id(session.pool, h, hlen);

  return 0;
}

static int handle_kex_rsa(struct proxy_ssh_kex *kex, conn_t *conn) {
  pool *tmp_pool;
  int res;
  struct proxy_ssh_packet *pkt;
  unsigned char *server_hostkey_data = NULL;
  uint32_t server_hostkey_datalen = 0;

  tmp_pool = make_sub_pool(session.pool);
  pr_pool_tag(tmp_pool, "KEXRSA pool");

  pr_trace_msg(trace_channel, 9, "reading KEXRSA_PUBKEY message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEXRSA_PUBKEY);

  res = read_kexrsa_pubkey(pkt, kex, tmp_pool, &server_hostkey_data,
    &server_hostkey_datalen);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "writing KEXRSA_SECRET message to server");
  pkt = proxy_ssh_packet_create(kex_pool);
  res = write_kexrsa_secret(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_trace_msg(trace_channel, 9, "sending KEXRSA_SECRET message to server");
  res = proxy_ssh_packet_write(conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "reading KEXRSA_DONE message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEXRSA_DONE);

  res = read_kexrsa_done(pkt, kex, server_hostkey_data, server_hostkey_datalen);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  destroy_pool(tmp_pool);

  return 0;
}

#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
static int write_curve25519_init(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  /* In our Curve25519 ECDH_INIT, send 'e', our client curve25519 public key. */

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 2048;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEX_ECDH_INIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_curve25519_pub_key,
    CURVE25519_SIZE, TRUE);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int read_curve25519_reply(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  const unsigned char *h;
  unsigned char zero_curve25519[CURVE25519_SIZE];
  unsigned char *buf, *buf2, *server_hostkey_data = NULL, *sig = NULL;
  uint32_t buflen, pub_keylen, server_hostkey_datalen = 0, siglen = 0, hlen = 0;
  const BIGNUM *k = NULL;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* See RFC 5656, Section 4 "ECDH Key Exchange", modified by RFC 8731. */

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &server_hostkey_datalen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, server_hostkey_datalen,
    &server_hostkey_data);

  res = handle_server_hostkey(pkt->pool, kex->use_hostkey_type,
    server_hostkey_data, server_hostkey_datalen);
  if (res < 0) {
    int xerrno;

    xerrno = errno;
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
  
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error handling server host key: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &pub_keylen);
  if (pub_keylen != CURVE25519_SIZE) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "rejecting invalid length (%lu %s, wanted %d) of server Curve25519 key",
      (unsigned long) pub_keylen, pub_keylen != 1 ? "bytes" : "byte",
      CURVE25519_SIZE);
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
    return -1;
  }

  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, pub_keylen,
    &(kex->server_curve25519_pub_key));
  if (kex->server_curve25519_pub_key == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error reading ECDH_REPLY: %s", strerror(errno));
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
    return -1;
  }

  /* Watch for all-zero public keys, and reject them. */
  sodium_memzero(zero_curve25519, CURVE25519_SIZE);
  if (sodium_memcmp(kex->server_curve25519_pub_key, zero_curve25519,
      CURVE25519_SIZE) == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "rejecting invalid (all-zero) server Curve25519 key");
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
    return -1;
  }

  /* Compute the shared secret */
  buf2 = palloc(kex_pool, CURVE25519_SIZE);

  pr_trace_msg(trace_channel, 12, "computing Curve25519 key");
  res = get_curve25519_shared_key((unsigned char *) buf2,
    kex->server_curve25519_pub_key, kex->client_curve25519_priv_key);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error computing Curve25519 shared secret: %s", strerror(errno));
    pr_memscrub(buf2, CURVE25519_SIZE);
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
    return -1;
  }

  k = BN_new();
  if (k == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BIGNUM: %s", proxy_ssh_crypto_get_errors());
    pr_memscrub(buf2, CURVE25519_SIZE);
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
    return -1;
  }

  if (BN_bin2bn(buf2, res, (BIGNUM *) k) == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error converting Curve25519 shared secret to BN: %s",
      proxy_ssh_crypto_get_errors());
    pr_memscrub(buf2, CURVE25519_SIZE);
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);
    return -1;
  }

  kex->k = k;
  pr_memscrub(buf2, CURVE25519_SIZE);

  /* Calculate H */
  h = calculate_curve25519_h(pkt->pool, kex, server_hostkey_data,
    server_hostkey_datalen, k, &hlen);
  if (h == NULL) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);

    return -1;
  }

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &siglen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, siglen, &sig);

  /* Verify H */
  res = verify_h(pkt->pool, kex, server_hostkey_data, server_hostkey_datalen,
    sig, siglen, h, hlen);
  if (res < 0) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);

    return -1;
  }

  kex->h = palloc(kex_pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID. */
  proxy_ssh_session_set_id(session.pool, h, hlen);

  /* We no longer need the private key. */
  pr_memscrub(kex->client_curve25519_priv_key, CURVE25519_SIZE);

  return 0;
}

static int handle_kex_curve25519(struct proxy_ssh_kex *kex, conn_t *conn) {
  int res;
  struct proxy_ssh_packet *pkt;

  pr_trace_msg(trace_channel, 9, "writing ECDH_INIT message to server");
  pkt = proxy_ssh_packet_create(kex_pool);
  res = write_curve25519_init(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = proxy_ssh_packet_write(conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "reading ECDH_REPLY message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEX_ECDH_REPLY);

  res = read_curve25519_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */

#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
static int write_curve448_init(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, len = 0;

  /* In our Curve448 ECDH_INIT, send 'e', our client curve448 public key. */

  /* XXX Is this buffer large enough? Too large? */
  bufsz = buflen = 2048;
  ptr = buf = palloc(pkt->pool, bufsz);

  len += proxy_ssh_msg_write_byte(&buf, &buflen, PROXY_SSH_MSG_KEX_ECDH_INIT);
  len += proxy_ssh_msg_write_data(&buf, &buflen, kex->client_curve448_pub_key,
    CURVE448_SIZE, TRUE);

  pkt->payload = ptr;
  pkt->payload_len = len;

  return 0;
}

static int read_curve448_reply(struct proxy_ssh_packet *pkt,
    struct proxy_ssh_kex *kex) {
  const unsigned char *h;
  unsigned char zero_curve448[CURVE448_SIZE];
  unsigned char *buf, *buf2, *server_hostkey_data = NULL, *sig = NULL;
  uint32_t buflen, pub_keylen, server_hostkey_datalen = 0, siglen = 0, hlen = 0;
  const BIGNUM *k = NULL;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* See RFC 5656, Section 4 "ECDH Key Exchange", modified by RFC 8731. */

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &server_hostkey_datalen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, server_hostkey_datalen,
    &server_hostkey_data);

  res = handle_server_hostkey(pkt->pool, kex->use_hostkey_type,
    server_hostkey_data, server_hostkey_datalen);
  if (res < 0) {
    int xerrno;

    xerrno = errno;
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);

    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error handling server host key: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &pub_keylen);
  if (pub_keylen != CURVE448_SIZE) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "rejecting invalid length (%lu %s, wanted %d) of server Curve448 key",
      (unsigned long) pub_keylen, pub_keylen != 1 ? "bytes" : "byte",
      CURVE448_SIZE);
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);
    return -1;
  }

  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, pub_keylen,
    &(kex->server_curve448_pub_key));
  if (kex->server_curve448_pub_key == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error reading ECDH_REPLY: %s", strerror(errno));
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);
    return -1;
  }

  /* Watch for all-zero public keys, and reject them. */
  memset(zero_curve448, '\0', sizeof(zero_curve448));
  if (memcmp(kex->server_curve448_pub_key, zero_curve448, CURVE448_SIZE) == 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "rejecting invalid (all-zero) server Curve448 key");
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);
    return -1;
  }

  /* Compute the shared secret */
  buf2 = palloc(kex_pool, CURVE448_SIZE);

  pr_trace_msg(trace_channel, 12, "computing Curve448 key");
  res = get_curve448_shared_key((unsigned char *) buf2,
    kex->server_curve448_pub_key, kex->client_curve448_priv_key);
  if (res < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error computing Curve448 shared secret: %s", strerror(errno));
    pr_memscrub(buf2, CURVE448_SIZE);
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);
    return -1;
  }

  k = BN_new();
  if (k == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error allocating new BIGNUM: %s", proxy_ssh_crypto_get_errors());
    pr_memscrub(buf2, CURVE448_SIZE);
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);
    return -1;
  }

  if (BN_bin2bn(buf2, res, (BIGNUM *) k) == NULL) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error converting Curve448 shared secret to BN: %s",
      proxy_ssh_crypto_get_errors());
    pr_memscrub(buf2, CURVE448_SIZE);
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);
    return -1;
  }

  kex->k = k;
  pr_memscrub(buf2, CURVE448_SIZE);

  /* Calculate H */
  h = calculate_curve448_h(pkt->pool, kex, server_hostkey_data,
    server_hostkey_datalen, k, &hlen);
  if (h == NULL) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);

    return -1;
  }

  proxy_ssh_msg_read_int(pkt->pool, &buf, &buflen, &siglen);
  proxy_ssh_msg_read_data(pkt->pool, &buf, &buflen, siglen, &sig);

  /* Verify H */
  res = verify_h(pkt->pool, kex, server_hostkey_data, server_hostkey_datalen,
    sig, siglen, h, hlen);
  if (res < 0) {
    BN_clear_free((BIGNUM *) kex->k);
    kex->k = NULL;
    pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);

    return -1;
  }

  kex->h = palloc(kex_pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID. */
  proxy_ssh_session_set_id(session.pool, h, hlen);

  /* We no longer need the private key. */
  pr_memscrub(kex->client_curve448_priv_key, CURVE448_SIZE);

  return 0;
}

static int handle_kex_curve448(struct proxy_ssh_kex *kex, conn_t *conn) {
  int res;
  struct proxy_ssh_packet *pkt;

  pr_trace_msg(trace_channel, 9, "writing ECDH_INIT message to server");
  pkt = proxy_ssh_packet_create(kex_pool);
  res = write_curve448_init(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = proxy_ssh_packet_write(conn, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "reading ECDH_REPLY message from server");
  pkt = read_kex_packet(kex_pool, kex, conn,
    PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL, 1,
    PROXY_SSH_MSG_KEX_ECDH_REPLY);

  res = read_curve448_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    PROXY_SSH_DISCONNECT_CONN(conn,
      PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */

static int run_kex(struct proxy_ssh_kex *kex, conn_t *conn) {
  const char *algo;

  algo = kex->session_names->kex_algo;

  if (strcmp(algo, "diffie-hellman-group1-sha1") == 0 ||
      strcmp(algo, "diffie-hellman-group14-sha1") == 0 ||
      strcmp(algo, "diffie-hellman-group14-sha256") == 0 ||
      strcmp(algo, "diffie-hellman-group16-sha512") == 0 ||
      strcmp(algo, "diffie-hellman-group18-sha512") == 0) {
    return handle_kex_dh(kex, conn);

  } else if (strcmp(algo, "diffie-hellman-group-exchange-sha1") == 0) {
    return handle_kex_dh_gex(kex, conn);

  } else if (strcmp(algo, "rsa1024-sha1") == 0) {
    return handle_kex_rsa(kex, conn);

#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  } else if (strcmp(algo, "diffie-hellman-group-exchange-sha256") == 0) {
    return handle_kex_dh_gex(kex, conn);

  } else if (strcmp(algo, "rsa2048-sha256") == 0) {
    return handle_kex_rsa(kex, conn);
#endif

#if defined(PR_USE_OPENSSL_ECC)
  } else if (strcmp(algo, "ecdh-sha2-nistp256") == 0 ||
             strcmp(algo, "ecdh-sha2-nistp384") == 0 ||
             strcmp(algo, "ecdh-sha2-nistp521") == 0) {
    return handle_kex_ecdh(kex, conn);
#endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
  } else if (strcmp(algo, "curve25519-sha256") == 0 ||
             strcmp(algo, "curve25519-sha256@libssh.org") == 0) {
    return handle_kex_curve25519(kex, conn);
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */

#if defined(HAVE_X448_OPENSSL) && defined(HAVE_SHA512_OPENSSL)
  } else if (strcmp(algo, "curve448-sha512") == 0) {
    return handle_kex_curve448(kex, conn);
#endif /* HAVE_X448_OPENSSL and HAVE_SHA512_OPENSSL */
  }

  (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
    "unsupported key exchange algorithm '%s'", algo);
  errno = EINVAL;
  return -1;
}

int proxy_ssh_kex_handle(struct proxy_ssh_packet *pkt,
    const struct proxy_session *proxy_sess) {
  int correct_guess = TRUE, res, sent_newkeys = FALSE;
  char msg_type;
  struct proxy_ssh_kex *kex;

  /* We may already have a kex structure, either from the client
   * initial connect (kex_first_kex not null), or because we
   * are in a server-initiated rekeying (kex_rekey_kex not null).
   */
  if (kex_first_kex != NULL) {
    kex = kex_first_kex;

    /* We need to assign the client/server versions, which this struct
     * will not have.
     */
    kex->client_version = kex_client_version;
    kex->server_version = kex_server_version;

  } else if (kex_rekey_kex != NULL) {
    kex = kex_rekey_kex;

  } else {
    kex = create_kex(kex_pool);
  }

  /* The packet we are given is guaranteed to be a KEXINIT packet. */

  pr_trace_msg(trace_channel, 9, "reading KEXINIT message from server");

  res = read_kexinit(pkt, kex);
  if (res < 0) {
    destroy_kex(kex);
    destroy_pool(pkt->pool);
    return -1;
  }

  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9,
    "determining shared algorithms for SSH session");

  if (get_session_names(kex, &correct_guess) < 0) {
    destroy_kex(kex);
    return -1;
  }

  /* Once we have received the server KEXINIT message, we can compare what we
   * want to send against what we already received from the server.
   *
   * If the server said that it was going to send a "guess" KEX packet,
   * and we determine that its key exchange guess matches what we would have
   * sent in our KEXINIT, then we proceed on with reading and handling that
   * guess packet.  If not, we ignore that packet, and proceed.
   */

  if (kex->first_kex_follows == FALSE) {
    /* No guess packet sent; send our KEXINIT as normal (as long as we are
     * not in a server-initiated rekeying).
     */

    if (kex_sent_kexinit == FALSE) {
      pkt = proxy_ssh_packet_create(kex_pool);
      res = write_kexinit(pkt, kex);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return -1;
      }

      pr_trace_msg(trace_channel, 9, "sending KEXINIT message to server");

      res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return res;
      }

      kex_sent_kexinit = TRUE;
      destroy_pool(pkt->pool);
    }

  } else {
    /* If the server sent a guess kex packet, but that guess was incorrect,
     * then we need to consume and silently ignore that packet, and proceed
     * as normal.
     */
    if (correct_guess == FALSE) {
      pr_trace_msg(trace_channel, 3, "server sent incorrect key exchange "
        "guess, ignoring guess packet");

      pkt = read_kex_packet(kex_pool, kex, proxy_sess->backend_ctrl_conn,
        PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED, &msg_type, 3,
        PROXY_SSH_MSG_KEX_DH_INIT,
        PROXY_SSH_MSG_KEX_DH_GEX_INIT,
        PROXY_SSH_MSG_KEX_ECDH_INIT);

      pr_trace_msg(trace_channel, 3,
        "ignored %s (%d) guess message sent by server",
        proxy_ssh_packet_get_msg_type_desc(msg_type), msg_type);

      destroy_pool(pkt->pool);

      if (kex_sent_kexinit == FALSE) {
        pkt = proxy_ssh_packet_create(kex_pool);
        res = write_kexinit(pkt, kex);
        if (res < 0) {
          destroy_kex(kex);
          destroy_pool(pkt->pool);
          return -1;
        }

        pr_trace_msg(trace_channel, 9, "sending KEXINIT message to server");

        res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
        if (res < 0) {
          destroy_kex(kex);
          destroy_pool(pkt->pool);
          return res;
        }

        kex_sent_kexinit = TRUE;
        destroy_pool(pkt->pool);
      }
    }

    if (kex_sent_kexinit == FALSE) {
      pkt = proxy_ssh_packet_create(kex_pool);
      res = write_kexinit(pkt, kex);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return -1;
      }

      pr_trace_msg(trace_channel, 9, "sending KEXINIT message to server");

      res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return res;
      }

      kex_sent_kexinit = TRUE;
      destroy_pool(pkt->pool);
    }
  }

  if (run_kex(kex, proxy_sess->backend_ctrl_conn) < 0) {
    destroy_kex(kex);
    return -1;
  }

  if (!proxy_ssh_interop_supports_feature(PROXY_SSH_FEAT_PESSIMISTIC_NEWKEYS)) {
    pr_trace_msg(trace_channel, 9, "sending NEWKEYS message to server");

    /* Send our NEWKEYS reply. */
    pkt = proxy_ssh_packet_create(kex_pool);
    res = write_newkeys_reply(pkt);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt->pool);
      return -1;
    }

    res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt->pool);
      return -1;
    }

    destroy_pool(pkt->pool);
    sent_newkeys = TRUE;
  }

  pkt = read_kex_packet(kex_pool, kex, proxy_sess->backend_ctrl_conn,
    PROXY_SSH_DISCONNECT_PROTOCOL_ERROR, NULL, 1, PROXY_SSH_MSG_NEWKEYS);

  /* If we didn't send our NEWKEYS message earlier, do it now. */
  if (sent_newkeys == FALSE) {
    struct proxy_ssh_packet *pkt2;

    pr_trace_msg(trace_channel, 9, "sending NEWKEYS message to server");

    /* Send our NEWKEYS reply. */
    pkt2 = proxy_ssh_packet_create(kex_pool);
    res = write_newkeys_reply(pkt2);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt2->pool);
      return -1;
    }

    res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt2);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt2->pool);
      return -1;
    }

    destroy_pool(pkt2->pool);
    sent_newkeys = TRUE;
  }

  /* Last but certainly not least, set up the keys for encryption and
   * authentication, based on H and K.
   */
  pr_trace_msg(trace_channel, 9, "setting session keys");
  if (set_session_keys(kex) < 0) {
    (void) pr_log_writefile(proxy_logfd, MOD_PROXY_VERSION,
      "error setting session keys, disconnecting");
    destroy_kex(kex);
    PROXY_SSH_DISCONNECT_CONN(proxy_sess->backend_ctrl_conn,
      PROXY_SSH_DISCONNECT_BY_APPLICATION, NULL);
  }

  destroy_pool(pkt->pool);
  destroy_kex(kex);
  return 0;
}

int proxy_ssh_kex_sess_free(void) {
  kex_ds = NULL;
  kex_verify_hostkeys = FALSE;

  return 0;
}

int proxy_ssh_kex_sess_init(pool *p, struct proxy_ssh_datastore *ds,
    int verify_hostkeys) {
  (void) p;

  kex_ds = ds;
  kex_verify_hostkeys = verify_hostkeys;
 
  return 0;
}

int proxy_ssh_kex_free(void) {
  struct proxy_ssh_kex *first_kex, *rekey_kex;

  /* destroy_kex() will set the kex_first_kex AND kex_rekey_kex pointers to
   * null, so we need to keep our own copies of those pointers here.
   */
  first_kex = kex_first_kex;
  rekey_kex = kex_rekey_kex;

  if (first_kex != NULL) {
    destroy_kex(first_kex);
  }

  if (rekey_kex != NULL) {
    destroy_kex(rekey_kex);
  }

  if (kex_pool != NULL) {
    destroy_pool(kex_pool);
    kex_pool = NULL;
  }

  return 0;
}

int proxy_ssh_kex_init(pool *p, const char *client_version,
    const char *server_version) {
  /* If we are called with client_version and server_version both NULL,
   * then we're setting up for a rekey.  We can destroy/create the Kex
   * pool in that case.  But not otherwise.
   */
  if (client_version == NULL &&
      server_version == NULL) {
    if (kex_pool != NULL) {
      destroy_pool(kex_pool);
      kex_pool = NULL;
    }
  }

  if (kex_pool == NULL) {
    kex_pool = make_sub_pool(p);
    pr_pool_tag(kex_pool, "Proxy SSH Kex Pool");
  }

  /* Save the client and server versions, the first time through.  They
   * will be used for any future rekey KEXINIT exchanges.
   */

  if (client_version != NULL &&
      kex_client_version == NULL) {
    kex_client_version = pstrdup(proxy_pool, client_version);
  }

  if (server_version != NULL &&
      kex_server_version == NULL) {
    kex_server_version = pstrdup(proxy_pool, server_version);
  }

  if (client_version == NULL &&
      server_version == NULL) {
    pr_trace_msg(trace_channel, 19, "preparing for rekey");
    kex_rekey_kex = create_kex(kex_pool);
    kex_sent_kexinit = FALSE;
  }

  return 0;
}

int proxy_ssh_kex_send_first_kexinit(pool *p,
    const struct proxy_session *proxy_sess) {
  struct proxy_ssh_packet *pkt;
  int res;

  if (kex_pool == NULL) {
    kex_pool = make_sub_pool(p);
    pr_pool_tag(kex_pool, "Proxy SSH Kex Pool");
  }

  /* We have just connected to the server.  We want to send our version
   * ID string _and_ the KEXINIT in the same TCP packet, and save a 
   * TCP round trip (one TCP ACK for both messages, rather than one ACK
   * per message).  The packet API will automatically send the version
   * ID string along with the first packet we send; we just have to
   * send a packet, and the KEXINIT is the first one in the protocol.
   */
  kex_first_kex = create_kex(kex_pool);

  pkt = proxy_ssh_packet_create(kex_pool); 
  res = write_kexinit(pkt, kex_first_kex);
  if (res < 0) {
    destroy_kex(kex_first_kex);
    destroy_pool(pkt->pool);
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "sending KEXINIT message to server");

  res = proxy_ssh_packet_write(proxy_sess->backend_ctrl_conn, pkt);
  if (res < 0) {
    destroy_kex(kex_first_kex);
    destroy_pool(pkt->pool);
    return -1;
  }
  kex_sent_kexinit = TRUE;

  destroy_pool(pkt->pool);
  return 0;
}
#endif /* PR_USE_OPENSSL */
