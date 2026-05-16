/*
 * ProFTPD - mod_proxy TLS PKCS11 implementation
 * Copyright (c) 2026 TJ Saunders
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_proxy.h"

#include "proxy/db.h"
#include "proxy/tls.h"
#include "proxy/tls/pkcs11.h"

#if defined(HAVE_OSSL_PROVIDER_LOAD_OPENSSL)
# include <openssl/provider.h>
# include <openssl/store.h>
#endif /* HAVE_OSSL_PROVIDER_LOAD_OPENSSL */

static const char *trace_channel = "proxy.tls.pkcs11";

static int have_pkcs11_support = -1;

int proxy_tls_pkcs11_supported(void) {
  int supports_pkcs11 = FALSE;
#if defined(HAVE_OSSL_PROVIDER_LOAD_OPENSSL)
  OSSL_PROVIDER *pkcs11;
#endif /* HAVE_OSSL_PROVIDER_LOAD_OPENSSL */

  if (have_pkcs11_support != -1) {
    return have_pkcs11_support;
  }

#if defined(HAVE_OSSL_PROVIDER_LOAD_OPENSSL)
  pkcs11 = OSSL_PROVIDER_load(NULL, "pkcs11");
  if (pkcs11 != NULL) {
    supports_pkcs11 = TRUE;

  } else {
    pr_trace_msg(trace_channel, 19, "unable to load PKCS11 provider: %s",
      proxy_tls_get_errors());
  }
#endif /* HAVE_OSSL_PROVIDER_LOAD_OPENSSL */

  have_pkcs11_support = supports_pkcs11;
  pr_trace_msg(trace_channel, 12, "PKCS11 provider present: %s",
    supports_pkcs11 ? "true" : "false");

  return supports_pkcs11;
}

int proxy_tls_pkcs11_uri(const char *text) {
  if (proxy_tls_pkcs11_supported() == FALSE) {
    return FALSE;
  }

  /* The scheme portion of URIs is considered case-insensitive. */
  if (strncasecmp(text, "pkcs11:", 7) == 0) {
    return TRUE;
  }

  return FALSE;
}

EVP_PKEY *proxy_tls_pkcs11_get_private_key(const char *text) {
#if defined(HAVE_OSSL_PROVIDER_LOAD_OPENSSL)
  OSSL_STORE_CTX *store_ctx;
  EVP_PKEY *pkey = NULL;

  store_ctx = OSSL_STORE_open(text, NULL, NULL, NULL, NULL);
  if (store_ctx == NULL) {
    pr_trace_msg(trace_channel, 9, "unable to use PKCS11 '%s': %s", text,
      proxy_tls_get_errors());
    return NULL;
  }

  /* Properly handle multiple potential things to load from this store;
   * we are only interested in private keys.
   */

  while (OSSL_STORE_eof(store_ctx) == 0) {
    OSSL_STORE_INFO *store_info;
    int item_type;
    const char *item_desc;

    pr_signals_handle();

    store_info = OSSL_STORE_load(store_ctx);
    if (store_info == NULL) {
      pr_trace_msg(trace_channel, 9, "unable to load info for PKCS11 '%s': %s",
        text, proxy_tls_get_errors());
      OSSL_STORE_close(store_ctx);
      return NULL;
    }

    item_type = OSSL_STORE_INFO_get_type(store_info);

    item_desc = OSSL_STORE_INFO_get0_NAME_description(store_info);
    if (item_desc == NULL) {
      item_desc = OSSL_STORE_INFO_get0_NAME(store_info);
    }

    if (item_desc == NULL) {
      item_desc = OSSL_STORE_INFO_type_string(item_type);
    }

    pr_trace_msg(trace_channel, 19,
      "checking '%s' item in PKCS11 '%s'", item_desc, text);

    /* Is it possible that this token contains multiple different private
     * keys?
     */
    if (item_type == OSSL_STORE_INFO_PKEY) {
      pkey = OSSL_STORE_INFO_get1_PKEY(store_info);
      if (pkey == NULL) {
        pr_trace_msg(trace_channel, 7,
          "unable to obtain private key from PKCS11 '%s': %s", text,
          proxy_tls_get_errors());
        OSSL_STORE_INFO_free(store_info);
        OSSL_STORE_close(store_ctx);
        return NULL;
      }

    } else {
      pr_trace_msg(trace_channel, 9,
        "ignoring '%s' from PKCS11 URI '%s'",
        OSSL_STORE_INFO_type_string(item_type), text);
    }

    OSSL_STORE_INFO_free(store_info);

    if (pkey != NULL) {
      break;
    }
  }

  OSSL_STORE_close(store_ctx);
  return pkey;
#endif /* HAVE_OSSL_PROVIDER_LOAD_OPENSSL */

  errno = ENOSYS;
  return NULL;
}
