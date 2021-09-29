/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#if HAVE_OPENSSL
#  include <openssl/bio.h>
#  include <openssl/evp.h>
#  include <openssl/pkcs7.h>
#  include <openssl/ssl.h>
#  include <openssl/x509v3.h>

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509*, X509_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509_NAME*, X509_NAME_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY_CTX*, EVP_PKEY_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_CIPHER_CTX*, EVP_CIPHER_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(PKCS7*, PKCS7_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SSL*, SSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIO*, BIO_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MD_CTX*, EVP_MD_CTX_free, NULL);

static inline void sk_X509_free_allp(STACK_OF(X509) **sk) {
        if (!sk || !*sk)
                return;

        sk_X509_pop_free(*sk, X509_free);
}

int rsa_encrypt_bytes(EVP_PKEY *pkey, const void *decrypted_key, size_t decrypted_key_size, void **ret_encrypt_key, size_t *ret_encrypt_key_size);

int rsa_pkey_to_suitable_key_size(EVP_PKEY *pkey, size_t *ret_suitable_key_size);

#endif
