/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <errno.h>

#if HAVE_OPENSSL

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#include "macro.h"

#define DIGEST_MAX EVP_MAX_MD_SIZE

int hmac(
        const EVP_MD *alg,
        const uint8_t *key,
        int key_len,
        const uint8_t *msg,
        int msg_len,
        uint8_t *md,
        unsigned int *md_len);

int openssl_hash(
        const EVP_MD *alg,
        const void *msg,
        size_t msg_len,
        uint8_t *md,
        unsigned int *md_len);

DEFINE_TRIVIAL_CLEANUP_FUNC(X509*, X509_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EVP_MD_CTX*, EVP_MD_CTX_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(X509_NAME*, X509_NAME_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EVP_PKEY_CTX*, EVP_PKEY_CTX_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EVP_CIPHER_CTX*, EVP_CIPHER_CTX_free);
#else

#define DIGEST_MAX 64 /* SHA512 */

#endif

static inline int hmac_sha256(
                const uint8_t *key,
                int key_len,
                const uint8_t *msg,
                int msg_len,
                uint8_t *md,
                unsigned int *md_len) {
#if HAVE_OPENSSL
        return hmac(EVP_sha256(), key, key_len, msg, msg_len, md, md_len);
#else
        return -EOPNOTSUPP;
#endif
}

static inline int sha256(
                const void *msg,
                uint8_t msg_len,
                uint8_t *md,
                unsigned int *md_len) {
#if HAVE_OPENSSL
        return openssl_hash(EVP_sha256(), msg, msg_len, md, md_len);
#else
        return -EOPNOTSUPP;
#endif
}
