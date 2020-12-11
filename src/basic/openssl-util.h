/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <errno.h>

#if HAVE_OPENSSL

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

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

int string_hashsum(
        const char *s,
        size_t len,
        const EVP_MD *md_algorithm,
        char **out);

DEFINE_TRIVIAL_CLEANUP_FUNC(X509*, X509_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EVP_MD_CTX*, EVP_MD_CTX_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(X509_NAME*, X509_NAME_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EVP_PKEY_CTX*, EVP_PKEY_CTX_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EVP_PKEY*, EVP_PKEY_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EVP_CIPHER_CTX*, EVP_CIPHER_CTX_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(RSA*, RSA_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EC_KEY*, EC_KEY_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EC_POINT*, EC_POINT_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(EC_GROUP*, EC_GROUP_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(BIGNUM*, BN_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(BN_CTX*, BN_CTX_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(ECDSA_SIG*, ECDSA_SIG_free);
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

static inline int string_hashsum_sha224(const char *s, size_t len, char **out) {
#if HAVE_OPENSSL
        return string_hashsum(s, len, EVP_sha224(), out);
#else
        return -EOPNOTSUPP;
#endif
}

static inline int string_hashsum_sha256(const char *s, size_t len, char **out) {
#if HAVE_OPENSSL
        return string_hashsum(s, len, EVP_sha256(), out);
#else
        return -EOPNOTSUPP;
#endif
}
