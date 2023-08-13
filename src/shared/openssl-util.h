/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "iovec-util.h"
#include "macro.h"
#include "sha256.h"

#define X509_FINGERPRINT_SIZE SHA256_DIGEST_SIZE

#if HAVE_OPENSSL
#  include <openssl/bio.h>
#  include <openssl/bn.h>
#  include <openssl/crypto.h>
#  include <openssl/err.h>
#  include <openssl/evp.h>
#  include <openssl/opensslv.h>
#  include <openssl/pkcs7.h>
#  include <openssl/ssl.h>
#  include <openssl/x509v3.h>
#  ifndef OPENSSL_VERSION_MAJOR
/* OPENSSL_VERSION_MAJOR macro was added in OpenSSL 3. Thus, if it doesn't exist,  we must be before OpenSSL 3. */
#    define OPENSSL_VERSION_MAJOR 1
#  endif
#  if OPENSSL_VERSION_MAJOR >= 3
#    include <openssl/core_names.h>
#    include <openssl/kdf.h>
#    include <openssl/param_build.h>
#  endif

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO(void*, OPENSSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509_NAME*, X509_NAME_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY_CTX*, EVP_PKEY_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_CIPHER_CTX*, EVP_CIPHER_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_POINT*, EC_POINT_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_GROUP*, EC_GROUP_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIGNUM*, BN_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BN_CTX*, BN_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ECDSA_SIG*, ECDSA_SIG_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(PKCS7*, PKCS7_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SSL*, SSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIO*, BIO_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MD_CTX*, EVP_MD_CTX_free, NULL);
#if OPENSSL_VERSION_MAJOR >= 3
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_CIPHER*, EVP_CIPHER_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_KDF*, EVP_KDF_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_KDF_CTX*, EVP_KDF_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MAC*, EVP_MAC_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MAC_CTX*, EVP_MAC_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MD*, EVP_MD_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_PARAM*, OSSL_PARAM_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_PARAM_BLD*, OSSL_PARAM_BLD_free, NULL);
#else
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_KEY*, EC_KEY_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(HMAC_CTX*, HMAC_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(RSA*, RSA_free, NULL);
#endif

static inline void sk_X509_free_allp(STACK_OF(X509) **sk) {
        if (!sk || !*sk)
                return;

        sk_X509_pop_free(*sk, X509_free);
}

int openssl_pkey_from_pem(const void *pem, size_t pem_size, EVP_PKEY **ret);

int openssl_digest_size(const char *digest_alg, size_t *ret_digest_size);

int openssl_digest_many(const char *digest_alg, const struct iovec data[], size_t n_data, void **ret_digest, size_t *ret_digest_size);

static inline int openssl_digest(const char *digest_alg, const void *buf, size_t len, void **ret_digest, size_t *ret_digest_size) {
        return openssl_digest_many(digest_alg, &IOVEC_MAKE((void*) buf, len), 1, ret_digest, ret_digest_size);
}

int openssl_hmac_many(const char *digest_alg, const void *key, size_t key_size, const struct iovec data[], size_t n_data, void **ret_digest, size_t *ret_digest_size);

static inline int openssl_hmac(const char *digest_alg, const void *key, size_t key_size, const void *buf, size_t len, void **ret_digest, size_t *ret_digest_size) {
        return openssl_hmac_many(digest_alg, key, key_size, &IOVEC_MAKE((void*) buf, len), 1, ret_digest, ret_digest_size);
}

int openssl_cipher_many(const char *alg, size_t bits, const char *mode, const void *key, size_t key_size, const void *iv, size_t iv_size, const struct iovec data[], size_t n_data, void **ret, size_t *ret_size);

static inline int openssl_cipher(const char *alg, size_t bits, const char *mode, const void *key, size_t key_size, const void *iv, size_t iv_size, const void *buf, size_t len, void **ret, size_t *ret_size) {
        return openssl_cipher_many(alg, bits, mode, key, key_size, iv, iv_size, &IOVEC_MAKE((void*) buf, len), 1, ret, ret_size);
}

int kdf_ss_derive(const char *digest, const void *key, size_t key_size, const void *salt, size_t salt_size, const void *info, size_t info_size, size_t derive_size, void **ret);

int kdf_kb_hmac_derive(const char *mode, const char *digest, const void *key, size_t key_size, const void *salt, size_t salt_size, const void *info, size_t info_size, const void *seed, size_t seed_size, size_t derive_size, void **ret);

int rsa_encrypt_bytes(EVP_PKEY *pkey, const void *decrypted_key, size_t decrypted_key_size, void **ret_encrypt_key, size_t *ret_encrypt_key_size);

int rsa_oaep_encrypt_bytes(const EVP_PKEY *pkey, const char *digest_alg, const char *label, const void *decrypted_key, size_t decrypted_key_size, void **ret_encrypt_key, size_t *ret_encrypt_key_size);

int rsa_pkey_to_suitable_key_size(EVP_PKEY *pkey, size_t *ret_suitable_key_size);

int rsa_pkey_new(size_t bits, EVP_PKEY **ret);

int rsa_pkey_from_n_e(const void *n, size_t n_size, const void *e, size_t e_size, EVP_PKEY **ret);

int rsa_pkey_to_n_e(const EVP_PKEY *pkey, void **ret_n, size_t *ret_n_size, void **ret_e, size_t *ret_e_size);

int ecc_pkey_from_curve_x_y(int curve_id, const void *x, size_t x_size, const void *y, size_t y_size, EVP_PKEY **ret);

int ecc_pkey_to_curve_x_y(const EVP_PKEY *pkey, int *ret_curve_id, void **ret_x, size_t *ret_x_size, void **ret_y, size_t *ret_y_size);

int ecc_pkey_new(int curve_id, EVP_PKEY **ret);

int ecc_ecdh(const EVP_PKEY *private_pkey, const EVP_PKEY *peer_pkey, void **ret_shared_secret, size_t *ret_shared_secret_size);

int x509_generate_volume_keys(X509 *cert, void **ret_decrypted_key, size_t *ret_decrypted_key_size, void **ret_saved_key, size_t *ret_saved_key_size);

int pubkey_fingerprint(EVP_PKEY *pk, const EVP_MD *md, void **ret, size_t *ret_size);

int digest_and_sign(const EVP_MD *md, EVP_PKEY *privkey, const void *data, size_t size, void **ret, size_t *ret_size);

#else

typedef struct X509 X509;
typedef struct EVP_PKEY EVP_PKEY;

static inline void *X509_free(X509 *p) {
        assert(p == NULL);
        return NULL;
}

static inline void *EVP_PKEY_free(EVP_PKEY *p) {
        assert(p == NULL);
        return NULL;
}

#endif

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509*, X509_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY*, EVP_PKEY_free, NULL);

int x509_fingerprint(X509 *cert, uint8_t buffer[static X509_FINGERPRINT_SIZE]);

#if PREFER_OPENSSL
/* The openssl definition */
typedef const EVP_MD* hash_md_t;
typedef const EVP_MD* hash_algorithm_t;
typedef int elliptic_curve_t;
typedef EVP_MD_CTX* hash_context_t;
#  define OPENSSL_OR_GCRYPT(a, b) (a)

#elif HAVE_GCRYPT

#  include <gcrypt.h>

/* The gcrypt definition */
typedef int hash_md_t;
typedef const char* hash_algorithm_t;
typedef const char* elliptic_curve_t;
typedef gcry_md_hd_t hash_context_t;
#  define OPENSSL_OR_GCRYPT(a, b) (b)
#endif

#if PREFER_OPENSSL
int string_hashsum(const char *s, size_t len, const char *md_algorithm, char **ret);

static inline int string_hashsum_sha224(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, "SHA224", ret);
}

static inline int string_hashsum_sha256(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, "SHA256", ret);
}
#endif
