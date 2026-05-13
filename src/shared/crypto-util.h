/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "iovec-util.h"
#include "sha256.h"

typedef enum CertificateSourceType {
        OPENSSL_CERTIFICATE_SOURCE_FILE,
        OPENSSL_CERTIFICATE_SOURCE_PROVIDER,
        _OPENSSL_CERTIFICATE_SOURCE_MAX,
        _OPENSSL_CERTIFICATE_SOURCE_INVALID = -EINVAL,
} CertificateSourceType;

typedef enum KeySourceType {
        OPENSSL_KEY_SOURCE_FILE,
        OPENSSL_KEY_SOURCE_ENGINE,
        OPENSSL_KEY_SOURCE_PROVIDER,
        _OPENSSL_KEY_SOURCE_MAX,
        _OPENSSL_KEY_SOURCE_INVALID = -EINVAL,
} KeySourceType;

typedef struct OpenSSLAskPasswordUI OpenSSLAskPasswordUI;

int parse_openssl_certificate_source_argument(const char *argument, char **certificate_source, CertificateSourceType *certificate_source_type);

int parse_openssl_key_source_argument(const char *argument, char **private_key_source, KeySourceType *private_key_source_type);

int dlopen_libcrypto(int log_level);

#define X509_FINGERPRINT_SIZE SHA256_DIGEST_SIZE

#if HAVE_OPENSSL
#  include <openssl/bio.h>              /* IWYU pragma: export */
#  include <openssl/bn.h>               /* IWYU pragma: export */
#  include <openssl/crypto.h>           /* IWYU pragma: export */
#  include <openssl/ec.h>               /* IWYU pragma: export */
#  include <openssl/err.h>              /* IWYU pragma: export */
#  include <openssl/evp.h>              /* IWYU pragma: export */
#  include <openssl/hmac.h>             /* IWYU pragma: export */
#  include <openssl/param_build.h>      /* IWYU pragma: export */
#  include <openssl/pem.h>              /* IWYU pragma: export */
#  include <openssl/pkcs7.h>            /* IWYU pragma: export */
#  include <openssl/rsa.h>              /* IWYU pragma: export */
#  include <openssl/sha.h>              /* IWYU pragma: export */

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(ASN1_ANY_it);
extern DLSYM_PROTOTYPE(ASN1_BIT_STRING_it);
extern DLSYM_PROTOTYPE(ASN1_BMPSTRING_it);
extern DLSYM_PROTOTYPE(ASN1_BMPSTRING_new);
extern DLSYM_PROTOTYPE(ASN1_get_object);
extern DLSYM_PROTOTYPE(ASN1_IA5STRING_it);
extern DLSYM_PROTOTYPE(ASN1_item_d2i);
extern DLSYM_PROTOTYPE(ASN1_item_free);
extern DLSYM_PROTOTYPE(ASN1_item_i2d);
extern DLSYM_PROTOTYPE(ASN1_item_new);
extern DLSYM_PROTOTYPE(ASN1_OBJECT_it);
extern DLSYM_PROTOTYPE(ASN1_OCTET_STRING_free);
extern DLSYM_PROTOTYPE(ASN1_OCTET_STRING_it);
extern DLSYM_PROTOTYPE(ASN1_OCTET_STRING_set);
extern DLSYM_PROTOTYPE(ASN1_STRING_get0_data);
extern DLSYM_PROTOTYPE(ASN1_STRING_length);
extern DLSYM_PROTOTYPE(ASN1_STRING_new);
extern DLSYM_PROTOTYPE(ASN1_STRING_set);
extern DLSYM_PROTOTYPE(ASN1_STRING_set0);
extern DLSYM_PROTOTYPE(ASN1_TIME_free);
extern DLSYM_PROTOTYPE(ASN1_TIME_set);
extern DLSYM_PROTOTYPE(ASN1_TYPE_new);
extern DLSYM_PROTOTYPE(BIO_ctrl);
extern DLSYM_PROTOTYPE(BIO_find_type);
extern DLSYM_PROTOTYPE(BIO_free_all);
extern DLSYM_PROTOTYPE(BIO_free);
extern DLSYM_PROTOTYPE(BIO_new_mem_buf);
extern DLSYM_PROTOTYPE(BIO_new_socket);
extern DLSYM_PROTOTYPE(BIO_new);
extern DLSYM_PROTOTYPE(BIO_s_mem);
extern DLSYM_PROTOTYPE(BIO_write);
extern DLSYM_PROTOTYPE(BN_bin2bn);
extern DLSYM_PROTOTYPE(BN_bn2nativepad);
extern DLSYM_PROTOTYPE(BN_CTX_free);
extern DLSYM_PROTOTYPE(BN_CTX_new);
extern DLSYM_PROTOTYPE(BN_free);
extern DLSYM_PROTOTYPE(BN_new);
extern DLSYM_PROTOTYPE(BN_num_bits);
extern DLSYM_PROTOTYPE(CRYPTO_free);
extern DLSYM_PROTOTYPE(d2i_ASN1_OCTET_STRING);
extern DLSYM_PROTOTYPE(d2i_ECPKParameters);
extern DLSYM_PROTOTYPE(d2i_PKCS7);
extern DLSYM_PROTOTYPE(d2i_PUBKEY);
extern DLSYM_PROTOTYPE(d2i_X509);
extern DLSYM_PROTOTYPE(EC_GROUP_free);
extern DLSYM_PROTOTYPE(EC_GROUP_get_curve_name);
extern DLSYM_PROTOTYPE(EC_GROUP_get_curve);
extern DLSYM_PROTOTYPE(EC_GROUP_get_field_type);
extern DLSYM_PROTOTYPE(EC_GROUP_get0_generator);
extern DLSYM_PROTOTYPE(EC_GROUP_get0_order);
extern DLSYM_PROTOTYPE(EC_GROUP_new_by_curve_name);
extern DLSYM_PROTOTYPE(EC_POINT_free);
extern DLSYM_PROTOTYPE(EC_POINT_new);
extern DLSYM_PROTOTYPE(EC_POINT_oct2point);
extern DLSYM_PROTOTYPE(EC_POINT_point2oct);
extern DLSYM_PROTOTYPE(ECDSA_SIG_free);
extern DLSYM_PROTOTYPE(ERR_clear_error);
extern DLSYM_PROTOTYPE(ERR_error_string_n);
extern DLSYM_PROTOTYPE(ERR_error_string);
extern DLSYM_PROTOTYPE(ERR_get_error);
extern DLSYM_PROTOTYPE(EVP_aes_256_ctr);
extern DLSYM_PROTOTYPE(EVP_aes_256_gcm);
extern DLSYM_PROTOTYPE(EVP_CIPHER_CTX_ctrl);
extern DLSYM_PROTOTYPE(EVP_CIPHER_CTX_free);
extern DLSYM_PROTOTYPE(EVP_CIPHER_CTX_new);
extern DLSYM_PROTOTYPE(EVP_CIPHER_free);
extern DLSYM_PROTOTYPE(EVP_CIPHER_get_block_size);
extern DLSYM_PROTOTYPE(EVP_CIPHER_get_iv_length);
extern DLSYM_PROTOTYPE(EVP_CIPHER_get_key_length);
extern DLSYM_PROTOTYPE(EVP_DecryptFinal_ex);
extern DLSYM_PROTOTYPE(EVP_DecryptInit_ex);
extern DLSYM_PROTOTYPE(EVP_DecryptUpdate);
extern DLSYM_PROTOTYPE(EVP_Digest);
extern DLSYM_PROTOTYPE(EVP_DigestFinal_ex);
extern DLSYM_PROTOTYPE(EVP_DigestInit_ex);
extern DLSYM_PROTOTYPE(EVP_DigestUpdate);
extern DLSYM_PROTOTYPE(EVP_DigestVerify);
extern DLSYM_PROTOTYPE(EVP_DigestVerifyInit);
extern DLSYM_PROTOTYPE(EVP_EncryptFinal_ex);
extern DLSYM_PROTOTYPE(EVP_EncryptInit_ex);
extern DLSYM_PROTOTYPE(EVP_EncryptUpdate);
extern DLSYM_PROTOTYPE(EVP_get_cipherbyname);
extern DLSYM_PROTOTYPE(EVP_get_digestbyname);
extern DLSYM_PROTOTYPE(EVP_MAC_CTX_free);
extern DLSYM_PROTOTYPE(EVP_MAC_free);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_free);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_get0_md);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_new);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_set_pkey_ctx);
extern DLSYM_PROTOTYPE(EVP_MD_free);
extern DLSYM_PROTOTYPE(EVP_MD_get_size);
extern DLSYM_PROTOTYPE(EVP_MD_get0_name);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_free);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_from_name);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_id);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_new);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_rsa_padding);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_signature_md);
extern DLSYM_PROTOTYPE(EVP_PKEY_eq);
extern DLSYM_PROTOTYPE(EVP_PKEY_free);
extern DLSYM_PROTOTYPE(EVP_PKEY_fromdata_init);
extern DLSYM_PROTOTYPE(EVP_PKEY_fromdata);
extern DLSYM_PROTOTYPE(EVP_PKEY_get_id);
extern DLSYM_PROTOTYPE(EVP_PKEY_keygen_init);
extern DLSYM_PROTOTYPE(EVP_PKEY_keygen);
extern DLSYM_PROTOTYPE(EVP_PKEY_new_raw_public_key);
extern DLSYM_PROTOTYPE(EVP_PKEY_new);
extern DLSYM_PROTOTYPE(EVP_PKEY_verify_init);
extern DLSYM_PROTOTYPE(EVP_PKEY_verify);
extern DLSYM_PROTOTYPE(EVP_sha1);
extern DLSYM_PROTOTYPE(EVP_sha256);
extern DLSYM_PROTOTYPE(EVP_sha384);
extern DLSYM_PROTOTYPE(EVP_sha512);
extern DLSYM_PROTOTYPE(HMAC);
extern DLSYM_PROTOTYPE(i2d_ASN1_INTEGER);
extern DLSYM_PROTOTYPE(i2d_PKCS7_fp);
extern DLSYM_PROTOTYPE(i2d_PKCS7);
extern DLSYM_PROTOTYPE(i2d_PUBKEY);
extern DLSYM_PROTOTYPE(i2d_X509_NAME);
extern DLSYM_PROTOTYPE(i2d_X509);
extern DLSYM_PROTOTYPE(OBJ_nid2obj);
extern DLSYM_PROTOTYPE(OBJ_nid2sn);
extern DLSYM_PROTOTYPE(OBJ_sn2nid);
extern DLSYM_PROTOTYPE(OBJ_txt2obj);
extern DLSYM_PROTOTYPE(OPENSSL_sk_new_null);
extern DLSYM_PROTOTYPE(OPENSSL_sk_num);
extern DLSYM_PROTOTYPE(OPENSSL_sk_pop_free);
extern DLSYM_PROTOTYPE(OPENSSL_sk_push);
extern DLSYM_PROTOTYPE(OPENSSL_sk_value);
extern DLSYM_PROTOTYPE(OSSL_EC_curve_nid2name);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_BN);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_end);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_octet_string);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_utf8_string);
extern DLSYM_PROTOTYPE(OSSL_PARAM_free);
extern DLSYM_PROTOTYPE(PEM_read_PrivateKey);
extern DLSYM_PROTOTYPE(PEM_read_PUBKEY);
extern DLSYM_PROTOTYPE(PEM_read_X509);
extern DLSYM_PROTOTYPE(PEM_write_PrivateKey);
extern DLSYM_PROTOTYPE(PEM_write_PUBKEY);
extern DLSYM_PROTOTYPE(PEM_write_X509);
extern DLSYM_PROTOTYPE(PKCS5_PBKDF2_HMAC);
extern DLSYM_PROTOTYPE(PKCS7_add_attrib_content_type);
extern DLSYM_PROTOTYPE(PKCS7_add_attrib_smimecap);
extern DLSYM_PROTOTYPE(PKCS7_add_signed_attribute);
extern DLSYM_PROTOTYPE(PKCS7_add0_attrib_signing_time);
extern DLSYM_PROTOTYPE(PKCS7_add1_attrib_digest);
extern DLSYM_PROTOTYPE(PKCS7_ATTR_SIGN_it);
extern DLSYM_PROTOTYPE(PKCS7_content_new);
extern DLSYM_PROTOTYPE(PKCS7_ctrl);
extern DLSYM_PROTOTYPE(PKCS7_dataFinal);
extern DLSYM_PROTOTYPE(PKCS7_dataInit);
extern DLSYM_PROTOTYPE(PKCS7_free);
extern DLSYM_PROTOTYPE(PKCS7_get_signer_info);
extern DLSYM_PROTOTYPE(PKCS7_new);
extern DLSYM_PROTOTYPE(PKCS7_set_content);
extern DLSYM_PROTOTYPE(PKCS7_sign);
extern DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_free);
extern DLSYM_PROTOTYPE(PKCS7_verify);
extern DLSYM_PROTOTYPE(SHA1);
extern DLSYM_PROTOTYPE(SHA512);
extern DLSYM_PROTOTYPE(X509_ALGOR_free);
extern DLSYM_PROTOTYPE(X509_ATTRIBUTE_free);
extern DLSYM_PROTOTYPE(X509_free);
extern DLSYM_PROTOTYPE(X509_get_pubkey);
extern DLSYM_PROTOTYPE(X509_get_subject_name);
extern DLSYM_PROTOTYPE(X509_gmtime_adj);
extern DLSYM_PROTOTYPE(X509_NAME_free);
extern DLSYM_PROTOTYPE(X509_NAME_oneline);
extern DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set_hostflags);
extern DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_host);
extern DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_ip);

#if !defined(OPENSSL_NO_DEPRECATED_3_0)
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
extern DLSYM_PROTOTYPE(ECDSA_SIG_new);
extern DLSYM_PROTOTYPE(ECDSA_SIG_set0);
extern DLSYM_PROTOTYPE(ECDSA_do_verify);
extern DLSYM_PROTOTYPE(EC_KEY_check_key);
extern DLSYM_PROTOTYPE(EC_KEY_free);
extern DLSYM_PROTOTYPE(EC_KEY_new);
extern DLSYM_PROTOTYPE(EC_KEY_set_group);
extern DLSYM_PROTOTYPE(EC_KEY_set_public_key);
extern DLSYM_PROTOTYPE(EVP_PKEY_assign);
extern DLSYM_PROTOTYPE(RSA_free);
extern DLSYM_PROTOTYPE(RSA_new);
extern DLSYM_PROTOTYPE(RSA_set0_key);
extern DLSYM_PROTOTYPE(RSA_size);
extern DLSYM_PROTOTYPE(RSAPublicKey_dup);
REENABLE_WARNING;

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EC_KEY*, sym_EC_KEY_free, EC_KEY_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(RSA*, sym_RSA_free, RSA_freep, NULL);
#endif

/* Mirrors of OpenSSL macros that go through our dlopen'd sym_* variants, so we don't end up linking against
 * libcrypto just for these. */
#define sym_BIO_get_md_ctx(b, mdcp) sym_BIO_ctrl((b), BIO_C_GET_MD_CTX, 0, (char*) (mdcp))
#define sym_BIO_get_mem_ptr(b, pp) sym_BIO_ctrl((b), BIO_C_GET_BUF_MEM_PTR, 0, (char *) (pp))
#define sym_BIO_reset(b) sym_BIO_ctrl((b), BIO_CTRL_RESET, 0, NULL)
#define sym_BN_num_bytes(a) ((sym_BN_num_bits(a) + 7) / 8)
#define sym_EVP_MD_CTX_get_size(ctx) sym_EVP_MD_get_size(sym_EVP_MD_CTX_get0_md(ctx))
#define sym_EVP_MD_CTX_get0_name(ctx) sym_EVP_MD_get0_name(sym_EVP_MD_CTX_get0_md(ctx))
#define sym_EVP_PKEY_assign_RSA(pkey, rsa) sym_EVP_PKEY_assign((pkey), EVP_PKEY_RSA, (rsa))
#define sym_OPENSSL_free(addr) sym_CRYPTO_free((addr), OPENSSL_FILE, OPENSSL_LINE)
#define sym_PKCS7_set_detached(p, v) sym_PKCS7_ctrl((p), PKCS7_OP_SET_DETACHED_SIGNATURE, (v), NULL)

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO_RENAME(void*, sym_OPENSSL_free, OPENSSL_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ASN1_OCTET_STRING*, sym_ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ASN1_TIME*, sym_ASN1_TIME_free, ASN1_TIME_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BIGNUM*, sym_BN_free, BN_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BIO*, sym_BIO_free_all, BIO_free_allp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BIO*, sym_BIO_free, BIO_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BN_CTX*, sym_BN_CTX_free, BN_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EC_GROUP*, sym_EC_GROUP_free, EC_GROUP_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EC_POINT*, sym_EC_POINT_free, EC_POINT_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ECDSA_SIG*, sym_ECDSA_SIG_free, ECDSA_SIG_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_CIPHER_CTX*, sym_EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_CIPHER*, sym_EVP_CIPHER_free, EVP_CIPHER_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MAC_CTX*, sym_EVP_MAC_CTX_free, EVP_MAC_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MAC*, sym_EVP_MAC_free, EVP_MAC_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MD_CTX*, sym_EVP_MD_CTX_free, EVP_MD_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MD*, sym_EVP_MD_free, EVP_MD_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_PKEY_CTX*, sym_EVP_PKEY_CTX_free, EVP_PKEY_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_PKEY*, sym_EVP_PKEY_free, EVP_PKEY_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(OSSL_PARAM*, sym_OSSL_PARAM_free, OSSL_PARAM_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(PKCS7_SIGNER_INFO*, sym_PKCS7_SIGNER_INFO_free, PKCS7_SIGNER_INFO_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(PKCS7*, sym_PKCS7_free, PKCS7_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(X509_NAME*, sym_X509_NAME_free, X509_NAME_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(X509*, sym_X509_free, X509_freep, NULL);

/* Stack-of macros that go through the dlopen'd sym_OPENSSL_sk_* variants, mirroring the sk_TYPE_OP() helpers
 * from <openssl/x509.h> and friends. */
#define sym_sk_X509_new_null() \
        ((STACK_OF(X509)*) sym_OPENSSL_sk_new_null())
#define sym_sk_X509_push(sk, ptr) \
        sym_OPENSSL_sk_push(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
#define sym_sk_X509_pop_free(sk, freefunc) \
        sym_OPENSSL_sk_pop_free(ossl_check_X509_sk_type(sk), ossl_check_X509_freefunc_type(freefunc))
#define sym_sk_X509_ALGOR_pop_free(sk, freefunc) \
        sym_OPENSSL_sk_pop_free(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_freefunc_type(freefunc))
#define sym_sk_X509_ATTRIBUTE_pop_free(sk, freefunc) \
        sym_OPENSSL_sk_pop_free(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_freefunc_type(freefunc))
#define sym_sk_PKCS7_SIGNER_INFO_num(sk) \
        sym_OPENSSL_sk_num(ossl_check_const_PKCS7_SIGNER_INFO_sk_type(sk))
#define sym_sk_PKCS7_SIGNER_INFO_value(sk, idx) \
        ((PKCS7_SIGNER_INFO*) sym_OPENSSL_sk_value(ossl_check_const_PKCS7_SIGNER_INFO_sk_type(sk), (idx)))

static inline STACK_OF(X509_ALGOR) *x509_algor_free_many(STACK_OF(X509_ALGOR) *attrs) {
        if (!attrs)
                return NULL;

        sym_sk_X509_ALGOR_pop_free(attrs, sym_X509_ALGOR_free);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(STACK_OF(X509_ALGOR)*, x509_algor_free_many, NULL);

static inline STACK_OF(X509_ATTRIBUTE) *x509_attribute_free_many(STACK_OF(X509_ATTRIBUTE) *attrs) {
        if (!attrs)
                return NULL;

        sym_sk_X509_ATTRIBUTE_pop_free(attrs, sym_X509_ATTRIBUTE_free);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(STACK_OF(X509_ATTRIBUTE)*, x509_attribute_free_many, NULL);

static inline void sk_X509_free_allp(STACK_OF(X509) **sk) {
        if (!sk || !*sk)
                return;

        sym_sk_X509_pop_free(*sk, sym_X509_free);
}

int openssl_pubkey_from_pem(const void *pem, size_t pem_size, EVP_PKEY **ret);
int openssl_pubkey_to_pem(EVP_PKEY *pkey, char **ret);

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

int rsa_pkey_from_n_e(const void *n, size_t n_size, const void *e, size_t e_size, EVP_PKEY **ret);

int rsa_pkey_to_n_e(const EVP_PKEY *pkey, void **ret_n, size_t *ret_n_size, void **ret_e, size_t *ret_e_size);

int ecc_pkey_from_curve_x_y(int curve_id, const void *x, size_t x_size, const void *y, size_t y_size, EVP_PKEY **ret);

int ecc_pkey_to_curve_x_y(const EVP_PKEY *pkey, int *ret_curve_id, void **ret_x, size_t *ret_x_size, void **ret_y, size_t *ret_y_size);

int ecc_pkey_new(int curve_id, EVP_PKEY **ret);

int ecc_ecdh(const EVP_PKEY *private_pkey, const EVP_PKEY *peer_pkey, void **ret_shared_secret, size_t *ret_shared_secret_size);

int pkey_generate_volume_keys(EVP_PKEY *pkey, void **ret_decrypted_key, size_t *ret_decrypted_key_size, void **ret_saved_key, size_t *ret_saved_key_size);

int pubkey_fingerprint(EVP_PKEY *pk, const EVP_MD *md, void **ret, size_t *ret_size);

int digest_and_sign(const EVP_MD *md, EVP_PKEY *privkey, const void *data, size_t size, void **ret, size_t *ret_size);

int pkcs7_new(X509 *certificate, EVP_PKEY *private_key, const char *hash_algorithm, PKCS7 **ret_p7, PKCS7_SIGNER_INFO **ret_si);

int string_hashsum(const char *s, size_t len, const char *md_algorithm, char **ret);
static inline int string_hashsum_sha224(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, "SHA224", ret);
}
static inline int string_hashsum_sha256(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, "SHA256", ret);
}

int x509_fingerprint(X509 *cert, uint8_t buffer[static X509_FINGERPRINT_SIZE]);

int openssl_load_x509_certificate(
                CertificateSourceType certificate_source_type,
                const char *certificate_source,
                const char *certificate,
                X509 **ret);

int openssl_load_private_key(
                KeySourceType private_key_source_type,
                const char *private_key_source,
                const char *private_key,
                const AskPasswordRequest *request,
                EVP_PKEY **ret_private_key,
                OpenSSLAskPasswordUI **ret_user_interface);

int openssl_extract_public_key(EVP_PKEY *private_key, EVP_PKEY **ret);

OpenSSLAskPasswordUI* openssl_ask_password_ui_free(OpenSSLAskPasswordUI *ui);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OpenSSLAskPasswordUI*, openssl_ask_password_ui_free, NULL);

#endif
