/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dlopen.h"

#include "basic-forward.h"

int dlopen_libcrypto(int log_level);

#if HAVE_OPENSSL
#define LIBCRYPTO_NOTE(priority)                                        \
        SD_ELF_NOTE_DLOPEN("libcrypto",                                 \
                           "Support for cryptographic operations",      \
                           priority,                                    \
                           "libcrypto.so.3", "libcrypto.so.4")

#define DLOPEN_LIBCRYPTO(log_level, priority)                           \
        ({                                                              \
                LIBCRYPTO_NOTE(priority);                               \
                dlopen_libcrypto(log_level);                            \
        })

#  include <openssl/bio.h>              /* IWYU pragma: export */
#  include <openssl/bn.h>               /* IWYU pragma: export */
#  include <openssl/core_names.h>       /* IWYU pragma: export */
#  include <openssl/crypto.h>           /* IWYU pragma: export */
#  include <openssl/ec.h>               /* IWYU pragma: export */
#  include <openssl/err.h>              /* IWYU pragma: export */
#  include <openssl/evp.h>              /* IWYU pragma: export */
#  include <openssl/hmac.h>             /* IWYU pragma: export */
#  include <openssl/kdf.h>              /* IWYU pragma: export */
#  include <openssl/param_build.h>      /* IWYU pragma: export */
#  include <openssl/pem.h>              /* IWYU pragma: export */
#  include <openssl/pkcs7.h>            /* IWYU pragma: export */
#  include <openssl/provider.h>         /* IWYU pragma: export */
#  include <openssl/rsa.h>              /* IWYU pragma: export */
#  include <openssl/sha.h>              /* IWYU pragma: export */
#  include <openssl/store.h>            /* IWYU pragma: export */

#  if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
#    include <openssl/engine.h>         /* IWYU pragma: export */
#  endif

#  ifndef OPENSSL_NO_UI_CONSOLE
#    include <openssl/ui.h>             /* IWYU pragma: export */
#  endif

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(ASN1_ANY_it);
extern DLSYM_PROTOTYPE(ASN1_BIT_STRING_it);
extern DLSYM_PROTOTYPE(ASN1_BMPSTRING_it);
extern DLSYM_PROTOTYPE(ASN1_BMPSTRING_new);
extern DLSYM_PROTOTYPE(ASN1_IA5STRING_it);
extern DLSYM_PROTOTYPE(ASN1_INTEGER_dup);
extern DLSYM_PROTOTYPE(ASN1_INTEGER_free);
extern DLSYM_PROTOTYPE(ASN1_INTEGER_set);
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
extern DLSYM_PROTOTYPE(ASN1_get_object);
extern DLSYM_PROTOTYPE(ASN1_item_d2i);
extern DLSYM_PROTOTYPE(ASN1_item_free);
extern DLSYM_PROTOTYPE(ASN1_item_i2d);
extern DLSYM_PROTOTYPE(ASN1_item_new);
extern DLSYM_PROTOTYPE(BIO_ctrl);
extern DLSYM_PROTOTYPE(BIO_find_type);
extern DLSYM_PROTOTYPE(BIO_free);
extern DLSYM_PROTOTYPE(BIO_free_all);
extern DLSYM_PROTOTYPE(BIO_new);
extern DLSYM_PROTOTYPE(BIO_new_mem_buf);
extern DLSYM_PROTOTYPE(BIO_new_socket);
extern DLSYM_PROTOTYPE(BIO_s_mem);
extern DLSYM_PROTOTYPE(BIO_write);
extern DLSYM_PROTOTYPE(BN_CTX_free);
extern DLSYM_PROTOTYPE(BN_CTX_new);
extern DLSYM_PROTOTYPE(BN_CTX_secure_new);
extern DLSYM_PROTOTYPE(BN_add);
extern DLSYM_PROTOTYPE(BN_add_word);
extern DLSYM_PROTOTYPE(BN_bin2bn);
extern DLSYM_PROTOTYPE(BN_bn2bin);
extern DLSYM_PROTOTYPE(BN_bn2binpad);
extern DLSYM_PROTOTYPE(BN_bn2nativepad);
extern DLSYM_PROTOTYPE(BN_check_prime);
extern DLSYM_PROTOTYPE(BN_clear_free);
extern DLSYM_PROTOTYPE(BN_cmp);
extern DLSYM_PROTOTYPE(BN_copy);
extern DLSYM_PROTOTYPE(BN_free);
extern DLSYM_PROTOTYPE(BN_is_negative);
extern DLSYM_PROTOTYPE(BN_mod_exp);
extern DLSYM_PROTOTYPE(BN_mod_inverse);
extern DLSYM_PROTOTYPE(BN_mod_lshift1_quick);
extern DLSYM_PROTOTYPE(BN_mod_mul);
extern DLSYM_PROTOTYPE(BN_mod_sqr);
extern DLSYM_PROTOTYPE(BN_mod_sub);
extern DLSYM_PROTOTYPE(BN_mul);
extern DLSYM_PROTOTYPE(BN_new);
extern DLSYM_PROTOTYPE(BN_nnmod);
extern DLSYM_PROTOTYPE(BN_num_bits);
extern DLSYM_PROTOTYPE(BN_secure_new);
extern DLSYM_PROTOTYPE(BN_set_word);
extern DLSYM_PROTOTYPE(BN_sub_word);
extern DLSYM_PROTOTYPE(CRYPTO_free);
extern DLSYM_PROTOTYPE(ECDSA_SIG_free);
extern DLSYM_PROTOTYPE(EC_GROUP_free);
extern DLSYM_PROTOTYPE(EC_GROUP_get0_generator);
extern DLSYM_PROTOTYPE(EC_GROUP_get0_order);
extern DLSYM_PROTOTYPE(EC_GROUP_get_curve);
extern DLSYM_PROTOTYPE(EC_GROUP_get_curve_name);
extern DLSYM_PROTOTYPE(EC_GROUP_get_field_type);
extern DLSYM_PROTOTYPE(EC_GROUP_new_by_curve_name);
extern DLSYM_PROTOTYPE(EC_POINT_free);
extern DLSYM_PROTOTYPE(EC_POINT_new);
extern DLSYM_PROTOTYPE(EC_POINT_oct2point);
extern DLSYM_PROTOTYPE(EC_POINT_point2buf);
extern DLSYM_PROTOTYPE(EC_POINT_point2oct);
extern DLSYM_PROTOTYPE(EC_POINT_set_affine_coordinates);
extern DLSYM_PROTOTYPE(ERR_clear_error);
extern DLSYM_PROTOTYPE(ERR_error_string);
extern DLSYM_PROTOTYPE(ERR_error_string_n);
extern DLSYM_PROTOTYPE(ERR_get_error);
extern DLSYM_PROTOTYPE(ERR_peek_last_error);
extern DLSYM_PROTOTYPE(EVP_CIPHER_CTX_ctrl);
extern DLSYM_PROTOTYPE(EVP_CIPHER_CTX_free);
extern DLSYM_PROTOTYPE(EVP_CIPHER_CTX_get_block_size);
extern DLSYM_PROTOTYPE(EVP_CIPHER_CTX_new);
extern DLSYM_PROTOTYPE(EVP_CIPHER_fetch);
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
extern DLSYM_PROTOTYPE(EVP_DigestSign);
extern DLSYM_PROTOTYPE(EVP_DigestSignInit);
extern DLSYM_PROTOTYPE(EVP_DigestUpdate);
extern DLSYM_PROTOTYPE(EVP_DigestVerify);
extern DLSYM_PROTOTYPE(EVP_DigestVerifyInit);
extern DLSYM_PROTOTYPE(EVP_EncryptFinal_ex);
extern DLSYM_PROTOTYPE(EVP_EncryptInit);
extern DLSYM_PROTOTYPE(EVP_EncryptInit_ex);
extern DLSYM_PROTOTYPE(EVP_EncryptUpdate);
extern DLSYM_PROTOTYPE(EVP_KDF_CTX_free);
extern DLSYM_PROTOTYPE(EVP_KDF_CTX_new);
extern DLSYM_PROTOTYPE(EVP_KDF_derive);
extern DLSYM_PROTOTYPE(EVP_KDF_fetch);
extern DLSYM_PROTOTYPE(EVP_KDF_free);
extern DLSYM_PROTOTYPE(EVP_MAC_CTX_free);
extern DLSYM_PROTOTYPE(EVP_MAC_CTX_get_mac_size);
extern DLSYM_PROTOTYPE(EVP_MAC_CTX_new);
extern DLSYM_PROTOTYPE(EVP_MAC_fetch);
extern DLSYM_PROTOTYPE(EVP_MAC_final);
extern DLSYM_PROTOTYPE(EVP_MAC_free);
extern DLSYM_PROTOTYPE(EVP_MAC_init);
extern DLSYM_PROTOTYPE(EVP_MAC_update);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_copy_ex);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_free);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_get0_md);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_new);
extern DLSYM_PROTOTYPE(EVP_MD_CTX_set_pkey_ctx);
extern DLSYM_PROTOTYPE(EVP_MD_fetch);
extern DLSYM_PROTOTYPE(EVP_MD_free);
extern DLSYM_PROTOTYPE(EVP_MD_get0_name);
extern DLSYM_PROTOTYPE(EVP_MD_get_size);
extern DLSYM_PROTOTYPE(EVP_MD_get_type);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_free);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_new);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_from_name);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_id);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_set0_rsa_oaep_label);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_rsa_oaep_md);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_rsa_padding);
extern DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_signature_md);
extern DLSYM_PROTOTYPE(EVP_PKEY_derive);
extern DLSYM_PROTOTYPE(EVP_PKEY_derive_init);
extern DLSYM_PROTOTYPE(EVP_PKEY_derive_set_peer);
extern DLSYM_PROTOTYPE(EVP_PKEY_encrypt);
extern DLSYM_PROTOTYPE(EVP_PKEY_encrypt_init);
extern DLSYM_PROTOTYPE(EVP_PKEY_eq);
extern DLSYM_PROTOTYPE(EVP_PKEY_free);
extern DLSYM_PROTOTYPE(EVP_PKEY_fromdata);
extern DLSYM_PROTOTYPE(EVP_PKEY_fromdata_init);
extern DLSYM_PROTOTYPE(EVP_PKEY_get1_encoded_public_key);
extern DLSYM_PROTOTYPE(EVP_PKEY_get_base_id);
extern DLSYM_PROTOTYPE(EVP_PKEY_get_bits);
extern DLSYM_PROTOTYPE(EVP_PKEY_get_bn_param);
extern DLSYM_PROTOTYPE(EVP_PKEY_get_group_name);
extern DLSYM_PROTOTYPE(EVP_PKEY_get_id);
extern DLSYM_PROTOTYPE(EVP_PKEY_get_utf8_string_param);
extern DLSYM_PROTOTYPE(EVP_PKEY_keygen);
extern DLSYM_PROTOTYPE(EVP_PKEY_keygen_init);
extern DLSYM_PROTOTYPE(EVP_PKEY_new);
extern DLSYM_PROTOTYPE(EVP_PKEY_new_raw_public_key);
extern DLSYM_PROTOTYPE(EVP_PKEY_verify);
extern DLSYM_PROTOTYPE(EVP_PKEY_verify_init);
extern DLSYM_PROTOTYPE(EVP_aes_256_ctr);
extern DLSYM_PROTOTYPE(EVP_aes_256_gcm);
extern DLSYM_PROTOTYPE(EVP_get_cipherbyname);
extern DLSYM_PROTOTYPE(EVP_get_digestbyname);
extern DLSYM_PROTOTYPE(EVP_sha1);
extern DLSYM_PROTOTYPE(EVP_sha256);
extern DLSYM_PROTOTYPE(EVP_sha384);
extern DLSYM_PROTOTYPE(EVP_sha512);
extern DLSYM_PROTOTYPE(HMAC);
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
extern DLSYM_PROTOTYPE(OSSL_PARAM_BLD_free);
extern DLSYM_PROTOTYPE(OSSL_PARAM_BLD_new);
extern DLSYM_PROTOTYPE(OSSL_PARAM_BLD_push_octet_string);
extern DLSYM_PROTOTYPE(OSSL_PARAM_BLD_push_utf8_string);
extern DLSYM_PROTOTYPE(OSSL_PARAM_BLD_to_param);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_BN);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_end);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_octet_string);
extern DLSYM_PROTOTYPE(OSSL_PARAM_construct_utf8_string);
extern DLSYM_PROTOTYPE(OSSL_PARAM_free);
extern DLSYM_PROTOTYPE(OSSL_PROVIDER_try_load);
extern DLSYM_PROTOTYPE(OSSL_STORE_INFO_free);
extern DLSYM_PROTOTYPE(OSSL_STORE_INFO_get1_CERT);
extern DLSYM_PROTOTYPE(OSSL_STORE_INFO_get1_PKEY);
extern DLSYM_PROTOTYPE(OSSL_STORE_close);
extern DLSYM_PROTOTYPE(OSSL_STORE_expect);
extern DLSYM_PROTOTYPE(OSSL_STORE_load);
extern DLSYM_PROTOTYPE(OSSL_STORE_open);
extern DLSYM_PROTOTYPE(PEM_read_PUBKEY);
extern DLSYM_PROTOTYPE(PEM_read_PrivateKey);
extern DLSYM_PROTOTYPE(PEM_read_X509);
extern DLSYM_PROTOTYPE(PEM_read_bio_PrivateKey);
extern DLSYM_PROTOTYPE(PEM_read_bio_X509);
extern DLSYM_PROTOTYPE(PEM_write_PUBKEY);
extern DLSYM_PROTOTYPE(PEM_write_PrivateKey);
extern DLSYM_PROTOTYPE(PEM_write_X509);
extern DLSYM_PROTOTYPE(PKCS5_PBKDF2_HMAC);
extern DLSYM_PROTOTYPE(PKCS7_ATTR_SIGN_it);
extern DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_free);
extern DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_new);
extern DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_set);
extern DLSYM_PROTOTYPE(PKCS7_add0_attrib_signing_time);
extern DLSYM_PROTOTYPE(PKCS7_add1_attrib_digest);
extern DLSYM_PROTOTYPE(PKCS7_add_attrib_content_type);
extern DLSYM_PROTOTYPE(PKCS7_add_attrib_smimecap);
extern DLSYM_PROTOTYPE(PKCS7_add_certificate);
extern DLSYM_PROTOTYPE(PKCS7_add_signed_attribute);
extern DLSYM_PROTOTYPE(PKCS7_add_signer);
extern DLSYM_PROTOTYPE(PKCS7_content_new);
extern DLSYM_PROTOTYPE(PKCS7_ctrl);
extern DLSYM_PROTOTYPE(PKCS7_dataFinal);
extern DLSYM_PROTOTYPE(PKCS7_dataInit);
extern DLSYM_PROTOTYPE(PKCS7_free);
extern DLSYM_PROTOTYPE(PKCS7_get_signer_info);
extern DLSYM_PROTOTYPE(PKCS7_new);
extern DLSYM_PROTOTYPE(PKCS7_set_content);
extern DLSYM_PROTOTYPE(PKCS7_set_type);
extern DLSYM_PROTOTYPE(PKCS7_sign);
extern DLSYM_PROTOTYPE(PKCS7_verify);
extern DLSYM_PROTOTYPE(SHA1);
extern DLSYM_PROTOTYPE(SHA512);
extern DLSYM_PROTOTYPE(X509_ALGOR_free);
extern DLSYM_PROTOTYPE(X509_ALGOR_set0);
extern DLSYM_PROTOTYPE(X509_ATTRIBUTE_free);
extern DLSYM_PROTOTYPE(X509_NAME_free);
extern DLSYM_PROTOTYPE(X509_NAME_oneline);
extern DLSYM_PROTOTYPE(X509_NAME_set);
extern DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_host);
extern DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_ip);
extern DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set_hostflags);
extern DLSYM_PROTOTYPE(X509_free);
extern DLSYM_PROTOTYPE(X509_get0_serialNumber);
extern DLSYM_PROTOTYPE(X509_get_issuer_name);
extern DLSYM_PROTOTYPE(X509_get_pubkey);
extern DLSYM_PROTOTYPE(X509_get_signature_info);
extern DLSYM_PROTOTYPE(X509_get_subject_name);
extern DLSYM_PROTOTYPE(X509_gmtime_adj);
extern DLSYM_PROTOTYPE(d2i_ASN1_OCTET_STRING);
extern DLSYM_PROTOTYPE(d2i_ECPKParameters);
extern DLSYM_PROTOTYPE(d2i_PKCS7);
extern DLSYM_PROTOTYPE(d2i_PUBKEY);
extern DLSYM_PROTOTYPE(d2i_X509);
extern DLSYM_PROTOTYPE(i2d_ASN1_INTEGER);
extern DLSYM_PROTOTYPE(i2d_PKCS7);
extern DLSYM_PROTOTYPE(i2d_PKCS7_fp);
extern DLSYM_PROTOTYPE(i2d_PUBKEY);
extern DLSYM_PROTOTYPE(i2d_PUBKEY_fp);
extern DLSYM_PROTOTYPE(i2d_PublicKey);
extern DLSYM_PROTOTYPE(i2d_X509);
extern DLSYM_PROTOTYPE(i2d_X509_NAME);

#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
extern DLSYM_PROTOTYPE(ENGINE_by_id);
extern DLSYM_PROTOTYPE(ENGINE_free);
extern DLSYM_PROTOTYPE(ENGINE_init);
extern DLSYM_PROTOTYPE(ENGINE_load_private_key);
REENABLE_WARNING;

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ENGINE*, sym_ENGINE_free, ENGINE_freep, NULL);
#endif

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

#ifndef OPENSSL_NO_UI_CONSOLE
extern DLSYM_PROTOTYPE(UI_OpenSSL);
extern DLSYM_PROTOTYPE(UI_create_method);
extern DLSYM_PROTOTYPE(UI_destroy_method);
extern DLSYM_PROTOTYPE(UI_get0_output_string);
extern DLSYM_PROTOTYPE(UI_get_default_method);
extern DLSYM_PROTOTYPE(UI_get_method);
extern DLSYM_PROTOTYPE(UI_get_string_type);
extern DLSYM_PROTOTYPE(UI_method_get_ex_data);
extern DLSYM_PROTOTYPE(UI_method_get_reader);
extern DLSYM_PROTOTYPE(UI_method_set_ex_data);
extern DLSYM_PROTOTYPE(UI_method_set_reader);
extern DLSYM_PROTOTYPE(UI_set_default_method);
extern DLSYM_PROTOTYPE(UI_set_result);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(UI_METHOD*, sym_UI_destroy_method, UI_destroy_methodp, NULL);
#endif

/* Mirrors of OpenSSL macros that go through our dlopen'd sym_* variants, so we don't end up linking against
 * libcrypto just for these. */
#define sym_BIO_get_md_ctx(b, mdcp) sym_BIO_ctrl((b), BIO_C_GET_MD_CTX, 0, (char*) (mdcp))
#define sym_BIO_get_mem_ptr(b, pp) sym_BIO_ctrl((b), BIO_C_GET_BUF_MEM_PTR, 0, (char *) (pp))
#define sym_BIO_reset(b) sym_BIO_ctrl((b), BIO_CTRL_RESET, 0, NULL)
#define sym_BN_num_bytes(a) ((sym_BN_num_bits(a) + 7) / 8)
#define sym_BN_one(a) sym_BN_set_word(a, 1)
#define sym_EVP_MD_CTX_get_size(ctx) sym_EVP_MD_get_size(sym_EVP_MD_CTX_get0_md(ctx))
#define sym_EVP_MD_CTX_get0_name(ctx) sym_EVP_MD_get0_name(sym_EVP_MD_CTX_get0_md(ctx))
#define sym_EVP_PKEY_assign_RSA(pkey, rsa) sym_EVP_PKEY_assign((pkey), EVP_PKEY_RSA, (rsa))
#define sym_OPENSSL_free(addr) sym_CRYPTO_free((addr), OPENSSL_FILE, OPENSSL_LINE)
#define sym_PKCS7_set_detached(p, v) sym_PKCS7_ctrl((p), PKCS7_OP_SET_DETACHED_SIGNATURE, (v), NULL)

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO_RENAME(void*, sym_OPENSSL_free, OPENSSL_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ASN1_OCTET_STRING*, sym_ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ASN1_TIME*, sym_ASN1_TIME_free, ASN1_TIME_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BIGNUM*, sym_BN_free, BN_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BIGNUM*, sym_BN_clear_free, BN_clear_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BIO*, sym_BIO_free, BIO_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BIO*, sym_BIO_free_all, BIO_free_allp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(BN_CTX*, sym_BN_CTX_free, BN_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ECDSA_SIG*, sym_ECDSA_SIG_free, ECDSA_SIG_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EC_GROUP*, sym_EC_GROUP_free, EC_GROUP_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EC_POINT*, sym_EC_POINT_free, EC_POINT_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_CIPHER*, sym_EVP_CIPHER_free, EVP_CIPHER_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_CIPHER_CTX*, sym_EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_KDF*, sym_EVP_KDF_free, EVP_KDF_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_KDF_CTX*, sym_EVP_KDF_CTX_free, EVP_KDF_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MAC*, sym_EVP_MAC_free, EVP_MAC_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MAC_CTX*, sym_EVP_MAC_CTX_free, EVP_MAC_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MD*, sym_EVP_MD_free, EVP_MD_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_MD_CTX*, sym_EVP_MD_CTX_free, EVP_MD_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_PKEY*, sym_EVP_PKEY_free, EVP_PKEY_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(EVP_PKEY_CTX*, sym_EVP_PKEY_CTX_free, EVP_PKEY_CTX_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(OSSL_PARAM*, sym_OSSL_PARAM_free, OSSL_PARAM_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(OSSL_PARAM_BLD*, sym_OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(OSSL_STORE_CTX*, sym_OSSL_STORE_close, OSSL_STORE_closep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(OSSL_STORE_INFO*, sym_OSSL_STORE_INFO_free, OSSL_STORE_INFO_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(PKCS7*, sym_PKCS7_free, PKCS7_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(PKCS7_SIGNER_INFO*, sym_PKCS7_SIGNER_INFO_free, PKCS7_SIGNER_INFO_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(X509*, sym_X509_free, X509_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(X509_NAME*, sym_X509_NAME_free, X509_NAME_freep, NULL);

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

/* Translates an OpenSSL error code (as returned by ERR_get_error()) into a negative errno. Returns
 * -ENOTRECOVERABLE when passed 0 or when the error's reason has no more specific errno. */
int openssl_to_errno(unsigned long e);

int log_openssl_errors_internal(int level, const char *file, int line, const char *func, const char *format, ...) _printf_(5, 6);

/* Logs `format` at `level`, suffixed with each error from the OpenSSL thread-local error queue (or
 * "No OpenSSL errors." when it is empty), and returns a negative errno derived from the last error
 * (-ENOTRECOVERABLE when the queue is empty or the reason isn't recognized). */
#define log_openssl_errors(level, format, ...)                          \
        log_openssl_errors_internal(level, PROJECT_FILE, __LINE__, __func__, format, ##__VA_ARGS__)

#else
#define DLOPEN_LIBCRYPTO(log_level, priority) dlopen_libcrypto(log_level)
#endif
