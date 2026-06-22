/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "crypto-util.h"
#include "log.h"
#include "strv.h"

#if HAVE_OPENSSL
DLSYM_PROTOTYPE(ASN1_ANY_it) = NULL;
DLSYM_PROTOTYPE(ASN1_BIT_STRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_BMPSTRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_BMPSTRING_new) = NULL;
DLSYM_PROTOTYPE(ASN1_IA5STRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_INTEGER_dup) = NULL;
DLSYM_PROTOTYPE(ASN1_INTEGER_free) = NULL;
DLSYM_PROTOTYPE(ASN1_INTEGER_set) = NULL;
DLSYM_PROTOTYPE(ASN1_OBJECT_it) = NULL;
DLSYM_PROTOTYPE(ASN1_OCTET_STRING_free) = NULL;
DLSYM_PROTOTYPE(ASN1_OCTET_STRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_OCTET_STRING_set) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_get0_data) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_length) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_new) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_set) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_set0) = NULL;
DLSYM_PROTOTYPE(ASN1_TIME_free) = NULL;
DLSYM_PROTOTYPE(ASN1_TIME_set) = NULL;
DLSYM_PROTOTYPE(ASN1_TYPE_new) = NULL;
DLSYM_PROTOTYPE(ASN1_get_object) = NULL;
DLSYM_PROTOTYPE(ASN1_item_d2i) = NULL;
DLSYM_PROTOTYPE(ASN1_item_free) = NULL;
DLSYM_PROTOTYPE(ASN1_item_i2d) = NULL;
DLSYM_PROTOTYPE(ASN1_item_new) = NULL;
DLSYM_PROTOTYPE(BIO_ctrl) = NULL;
DLSYM_PROTOTYPE(BIO_find_type) = NULL;
DLSYM_PROTOTYPE(BIO_free) = NULL;
DLSYM_PROTOTYPE(BIO_free_all) = NULL;
DLSYM_PROTOTYPE(BIO_new) = NULL;
DLSYM_PROTOTYPE(BIO_new_mem_buf) = NULL;
DLSYM_PROTOTYPE(BIO_new_socket) = NULL;
DLSYM_PROTOTYPE(BIO_s_mem) = NULL;
DLSYM_PROTOTYPE(BIO_write) = NULL;
DLSYM_PROTOTYPE(BN_CTX_free) = NULL;
DLSYM_PROTOTYPE(BN_CTX_new) = NULL;
DLSYM_PROTOTYPE(BN_CTX_secure_new) = NULL;
DLSYM_PROTOTYPE(BN_add) = NULL;
DLSYM_PROTOTYPE(BN_add_word) = NULL;
DLSYM_PROTOTYPE(BN_bin2bn) = NULL;
DLSYM_PROTOTYPE(BN_bn2bin) = NULL;
DLSYM_PROTOTYPE(BN_bn2binpad) = NULL;
DLSYM_PROTOTYPE(BN_bn2nativepad) = NULL;
DLSYM_PROTOTYPE(BN_check_prime) = NULL;
DLSYM_PROTOTYPE(BN_clear_free) = NULL;
DLSYM_PROTOTYPE(BN_cmp) = NULL;
DLSYM_PROTOTYPE(BN_copy) = NULL;
DLSYM_PROTOTYPE(BN_free) = NULL;
DLSYM_PROTOTYPE(BN_is_negative) = NULL;
DLSYM_PROTOTYPE(BN_mod_exp) = NULL;
DLSYM_PROTOTYPE(BN_mod_inverse) = NULL;
DLSYM_PROTOTYPE(BN_mod_lshift1_quick) = NULL;
DLSYM_PROTOTYPE(BN_mod_mul) = NULL;
DLSYM_PROTOTYPE(BN_mod_sqr) = NULL;
DLSYM_PROTOTYPE(BN_mod_sub) = NULL;
DLSYM_PROTOTYPE(BN_mul) = NULL;
DLSYM_PROTOTYPE(BN_new) = NULL;
DLSYM_PROTOTYPE(BN_nnmod) = NULL;
DLSYM_PROTOTYPE(BN_num_bits) = NULL;
DLSYM_PROTOTYPE(BN_set_word) = NULL;
DLSYM_PROTOTYPE(BN_secure_new) = NULL;
DLSYM_PROTOTYPE(BN_sub_word) = NULL;
DLSYM_PROTOTYPE(CRYPTO_free) = NULL;
DLSYM_PROTOTYPE(ECDSA_SIG_free) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_free) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get0_generator) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get0_order) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get_curve) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get_curve_name) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get_field_type) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_new_by_curve_name) = NULL;
DLSYM_PROTOTYPE(EC_POINT_free) = NULL;
DLSYM_PROTOTYPE(EC_POINT_new) = NULL;
DLSYM_PROTOTYPE(EC_POINT_oct2point) = NULL;
DLSYM_PROTOTYPE(EC_POINT_point2buf) = NULL;
DLSYM_PROTOTYPE(EC_POINT_point2oct) = NULL;
DLSYM_PROTOTYPE(EC_POINT_set_affine_coordinates) = NULL;
DLSYM_PROTOTYPE(ERR_clear_error) = NULL;
DLSYM_PROTOTYPE(ERR_error_string) = NULL;
DLSYM_PROTOTYPE(ERR_error_string_n) = NULL;
DLSYM_PROTOTYPE(ERR_get_error) = NULL;
DLSYM_PROTOTYPE(ERR_peek_last_error) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_ctrl) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_get_block_size) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_free) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_get_block_size) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_get_iv_length) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_get_key_length) = NULL;
DLSYM_PROTOTYPE(EVP_DecryptFinal_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DecryptInit_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DecryptUpdate) = NULL;
DLSYM_PROTOTYPE(EVP_Digest) = NULL;
DLSYM_PROTOTYPE(EVP_DigestFinal_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DigestInit_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DigestSign) = NULL;
DLSYM_PROTOTYPE(EVP_DigestSignInit) = NULL;
DLSYM_PROTOTYPE(EVP_DigestUpdate) = NULL;
DLSYM_PROTOTYPE(EVP_DigestVerify) = NULL;
DLSYM_PROTOTYPE(EVP_DigestVerifyInit) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptFinal_ex) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptInit) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptInit_ex) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptUpdate) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_derive) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_free) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_CTX_get_mac_size) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_final) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_free) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_init) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_update) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_copy_ex) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_get0_md) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_set_pkey_ctx) = NULL;
DLSYM_PROTOTYPE(EVP_MD_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_MD_free) = NULL;
DLSYM_PROTOTYPE(EVP_MD_get0_name) = NULL;
DLSYM_PROTOTYPE(EVP_MD_get_size) = NULL;
DLSYM_PROTOTYPE(EVP_MD_get_type) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_from_name) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_id) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set0_rsa_oaep_label) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_rsa_oaep_md) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_rsa_padding) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_signature_md) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_derive) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_derive_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_derive_set_peer) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_encrypt) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_encrypt_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_eq) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_free) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_fromdata) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_fromdata_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get1_encoded_public_key) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_base_id) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_bits) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_bn_param) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_group_name) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_id) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_utf8_string_param) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_keygen) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_keygen_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_new) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_new_raw_public_key) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_verify) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_verify_init) = NULL;
DLSYM_PROTOTYPE(EVP_aes_256_ctr) = NULL;
DLSYM_PROTOTYPE(EVP_aes_256_gcm) = NULL;
DLSYM_PROTOTYPE(EVP_get_cipherbyname) = NULL;
DLSYM_PROTOTYPE(EVP_get_digestbyname) = NULL;
DLSYM_PROTOTYPE(EVP_sha1) = NULL;
DLSYM_PROTOTYPE(EVP_sha256) = NULL;
DLSYM_PROTOTYPE(EVP_sha384) = NULL;
DLSYM_PROTOTYPE(EVP_sha512) = NULL;
DLSYM_PROTOTYPE(HMAC) = NULL;
DLSYM_PROTOTYPE(OBJ_nid2obj) = NULL;
DLSYM_PROTOTYPE(OBJ_nid2sn) = NULL;
DLSYM_PROTOTYPE(OBJ_sn2nid) = NULL;
DLSYM_PROTOTYPE(OBJ_txt2obj) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_new_null) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_num) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_pop_free) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_push) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_value) = NULL;
DLSYM_PROTOTYPE(OSSL_EC_curve_nid2name) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_free) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_new) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_push_octet_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_push_utf8_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_to_param) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_BN) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_end) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_octet_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_utf8_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_free) = NULL;
DLSYM_PROTOTYPE(OSSL_PROVIDER_try_load) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_INFO_free) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_INFO_get1_CERT) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_INFO_get1_PKEY) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_close) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_expect) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_load) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_open) = NULL;
DLSYM_PROTOTYPE(PEM_read_PUBKEY) = NULL;
DLSYM_PROTOTYPE(PEM_read_PrivateKey) = NULL;
DLSYM_PROTOTYPE(PEM_read_X509) = NULL;
DLSYM_PROTOTYPE(PEM_read_bio_PrivateKey) = NULL;
DLSYM_PROTOTYPE(PEM_read_bio_X509) = NULL;
DLSYM_PROTOTYPE(PEM_write_PUBKEY) = NULL;
DLSYM_PROTOTYPE(PEM_write_PrivateKey) = NULL;
DLSYM_PROTOTYPE(PEM_write_X509) = NULL;
DLSYM_PROTOTYPE(PKCS5_PBKDF2_HMAC) = NULL;
DLSYM_PROTOTYPE(PKCS7_ATTR_SIGN_it) = NULL;
DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_free) = NULL;
DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_new) = NULL;
DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_set) = NULL;
DLSYM_PROTOTYPE(PKCS7_add0_attrib_signing_time) = NULL;
DLSYM_PROTOTYPE(PKCS7_add1_attrib_digest) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_attrib_content_type) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_attrib_smimecap) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_certificate) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_signed_attribute) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_signer) = NULL;
DLSYM_PROTOTYPE(PKCS7_content_new) = NULL;
DLSYM_PROTOTYPE(PKCS7_ctrl) = NULL;
DLSYM_PROTOTYPE(PKCS7_dataFinal) = NULL;
DLSYM_PROTOTYPE(PKCS7_dataInit) = NULL;
DLSYM_PROTOTYPE(PKCS7_free) = NULL;
DLSYM_PROTOTYPE(PKCS7_get_signer_info) = NULL;
DLSYM_PROTOTYPE(PKCS7_new) = NULL;
DLSYM_PROTOTYPE(PKCS7_set_content) = NULL;
DLSYM_PROTOTYPE(PKCS7_set_type) = NULL;
DLSYM_PROTOTYPE(PKCS7_sign) = NULL;
DLSYM_PROTOTYPE(PKCS7_verify) = NULL;
DLSYM_PROTOTYPE(SHA1) = NULL;
DLSYM_PROTOTYPE(SHA512) = NULL;
DLSYM_PROTOTYPE(X509_ALGOR_free) = NULL;
DLSYM_PROTOTYPE(X509_ALGOR_set0) = NULL;
DLSYM_PROTOTYPE(X509_ATTRIBUTE_free) = NULL;
DLSYM_PROTOTYPE(X509_NAME_free) = NULL;
DLSYM_PROTOTYPE(X509_NAME_oneline) = NULL;
DLSYM_PROTOTYPE(X509_NAME_set) = NULL;
DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_host) = NULL;
DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_ip) = NULL;
DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set_hostflags) = NULL;
DLSYM_PROTOTYPE(X509_free) = NULL;
DLSYM_PROTOTYPE(X509_get0_serialNumber) = NULL;
DLSYM_PROTOTYPE(X509_get_issuer_name) = NULL;
DLSYM_PROTOTYPE(X509_get_pubkey) = NULL;
DLSYM_PROTOTYPE(X509_get_signature_info) = NULL;
DLSYM_PROTOTYPE(X509_get_subject_name) = NULL;
DLSYM_PROTOTYPE(X509_gmtime_adj) = NULL;
DLSYM_PROTOTYPE(d2i_ASN1_OCTET_STRING) = NULL;
DLSYM_PROTOTYPE(d2i_ECPKParameters) = NULL;
DLSYM_PROTOTYPE(d2i_PKCS7) = NULL;
DLSYM_PROTOTYPE(d2i_PUBKEY) = NULL;
DLSYM_PROTOTYPE(d2i_X509) = NULL;
DLSYM_PROTOTYPE(i2d_ASN1_INTEGER) = NULL;
DLSYM_PROTOTYPE(i2d_PKCS7) = NULL;
DLSYM_PROTOTYPE(i2d_PKCS7_fp) = NULL;
DLSYM_PROTOTYPE(i2d_PUBKEY) = NULL;
DLSYM_PROTOTYPE(i2d_PUBKEY_fp) = NULL;
DLSYM_PROTOTYPE(i2d_PublicKey) = NULL;
DLSYM_PROTOTYPE(i2d_X509) = NULL;
DLSYM_PROTOTYPE(i2d_X509_NAME) = NULL;

#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(ENGINE_by_id) = NULL;
DLSYM_PROTOTYPE(ENGINE_free) = NULL;
DLSYM_PROTOTYPE(ENGINE_init) = NULL;
DLSYM_PROTOTYPE(ENGINE_load_private_key) = NULL;
REENABLE_WARNING;
#endif

#if !defined(OPENSSL_NO_DEPRECATED_3_0)
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(ECDSA_SIG_new) = NULL;
DLSYM_PROTOTYPE(ECDSA_SIG_set0) = NULL;
DLSYM_PROTOTYPE(ECDSA_do_verify) = NULL;
DLSYM_PROTOTYPE(EC_KEY_check_key) = NULL;
DLSYM_PROTOTYPE(EC_KEY_free) = NULL;
DLSYM_PROTOTYPE(EC_KEY_new) = NULL;
DLSYM_PROTOTYPE(EC_KEY_set_group) = NULL;
DLSYM_PROTOTYPE(EC_KEY_set_public_key) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_assign) = NULL;
DLSYM_PROTOTYPE(RSA_free) = NULL;
DLSYM_PROTOTYPE(RSA_new) = NULL;
DLSYM_PROTOTYPE(RSA_set0_key) = NULL;
DLSYM_PROTOTYPE(RSA_size) = NULL;
DLSYM_PROTOTYPE(RSAPublicKey_dup) = NULL;
REENABLE_WARNING;
#endif

#ifndef OPENSSL_NO_UI_CONSOLE
DLSYM_PROTOTYPE(UI_OpenSSL) = NULL;
DLSYM_PROTOTYPE(UI_create_method) = NULL;
DLSYM_PROTOTYPE(UI_destroy_method) = NULL;
DLSYM_PROTOTYPE(UI_get0_output_string) = NULL;
DLSYM_PROTOTYPE(UI_get_default_method) = NULL;
DLSYM_PROTOTYPE(UI_get_method) = NULL;
DLSYM_PROTOTYPE(UI_get_string_type) = NULL;
DLSYM_PROTOTYPE(UI_method_get_ex_data) = NULL;
DLSYM_PROTOTYPE(UI_method_get_reader) = NULL;
DLSYM_PROTOTYPE(UI_method_set_ex_data) = NULL;
DLSYM_PROTOTYPE(UI_method_set_reader) = NULL;
DLSYM_PROTOTYPE(UI_set_default_method) = NULL;
DLSYM_PROTOTYPE(UI_set_result) = NULL;
#endif

#endif /* HAVE_OPENSSL */

int dlopen_libcrypto(int log_level) {
#if HAVE_OPENSSL
        static void *libcrypto_dl = NULL;
        int r;

        LIBCRYPTO_NOTE(SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED);

        // FIXME: switch order to prefer libcrypto.so.4 in a future version once it has stabilized
        FOREACH_STRING(soname, "libcrypto.so.3", "libcrypto.so.4") {
                r = dlopen_many_sym_or_warn(
                        &libcrypto_dl,
                        soname,
                        log_level,
                        DLSYM_ARG(ASN1_ANY_it),
                        DLSYM_ARG(ASN1_BIT_STRING_it),
                        DLSYM_ARG(ASN1_BMPSTRING_it),
                        DLSYM_ARG(ASN1_BMPSTRING_new),
                        DLSYM_ARG(ASN1_IA5STRING_it),
                        DLSYM_ARG(ASN1_INTEGER_dup),
                        DLSYM_ARG(ASN1_INTEGER_free),
                        DLSYM_ARG(ASN1_INTEGER_set),
                        DLSYM_ARG(ASN1_OBJECT_it),
                        DLSYM_ARG(ASN1_OCTET_STRING_free),
                        DLSYM_ARG(ASN1_OCTET_STRING_it),
                        DLSYM_ARG(ASN1_OCTET_STRING_set),
                        DLSYM_ARG(ASN1_STRING_get0_data),
                        DLSYM_ARG(ASN1_STRING_length),
                        DLSYM_ARG(ASN1_STRING_new),
                        DLSYM_ARG(ASN1_STRING_set),
                        DLSYM_ARG(ASN1_STRING_set0),
                        DLSYM_ARG(ASN1_TIME_free),
                        DLSYM_ARG(ASN1_TIME_set),
                        DLSYM_ARG(ASN1_TYPE_new),
                        DLSYM_ARG(ASN1_get_object),
                        DLSYM_ARG(ASN1_item_d2i),
                        DLSYM_ARG(ASN1_item_free),
                        DLSYM_ARG(ASN1_item_i2d),
                        DLSYM_ARG(ASN1_item_new),
                        DLSYM_ARG(BIO_ctrl),
                        DLSYM_ARG(BIO_find_type),
                        DLSYM_ARG(BIO_free),
                        DLSYM_ARG(BIO_free_all),
                        DLSYM_ARG(BIO_new),
                        DLSYM_ARG(BIO_new_mem_buf),
                        DLSYM_ARG(BIO_new_socket),
                        DLSYM_ARG(BIO_s_mem),
                        DLSYM_ARG(BIO_write),
                        DLSYM_ARG(BN_CTX_free),
                        DLSYM_ARG(BN_CTX_new),
                        DLSYM_ARG(BN_CTX_secure_new),
                        DLSYM_ARG(BN_add),
                        DLSYM_ARG(BN_add_word),
                        DLSYM_ARG(BN_bin2bn),
                        DLSYM_ARG(BN_bn2bin),
                        DLSYM_ARG(BN_bn2binpad),
                        DLSYM_ARG(BN_bn2nativepad),
                        DLSYM_ARG(BN_check_prime),
                        DLSYM_ARG(BN_clear_free),
                        DLSYM_ARG(BN_cmp),
                        DLSYM_ARG(BN_copy),
                        DLSYM_ARG(BN_free),
                        DLSYM_ARG(BN_is_negative),
                        DLSYM_ARG(BN_mod_exp),
                        DLSYM_ARG(BN_mod_inverse),
                        DLSYM_ARG(BN_mod_lshift1_quick),
                        DLSYM_ARG(BN_mod_mul),
                        DLSYM_ARG(BN_mod_sqr),
                        DLSYM_ARG(BN_mod_sub),
                        DLSYM_ARG(BN_mul),
                        DLSYM_ARG(BN_new),
                        DLSYM_ARG(BN_nnmod),
                        DLSYM_ARG(BN_num_bits),
                        DLSYM_ARG(BN_secure_new),
                        DLSYM_ARG(BN_set_word),
                        DLSYM_ARG(BN_sub_word),
                        DLSYM_ARG(CRYPTO_free),
                        DLSYM_ARG(ECDSA_SIG_free),
                        DLSYM_ARG(EC_GROUP_free),
                        DLSYM_ARG(EC_GROUP_get0_generator),
                        DLSYM_ARG(EC_GROUP_get0_order),
                        DLSYM_ARG(EC_GROUP_get_curve),
                        DLSYM_ARG(EC_GROUP_get_curve_name),
                        DLSYM_ARG(EC_GROUP_get_field_type),
                        DLSYM_ARG(EC_GROUP_new_by_curve_name),
                        DLSYM_ARG(EC_POINT_free),
                        DLSYM_ARG(EC_POINT_new),
                        DLSYM_ARG(EC_POINT_oct2point),
                        DLSYM_ARG(EC_POINT_point2buf),
                        DLSYM_ARG(EC_POINT_point2oct),
                        DLSYM_ARG(EC_POINT_set_affine_coordinates),
                        DLSYM_ARG(ERR_clear_error),
                        DLSYM_ARG(ERR_error_string),
                        DLSYM_ARG(ERR_error_string_n),
                        DLSYM_ARG(ERR_get_error),
                        DLSYM_ARG(ERR_peek_last_error),
                        DLSYM_ARG(EVP_CIPHER_CTX_ctrl),
                        DLSYM_ARG(EVP_CIPHER_CTX_free),
                        DLSYM_ARG(EVP_CIPHER_CTX_get_block_size),
                        DLSYM_ARG(EVP_CIPHER_CTX_new),
                        DLSYM_ARG(EVP_CIPHER_fetch),
                        DLSYM_ARG(EVP_CIPHER_free),
                        DLSYM_ARG(EVP_CIPHER_get_block_size),
                        DLSYM_ARG(EVP_CIPHER_get_iv_length),
                        DLSYM_ARG(EVP_CIPHER_get_key_length),
                        DLSYM_ARG(EVP_DecryptFinal_ex),
                        DLSYM_ARG(EVP_DecryptInit_ex),
                        DLSYM_ARG(EVP_DecryptUpdate),
                        DLSYM_ARG(EVP_Digest),
                        DLSYM_ARG(EVP_DigestFinal_ex),
                        DLSYM_ARG(EVP_DigestInit_ex),
                        DLSYM_ARG(EVP_DigestSign),
                        DLSYM_ARG(EVP_DigestSignInit),
                        DLSYM_ARG(EVP_DigestUpdate),
                        DLSYM_ARG(EVP_DigestVerify),
                        DLSYM_ARG(EVP_DigestVerifyInit),
                        DLSYM_ARG(EVP_EncryptFinal_ex),
                        DLSYM_ARG(EVP_EncryptInit),
                        DLSYM_ARG(EVP_EncryptInit_ex),
                        DLSYM_ARG(EVP_EncryptUpdate),
                        DLSYM_ARG(EVP_KDF_CTX_free),
                        DLSYM_ARG(EVP_KDF_CTX_new),
                        DLSYM_ARG(EVP_KDF_derive),
                        DLSYM_ARG(EVP_KDF_fetch),
                        DLSYM_ARG(EVP_KDF_free),
                        DLSYM_ARG(EVP_MAC_CTX_free),
                        DLSYM_ARG(EVP_MAC_CTX_get_mac_size),
                        DLSYM_ARG(EVP_MAC_CTX_new),
                        DLSYM_ARG(EVP_MAC_fetch),
                        DLSYM_ARG(EVP_MAC_final),
                        DLSYM_ARG(EVP_MAC_free),
                        DLSYM_ARG(EVP_MAC_init),
                        DLSYM_ARG(EVP_MAC_update),
                        DLSYM_ARG(EVP_MD_CTX_copy_ex),
                        DLSYM_ARG(EVP_MD_CTX_free),
                        DLSYM_ARG(EVP_MD_CTX_get0_md),
                        DLSYM_ARG(EVP_MD_CTX_new),
                        DLSYM_ARG(EVP_MD_CTX_set_pkey_ctx),
                        DLSYM_ARG(EVP_MD_fetch),
                        DLSYM_ARG(EVP_MD_free),
                        DLSYM_ARG(EVP_MD_get0_name),
                        DLSYM_ARG(EVP_MD_get_size),
                        DLSYM_ARG(EVP_MD_get_type),
                        DLSYM_ARG(EVP_PKEY_CTX_free),
                        DLSYM_ARG(EVP_PKEY_CTX_new),
                        DLSYM_ARG(EVP_PKEY_CTX_new_from_name),
                        DLSYM_ARG(EVP_PKEY_CTX_new_id),
                        DLSYM_ARG(EVP_PKEY_CTX_set0_rsa_oaep_label),
                        DLSYM_ARG(EVP_PKEY_CTX_set_ec_paramgen_curve_nid),
                        DLSYM_ARG(EVP_PKEY_CTX_set_rsa_oaep_md),
                        DLSYM_ARG(EVP_PKEY_CTX_set_rsa_padding),
                        DLSYM_ARG(EVP_PKEY_CTX_set_signature_md),
                        DLSYM_ARG(EVP_PKEY_derive),
                        DLSYM_ARG(EVP_PKEY_derive_init),
                        DLSYM_ARG(EVP_PKEY_derive_set_peer),
                        DLSYM_ARG(EVP_PKEY_encrypt),
                        DLSYM_ARG(EVP_PKEY_encrypt_init),
                        DLSYM_ARG(EVP_PKEY_eq),
                        DLSYM_ARG(EVP_PKEY_free),
                        DLSYM_ARG(EVP_PKEY_fromdata),
                        DLSYM_ARG(EVP_PKEY_fromdata_init),
                        DLSYM_ARG(EVP_PKEY_get1_encoded_public_key),
                        DLSYM_ARG(EVP_PKEY_get_base_id),
                        DLSYM_ARG(EVP_PKEY_get_bits),
                        DLSYM_ARG(EVP_PKEY_get_bn_param),
                        DLSYM_ARG(EVP_PKEY_get_group_name),
                        DLSYM_ARG(EVP_PKEY_get_id),
                        DLSYM_ARG(EVP_PKEY_get_utf8_string_param),
                        DLSYM_ARG(EVP_PKEY_keygen),
                        DLSYM_ARG(EVP_PKEY_keygen_init),
                        DLSYM_ARG(EVP_PKEY_new),
                        DLSYM_ARG(EVP_PKEY_new_raw_public_key),
                        DLSYM_ARG(EVP_PKEY_verify),
                        DLSYM_ARG(EVP_PKEY_verify_init),
                        DLSYM_ARG(EVP_aes_256_ctr),
                        DLSYM_ARG(EVP_aes_256_gcm),
                        DLSYM_ARG(EVP_get_cipherbyname),
                        DLSYM_ARG(EVP_get_digestbyname),
                        DLSYM_ARG(EVP_sha1),
                        DLSYM_ARG(EVP_sha256),
                        DLSYM_ARG(EVP_sha384),
                        DLSYM_ARG(EVP_sha512),
                        DLSYM_ARG(HMAC),
                        DLSYM_ARG(OBJ_nid2obj),
                        DLSYM_ARG(OBJ_nid2sn),
                        DLSYM_ARG(OBJ_sn2nid),
                        DLSYM_ARG(OBJ_txt2obj),
                        DLSYM_ARG(OPENSSL_sk_new_null),
                        DLSYM_ARG(OPENSSL_sk_num),
                        DLSYM_ARG(OPENSSL_sk_pop_free),
                        DLSYM_ARG(OPENSSL_sk_push),
                        DLSYM_ARG(OPENSSL_sk_value),
                        DLSYM_ARG(OSSL_EC_curve_nid2name),
                        DLSYM_ARG(OSSL_PARAM_BLD_free),
                        DLSYM_ARG(OSSL_PARAM_BLD_new),
                        DLSYM_ARG(OSSL_PARAM_BLD_push_octet_string),
                        DLSYM_ARG(OSSL_PARAM_BLD_push_utf8_string),
                        DLSYM_ARG(OSSL_PARAM_BLD_to_param),
                        DLSYM_ARG(OSSL_PARAM_construct_BN),
                        DLSYM_ARG(OSSL_PARAM_construct_end),
                        DLSYM_ARG(OSSL_PARAM_construct_octet_string),
                        DLSYM_ARG(OSSL_PARAM_construct_utf8_string),
                        DLSYM_ARG(OSSL_PARAM_free),
                        DLSYM_ARG(OSSL_PROVIDER_try_load),
                        DLSYM_ARG(OSSL_STORE_INFO_free),
                        DLSYM_ARG(OSSL_STORE_INFO_get1_CERT),
                        DLSYM_ARG(OSSL_STORE_INFO_get1_PKEY),
                        DLSYM_ARG(OSSL_STORE_close),
                        DLSYM_ARG(OSSL_STORE_expect),
                        DLSYM_ARG(OSSL_STORE_load),
                        DLSYM_ARG(OSSL_STORE_open),
                        DLSYM_ARG(PEM_read_PUBKEY),
                        DLSYM_ARG(PEM_read_PrivateKey),
                        DLSYM_ARG(PEM_read_X509),
                        DLSYM_ARG(PEM_read_bio_PrivateKey),
                        DLSYM_ARG(PEM_read_bio_X509),
                        DLSYM_ARG(PEM_write_PUBKEY),
                        DLSYM_ARG(PEM_write_PrivateKey),
                        DLSYM_ARG(PEM_write_X509),
                        DLSYM_ARG(PKCS5_PBKDF2_HMAC),
                        DLSYM_ARG(PKCS7_ATTR_SIGN_it),
                        DLSYM_ARG(PKCS7_SIGNER_INFO_free),
                        DLSYM_ARG(PKCS7_SIGNER_INFO_new),
                        DLSYM_ARG(PKCS7_SIGNER_INFO_set),
                        DLSYM_ARG(PKCS7_add0_attrib_signing_time),
                        DLSYM_ARG(PKCS7_add1_attrib_digest),
                        DLSYM_ARG(PKCS7_add_attrib_content_type),
                        DLSYM_ARG(PKCS7_add_attrib_smimecap),
                        DLSYM_ARG(PKCS7_add_certificate),
                        DLSYM_ARG(PKCS7_add_signed_attribute),
                        DLSYM_ARG(PKCS7_add_signer),
                        DLSYM_ARG(PKCS7_content_new),
                        DLSYM_ARG(PKCS7_ctrl),
                        DLSYM_ARG(PKCS7_dataFinal),
                        DLSYM_ARG(PKCS7_dataInit),
                        DLSYM_ARG(PKCS7_free),
                        DLSYM_ARG(PKCS7_get_signer_info),
                        DLSYM_ARG(PKCS7_new),
                        DLSYM_ARG(PKCS7_set_content),
                        DLSYM_ARG(PKCS7_set_type),
                        DLSYM_ARG(PKCS7_sign),
                        DLSYM_ARG(PKCS7_verify),
                        DLSYM_ARG(SHA1),
                        DLSYM_ARG(SHA512),
                        DLSYM_ARG(X509_ALGOR_free),
                        DLSYM_ARG(X509_ALGOR_set0),
                        DLSYM_ARG(X509_ATTRIBUTE_free),
                        DLSYM_ARG(X509_NAME_free),
                        DLSYM_ARG(X509_NAME_oneline),
                        DLSYM_ARG(X509_NAME_set),
                        DLSYM_ARG(X509_VERIFY_PARAM_set1_host),
                        DLSYM_ARG(X509_VERIFY_PARAM_set1_ip),
                        DLSYM_ARG(X509_VERIFY_PARAM_set_hostflags),
                        DLSYM_ARG(X509_free),
                        DLSYM_ARG(X509_get0_serialNumber),
                        DLSYM_ARG(X509_get_issuer_name),
                        DLSYM_ARG(X509_get_pubkey),
                        DLSYM_ARG(X509_get_signature_info),
                        DLSYM_ARG(X509_get_subject_name),
                        DLSYM_ARG(X509_gmtime_adj),
                        DLSYM_ARG(d2i_ASN1_OCTET_STRING),
                        DLSYM_ARG(d2i_ECPKParameters),
                        DLSYM_ARG(d2i_PKCS7),
                        DLSYM_ARG(d2i_PUBKEY),
                        DLSYM_ARG(d2i_X509),
                        DLSYM_ARG(i2d_ASN1_INTEGER),
                        DLSYM_ARG(i2d_PKCS7),
                        DLSYM_ARG(i2d_PKCS7_fp),
                        DLSYM_ARG(i2d_PUBKEY),
                        DLSYM_ARG(i2d_PUBKEY_fp),
                        DLSYM_ARG(i2d_PublicKey),
                        DLSYM_ARG(i2d_X509),
                        DLSYM_ARG(i2d_X509_NAME),
#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
                        DLSYM_ARG_FORCE(ENGINE_by_id),
                        DLSYM_ARG_FORCE(ENGINE_free),
                        DLSYM_ARG_FORCE(ENGINE_init),
                        DLSYM_ARG_FORCE(ENGINE_load_private_key),
#endif
#if !defined(OPENSSL_NO_DEPRECATED_3_0)
                        DLSYM_ARG_FORCE(EC_KEY_check_key),
                        DLSYM_ARG_FORCE(EC_KEY_free),
                        DLSYM_ARG_FORCE(EC_KEY_new),
                        DLSYM_ARG_FORCE(EC_KEY_set_group),
                        DLSYM_ARG_FORCE(EC_KEY_set_public_key),
                        DLSYM_ARG_FORCE(ECDSA_do_verify),
                        DLSYM_ARG_FORCE(ECDSA_SIG_new),
                        DLSYM_ARG_FORCE(ECDSA_SIG_set0),
                        DLSYM_ARG_FORCE(EVP_PKEY_assign),
                        DLSYM_ARG_FORCE(RSA_free),
                        DLSYM_ARG_FORCE(RSA_new),
                        DLSYM_ARG_FORCE(RSA_set0_key),
                        DLSYM_ARG_FORCE(RSA_size),
                        DLSYM_ARG_FORCE(RSAPublicKey_dup),
#endif
#ifndef OPENSSL_NO_UI_CONSOLE
                        DLSYM_ARG(UI_create_method),
                        DLSYM_ARG(UI_destroy_method),
                        DLSYM_ARG(UI_get_default_method),
                        DLSYM_ARG(UI_get_method),
                        DLSYM_ARG(UI_get_string_type),
                        DLSYM_ARG(UI_get0_output_string),
                        DLSYM_ARG(UI_method_get_ex_data),
                        DLSYM_ARG(UI_method_get_reader),
                        DLSYM_ARG(UI_method_set_ex_data),
                        DLSYM_ARG(UI_method_set_reader),
                        DLSYM_ARG(UI_OpenSSL),
                        DLSYM_ARG(UI_set_default_method),
                        DLSYM_ARG(UI_set_result),
#endif
                        NULL);
                if (r >= 0)
                        break;
        }
        if (r < 0) {
                log_full_errno(log_level, r, "Neither libcrypto.so.4 nor libcrypto.so.3 could be loaded");
                return -EOPNOTSUPP; /* turn into recognizable error */
        }

        return r;
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libcrypto support is not compiled in.");
#endif
}

#if HAVE_OPENSSL
int openssl_to_errno(unsigned long e) {
        if (e == 0)
                return -ENOTRECOVERABLE;

        if (ERR_SYSTEM_ERROR(e))
                /* ERR_GET_REASON() returns the raw errno in this case. OpenSSL can record a system error
                 * with a zero errno though (e.g. bio_sock2.c raises ERR_LIB_SYS with a socket error that
                 * "may be 0"), which would yield 0 here. Clamp that to -ENOTRECOVERABLE so we never return 0
                 * and break the negative-return invariant that the log_openssl_errors() call sites depend
                 * on. */
                return -ERR_GET_REASON(e) ?: -ENOTRECOVERABLE;

        switch (ERR_GET_REASON(e)) {

        case ERR_R_MALLOC_FAILURE:
                return -ENOMEM;

        case ERR_R_PASSED_NULL_PARAMETER:
        case ERR_R_PASSED_INVALID_ARGUMENT:
#ifdef ERR_R_INVALID_PROPERTY_DEFINITION
        case ERR_R_INVALID_PROPERTY_DEFINITION:
#endif
                return -EINVAL;

        case ERR_R_UNSUPPORTED:
        case ERR_R_FETCH_FAILED:
        case ERR_R_DISABLED:
                return -EOPNOTSUPP;

        case ERR_R_NESTED_ASN1_ERROR:
        case ERR_R_MISSING_ASN1_EOS:
                return -EBADMSG;

#ifdef ERR_R_INTERRUPTED_OR_CANCELLED
        case ERR_R_INTERRUPTED_OR_CANCELLED:
                return -EINTR;
#endif

        default:
                /* Includes the internal/should-not-happen reasons (ERR_R_INTERNAL_ERROR,
                 * ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, ERR_R_INIT_FAIL, ERR_R_OPERATION_FAIL, …) and the
                 * "error originated in sub-library X" markers, none of which have a meaningful errno. Use
                 * -ENOTRECOVERABLE for these opaque OpenSSL failures, matching the convention used for
                 * unexpected crypto/digest failures elsewhere in the tree, and keeping them distinct from
                 * genuine -EIO (disk/socket) errors. */
                return -ENOTRECOVERABLE;
        }
}

int log_openssl_errors_internal(int level, const char *file, int line, const char *func, const char *format, ...) {
        _cleanup_free_ char *prefix = NULL;
        va_list ap;
        int r;

        va_start(ap, format);
        r = vasprintf(&prefix, format, ap);
        va_end(ap);
        if (r < 0)
                return log_oom_full(level);

        char buf[512]; /* openssl docs require >= 256 */
        int ret = 0;
        for (;;) {
                unsigned long e = sym_ERR_get_error();
                if (e == 0)
                        break;

                sym_ERR_error_string_n(e, buf, sizeof(buf));

                /* The queue is drained oldest-first (ERR_get_error() is FIFO), and the oldest entry is
                 * normally the deepest, most-specific reason while newer entries are higher-level
                 * "came-from" wrappers that translate to the -ENOTRECOVERABLE fallback. Keep the first
                 * specific (non-fallback) errno we see, so a trailing wrapper can't shadow it. */
                int translated = openssl_to_errno(e);
                if (ret == 0 || (ret == -ENOTRECOVERABLE && translated != -ENOTRECOVERABLE))
                        ret = translated;

                log_internal(level, SYNTHETIC_ERRNO(translated), file, line, func, "%s: %s", prefix, buf);
        }

        if (ret == 0) /* The queue was empty. */
                return log_internal(level, SYNTHETIC_ERRNO(ENOTRECOVERABLE), file, line, func, "%s: No OpenSSL errors.", prefix);

        return ret;
}
#endif
