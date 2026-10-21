/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <openssl/evp.h>

#include "sd-id128.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "crypto-util.h"
#include "errno-util.h"
#include "homework-luks-token.h"
#include "iovec-util.h"
#include "memory-util.h"
#include "string-util.h"

#define HOME_LUKS_TOKEN_V2_CIPHER "aes-256-gcm"
#define HOME_LUKS_TOKEN_V2_KDF "hkdf-sha256"

static const uint8_t home_luks_token_v2_hkdf_info[] =
        "systemd-homed identity-token v2";
static const uint8_t home_luks_token_v2_aad[] =
        "type=systemd-homed\0"
        "version=2\0"
        "cipher=" HOME_LUKS_TOKEN_V2_CIPHER "\0"
        "kdf=" HOME_LUKS_TOKEN_V2_KDF "\0";

int home_luks_token_encrypt_legacy(
                const void *plaintext,
                size_t plaintext_size,
                const EVP_CIPHER *cipher,
                const void *volume_key,
                size_t volume_key_size,
                const void *iv,
                size_t iv_size,
                char **ret) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *token = NULL;
        _cleanup_(erase_and_freep) void *ciphertext = NULL;
        int encrypted_size_out1 = 0, encrypted_size_out2 = 0;
        size_t ciphertext_size;
        int r;

        assert(plaintext);
        assert(plaintext_size > 0);
        assert(cipher);
        assert(volume_key);
        assert(ret);

        if (plaintext_size > INT_MAX || volume_key_size != (size_t) sym_EVP_CIPHER_get_key_length(cipher) ||
            iv_size != (size_t) sym_EVP_CIPHER_get_iv_length(cipher) || (iv_size > 0 && !iv))
                return -EINVAL;

        if (__builtin_add_overflow(plaintext_size,
                                   (size_t) sym_EVP_CIPHER_get_block_size(cipher),
                                   &ciphertext_size))
                return -EOVERFLOW;

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return -ENOMEM;

        if (sym_EVP_EncryptInit_ex(context, cipher, NULL, volume_key, iv) != 1)
                return -EINVAL;

        ciphertext = malloc(ciphertext_size);
        if (!ciphertext)
                return -ENOMEM;

        if (sym_EVP_EncryptUpdate(context, ciphertext, &encrypted_size_out1,
                                  plaintext, (int) plaintext_size) != 1)
                return -EINVAL;
        if (sym_EVP_EncryptFinal_ex(context,
                                    (uint8_t*) ciphertext + encrypted_size_out1,
                                    &encrypted_size_out2) != 1)
                return -EINVAL;

        assert((size_t) encrypted_size_out1 + (size_t) encrypted_size_out2 <= ciphertext_size);
        ciphertext_size = (size_t) encrypted_size_out1 + (size_t) encrypted_size_out2;

        r = sd_json_buildo(
                        &token,
                        SD_JSON_BUILD_PAIR_STRING("type", "systemd-homed"),
                        SD_JSON_BUILD_PAIR("keyslots", SD_JSON_BUILD_EMPTY_ARRAY),
                        SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_BASE64(ciphertext, ciphertext_size)),
                        SD_JSON_BUILD_PAIR("iv", SD_JSON_BUILD_BASE64(iv, iv_size)));
        if (r < 0)
                return r;

        return sd_json_variant_format(token, 0, ret);
}

int home_luks_token_decrypt_legacy(
                sd_json_variant *token,
                const EVP_CIPHER *cipher,
                const void *volume_key,
                size_t volume_key_size,
                void **ret_plaintext,
                size_t *ret_plaintext_size) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_free_ void *ciphertext = NULL, *iv = NULL;
        _cleanup_(erase_and_freep) void *plaintext = NULL;
        int decrypted_size_out1 = 0, decrypted_size_out2 = 0;
        size_t ciphertext_size, iv_size, plaintext_size;
        sd_json_variant *field;
        int r;

        assert(token);
        assert(cipher);
        assert(volume_key);
        assert(ret_plaintext);
        assert(ret_plaintext_size);

        *ret_plaintext = NULL;
        *ret_plaintext_size = 0;

        if (volume_key_size != (size_t) sym_EVP_CIPHER_get_key_length(cipher))
                return -EINVAL;

        field = sd_json_variant_by_key(token, "type");
        if (!field || !streq_ptr(sd_json_variant_string(field), "systemd-homed"))
                return -EINVAL;
        if (sd_json_variant_by_key(token, "version"))
                return -EINVAL;

        field = sd_json_variant_by_key(token, "record");
        if (!field)
                return -EINVAL;
        r = sd_json_variant_unbase64(field, &ciphertext, &ciphertext_size);
        if (r < 0 || ciphertext_size == 0 || ciphertext_size > INT_MAX)
                return -EINVAL;

        field = sd_json_variant_by_key(token, "iv");
        if (!field)
                return -EINVAL;
        r = sd_json_variant_unbase64(field, &iv, &iv_size);
        if (r < 0 || iv_size != (size_t) sym_EVP_CIPHER_get_iv_length(cipher))
                return -EINVAL;

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return -ENOMEM;
        if (sym_EVP_DecryptInit_ex(context, cipher, NULL, volume_key, iv) != 1)
                return -EINVAL;

        if (__builtin_add_overflow(ciphertext_size,
                                   (size_t) sym_EVP_CIPHER_get_block_size(cipher),
                                   &plaintext_size) ||
            __builtin_add_overflow(plaintext_size, 1U, &plaintext_size))
                return -EOVERFLOW;

        plaintext = malloc(plaintext_size);
        if (!plaintext)
                return -ENOMEM;

        if (sym_EVP_DecryptUpdate(context, plaintext, &decrypted_size_out1,
                                  ciphertext, (int) ciphertext_size) != 1)
                return -EINVAL;
        if (sym_EVP_DecryptFinal_ex(context,
                                    (uint8_t*) plaintext + decrypted_size_out1,
                                    &decrypted_size_out2) != 1)
                return -EBADMSG;

        assert((size_t) decrypted_size_out1 + (size_t) decrypted_size_out2 < plaintext_size);
        plaintext_size = (size_t) decrypted_size_out1 + (size_t) decrypted_size_out2;
        ((uint8_t*) plaintext)[plaintext_size] = 0;

        *ret_plaintext = TAKE_PTR(plaintext);
        *ret_plaintext_size = plaintext_size;
        return 0;
}

static int home_luks_token_v2_derive_key(
                const void *software_secret,
                size_t software_secret_size,
                sd_id128_t luks_uuid,
                struct iovec *ret) {

        assert(software_secret);
        assert(software_secret_size > 0);
        assert(ret);

        return kdf_hkdf_sha256(
                        &IOVEC_MAKE((void*) software_secret, software_secret_size),
                        &IOVEC_MAKE(luks_uuid.bytes, sizeof(luks_uuid.bytes)),
                        &IOVEC_MAKE((void*) home_luks_token_v2_hkdf_info,
                                    sizeof(home_luks_token_v2_hkdf_info) - 1),
                        HOME_LUKS_TOKEN_V2_KEY_SIZE,
                        ret);
}

static int home_luks_token_v2_add_aad(EVP_CIPHER_CTX *context, bool encrypt, sd_id128_t luks_uuid) {
        int added;

        assert(context);

        if (encrypt) {
                if (sym_EVP_EncryptUpdate(context, NULL, &added,
                                          home_luks_token_v2_aad,
                                          (int) sizeof(home_luks_token_v2_aad)) != 1)
                        return -EINVAL;
                if (sym_EVP_EncryptUpdate(context, NULL, &added,
                                          luks_uuid.bytes,
                                          (int) sizeof(luks_uuid.bytes)) != 1)
                        return -EINVAL;
        } else {
                if (sym_EVP_DecryptUpdate(context, NULL, &added,
                                          home_luks_token_v2_aad,
                                          (int) sizeof(home_luks_token_v2_aad)) != 1)
                        return -EINVAL;
                if (sym_EVP_DecryptUpdate(context, NULL, &added,
                                          luks_uuid.bytes,
                                          (int) sizeof(luks_uuid.bytes)) != 1)
                        return -EINVAL;
        }

        return 0;
}

int home_luks_token_encrypt_v2(
                const void *plaintext,
                size_t plaintext_size,
                const void *software_secret,
                size_t software_secret_size,
                const char *luks_uuid,
                const uint8_t iv[static HOME_LUKS_TOKEN_V2_IV_SIZE],
                char **ret) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(iovec_done_erase) struct iovec key = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *token = NULL;
        _cleanup_(erase_and_freep) void *ciphertext = NULL;
        uint8_t tag[HOME_LUKS_TOKEN_V2_TAG_SIZE] = {};
        int encrypted_size_out1 = 0, encrypted_size_out2 = 0;
        size_t ciphertext_size;
        sd_id128_t uuid;
        const EVP_CIPHER *cipher;
        int r;

        assert(plaintext);
        assert(plaintext_size > 0);
        assert(software_secret);
        assert(software_secret_size == HOME_LUKS_TOKEN_V2_KEY_SIZE);
        assert(luks_uuid);
        assert(iv);
        assert(ret);

        if (plaintext_size > INT_MAX)
                return -E2BIG;

        CLEANUP_ERASE(tag);

        r = sd_id128_from_string(luks_uuid, &uuid);
        if (r < 0)
                return -EINVAL;

        r = home_luks_token_v2_derive_key(software_secret, software_secret_size, uuid, &key);
        if (r < 0)
                return r;

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return -ENOMEM;

        assert_se(cipher = sym_EVP_aes_256_gcm());
        if (sym_EVP_EncryptInit_ex(context, cipher, NULL, NULL, NULL) != 1)
                return -EINVAL;
        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                                    HOME_LUKS_TOKEN_V2_IV_SIZE, NULL) != 1)
                return -EINVAL;
        if (sym_EVP_EncryptInit_ex(context, NULL, NULL, key.iov_base, iv) != 1)
                return -EINVAL;

        r = home_luks_token_v2_add_aad(context, true, uuid);
        if (r < 0)
                return r;

        if (__builtin_add_overflow(plaintext_size,
                                   (size_t) sym_EVP_CIPHER_get_block_size(cipher),
                                   &ciphertext_size))
                return -EOVERFLOW;

        ciphertext = malloc(ciphertext_size);
        if (!ciphertext)
                return -ENOMEM;

        if (sym_EVP_EncryptUpdate(context, ciphertext, &encrypted_size_out1,
                                  plaintext, (int) plaintext_size) != 1)
                return -EINVAL;
        if (sym_EVP_EncryptFinal_ex(context,
                                    (uint8_t*) ciphertext + encrypted_size_out1,
                                    &encrypted_size_out2) != 1)
                return -EINVAL;

        assert((size_t) encrypted_size_out1 + (size_t) encrypted_size_out2 <= ciphertext_size);
        ciphertext_size = (size_t) encrypted_size_out1 + (size_t) encrypted_size_out2;

        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                                    (int) sizeof(tag), tag) != 1)
                return -EINVAL;

        r = sd_json_buildo(
                        &token,
                        SD_JSON_BUILD_PAIR_STRING("type", "systemd-homed"),
                        SD_JSON_BUILD_PAIR("keyslots", SD_JSON_BUILD_EMPTY_ARRAY),
                        SD_JSON_BUILD_PAIR_UNSIGNED("version", 2),
                        SD_JSON_BUILD_PAIR_STRING("cipher", HOME_LUKS_TOKEN_V2_CIPHER),
                        SD_JSON_BUILD_PAIR_STRING("kdf", HOME_LUKS_TOKEN_V2_KDF),
                        SD_JSON_BUILD_PAIR("iv", SD_JSON_BUILD_BASE64(iv, HOME_LUKS_TOKEN_V2_IV_SIZE)),
                        SD_JSON_BUILD_PAIR("tag", SD_JSON_BUILD_BASE64(tag, sizeof(tag))),
                        SD_JSON_BUILD_PAIR("ciphertext", SD_JSON_BUILD_BASE64(ciphertext, ciphertext_size)));
        if (r < 0)
                return r;

        return sd_json_variant_format(token, 0, ret);
}

int home_luks_token_decrypt_v2(
                sd_json_variant *token,
                const void *software_secret,
                size_t software_secret_size,
                const char *luks_uuid,
                void **ret_plaintext,
                size_t *ret_plaintext_size) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(iovec_done_erase) struct iovec key = {};
        _cleanup_free_ void *ciphertext = NULL, *iv = NULL, *tag = NULL;
        _cleanup_(erase_and_freep) void *plaintext = NULL;
        sd_json_variant *field;
        size_t ciphertext_size, iv_size, plaintext_size, tag_size;
        int decrypted_size_out1 = 0, decrypted_size_out2 = 0;
        sd_id128_t uuid;
        const EVP_CIPHER *cipher;
        int r;

        assert(token);
        assert(software_secret);
        assert(software_secret_size == HOME_LUKS_TOKEN_V2_KEY_SIZE);
        assert(luks_uuid);
        assert(ret_plaintext);
        assert(ret_plaintext_size);

        *ret_plaintext = NULL;
        *ret_plaintext_size = 0;

        field = sd_json_variant_by_key(token, "type");
        if (!field || !streq_ptr(sd_json_variant_string(field), "systemd-homed"))
                return -EINVAL;
        field = sd_json_variant_by_key(token, "version");
        if (!sd_json_variant_is_unsigned(field) || sd_json_variant_unsigned(field) != 2)
                return -EINVAL;
        field = sd_json_variant_by_key(token, "cipher");
        if (!field || !streq_ptr(sd_json_variant_string(field), HOME_LUKS_TOKEN_V2_CIPHER))
                return -EINVAL;
        field = sd_json_variant_by_key(token, "kdf");
        if (!field || !streq_ptr(sd_json_variant_string(field), HOME_LUKS_TOKEN_V2_KDF))
                return -EINVAL;

        field = sd_json_variant_by_key(token, "iv");
        if (!field)
                return -EINVAL;
        r = sd_json_variant_unbase64(field, &iv, &iv_size);
        if (r < 0 || iv_size != HOME_LUKS_TOKEN_V2_IV_SIZE)
                return -EINVAL;
        field = sd_json_variant_by_key(token, "tag");
        if (!field)
                return -EINVAL;
        r = sd_json_variant_unbase64(field, &tag, &tag_size);
        if (r < 0 || tag_size != HOME_LUKS_TOKEN_V2_TAG_SIZE)
                return -EINVAL;
        field = sd_json_variant_by_key(token, "ciphertext");
        if (!field)
                return -EINVAL;
        r = sd_json_variant_unbase64(field, &ciphertext, &ciphertext_size);
        if (r < 0 || ciphertext_size == 0 || ciphertext_size > INT_MAX)
                return -EINVAL;

        r = sd_id128_from_string(luks_uuid, &uuid);
        if (r < 0)
                return -EINVAL;

        r = home_luks_token_v2_derive_key(software_secret, software_secret_size, uuid, &key);
        if (r < 0)
                return r;

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return -ENOMEM;

        assert_se(cipher = sym_EVP_aes_256_gcm());
        if (sym_EVP_DecryptInit_ex(context, cipher, NULL, NULL, NULL) != 1)
                return -EINVAL;
        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int) iv_size, NULL) != 1)
                return -EINVAL;
        if (sym_EVP_DecryptInit_ex(context, NULL, NULL, key.iov_base, iv) != 1)
                return -EINVAL;

        r = home_luks_token_v2_add_aad(context, false, uuid);
        if (r < 0)
                return r;

        if (__builtin_add_overflow(ciphertext_size,
                                   (size_t) sym_EVP_CIPHER_get_block_size(cipher),
                                   &plaintext_size))
                return -EOVERFLOW;

        plaintext = malloc(plaintext_size);
        if (!plaintext)
                return -ENOMEM;

        if (sym_EVP_DecryptUpdate(context, plaintext, &decrypted_size_out1,
                                  ciphertext, (int) ciphertext_size) != 1)
                return -EINVAL;

        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, (int) tag_size, tag) != 1)
                return -EINVAL;
        if (sym_EVP_DecryptFinal_ex(context,
                                    (uint8_t*) plaintext + decrypted_size_out1,
                                    &decrypted_size_out2) != 1)
                return -EBADMSG;

        assert((size_t) decrypted_size_out1 + (size_t) decrypted_size_out2 <= plaintext_size);
        plaintext_size = (size_t) decrypted_size_out1 + (size_t) decrypted_size_out2;
        ((uint8_t*) plaintext)[plaintext_size] = 0;

        *ret_plaintext = TAKE_PTR(plaintext);
        *ret_plaintext_size = plaintext_size;
        return 0;
}
