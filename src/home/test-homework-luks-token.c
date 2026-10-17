/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "crypto-util.h"
#include "homework-luks-token.h"
#include "memory-util.h"
#include "strv.h"
#include "tests.h"

static const uint8_t test_secret[HOME_LUKS_TOKEN_V2_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const uint8_t test_iv[HOME_LUKS_TOKEN_V2_IV_SIZE] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
        0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
};
static const char test_uuid[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char test_plaintext[] = "{\"userName\":\"alice\",\"uid\":1000}";

static sd_json_variant* parse_token(const char *text);

TEST(legacy_roundtrip) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *token = NULL;
        _cleanup_free_ char *text = NULL;
        _cleanup_(erase_and_freep) void *plaintext = NULL;
        uint8_t iv[16], volume_key[64];
        const EVP_CIPHER *cipher;
        size_t plaintext_size = 0;

        for (size_t i = 0; i < sizeof(volume_key); i++)
                volume_key[i] = (uint8_t) i;
        for (size_t i = 0; i < sizeof(iv); i++)
                iv[i] = (uint8_t) (0x80U + i);

        ASSERT_OK(dlopen_libcrypto(LOG_DEBUG));
        ASSERT_NOT_NULL(cipher = sym_EVP_get_cipherbyname("aes-256-xts"));
        ASSERT_OK(home_luks_token_encrypt_legacy(
                          test_plaintext,
                          strlen(test_plaintext),
                          cipher,
                          volume_key,
                          sizeof(volume_key),
                          iv,
                          sizeof(iv),
                          &text));

        token = parse_token(text);
        ASSERT_NULL(sd_json_variant_by_key(token, "version"));
        ASSERT_NOT_NULL(sd_json_variant_by_key(token, "record"));
        ASSERT_NOT_NULL(sd_json_variant_by_key(token, "iv"));

        ASSERT_OK(home_luks_token_decrypt_legacy(
                          token,
                          cipher,
                          volume_key,
                          sizeof(volume_key),
                          &plaintext,
                          &plaintext_size));
        ASSERT_EQ(plaintext_size, strlen(test_plaintext));
        ASSERT_EQ(memcmp(plaintext, test_plaintext, plaintext_size), 0);

        ASSERT_OK(sd_json_variant_set_field_unsigned(&token, "version", 2));
        plaintext = erase_and_free(plaintext);
        ASSERT_ERROR(home_luks_token_decrypt_legacy(
                             token,
                             cipher,
                             volume_key,
                             sizeof(volume_key),
                             &plaintext,
                             &plaintext_size), EINVAL);
}

static sd_json_variant* parse_token(const char *text) {
        sd_json_variant *token = NULL;

        ASSERT_OK(sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_SENSITIVE,
                                &token, NULL, NULL));
        return token;
}

static void assert_decrypts(sd_json_variant *token) {
        _cleanup_(erase_and_freep) void *plaintext = NULL;
        size_t plaintext_size = 0;

        ASSERT_OK(home_luks_token_decrypt_v2(
                          token,
                          test_secret,
                          sizeof(test_secret),
                          test_uuid,
                          &plaintext,
                          &plaintext_size));
        ASSERT_EQ(plaintext_size, strlen(test_plaintext));
        ASSERT_EQ(memcmp(plaintext, test_plaintext, plaintext_size), 0);
}

static void corrupt_binary_field(sd_json_variant **token, const char *name, bool truncate) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *encoded = NULL;
        _cleanup_free_ void *data = NULL;
        size_t size;

        ASSERT_OK(sd_json_variant_unbase64(sd_json_variant_by_key(*token, name), &data, &size));
        ASSERT_GT(size, 1U);
        if (truncate)
                size--;
        else
                ((uint8_t*) data)[0] ^= 1U;

        ASSERT_OK(sd_json_variant_new_base64(&encoded, data, size));
        ASSERT_OK(sd_json_variant_set_field(token, name, encoded));
}

TEST(v2_roundtrip_and_fail_closed) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *token = NULL;
        _cleanup_free_ char *text = NULL, *text_again = NULL;
        _cleanup_(erase_and_freep) void *plaintext = NULL;
        uint8_t wrong_secret[sizeof(test_secret)];
        size_t plaintext_size = 0;

        ASSERT_OK(home_luks_token_encrypt_v2(
                          test_plaintext,
                          strlen(test_plaintext),
                          test_secret,
                          sizeof(test_secret),
                          test_uuid,
                          test_iv,
                          &text));
        ASSERT_OK(home_luks_token_encrypt_v2(
                          test_plaintext,
                          strlen(test_plaintext),
                          test_secret,
                          sizeof(test_secret),
                          test_uuid,
                          test_iv,
                          &text_again));
        ASSERT_STREQ(text, text_again);

        token = parse_token(text);
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(token, "version")), 2U);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(token, "cipher")), "aes-256-gcm");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(token, "kdf")), "hkdf-sha256");
        assert_decrypts(token);

        memcpy(wrong_secret, test_secret, sizeof(wrong_secret));
        wrong_secret[0] ^= 1U;
        ASSERT_ERROR(home_luks_token_decrypt_v2(
                             token, wrong_secret, sizeof(wrong_secret), test_uuid,
                             &plaintext, &plaintext_size), EBADMSG);
        ASSERT_ERROR(home_luks_token_decrypt_v2(
                             token, test_secret, sizeof(test_secret),
                             "fedcba98-7654-3210-fedc-ba9876543210",
                             &plaintext, &plaintext_size), EBADMSG);

        token = sd_json_variant_unref(token);
        token = parse_token(text);
        ASSERT_OK(sd_json_variant_set_field_string(&token, "cipher", "aes-128-gcm"));
        ASSERT_ERROR(home_luks_token_decrypt_v2(
                             token, test_secret, sizeof(test_secret), test_uuid,
                             &plaintext, &plaintext_size), EINVAL);

        token = sd_json_variant_unref(token);
        token = parse_token(text);
        ASSERT_OK(sd_json_variant_set_field_unsigned(&token, "version", 3));
        ASSERT_ERROR(home_luks_token_decrypt_v2(
                             token, test_secret, sizeof(test_secret), test_uuid,
                             &plaintext, &plaintext_size), EINVAL);

        FOREACH_STRING(field, "iv", "tag", "ciphertext") {
                token = sd_json_variant_unref(token);
                token = parse_token(text);
                corrupt_binary_field(&token, field, false);
                ASSERT_ERROR(home_luks_token_decrypt_v2(
                                     token, test_secret, sizeof(test_secret), test_uuid,
                                     &plaintext, &plaintext_size), EBADMSG);
        }

        token = sd_json_variant_unref(token);
        token = parse_token(text);
        corrupt_binary_field(&token, "ciphertext", true);
        ASSERT_ERROR(home_luks_token_decrypt_v2(
                             token, test_secret, sizeof(test_secret), test_uuid,
                             &plaintext, &plaintext_size), EBADMSG);
}

DEFINE_TEST_MAIN(LOG_INFO);
