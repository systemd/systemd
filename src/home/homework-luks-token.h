/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "forward.h"

#define HOME_LUKS_TOKEN_V2_IV_SIZE 12U
#define HOME_LUKS_TOKEN_V2_TAG_SIZE 16U
#define HOME_LUKS_TOKEN_V2_KEY_SIZE 32U

int home_luks_token_encrypt_legacy(
                const void *plaintext,
                size_t plaintext_size,
                const EVP_CIPHER *cipher,
                const void *volume_key,
                size_t volume_key_size,
                const void *iv,
                size_t iv_size,
                char **ret);

int home_luks_token_decrypt_legacy(
                sd_json_variant *token,
                const EVP_CIPHER *cipher,
                const void *volume_key,
                size_t volume_key_size,
                void **ret_plaintext,
                size_t *ret_plaintext_size);

int home_luks_token_encrypt_v2(
                const void *plaintext,
                size_t plaintext_size,
                const void *software_secret,
                size_t software_secret_size,
                const char *luks_uuid,
                const uint8_t iv[static HOME_LUKS_TOKEN_V2_IV_SIZE],
                char **ret);

int home_luks_token_decrypt_v2(
                sd_json_variant *token,
                const void *software_secret,
                size_t software_secret_size,
                const char *luks_uuid,
                void **ret_plaintext,
                size_t *ret_plaintext_size);
