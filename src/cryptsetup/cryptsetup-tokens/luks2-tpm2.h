/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "tpm2-util.h"

struct crypt_device;

int acquire_luks2_key(
                uint32_t pcr_mask,
                uint16_t pcr_bank,
                uint16_t primary_alg,
                const char *device,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                TPM2Flags flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);

int parse_luks2_tpm2_data(
                const char *json,
                uint32_t search_pcr_mask,
                uint32_t *ret_pcr_mask,
                uint16_t *ret_pcr_bank,
                uint16_t *ret_primary_alg,
                char **ret_base64_blob,
                char **ret_hex_policy_hash,
                TPM2Flags *ret_flags);
