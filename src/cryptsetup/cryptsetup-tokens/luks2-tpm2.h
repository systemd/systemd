/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "tpm2-util.h"

struct crypt_device;

int acquire_luks2_key(
                const char *device,
                uint32_t pcr_mask,
                uint16_t pcr_bank,
                const void *pubkey,
                size_t pubkey_size,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                const char *pin,
                uint16_t primary_alg,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                TPM2Flags flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);
