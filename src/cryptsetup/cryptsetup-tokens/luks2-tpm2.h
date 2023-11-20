/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "tpm2-util.h"

struct crypt_device;

int acquire_luks2_key(
                const char *device,
                uint32_t pcr_mask,
                uint16_t pcr_bank,
                const struct iovec *pubkey,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                const char *pcrlock_path,
                const char *pin,
                uint16_t primary_alg,
                const struct iovec *key_data,
                const struct iovec *policy_hash,
                const struct iovec *salt,
                const struct iovec *srk,
                TPM2Flags flags,
                struct iovec *decrypted_key);
