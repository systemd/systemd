/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "forward.h"

int acquire_tpm2_key(
                const char *volume_name,
                const char *device,
                uint32_t hash_pcr_mask,
                uint16_t pcr_bank,
                const struct iovec *pubkey,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                const char *pcrlock_path,
                uint16_t primary_alg,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const struct iovec blobs[],
                size_t n_blobs,
                const struct iovec policy_hash[],
                size_t n_policy_hash,
                const struct iovec *salt,
                const struct iovec *srk,
                const struct iovec *pcrlock_nv,
                TPM2Flags flags,
                usec_t until,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                struct iovec *ret_decrypted_key);

int find_tpm2_auto_data(
                struct crypt_device *cd,
                uint32_t search_pcr_mask,
                int start_token,
                uint32_t *ret_hash_pcr_mask,
                uint16_t *ret_pcr_bank,
                struct iovec *ret_pubkey,
                uint32_t *ret_pubkey_pcr_mask,
                uint16_t *ret_primary_alg,
                struct iovec **ret_blobs,
                size_t *ret_n_blobs,
                struct iovec **ret_policy_hash,
                size_t *ret_n_policy_hash,
                struct iovec *ret_salt,
                struct iovec *ret_srk,
                struct iovec *ret_pcrlock_nv,
                TPM2Flags *ret_flags,
                int *ret_keyslot,
                int *ret_token);
