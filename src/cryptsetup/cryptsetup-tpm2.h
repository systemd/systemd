/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "log.h"
#include "time-util.h"

#if HAVE_TPM2

int acquire_tpm2_key(
                const char *volume_name,
                const char *device,
                uint32_t pcr_mask,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);

#else

static inline int acquire_tpm2_key(
                const char *volume_name,
                const char *device,
                uint32_t pcr_mask,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "TPM2 support not available.");
}

#endif
