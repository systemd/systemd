/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum {
        INTEGRITY_ALGORITHM_CRC32,
        INTEGRITY_ALGORITHM_CRC32C,
        INTEGRITY_ALGORITHM_XXHASH64,
        INTEGRITY_ALGORITHM_SHA1,
        INTEGRITY_ALGORITHM_SHA256,
        INTEGRITY_ALGORITHM_HMAC_SHA256,
        INTEGRITY_ALGORITHM_HMAC_SHA512,
        INTEGRITY_ALGORITHM_PHMAC_SHA256,
        INTEGRITY_ALGORITHM_PHMAC_SHA512,
        _INTEGRITY_ALGORITHM_MAX,
        _INTEGRITY_ALGORITHM_INVALID = -EINVAL,
} IntegrityAlgorithm;

int parse_integrity_options(
                const char *options,
                uint32_t *ret_activate_flags,
                int *ret_percent,
                usec_t *ret_commit_time,
                char **ret_data_device,
                IntegrityAlgorithm *ret_integrity_alg);

#define DM_MAX_KEY_SIZE 4096            /* Maximum size of key allowed for dm-integrity */
