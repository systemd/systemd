/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "cryptsetup-util.h"
#include "time-util.h"

int parse_integrity_options(
                const char *options,
                uint32_t *ret_activate_flags,
                int *ret_percent,
                usec_t *ret_commit_time,
                char **ret_data_device,
                char **ret_integrity_alg);

#define DM_HMAC_256 "hmac(sha256)"
#define DM_MAX_KEY_SIZE 4096            /* Maximum size of key allowed for dm-integrity */
