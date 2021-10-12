/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "cryptsetup-util.h"
#include "time-util.h"


int parse_integrity_options(
                const char *options,
                uint32_t *activate_flags,
                int *percent,
                usec_t *commit_time,
                char **data_device,
                char **integrity_alg);
