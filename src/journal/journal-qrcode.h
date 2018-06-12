/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdio.h>

#include "sd-id128.h"

int print_qr_code(FILE *f, const void *seed, size_t seed_size, uint64_t start, uint64_t interval, const char *hn, sd_id128_t machine);
