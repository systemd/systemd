/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>

#include "sd-id128.h"

typedef enum Id128PrettyPrintMode {
        ID128_PRINT_ID128,
        ID128_PRINT_UUID,
        ID128_PRINT_PRETTY,
        _ID128_PRETTY_PRINT_MODE_MAX,
        _ID128_PRETTY_PRINT_MODE_INVALID = -EINVAL,
} Id128PrettyPrintMode;

int id128_pretty_print_sample(const char *name, sd_id128_t id);
int id128_pretty_print(sd_id128_t id, Id128PrettyPrintMode mode);
int id128_print_new(Id128PrettyPrintMode mode);
