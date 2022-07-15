/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct UpdateSet UpdateSet;

#include "sysupdate-instance.h"

typedef enum UpdateSetFlags {
        UPDATE_NEWEST    = 1 << 0,
        UPDATE_AVAILABLE = 1 << 1,
        UPDATE_INSTALLED = 1 << 2,
        UPDATE_OBSOLETE  = 1 << 3,
        UPDATE_PROTECTED = 1 << 4,
} UpdateSetFlags;

struct UpdateSet {
        UpdateSetFlags flags;
        char *version;
        Instance **instances;
        size_t n_instances;
};

UpdateSet *update_set_free(UpdateSet *us);

int update_set_cmp(UpdateSet *const*a, UpdateSet *const*b);

const char *update_set_flags_to_color(UpdateSetFlags flags);
const char *update_set_flags_to_glyph(UpdateSetFlags flags);
