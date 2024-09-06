/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct UpdateSet UpdateSet;

#include "sysupdate-instance.h"
#include "sysupdate-update-set-flags.h"

struct UpdateSet {
        UpdateSetFlags flags;
        char *version;
        Instance **instances;
        size_t n_instances;
};

UpdateSet* update_set_free(UpdateSet *us);
int update_set_cmp(UpdateSet *const*a, UpdateSet *const*b);
