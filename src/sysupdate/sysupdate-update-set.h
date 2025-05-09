/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "sysupdate-update-set-flags.h"

typedef struct Instance Instance;
typedef struct UpdateSet UpdateSet;

struct UpdateSet {
        UpdateSetFlags flags;
        char *version;
        Instance **instances;
        size_t n_instances;
};

UpdateSet* update_set_free(UpdateSet *us);
int update_set_cmp(UpdateSet *const*a, UpdateSet *const*b);
