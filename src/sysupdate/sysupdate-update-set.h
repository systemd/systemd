/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"
#include "sysupdate-update-set-flags.h"

typedef struct UpdateSet {
        UpdateSetFlags flags;
        char *version;
        Instance **instances;
        size_t n_instances;
} UpdateSet;

UpdateSet* update_set_free(UpdateSet *us);
int update_set_cmp(UpdateSet *const*a, UpdateSet *const*b);
