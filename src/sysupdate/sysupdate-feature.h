/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"

typedef struct Feature {
        unsigned n_ref;

        char *id;

        char *description;
        char *documentation;
        char *appstream;

        bool enabled;
} Feature;

Feature *feature_new(void);

Feature *feature_ref(Feature *f);
Feature *feature_unref(Feature *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(Feature*, feature_unref);

extern const struct hash_ops feature_hash_ops;

int feature_read_definition(Feature *f, const char *path, const char *const *conf_file_dirs);
