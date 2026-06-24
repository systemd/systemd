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

        int suggest;
        Condition *suggest_on;
} Feature;

Feature *feature_new(void);

DECLARE_TRIVIAL_REF_UNREF_FUNC(Feature, feature);
DEFINE_TRIVIAL_CLEANUP_FUNC(Feature*, feature_unref);

extern const struct hash_ops feature_hash_ops;

int feature_read_definition(Feature *f, const char *root, const char *path, const char *const *conf_file_dirs);

int feature_is_suggested(Feature *f);
