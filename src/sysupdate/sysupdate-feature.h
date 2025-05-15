/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hash-funcs.h"
#include "memory-util.h"

typedef struct Feature {
        char *id;

        char *description;
        char *documentation;
        char *appstream;

        unsigned n_ref;

        bool enabled;
} Feature;

Feature *feature_new(void);

Feature *feature_ref(Feature *f);
Feature *feature_unref(Feature *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(Feature*, feature_unref);

extern const struct hash_ops feature_hash_ops;

int feature_read_definition(Feature *f, const char *path, const char *const *conf_file_dirs);
