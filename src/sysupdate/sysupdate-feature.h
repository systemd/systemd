/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysupdate-transfer.h"

typedef struct Feature {
        char *id;

        char *title;
        char *documentation;

        bool enabled;

        Transfer **transfers;
        size_t n_transfers;
} Feature;

Feature *feature_new(void);
Feature *feature_free(Feature *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(Feature*, feature_free);

int feature_read_definition(Feature *f, const char *path, const char *const *conf_file_dirs);
