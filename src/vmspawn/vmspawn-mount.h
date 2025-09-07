/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct RuntimeMount {
        bool read_only;
        char *source;
        uid_t source_uid;
        char *target;
        uid_t target_uid;
} RuntimeMount;

typedef struct RuntimeMountContext {
        RuntimeMount *mounts;
        size_t n_mounts;
} RuntimeMountContext;

void runtime_mount_done(RuntimeMount *mount);
void runtime_mount_context_done(RuntimeMountContext *ctx);
int runtime_mount_parse(RuntimeMountContext *ctx, const char *s, bool read_only);
