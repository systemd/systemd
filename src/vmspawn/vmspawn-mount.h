/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct RuntimeMount {
        bool read_only;
        char *source;
        char *target;
} RuntimeMount;

void runtime_mount_free_all(RuntimeMount *l, size_t n);
int runtime_mount_parse(RuntimeMount **l, size_t *n, const char *s, bool read_only);
