/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "stat-util.h"
#include "nulstr-util.h"
#include "string-util.h"

typedef enum FilesystemGroups {
        /* Please leave BASIC_API first and KNOWN last, but sort the rest alphabetically */
        FILESYSTEM_SET_BASIC_API,
        FILESYSTEM_SET_COMMON_BLOCK,
        FILESYSTEM_SET_NETWORK,
        FILESYSTEM_SET_TEMPORARY,
        FILESYSTEM_SET_KNOWN,
        _FILESYSTEM_SET_MAX
} FilesystemGroups;

typedef struct FilesystemSet {
        const char *name;
        const char *help;
        const char *value;
} FilesystemSet;

extern const FilesystemSet filesystem_sets[];

const FilesystemSet *filesystem_set_find(const char *name);

int fs_type_from_string(const char *name, statfs_f_type_t **ret);
int fs_in_group(const struct statfs *s, enum FilesystemGroups fs_group);

/* gperf prototypes */
const struct FilesystemMagic* filesystems_gperf_lookup(const char *key, GPERF_LEN_TYPE length);
