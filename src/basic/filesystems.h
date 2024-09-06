/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "nulstr-util.h"
#include "stat-util.h"
#include "string-util.h"

#define FILESYSTEM_MAGIC_MAX 10

typedef enum FilesystemGroups {
        /* Please leave BASIC_API first and KNOWN last, but sort the rest alphabetically */
        FILESYSTEM_SET_BASIC_API,
        FILESYSTEM_SET_ANONYMOUS,
        FILESYSTEM_SET_APPLICATION,
        FILESYSTEM_SET_AUXILIARY_API,
        FILESYSTEM_SET_COMMON_BLOCK,
        FILESYSTEM_SET_HISTORICAL_BLOCK,
        FILESYSTEM_SET_NETWORK,
        FILESYSTEM_SET_PRIVILEGED_API,
        FILESYSTEM_SET_SECURITY,
        FILESYSTEM_SET_TEMPORARY,
        FILESYSTEM_SET_KNOWN,
        _FILESYSTEM_SET_MAX,
        _FILESYSTEM_SET_INVALID = -EINVAL,
} FilesystemGroups;

typedef struct FilesystemSet {
        const char *name;
        const char *help;
        const char *value;
} FilesystemSet;

extern const FilesystemSet filesystem_sets[];

const FilesystemSet *filesystem_set_find(const char *name);

const char* fs_type_to_string(statfs_f_type_t magic);
int fs_type_from_string(const char *name, const statfs_f_type_t **ret);
bool fs_in_group(const struct statfs *s, enum FilesystemGroups fs_group);

/* gperf prototypes */
const struct FilesystemMagic* filesystems_gperf_lookup(const char *key, GPERF_LEN_TYPE length);
