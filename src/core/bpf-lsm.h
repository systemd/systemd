/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"

typedef enum FilesystemParseFlags {
        FILESYSTEM_PARSE_INVERT     = 1 << 0,
        FILESYSTEM_PARSE_ALLOW_LIST = 1 << 1,
        FILESYSTEM_PARSE_LOG        = 1 << 2,
} FilesystemParseFlags;

int lsm_bpf_supported(void);
int lsm_bpf_setup(void);
int bpf_restrict_filesystems(const Set *filesystems, const bool allow_list, const char *cgroup_path);
int cleanup_lsm_bpf(const char *cgroup_path);
int bpf_lsm_parse_filesystem(const char *name,
                             Set *filesystems,
                             FilesystemParseFlags flags,
                             const char *unit,
                             const char *filename,
                             unsigned line);
