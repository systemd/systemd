/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"

typedef enum FilesystemParseFlags {
        FILESYSTEM_PARSE_INVERT     = 1 << 0,
        FILESYSTEM_PARSE_ALLOW_LIST = 1 << 1,
        FILESYSTEM_PARSE_LOG        = 1 << 2,
} FilesystemParseFlags;

typedef struct Unit Unit;
typedef struct Manager Manager;

typedef struct restrict_fs_bpf restrict_fs_bpf;

bool lsm_bpf_supported(bool initialize);
int lsm_bpf_setup(Manager *m);
int lsm_bpf_unit_restrict_filesystems(Unit *u, const Set *filesystems, bool allow_list);
int lsm_bpf_cleanup(const Unit *u);
int lsm_bpf_map_restrict_fs_fd(Unit *u);
void lsm_bpf_destroy(struct restrict_fs_bpf *prog);
int lsm_bpf_parse_filesystem(const char *name,
                             Set **filesystems,
                             FilesystemParseFlags flags,
                             const char *unit,
                             const char *filename,
                             unsigned line);
