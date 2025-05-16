/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

typedef enum FilesystemParseFlags {
        FILESYSTEM_PARSE_INVERT     = 1 << 0,
        FILESYSTEM_PARSE_ALLOW_LIST = 1 << 1,
        FILESYSTEM_PARSE_LOG        = 1 << 2,
} FilesystemParseFlags;

bool bpf_restrict_fs_supported(bool initialize);
int bpf_restrict_fs_setup(Manager *m);
int bpf_restrict_fs_update(const Set *filesystems, uint64_t cgroup_id, int outer_map_fd, bool allow_list);
int bpf_restrict_fs_cleanup(Unit *u);
int bpf_restrict_fs_map_fd(Unit *u);
void bpf_restrict_fs_destroy(struct restrict_fs_bpf *prog);
int bpf_restrict_fs_parse_filesystem(const char *name, Set **filesystems, FilesystemParseFlags flags, const char *unit, const char *filename, unsigned line);
