/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"
#include "macro.h"
#include "forward.h"

typedef enum RestrictFileSystemAccess {
        RESTRICT_FILESYSTEM_ACCESS_NO,
        RESTRICT_FILESYSTEM_ACCESS_EXEC,
        _RESTRICT_FILESYSTEM_ACCESS_MAX,
        _RESTRICT_FILESYSTEM_ACCESS_INVALID = -EINVAL,
} RestrictFileSystemAccess;

const char* restrict_filesystem_access_to_string(RestrictFileSystemAccess i) _const_;
RestrictFileSystemAccess restrict_filesystem_access_from_string(const char *s) _pure_;

enum {
        RESTRICT_FILESYSTEM_ACCESS_LINK_BDEV_SETINTEGRITY,
        RESTRICT_FILESYSTEM_ACCESS_LINK_BDEV_FREE,
        RESTRICT_FILESYSTEM_ACCESS_LINK_BPRM_CHECK,
        RESTRICT_FILESYSTEM_ACCESS_LINK_MMAP_FILE,
        RESTRICT_FILESYSTEM_ACCESS_LINK_FILE_MPROTECT,
        RESTRICT_FILESYSTEM_ACCESS_LINK_PTRACE_GUARD,
        RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_MAP_GUARD,
        RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_PROG_GUARD,
        RESTRICT_FILESYSTEM_ACCESS_LINK_BPF_GUARD,
        _RESTRICT_FILESYSTEM_ACCESS_LINK_MAX,
};

/* Maximum number of dm-verity devices tracked in the BPF hash map. */
#define DMVERITY_DEVICES_MAX (16U*1024U)

extern const char* const restrict_fsaccess_link_names[_RESTRICT_FILESYSTEM_ACCESS_LINK_MAX];

bool dm_verity_require_signatures(void);
bool bpf_restrict_fsaccess_supported(void);
int bpf_restrict_fsaccess_setup(Manager *m);
int bpf_restrict_fsaccess_prepare(struct restrict_fsaccess_bpf **ret);
int bpf_restrict_fsaccess_populate_guard(struct restrict_fsaccess_bpf *obj);

int bpf_restrict_fsaccess_close_initramfs_trust(Manager *m);
int bpf_restrict_fsaccess_serialize(Manager *m, FILE *f, FDSet *fds);
