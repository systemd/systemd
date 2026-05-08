/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/sysmacros.h>

#include "core-forward.h"
#include "macro.h"
#include "shared-forward.h"

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

/* Convert userspace dev_t (from stat()) to kernel dev_t encoding (MKDEV).
 * stat() returns new_encode_dev(s_dev); the BPF program reads s_dev directly
 * which uses MKDEV(major, minor) = (major << 20) | minor. */
#define STAT_DEV_TO_KERNEL(dev) \
        ((uint32_t)major(dev) << 20 | (uint32_t)minor(dev))

/* Mirrors the BPF program's .bss section layout for read-modify-write via
 * bpf_map_lookup_elem/bpf_map_update_elem on the serialized .bss map FD. */
struct restrict_fsaccess_bss {
        uint32_t initramfs_s_dev; /* kernel dev_t encoding: (major << 20) | minor */
        uint32_t protected_map_id_verity;
        uint32_t protected_map_id_bss;
        uint32_t protected_prog_ids[_RESTRICT_FILESYSTEM_ACCESS_LINK_MAX];
        uint32_t protected_link_ids[_RESTRICT_FILESYSTEM_ACCESS_LINK_MAX];
};

extern const char* const restrict_fsaccess_link_names[_RESTRICT_FILESYSTEM_ACCESS_LINK_MAX];

bool bpf_restrict_fsaccess_supported(void);
int bpf_restrict_fsaccess_setup(Manager *m);
int bpf_restrict_fsaccess_populate_guard(struct restrict_fsaccess_bpf *obj);

int bpf_restrict_fsaccess_close_initramfs_trust(Manager *m);
int bpf_restrict_fsaccess_serialize(Manager *m, FILE *f, FDSet *fds);
