/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/sysmacros.h>

#include "core-forward.h"
#include "macro.h"
#include "shared-forward.h"

typedef enum RestrictExec {
        RESTRICT_EXEC_NO,
        RESTRICT_EXEC_STRICT,
        _RESTRICT_EXEC_MAX,
        _RESTRICT_EXEC_INVALID = -EINVAL,
} RestrictExec;

const char* restrict_exec_to_string(RestrictExec i) _const_;
RestrictExec restrict_exec_from_string(const char *s) _pure_;

enum {
        RESTRICT_EXEC_LINK_BDEV_SETINTEGRITY,
        RESTRICT_EXEC_LINK_BDEV_FREE,
        RESTRICT_EXEC_LINK_BPRM_CHECK,
        RESTRICT_EXEC_LINK_MMAP_FILE,
        RESTRICT_EXEC_LINK_FILE_MPROTECT,
        RESTRICT_EXEC_LINK_PTRACE_GUARD,
        RESTRICT_EXEC_LINK_BPF_MAP_GUARD,
        RESTRICT_EXEC_LINK_BPF_PROG_GUARD,
        RESTRICT_EXEC_LINK_BPF_GUARD,
        _RESTRICT_EXEC_LINK_MAX,
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
struct restrict_exec_bss {
        uint32_t initramfs_s_dev; /* kernel dev_t encoding: (major << 20) | minor */
        uint32_t protected_map_id_verity;
        uint32_t protected_map_id_bss;
        uint32_t protected_prog_ids[_RESTRICT_EXEC_LINK_MAX];
        uint32_t protected_link_ids[_RESTRICT_EXEC_LINK_MAX];
};

extern const char* const restrict_exec_link_names[_RESTRICT_EXEC_LINK_MAX];

bool dm_verity_require_signatures(void);
bool bpf_restrict_exec_supported(void);
int bpf_restrict_exec_setup(Manager *m);
int bpf_restrict_exec_populate_guard(struct restrict_exec_bpf *obj);

int bpf_restrict_exec_close_initramfs_trust(Manager *m);
int bpf_restrict_exec_serialize(Manager *m, FILE *f, FDSet *fds);
