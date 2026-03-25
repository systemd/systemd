/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/sysmacros.h>

#include "core-forward.h"
#include "shared-forward.h"

enum {
        TRUSTED_EXEC_LINK_BDEV_SETINTEGRITY,
        TRUSTED_EXEC_LINK_BDEV_FREE,
        TRUSTED_EXEC_LINK_BPRM_CHECK,
        TRUSTED_EXEC_LINK_MMAP_FILE,
        TRUSTED_EXEC_LINK_FILE_MPROTECT,
        TRUSTED_EXEC_LINK_PTRACE_GUARD,
        TRUSTED_EXEC_LINK_BPF_MAP_GUARD,
        TRUSTED_EXEC_LINK_BPF_PROG_GUARD,
        TRUSTED_EXEC_LINK_BPF_GUARD,
        _TRUSTED_EXEC_LINK_MAX,
};

/* Convert userspace dev_t (from stat()) to kernel dev_t encoding (MKDEV).
 * stat() returns new_encode_dev(s_dev); the BPF program reads s_dev directly
 * which uses MKDEV(major, minor) = (major << 20) | minor. */
#define STAT_DEV_TO_KERNEL(dev) \
        ((uint32_t)major(dev) << 20 | (uint32_t)minor(dev))

/* Mirrors the BPF program's .bss section layout for read-modify-write via
 * bpf_map_lookup_elem/bpf_map_update_elem on the serialized .bss map FD. */
struct trusted_exec_bss {
        uint32_t initramfs_s_dev;
        uint32_t protected_map_id_verity;
        uint32_t protected_map_id_bss;
        uint32_t protected_prog_ids[_TRUSTED_EXEC_LINK_MAX];
        uint32_t protected_link_ids[_TRUSTED_EXEC_LINK_MAX];
};

extern const char* const trusted_exec_link_names[_TRUSTED_EXEC_LINK_MAX];

bool bpf_trusted_exec_supported(void);
int bpf_trusted_exec_setup(Manager *m);
void bpf_trusted_exec_destroy(struct trusted_exec_bpf *prog);
int bpf_trusted_exec_populate_guard(struct trusted_exec_bpf *obj);

int bpf_trusted_exec_serialize(Manager *m, FILE *f, FDSet *fds);
