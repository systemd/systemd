/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/sysmacros.h>

#include "core-forward.h"

enum {
        TRUSTED_EXEC_LINK_BDEV_SETINTEGRITY,
        TRUSTED_EXEC_LINK_BDEV_FREE,
        TRUSTED_EXEC_LINK_BPRM_CHECK,
        TRUSTED_EXEC_LINK_MMAP_FILE,
        TRUSTED_EXEC_LINK_FILE_MPROTECT,
        _TRUSTED_EXEC_LINK_MAX,
};

/* Convert userspace dev_t (from stat()) to kernel dev_t encoding (MKDEV).
 * stat() returns new_encode_dev(s_dev); the BPF program reads s_dev directly
 * which uses MKDEV(major, minor) = (major << 20) | minor. */
#define STAT_DEV_TO_KERNEL(dev) \
        ((uint32_t)major(dev) << 20 | (uint32_t)minor(dev))

bool bpf_trusted_exec_supported(void);
int bpf_trusted_exec_setup(Manager *m);
void bpf_trusted_exec_destroy(struct trusted_exec_bpf *prog);
