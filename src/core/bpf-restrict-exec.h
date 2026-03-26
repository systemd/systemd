/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/sysmacros.h>

#include "core-forward.h"
#include "macro.h"

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
        _RESTRICT_EXEC_LINK_MAX,
};

/* Convert userspace dev_t (from stat()) to kernel dev_t encoding (MKDEV).
 * stat() returns new_encode_dev(s_dev); the BPF program reads s_dev directly
 * which uses MKDEV(major, minor) = (major << 20) | minor. */
#define STAT_DEV_TO_KERNEL(dev) \
        ((uint32_t)major(dev) << 20 | (uint32_t)minor(dev))

bool bpf_restrict_exec_supported(void);
int bpf_restrict_exec_setup(Manager *m);
