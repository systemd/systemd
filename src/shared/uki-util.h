/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "macro.h"

typedef enum KernelType {
        KERNEL_TYPE_UNKNOWN,
        KERNEL_TYPE_UKI,
        KERNEL_TYPE_PE,
        _KERNEL_TYPE_MAX,
        _KERNEL_TYPE_INVALID = -EINVAL,
} KernelType;

const char* kernel_type_to_string(KernelType t) _const_;

int inspect_kernel(
                const char *filename,
                KernelType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name);
