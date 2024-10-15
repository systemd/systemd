/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "macro.h"

typedef enum KernelImageType {
        KERNEL_IMAGE_TYPE_UNKNOWN,
        KERNEL_IMAGE_TYPE_UKI,
        KERNEL_IMAGE_TYPE_ADDON,
        KERNEL_IMAGE_TYPE_PE,
        _KERNEL_IMAGE_TYPE_MAX,
        _KERNEL_IMAGE_TYPE_INVALID = -EINVAL,
} KernelImageType;

const char* kernel_image_type_to_string(KernelImageType t) _const_;

int inspect_kernel(
                int dir_fd,
                const char *filename,
                KernelImageType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name);
