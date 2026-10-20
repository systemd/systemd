/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "bootctl-uki.h"
#include "data-fd-util.h"
#include "fd-util.h"
#include "kernel-image.h"
#include "log.h"
#include "pe-binary.h"

int verb_kernel_identify(int argc, char *argv[], uintptr_t _data, void *userdata) {
        KernelImageType t;
        int r;

        _cleanup_close_ int fd = open_seekable_data_fd(AT_FDCWD, argv[1], PE_IMAGE_SIZE_MAX);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", argv[1]);

        r = inspect_kernel_fd(fd, &t, /* ret_cmdline= */ NULL, /* ret_uname= */ NULL, /* ret_pretty_name= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect '%s': %m", argv[1]);

        puts(kernel_image_type_to_string(t));
        return 0;
}

int verb_kernel_inspect(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_free_ char *cmdline = NULL, *uname = NULL, *pname = NULL;
        KernelImageType t;
        int r;

        _cleanup_close_ int fd = open_seekable_data_fd(AT_FDCWD, argv[1], PE_IMAGE_SIZE_MAX);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", argv[1]);

        r = inspect_kernel_fd(fd, &t, &cmdline, &uname, &pname);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect '%s': %m", argv[1]);

        printf("Kernel Type: %s\n", kernel_image_type_to_string(t));
        if (cmdline)
                printf("    Cmdline: %s\n", cmdline);
        if (uname)
                printf("    Version: %s\n", uname);
        if (pname)
                printf("         OS: %s\n", pname);

        return 0;
}
