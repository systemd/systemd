/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "bootctl-uki.h"
#include "data-fd-util.h"
#include "fd-util.h"
#include "kernel-image.h"
#include "log.h"

int verb_kernel_identify(int argc, char *argv[], uintptr_t _data, void *userdata) {
        KernelImageType t;
        int r;

        _cleanup_close_ int fd = open_seekable_data_fd(argv[1]);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", argv[1]);

        r = inspect_kernel(fd, /* filename= */ NULL, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect '%s': %m", argv[1]);

        puts(kernel_image_type_to_string(t));
        return 0;
}

int verb_kernel_inspect(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_free_ char *cmdline = NULL, *uname = NULL, *pname = NULL;
        KernelImageType t;
        int r;

        _cleanup_close_ int fd = open_seekable_data_fd(argv[1]);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", argv[1]);

        r = inspect_kernel_full(fd, /* filename= */ NULL, &t, &cmdline, &uname, &pname);
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
