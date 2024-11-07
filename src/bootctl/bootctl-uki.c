/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "alloc-util.h"
#include "bootctl-uki.h"
#include "kernel-image.h"

int verb_kernel_identify(int argc, char *argv[], void *userdata) {
        KernelImageType t;
        int r;

        r = inspect_kernel(AT_FDCWD, argv[1], &t, NULL, NULL, NULL);
        if (r < 0)
                return r;

        puts(kernel_image_type_to_string(t));
        return 0;
}

int verb_kernel_inspect(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *cmdline = NULL, *uname = NULL, *pname = NULL;
        KernelImageType t;
        int r;

        r = inspect_kernel(AT_FDCWD, argv[1], &t, &cmdline, &uname, &pname);
        if (r < 0)
                return r;

        printf("Kernel Type: %s\n", kernel_image_type_to_string(t));
        if (cmdline)
                printf("    Cmdline: %s\n", cmdline);
        if (uname)
                printf("    Version: %s\n", uname);
        if (pname)
                printf("         OS: %s\n", pname);

        return 0;
}
