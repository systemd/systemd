/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "bootctl-uki.h"
#include "data-fd-util.h"
#include "fd-util.h"
#include "kernel-image.h"
#include "log.h"
#include "pe-binary.h"

static int inspect_kernel_path(
                const char *path,
                KernelImageType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(path);
        assert(ret_type);

        fd = open_seekable_data_fd(AT_FDCWD, path, PE_IMAGE_SIZE_MAX);
        if (IN_SET(fd, -EBADFD, -EFBIG)) {
                /* open_seekable_data_fd() refuses devices and input larger than PE_IMAGE_SIZE_MAX. A PE
                 * image is at most PE_IMAGE_SIZE_MAX bytes in size. Devices report a size of zero, and
                 * pe_load_sections() rejects a PE image whose sections end past that size. We report
                 * devices and larger input as an unknown kernel type, like any other input that is not a
                 * PE image. */
                log_debug_errno(fd, "Not inspecting '%s', assuming an unknown kernel image type: %m", path);

                *ret_type = KERNEL_IMAGE_TYPE_UNKNOWN;
                if (ret_cmdline)
                        *ret_cmdline = NULL;
                if (ret_uname)
                        *ret_uname = NULL;
                if (ret_pretty_name)
                        *ret_pretty_name = NULL;
                return 0;
        }
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", path);

        r = inspect_kernel_fd(fd, ret_type, ret_cmdline, ret_uname, ret_pretty_name);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect '%s': %m", path);

        if (ret_uname && IN_SET(*ret_type, KERNEL_IMAGE_TYPE_PE, KERNEL_IMAGE_TYPE_UNKNOWN)) {
                r = kernel_find_uname(fd, ret_uname);
                if (r < 0)
                        log_debug_errno(r, "Failed to find the version of '%s', ignoring: %m", path);
        }

        return 0;
}

int verb_kernel_identify(int argc, char *argv[], uintptr_t _data, void *userdata) {
        KernelImageType t;
        int r;

        r = inspect_kernel_path(argv[1], &t, /* ret_cmdline= */ NULL, /* ret_uname= */ NULL, /* ret_pretty_name= */ NULL);
        if (r < 0)
                return r;

        puts(kernel_image_type_to_string(t));
        return 0;
}

int verb_kernel_inspect(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_free_ char *cmdline = NULL, *uname = NULL, *pname = NULL;
        KernelImageType t;
        int r;

        r = inspect_kernel_path(argv[1], &t, &cmdline, &uname, &pname);
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
