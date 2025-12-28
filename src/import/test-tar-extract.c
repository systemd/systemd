/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "libarchive-util.h"
#include "main-func.h"
#include "tar-util.h"
#include "tests.h"

static int run(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need two arguments exactly: <input> <output>");

        r = dlopen_libarchive();
        if (r < 0)
                return r;

        _cleanup_close_ int input_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
        if (input_fd < 0)
                return log_error_errno(input_fd, "Cannot open %s: %m", argv[1]);

        _cleanup_close_ int output_fd = open(argv[2], O_DIRECTORY | O_CLOEXEC);
        if (output_fd < 0)
                return log_error_errno(output_fd, "Cannot open %s: %m", argv[2]);

        r = tar_x(input_fd, output_fd, /* flags= */ TAR_SELINUX);
        if (r < 0)
                return log_error_errno(r, "tar_x failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
