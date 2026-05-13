/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <bpf/bpf.h>
#include <fcntl.h>

#include "fd-util.h"
#include "main-func.h"
#include "tests.h"  /* NOLINT(misc-include-cleaner): this is needed conditionally */

static int run(int argc, char *argv[]) {
#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION > 1 || (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 5))
        _cleanup_close_ int bpffs_fd = open("/sys/fs/bpf", O_RDONLY);
        if (bpffs_fd < 0)
                return log_error_errno(errno, "Failed to open '/sys/fs/bpf': %m");

        _cleanup_close_ int token_fd = bpf_token_create(bpffs_fd, /* opts= */ NULL);
        if (token_fd < 0)
                return log_error_errno(errno, "Failed to create bpf token: %m");

        log_info("Successfully created token fd.");
        return 0;
#else
        return log_tests_skipped("libbpf is older than v1.5");
#endif
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
