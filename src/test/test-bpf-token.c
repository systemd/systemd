/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBBPF
#include <bpf/bpf.h>
#endif
#include <fcntl.h>

#include "fd-util.h"
#include "mountpoint-util.h"
#include "tests.h"

static int intro(void) {
        /* First, check if fsconfig() for bpffs is supported. */
        if (!fsconfig_bpffs_supported())
                return EXIT_FAILURE;

#if HAVE_LIBBPF
#  if __LIBBPF_CURRENT_VERSION_GEQ(1, 5)
        /* Then, check if bpf token can be created. */
        _cleanup_close_ int bpffs_fd = open("/sys/fs/bpf", O_RDONLY);
        if (bpffs_fd < 0)
                return log_error_errno(errno, "Failed to open '/sys/fs/bpf': %m");

        _cleanup_close_ int token_fd = bpf_token_create(bpffs_fd, /* opts = */ NULL);
        if (token_fd < 0)
                return log_error_errno(errno, "Failed to create bpf token: %m");

        return EXIT_SUCCESS;
#  else
        return log_tests_skipped("libbpf is older than v1.5");
#  endif
#else
        return log_tests_skipped("libbpf is not supported");
#endif
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
