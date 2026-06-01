/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "bpf-util.h"
#include "fd-util.h"
#include "main-func.h"
#include "tests.h"

static int run(int argc, char *argv[]) {
#if HAVE_LIBBPF
        int r;

        r = DLOPEN_BPF(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED);
        if (r < 0)
                return r;

        _cleanup_close_ int bpffs_fd = open("/sys/fs/bpf", O_CLOEXEC|O_RDONLY);
        if (bpffs_fd < 0)
                return log_error_errno(errno, "Failed to open '/sys/fs/bpf': %m");

        _cleanup_close_ int token_fd = sym_bpf_token_create(bpffs_fd, /* opts= */ NULL);
        if (token_fd == -ENOSYS)
                return log_tests_skipped("bpf_token_create() unavailable (libbpf too old or kernel lacks BPF_TOKEN_CREATE support)");
        if (token_fd < 0)
                return log_error_errno(token_fd, "Failed to create bpf token: %m");

        log_info("Successfully created token fd.");
        return 0;
#else
        return log_tests_skipped("BPF framework support is disabled");
#endif
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
