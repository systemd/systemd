/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <bpf/bpf.h>
#include <fcntl.h>

#include "fd-util.h"
#include "main-func.h"
#include "tests.h"

static int run(int argc, char *argv[]) {
#if __LIBBPF_CURRENT_VERSION_GEQ(1, 5)
        _cleanup_close_ int bpffs_fd = -EBADF, token_fd = -EBADF;

        bpffs_fd = open("/sys/fs/bpf", O_RDONLY);
        if (bpffs_fd < 0)
                return -errno;

        token_fd = bpf_token_create(bpffs_fd, /* opts = */ NULL);
        if (token_fd < 0)
                return -errno;

        return 0;
#else
        exit(77);
#endif
}

DEFINE_MAIN_FUNCTION(run);
