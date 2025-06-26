/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <bpf/bpf.h>
#include <fcntl.h>

#include "tests.h"

int main(void) {
#if __LIBBPF_CURRENT_VERSION_GEQ(1, 5)
        int bpffs_fd = open("/sys/fs/bpf", O_RDONLY);
        assert_se(bpffs_fd >= 0);

        int token_fd = bpf_token_create(bpffs_fd, NULL);
        assert_se(token_fd >= 0);

        return 0;
#else
        return 77;
#endif
}
