/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <bpf/bpf.h>

#include "tests.h"

int main(void)
{
        int bpffs_fd = open("/sys/fs/bpf", O_RDONLY);
        assert_se(bpffs_fd >= 0);

        int token_fd = bpf_token_create(bpffs_fd, NULL);
        assert_se(token_fd >= 0);

        return 0;
}
