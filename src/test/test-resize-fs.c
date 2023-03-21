/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>

#include "missing_magic.h"
#include "resize-fs.h"
#include "tests.h"

TEST(resize_fs) {
        int fd;
        fd = open("/tmp/file", O_RDWR | O_CREAT, 0656);
        if(fd < 0) {
                perror("open");
                exit(EXIT_FAILURE);
        }
        assert_se (resize_fs(fd, 12U*1024U*1024U, NULL) == -1);
        assert_se (resize_fs(2, UINT64_MAX, NULL) == -ERANGE);
        assert_se (resize_fs(2, 0, NULL) == -ERANGE);
}

TEST(minimal_size_by_name) {
        assert_se (minimal_size_by_fs_name("ext4") == EXT4_MINIMAL_SIZE);
        assert_se (minimal_size_by_fs_name("xfs") == XFS_MINIMAL_SIZE);
        assert_se (minimal_size_by_fs_name("btrfs") == BTRFS_MINIMAL_SIZE);
        assert_se (minimal_size_by_fs_name("others") == UINT64_MAX);
}

TEST(minimal_size_by_magic) {
        assert_se (minimal_size_by_fs_magic(EXT4_SUPER_MAGIC) == EXT4_MINIMAL_SIZE);
        assert_se (minimal_size_by_fs_magic(BTRFS_SUPER_MAGIC) == BTRFS_MINIMAL_SIZE);
        assert_se (minimal_size_by_fs_magic(XFS_SB_MAGIC) == XFS_MINIMAL_SIZE);
        assert_se (minimal_size_by_fs_magic(1024) == UINT64_MAX);
}

DEFINE_TEST_MAIN(LOG_INFO);
