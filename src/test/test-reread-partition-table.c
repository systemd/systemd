/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>

#include "blockdev-util.h"
#include "fd-util.h"
#include "loop-util.h"
#include "memfd-util.h"
#include "path-util.h"
#include "process-util.h"
#include "reread-partition-table.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "virt.h"

static void sfdisk(const char *sfdisk_path, LoopDevice *loop, const char *definition) {
        int r;

        assert(sfdisk_path);
        assert(loop);
        assert(definition);

        _cleanup_close_ int memfd = memfd_new_and_seal("sfdisk", definition, SIZE_MAX);
        ASSERT_OK(memfd);

        r = safe_fork_full(
                        "(sfdisk)",
                        (int[]) { memfd, STDOUT_FILENO, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_CLOSE_ALL_FDS|FORK_RESET_SIGNALS|FORK_REARRANGE_STDIO|FORK_LOG|FORK_WAIT,
                        /* ret_pid= */ NULL);
        if (r == 0) {
                /* child */
                execl(sfdisk_path, "fdisk", "--no-tell-kernel", "--no-reread", loop->node, NULL);
                _exit(EXIT_FAILURE);
        }

        ASSERT_OK(r);
}

TEST(rereadpt) {
        int r;

        if (detect_container() > 0)
                return (void) log_tests_skipped("test not available in container");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("test not available in chroot()");

        _cleanup_free_ char *sfdisk_path = NULL;
        r = find_executable("sfdisk", &sfdisk_path);
        if (r == -ENOENT)
                return (void) log_tests_skipped("sfdisk not found");
        ASSERT_OK(r);

        _cleanup_close_ int fd = open_tmpfile_unlinkable("/var/tmp", O_RDWR);
        ASSERT_FD(fd);

        ASSERT_OK_ERRNO(ftruncate(fd, 100 * 1024 * 1024));

        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        r = loop_device_make(
                        fd,
                        O_RDWR,
                        /* offset= */ 0,
                        /* size= */ UINT64_MAX,
                        /* sector_size= */ 512U,
                        LO_FLAGS_PARTSCAN,
                        LOCK_EX, &loop);
        if (ERRNO_IS_NEG_PRIVILEGE(r) || ERRNO_IS_NOT_SUPPORTED(r))
                return (void) log_tests_skipped("loopback block devices not available");

        _cleanup_free_ char *p = NULL;
        ASSERT_OK(partition_node_of(loop->node, 1, &p));
        ASSERT_ERROR_ERRNO(access(p, F_OK), ENOENT);

        /* No change */
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));
        ASSERT_ERROR_ERRNO(access(p, F_OK), ENOENT);

        /* Create */
        log_notice("CREATING 20M");
        sfdisk(sfdisk_path,
               loop,
               "label: gpt\n"
               "start=, size=20M, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n");

        ASSERT_ERROR_ERRNO(access(p, F_OK), ENOENT);
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));

        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));

        _cleanup_close_ int pfd = open(p, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        ASSERT_OK_ERRNO(pfd);
        uint64_t size;
        ASSERT_OK(blockdev_get_device_size(pfd, &size));
        ASSERT_EQ(size, 20U*1024U*1024U);

        /* No change */
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));
        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));

        /* No change, but synthesize change anyway */
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ REREADPT_FORCE_UEVENT));
        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));

        /* Resize */
        log_notice("RESIZING TO 30M");
        sfdisk(sfdisk_path,
               loop,
               "label: gpt\n"
               "start=, size=30M, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n");

        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));
        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));

        ASSERT_OK(blockdev_get_device_size(pfd, &size));
        ASSERT_EQ(size, 30U*1024U*1024U);

        /* No change */
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));

        /* Move */
        log_notice("MOVING BY 50M");
        sfdisk(sfdisk_path,
               loop,
               "label: gpt\n"
               "start=50M, size=15M, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n");

        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));
        ASSERT_ERROR(reread_partition_table_fd(loop->fd, /* flags= */ 0), EBUSY);
        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));

        safe_close(pfd);

        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));

        pfd = open(p, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        ASSERT_OK_ERRNO(pfd);
        ASSERT_OK(blockdev_get_device_size(pfd, &size));
        ASSERT_EQ(size, 15U*1024U*1024U);

        /* No change */
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));

        /* Remove */
        log_notice("REMOVING");
        sfdisk(sfdisk_path,
               loop,
               "label: gpt\n");

        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));
        ASSERT_ERROR(reread_partition_table_fd(loop->fd, /* flags= */ 0), EBUSY);

        ASSERT_OK_ZERO_ERRNO(access(p, F_OK));
        pfd = safe_close(pfd);
        ASSERT_OK(reread_partition_table_fd(loop->fd, /* flags= */ 0));
        ASSERT_ERROR_ERRNO(access(p, F_OK), ENOENT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
