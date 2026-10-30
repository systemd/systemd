/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_path_is_encrypted_one(const char *p, int expect) {
        int r;

        r = path_is_encrypted(p);
        if (IN_SET(r, -ENOENT, -ELOOP) || ERRNO_IS_NEG_PRIVILEGE(r))
                /* This might fail, if btrfs is used and we run in a container. In that case we cannot
                 * resolve the device node paths that BTRFS_IOC_DEV_INFO returns, because the device nodes
                 * are unlikely to exist in the container. But if we can't stat() them we cannot determine
                 * the dev_t of them, and thus cannot figure out if they are encrypted. Hence let's just
                 * ignore ENOENT here. Also skip the test if we lack privileges.
                 * ELOOP might happen if the mount point is a symlink, as seen with under
                 * some rpm-ostree distros */
                return;
        assert_se(r >= 0);

        log_info("%s encrypted: %s", p, yes_no(r));

        assert_se(expect < 0 || ((r > 0) == (expect > 0)));
}

TEST(path_is_encrypted) {
        int booted = sd_booted(); /* If this is run in build environments such as koji, /dev/ might be a
                                   * regular fs. Don't assume too much if not running under systemd. */

        log_info("/* %s (sd_booted=%d) */", __func__, booted);

        test_path_is_encrypted_one("/home", -1);
        test_path_is_encrypted_one("/var", -1);
        test_path_is_encrypted_one("/", -1);
        test_path_is_encrypted_one("/proc", false);
        test_path_is_encrypted_one("/sys", false);
        test_path_is_encrypted_one("/dev", booted > 0 ? false : -1);
}

TEST(partscan_enabled) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "block", /* match= */ true) >= 0);

        FOREACH_DEVICE(e, dev) {
                _cleanup_close_ int fd = -EBADF;
                const char *name;

                r = sd_device_get_devname(dev, &name);
                if (r < 0) {
                        log_warning_errno(r, "Found block device without a name, skipping.");
                        continue;
                }

                fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                if (fd < 0) {
                        log_warning_errno(fd, "Found block device '%s' which we cannot open, skipping: %m", name);
                        continue;
                }

                r = blockdev_partscan_enabled_fd(fd);
                if (r < 0) {
                        log_warning_errno(r, "Failed to determine if block device '%s' has partition scanning enabled, skipping: %m", name);
                        continue;
                }

                log_info("%s has partition scanning enabled: %s", name, yes_no(r));
        }
}

static void test_partition_node_of_one(const char *main, unsigned partition, const char *result, int retval) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = partition_node_of(main, partition, &s);
        ASSERT_EQ(r, retval);
        if (r < 0)
                return;
        ASSERT_STREQ(s, result);

        log_info("%s with %u → %s", main, partition, result);
}

TEST(partition_node_of) {
        test_partition_node_of_one("/dev/sda", 2, "/dev/sda2", 0);
        test_partition_node_of_one("sda", 3, "sda3", 0);
        test_partition_node_of_one("/dev/nvme0n1", 7, "/dev/nvme0n1p7", 0);
        test_partition_node_of_one("nvme0n1", 8, "nvme0n1p8", 0);
        test_partition_node_of_one("/dev/loop1", 3, "/dev/loop1p3", 0);
        test_partition_node_of_one("", 1, NULL, -EINVAL);
        test_partition_node_of_one("/", 1, NULL, -EADDRNOTAVAIL);
        test_partition_node_of_one("/dev/", 1, NULL, -EISDIR);
        test_partition_node_of_one("/sda", 1, "/sda1", 0);
        test_partition_node_of_one(".", 1, NULL, -EADDRNOTAVAIL);
}

static void verify_range(int fd, uint64_t offset, uint64_t size, uint8_t expected) {
        uint8_t buffer[4096];

        /* Checks that every byte in the specified range of the file is 'expected' */

        while (size > 0) {
                ssize_t n;

                n = pread(fd, buffer, MIN(size, sizeof(buffer)), offset);
                ASSERT_OK_ERRNO(n);
                ASSERT_GT(n, 0);

                for (ssize_t i = 0; i < n; i++)
                        ASSERT_EQ(buffer[i], expected);

                offset += n;
                size -= n;
        }
}

TEST(blockdev_zero_out) {
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/test-blockdev-zero-out.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ uint8_t *pattern = NULL;
        struct stat st;

        /* Larger than the 64K buffer write_zeroes() operates with internally, so that the chunking is exercised */
        const uint64_t file_size = 200U*1024U;

        fd = mkostemp_safe(path);
        ASSERT_OK(fd);

        ASSERT_NOT_NULL(pattern = malloc(file_size));
        memset(pattern, 0xAA, file_size);
        ASSERT_OK(loop_write(fd, pattern, file_size));

        /* Zero-sized range is a NOP */
        ASSERT_OK(blockdev_zero_out(fd, 17, 0));
        verify_range(fd, 0, file_size, 0xAA);
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, file_size);

        /* Overflowing range is refused */
        ASSERT_ERROR(blockdev_zero_out(fd, UINT64_MAX - 5, 10), EOVERFLOW);
        ASSERT_ERROR(blockdev_zero_out(fd, UINT64_MAX, 1), EOVERFLOW);
        verify_range(fd, 0, file_size, 0xAA);

        /* Unaligned range in the middle of the file, spanning multiple write_zeroes() chunks; bytes outside of
         * it must stay intact */
        const uint64_t offset = 1234, size = 150U*1024U + 77;
        ASSERT_OK(blockdev_zero_out(fd, offset, size));
        verify_range(fd, 0, offset, 0xAA);
        verify_range(fd, offset, size, 0);
        verify_range(fd, offset + size, file_size - offset - size, 0xAA);
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, file_size);

        /* Range extending beyond the end of the file grows it */
        ASSERT_OK(blockdev_zero_out(fd, file_size - 100, 300));
        verify_range(fd, offset + size, file_size - offset - size - 100, 0xAA);
        verify_range(fd, file_size - 100, 300, 0);
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, file_size + 200);

        /* Range entirely beyond the end of the file grows it too, the gap reads back as zeroes */
        ASSERT_OK(blockdev_zero_out(fd, file_size + 1000, 50));
        verify_range(fd, file_size - 100, 1150, 0);
        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ((uint64_t) st.st_size, file_size + 1050);

        /* Neither a regular file nor a block device */
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC));
        ASSERT_ERROR(blockdev_zero_out(pipe_fds[1], 0, 10), ENOTBLK);
}

DEFINE_TEST_MAIN(LOG_INFO);
