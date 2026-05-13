/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "chattr-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "memory-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static int open_test_subvol(char **ret_path) {
        const char *vtd;
        int r;

        r = var_tmp_dir(&vtd);
        if (r < 0)
                return r;

        _cleanup_free_ char *base = path_join(vtd, "test-btrfs"), *p = NULL;
        if (!base)
                return -ENOMEM;

        r = tempfn_random(base, /* extra= */ NULL, &p);
        if (r < 0)
                return r;

        int fd = xopenat_full(AT_FDCWD, p, O_DIRECTORY|O_CREAT|O_CLOEXEC, XO_SUBVOLUME, MODE_INVALID);
        if (fd < 0)
                return fd;

        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return fd;
}

TEST(info) {
        _cleanup_(rm_rf_subvolume_and_freep) char *dir = NULL;
        _cleanup_close_ int dir_fd = ASSERT_OK(open_test_subvol(&dir));
        BtrfsSubvolInfo info;
        BtrfsQuotaInfo quota;
        int r;

        ASSERT_OK(btrfs_subvol_get_info_fd(dir_fd, 0, &info));
        log_info("otime: %s", FORMAT_TIMESTAMP(info.otime));
        log_info("read-only (search): %s", yes_no(info.read_only));

        r = btrfs_qgroup_get_quota_fd(dir_fd, 0, &quota);
        if (r < 0)
                log_info_errno(r, "Failed to get quota info: %m");
        else {
                log_info("referenced: %s", strna(FORMAT_BYTES(quota.referenced)));
                log_info("exclusive: %s", strna(FORMAT_BYTES(quota.exclusive)));
                log_info("referenced_max: %s", strna(FORMAT_BYTES(quota.referenced_max)));
                log_info("exclusive_max: %s", strna(FORMAT_BYTES(quota.exclusive_max)));
        }

        r = ASSERT_OK(btrfs_subvol_get_read_only_fd(dir_fd));
        log_info("read-only (ioctl): %s", yes_no(r));
}

TEST(subvol) {
        _cleanup_(rm_rf_subvolume_and_freep) char *dir = NULL;
        _cleanup_close_ int dir_fd = ASSERT_OK(open_test_subvol(&dir));

        ASSERT_OK(btrfs_subvol_make(dir_fd, "test1"));
        ASSERT_OK(write_string_file_at(dir_fd, "test1/file", "ljsadhfljasdkfhlkjdsfha", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(btrfs_subvol_snapshot_at(dir_fd, "test1", dir_fd, "test2", 0));
        ASSERT_OK(btrfs_subvol_snapshot_at(dir_fd, "test1", dir_fd, "test3", BTRFS_SNAPSHOT_READ_ONLY));

        _unused_ _cleanup_close_ int locked_fd = ASSERT_OK(btrfs_subvol_snapshot_at(dir_fd, "test1", dir_fd, "test4", BTRFS_SNAPSHOT_LOCK_BSD));
        ASSERT_ERROR(xopenat_lock(dir_fd, "test4", 0, LOCK_BSD, LOCK_EX|LOCK_NB), EAGAIN);

        /* The destroy ioctl needs CAP_SYS_ADMIN; without it, leave cleanup to rm_rf_subvolume_and_freep. */
        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "test1", BTRFS_REMOVE_QUOTA), -EPERM);
        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "test2", BTRFS_REMOVE_QUOTA), -EPERM);
        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "test3", BTRFS_REMOVE_QUOTA), -EPERM);
        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "test4", BTRFS_REMOVE_QUOTA), -EPERM);
}

TEST(fallback_copy) {
        _cleanup_(rm_rf_subvolume_and_freep) char *dir = NULL;
        _cleanup_close_ int dir_fd = ASSERT_OK(open_test_subvol(&dir));

        /* Snapshot a regular directory (not a subvolume) — exercises the FALLBACK_COPY path. */
        ASSERT_OK_ERRNO(mkdirat(dir_fd, "src", 0755));
        ASSERT_OK(write_string_file_at(dir_fd, "src/file1", "hello", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(dir_fd, "src/file2", "world", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(btrfs_subvol_snapshot_at(dir_fd, "src", dir_fd, "snap",
                                           BTRFS_SNAPSHOT_READ_ONLY|BTRFS_SNAPSHOT_FALLBACK_COPY));

        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "snap", BTRFS_REMOVE_QUOTA), -EPERM);
}

TEST(recursive) {
        _cleanup_(rm_rf_subvolume_and_freep) char *dir = NULL;
        _cleanup_close_ int dir_fd = ASSERT_OK(open_test_subvol(&dir));

        ASSERT_OK(btrfs_subvol_make(dir_fd, "rec"));
        ASSERT_OK(btrfs_subvol_make(dir_fd, "rec/sv2"));
        ASSERT_OK(btrfs_subvol_make(dir_fd, "rec/sv3"));
        ASSERT_OK(btrfs_subvol_make(dir_fd, "rec/sv3/sub"));

        ASSERT_OK_ERRNO(mkdirat(dir_fd, "rec/dir", 0755));
        ASSERT_OK(btrfs_subvol_make(dir_fd, "rec/dir/sv4"));
        ASSERT_OK_ERRNO(mkdirat(dir_fd, "rec/dir/sv4/dir", 0755));
        ASSERT_OK(btrfs_subvol_make(dir_fd, "rec/dir/sv4/dir/sv5"));

        ASSERT_OK_ERRNO(mkdirat(dir_fd, "rec/mnt", 0755));

        ASSERT_OK(btrfs_subvol_snapshot_at(dir_fd, "rec", dir_fd, "rec-snap", BTRFS_SNAPSHOT_RECURSIVE));

        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "rec", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE), -EPERM);
        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "rec-snap", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE), -EPERM);
}

TEST(quota) {
        _cleanup_(rm_rf_subvolume_and_freep) char *dir = NULL;
        _cleanup_close_ int dir_fd = ASSERT_OK(open_test_subvol(&dir));
        BtrfsQuotaInfo quota;
        int r;

        _cleanup_free_ char *qt = ASSERT_NOT_NULL(path_join(dir, "quotatest")),
                            *qt2 = ASSERT_NOT_NULL(path_join(dir, "quotatest2")),
                            *beneath = ASSERT_NOT_NULL(path_join(dir, "quotatest/beneath")),
                            *snap_beneath = ASSERT_NOT_NULL(path_join(dir, "quotatest2/beneath"));

        ASSERT_OK(btrfs_subvol_make(dir_fd, "quotatest"));
        /* The qgroup/quota ioctls require CAP_SYS_ADMIN; skip the rest of the test if we don't have it
         * or quotas are not enabled on this filesystem. */
        r = btrfs_subvol_auto_qgroup(qt, 0, true);
        if (r == -EPERM)
                return (void) log_tests_skipped("not running privileged");
        if (IN_SET(r, -ENOTCONN, -ENOENT))
                return (void) log_tests_skipped_errno(r, "btrfs quotas not enabled on this filesystem");
        ASSERT_OK(r);

        ASSERT_OK(btrfs_subvol_make(dir_fd, "quotatest/beneath"));
        ASSERT_OK(btrfs_subvol_auto_qgroup(beneath, 0, false));
        ASSERT_OK(btrfs_qgroup_set_limit(beneath, 0, 4ULL * 1024 * 1024 * 1024));

        ASSERT_OK(btrfs_subvol_set_subtree_quota_limit(qt, 0, 5ULL * 1024 * 1024 * 1024));

        ASSERT_OK(btrfs_subvol_snapshot_at(dir_fd, "quotatest", dir_fd, "quotatest2",
                                           BTRFS_SNAPSHOT_RECURSIVE|BTRFS_SNAPSHOT_QUOTA));

        ASSERT_OK(btrfs_qgroup_get_quota(snap_beneath, 0, &quota));
        ASSERT_EQ(quota.referenced_max, 4ULL * 1024 * 1024 * 1024);

        ASSERT_OK(btrfs_subvol_get_subtree_quota(qt2, 0, &quota));
        ASSERT_EQ(quota.referenced_max, 5ULL * 1024 * 1024 * 1024);

        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "quotatest", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE), -EPERM);
        ASSERT_OK_OR(btrfs_subvol_remove_at(dir_fd, "quotatest2", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE), -EPERM);
}

TEST(physical_offset) {
        _cleanup_free_ char *btrfs_progs = NULL;
        int r = find_executable("btrfs", &btrfs_progs);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "btrfs(8) not found");

        _cleanup_(rm_rf_subvolume_and_freep) char *dir = NULL;
        _cleanup_close_ int dir_fd = ASSERT_OK(open_test_subvol(&dir));

        /* Set NOCOW on the subvol dir so the swapfile inherits it on creation. Older btrfs-progs
         * versions don't reliably set NOCOW from `btrfs filesystem mkswapfile`. */
        ASSERT_OK(chattr_fd(dir_fd, FS_NOCOW_FL, FS_NOCOW_FL));

        /* btrfs filesystem mkswapfile produces a NOCOW, contiguous file with a swap header — exactly
         * what btrfs inspect-internal map-swapfile expects, and what btrfs_get_file_physical_offset_fd
         * works with. */
        _cleanup_free_ char *path = ASSERT_NOT_NULL(path_join(dir, "swapfile"));
        r = ASSERT_OK(pidref_safe_fork("(mkswapfile)",
                        FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG|FORK_WAIT,
                        NULL));
        if (r == 0) {
                execlp(btrfs_progs, "btrfs", "filesystem", "mkswapfile", "-s", "1m", path, NULL);
                _exit(EXIT_FAILURE);
        }

        _cleanup_close_ int fd = ASSERT_OK_ERRNO(openat(dir_fd, "swapfile", O_RDONLY|O_CLOEXEC|O_NOCTTY));

        unsigned attrs;
        ASSERT_OK(read_attr_fd(fd, &attrs));
        if (!FLAGS_SET(attrs, FS_NOCOW_FL) || FLAGS_SET(attrs, FS_COMPR_FL))
                return (void) log_tests_skipped("swapfile is not NOCOW/non-compressed (old btrfs-progs?)");

        /* btrfs_get_file_physical_offset_fd() uses BTRFS_IOC_TREE_SEARCH, which needs CAP_SYS_ADMIN. */
        uint64_t offset;
        r = btrfs_get_file_physical_offset_fd(fd, &offset);
        if (r == -EPERM)
                return (void) log_tests_skipped("not running privileged");
        ASSERT_OK(r);

        /* Cross-check against `btrfs inspect-internal map-swapfile -r`, which prints the first
         * physical address in page units. */
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC));

        _cleanup_(pidref_done) PidRef inspect = PIDREF_NULL;
        r = pidref_safe_fork_full("(btrfs-inspect)",
                                  (int[3]) { -EBADF, pipe_fds[1], STDERR_FILENO },
                                  /* except_fds= */ NULL, /* n_except_fds= */ 0,
                                  FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG|FORK_REARRANGE_STDIO,
                                  &inspect);
        ASSERT_OK(r);
        if (r == 0) {
                execlp(btrfs_progs, "btrfs", "inspect-internal", "map-swapfile", "-r", path, NULL);
                _exit(EXIT_FAILURE);
        }
        pipe_fds[1] = safe_close(pipe_fds[1]);

        _cleanup_fclose_ FILE *f = ASSERT_NOT_NULL(take_fdopen(&pipe_fds[0], "r"));
        _cleanup_free_ char *out = NULL;
        ASSERT_OK(read_full_stream(f, &out, /* ret_size= */ NULL));
        ASSERT_OK_EQ(pidref_wait_for_terminate_and_check("(btrfs-inspect)", &inspect, 0), 0);

        uint64_t expected;
        ASSERT_OK(safe_atou64(strstrip(out), &expected));
        ASSERT_EQ(offset / page_size(), expected);
        log_info("physical offset: page %" PRIu64, expected);
}

static int intro(void) {
        const char *vtd;
        int r;

        r = var_tmp_dir(&vtd);
        if (r < 0)
                return log_tests_skipped_errno(r, "Failed to resolve /var/tmp");

        r = path_is_fs_type(vtd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return log_tests_skipped_errno(r, "Failed to determine filesystem type of %s", vtd);
        if (r == 0)
                return log_tests_skipped("%s is not on btrfs", vtd);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
