/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "btrfs-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

int main(int argc, char *argv[]) {
        BtrfsQuotaInfo quota;
        int r, fd;

        test_setup_logging(LOG_DEBUG);

        fd = open("/", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                log_error_errno(errno, "Failed to open root directory: %m");
        else {
                BtrfsSubvolInfo info;

                r = btrfs_subvol_get_info_fd(fd, 0, &info);
                if (r < 0)
                        log_error_errno(r, "Failed to get subvolume info: %m");
                else {
                        log_info("otime: %s", FORMAT_TIMESTAMP(info.otime));
                        log_info("read-only (search): %s", yes_no(info.read_only));
                }

                r = btrfs_qgroup_get_quota_fd(fd, 0, &quota);
                if (r < 0)
                        log_error_errno(r, "Failed to get quota info: %m");
                else {
                        log_info("referenced: %s", strna(FORMAT_BYTES(quota.referenced)));
                        log_info("exclusive: %s", strna(FORMAT_BYTES(quota.exclusive)));
                        log_info("referenced_max: %s", strna(FORMAT_BYTES(quota.referenced_max)));
                        log_info("exclusive_max: %s", strna(FORMAT_BYTES(quota.exclusive_max)));
                }

                r = btrfs_subvol_get_read_only_fd(fd);
                if (r < 0)
                        log_error_errno(r, "Failed to get read only flag: %m");
                else
                        log_info("read-only (ioctl): %s", yes_no(r));

                safe_close(fd);
        }

        r = btrfs_subvol_make(AT_FDCWD, "/xxxtest");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        r = write_string_file("/xxxtest/file", "ljsadhfljasdkfhlkjdsfha", WRITE_STRING_FILE_CREATE);
        if (r < 0)
                log_error_errno(r, "Failed to write file: %m");

        r = btrfs_subvol_snapshot_at(AT_FDCWD, "/xxxtest", AT_FDCWD, "/xxxtest2", 0);
        if (r < 0)
                log_error_errno(r, "Failed to make snapshot: %m");

        r = btrfs_subvol_snapshot_at(AT_FDCWD, "/xxxtest", AT_FDCWD, "/xxxtest3", BTRFS_SNAPSHOT_READ_ONLY);
        if (r < 0)
                log_error_errno(r, "Failed to make snapshot: %m");

        r = btrfs_subvol_snapshot_at(AT_FDCWD, "/xxxtest", AT_FDCWD, "/xxxtest4", BTRFS_SNAPSHOT_LOCK_BSD);
        if (r < 0)
                log_error_errno(r, "Failed to make snapshot: %m");
        if (r >= 0)
                assert_se(xopenat_lock(AT_FDCWD, "/xxxtest4", 0, LOCK_BSD, LOCK_EX|LOCK_NB) == -EAGAIN);

        safe_close(r);

        r = btrfs_subvol_remove("/xxxtest", BTRFS_REMOVE_QUOTA);
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_remove("/xxxtest2", BTRFS_REMOVE_QUOTA);
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_remove("/xxxtest3", BTRFS_REMOVE_QUOTA);
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_remove("/xxxtest4", BTRFS_REMOVE_QUOTA);
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_snapshot_at(AT_FDCWD, "/etc", AT_FDCWD, "/etc2",
                                     BTRFS_SNAPSHOT_READ_ONLY|BTRFS_SNAPSHOT_FALLBACK_COPY);
        if (r < 0)
                log_error_errno(r, "Failed to make snapshot: %m");

        r = btrfs_subvol_remove("/etc2", BTRFS_REMOVE_QUOTA);
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxrectest");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxrectest/xxxrectest2");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxrectest/xxxrectest3");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxrectest/xxxrectest3/sub");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        if (mkdir("/xxxrectest/dir", 0755) < 0)
                log_error_errno(errno, "Failed to make directory: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxrectest/dir/xxxrectest4");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        if (mkdir("/xxxrectest/dir/xxxrectest4/dir", 0755) < 0)
                log_error_errno(errno, "Failed to make directory: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxrectest/dir/xxxrectest4/dir/xxxrectest5");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        if (mkdir("/xxxrectest/mnt", 0755) < 0)
                log_error_errno(errno, "Failed to make directory: %m");

        r = btrfs_subvol_snapshot_at(AT_FDCWD, "/xxxrectest", AT_FDCWD, "/xxxrectest2", BTRFS_SNAPSHOT_RECURSIVE);
        if (r < 0)
                log_error_errno(r, "Failed to snapshot subvolume: %m");

        r = btrfs_subvol_remove("/xxxrectest", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE);
        if (r < 0)
                log_error_errno(r, "Failed to recursively remove subvolume: %m");

        r = btrfs_subvol_remove("/xxxrectest2", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE);
        if (r < 0)
                log_error_errno(r, "Failed to recursively remove subvolume: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxquotatest");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        r = btrfs_subvol_auto_qgroup("/xxxquotatest", 0, true);
        if (r < 0)
                log_error_errno(r, "Failed to set up auto qgroup: %m");

        r = btrfs_subvol_make(AT_FDCWD, "/xxxquotatest/beneath");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        r = btrfs_subvol_auto_qgroup("/xxxquotatest/beneath", 0, false);
        if (r < 0)
                log_error_errno(r, "Failed to set up auto qgroup: %m");

        r = btrfs_qgroup_set_limit("/xxxquotatest/beneath", 0, 4ULL * 1024 * 1024 * 1024);
        if (r < 0)
                log_error_errno(r, "Failed to set up quota limit: %m");

        r = btrfs_subvol_set_subtree_quota_limit("/xxxquotatest", 0, 5ULL * 1024 * 1024 * 1024);
        if (r < 0)
                log_error_errno(r, "Failed to set up quota limit: %m");

        r = btrfs_subvol_snapshot_at(AT_FDCWD, "/xxxquotatest", AT_FDCWD, "/xxxquotatest2",
                                     BTRFS_SNAPSHOT_RECURSIVE|BTRFS_SNAPSHOT_QUOTA);
        if (r < 0)
                log_error_errno(r, "Failed to set up snapshot: %m");

        r = btrfs_qgroup_get_quota("/xxxquotatest2/beneath", 0, &quota);
        if (r < 0)
                log_error_errno(r, "Failed to query quota: %m");

        if (r >= 0)
                assert_se(quota.referenced_max == 4ULL * 1024 * 1024 * 1024);

        r = btrfs_subvol_get_subtree_quota("/xxxquotatest2", 0, &quota);
        if (r < 0)
                log_error_errno(r, "Failed to query quota: %m");

        if (r >= 0)
                assert_se(quota.referenced_max == 5ULL * 1024 * 1024 * 1024);

        r = btrfs_subvol_remove("/xxxquotatest", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE);
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_remove("/xxxquotatest2", BTRFS_REMOVE_QUOTA|BTRFS_REMOVE_RECURSIVE);
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        return 0;
}
