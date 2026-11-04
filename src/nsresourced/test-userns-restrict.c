/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/btrfs.h>
#include <linux/magic.h>
#include <sched.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "btrfs-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "namespace-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "userns-restrict.h"

static int make_tmpfs_fsmount(void) {
        _cleanup_close_ int fsfd = -EBADF, mntfd = -EBADF;

        fsfd = fsopen("tmpfs", FSOPEN_CLOEXEC);
        assert_se(fsfd >= 0);
        assert_se(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) >= 0);

        mntfd = fsmount(fsfd, FSMOUNT_CLOEXEC, 0);
        assert_se(mntfd >= 0);

        return TAKE_FD(mntfd);
}

static void test_works_reg(int parent_fd, const char *fname) {
        _cleanup_close_ int fd = -EBADF;

        fd = openat(parent_fd, fname, O_RDWR|O_CREAT|O_CLOEXEC, 0666);
        assert_se(fd >= 0);
}

static void test_fails_reg(int parent_fd, const char *fname) {
        errno = 0;
        assert_se(openat(parent_fd, fname, O_RDWR|O_CREAT|O_CLOEXEC, 0666) < 0);
        assert_se(errno == EPERM);
}

static void test_works_dir(int parent_fd, const char *fname) {
        assert_se(mkdirat(parent_fd, fname, 0666) >= 0);
}

static void test_fails_dir(int parent_fd, const char *fname) {
        errno = 0;
        assert_se(mkdirat(parent_fd, fname, 0666) < 0);
        assert_se(errno == EPERM);
}

static void test_userns_restrict_btrfs(struct userns_restrict_bpf *obj) {
        _cleanup_(rm_rf_subvolume_and_freep) char *t = NULL;
        _cleanup_close_ int dir_fd = -EBADF, host_fd = -EBADF, mapped_fd = -EBADF,
                             mount_fd = -EBADF, idmapped_fd = -EBADF, userns_fd = -EBADF,
                             tmpfs_mount = -EBADF, tmpfs_fd = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *idmap = NULL;
        struct stat st;
        int r;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-userns-restrict-btrfs.XXXXXX", &t));
        dir_fd = ASSERT_OK(xopenat(AT_FDCWD, t, O_DIRECTORY|O_CLOEXEC));
        if (ASSERT_OK(fd_is_fs_type(dir_fd, BTRFS_SUPER_MAGIC)) == 0)
                return (void) log_tests_skipped("Temporary directory is not on Btrfs");

        host_fd = ASSERT_OK(xopenat_full(dir_fd, "host", O_DIRECTORY|O_CREAT|O_CLOEXEC, /* xopen_flags= */ 0, 0700));
        mapped_fd = ASSERT_OK(xopenat_full(dir_fd, "mapped", O_DIRECTORY|O_CREAT|O_CLOEXEC, /* xopen_flags= */ 0, 0700));
        ASSERT_OK_ERRNO(fchown(host_fd, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        ASSERT_OK(btrfs_subvol_make(host_fd, "probe"));
        ASSERT_OK(btrfs_subvol_remove_at(host_fd, "probe", /* flags= */ 0));

        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", (uid_t) CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        mount_fd = ASSERT_OK_ERRNO(open_tree(mapped_fd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH));
        ASSERT_OK_ERRNO(mount_setattr(mount_fd, "", AT_EMPTY_PATH,
                                      &(struct mount_attr) {
                                              .attr_set = MOUNT_ATTR_IDMAP,
                                              .userns_fd = userns_fd,
                                      }, sizeof(struct mount_attr)));
        idmapped_fd = ASSERT_OK(xopenat(mount_fd, ".", O_DIRECTORY|O_CLOEXEC));

        tmpfs_mount = ASSERT_OK(make_tmpfs_fsmount());
        tmpfs_fd = ASSERT_OK(xopenat(tmpfs_mount, ".", O_DIRECTORY|O_CLOEXEC));

        /* The idmapped mount must be explicitly allowlisted under the mount-based policy. */
        ASSERT_OK(userns_restrict_put_by_fd(obj, userns_fd, /* replace= */ true, &idmapped_fd, 1));

        r = ASSERT_OK(pidref_safe_fork("(btrfs)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                struct btrfs_ioctl_vol_args legacy = { .name = "legacy" };
                struct btrfs_ioctl_vol_args_v2 modern = { .name = "modern" };
                struct btrfs_ioctl_fs_info_args info = {};

                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));

                ASSERT_ERROR_ERRNO(ioctl(host_fd, BTRFS_IOC_SUBVOL_CREATE, &legacy), EPERM);
                ASSERT_ERROR_ERRNO(ioctl(host_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &modern), EPERM);
                ASSERT_OK_ERRNO(ioctl(idmapped_fd, BTRFS_IOC_SUBVOL_CREATE, &legacy));
                ASSERT_OK_ERRNO(ioctl(idmapped_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &modern));
                ASSERT_OK_ERRNO(ioctl(host_fd, BTRFS_IOC_FS_INFO, &info));

                ASSERT_ERROR_ERRNO(ioctl(tmpfs_fd, BTRFS_IOC_SUBVOL_CREATE, &legacy), ENOTTY);
                ASSERT_ERROR_ERRNO(ioctl(tmpfs_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &modern), ENOTTY);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(btrfs)", &pidref, WAIT_LOG));

        FOREACH_STRING(name, "legacy", "modern") {
                ASSERT_OK_ERRNO(fstatat(mapped_fd, name, &st, 0));
                ASSERT_EQ(st.st_uid, 0U);
                ASSERT_EQ(st.st_gid, 0U);
        }

        ASSERT_OK_ERRNO(fstat(userns_fd, &st));
        ASSERT_OK(userns_restrict_reset_by_inode(obj, st.st_ino));
}

static int run(int argc, char *argv[]) {
        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *obj = NULL;
        _cleanup_close_ int userns_fd = -EBADF, host_fd1 = -EBADF, host_tmpfs = -EBADF, afd = -EBADF, bfd = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        bool have_tmpfile;
        int r;

        log_set_max_level(LOG_DEBUG);
        log_setup();

        r = userns_restrict_install(/* pin= */ false, &obj);
        if (ERRNO_IS_NOT_SUPPORTED(r)) {
                log_notice("Skipping test, LSM-BPF logic not supported.");
                return EXIT_TEST_SKIP;
        }
        if (ERRNO_IS_PRIVILEGE(r)) {
                log_notice("Skipping test, lacking privileges.");
                return EXIT_TEST_SKIP;
        }
        if (r < 0)
                return r;

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        host_fd1 = open(t, O_DIRECTORY|O_CLOEXEC);
        assert_se(host_fd1 >= 0);

        host_tmpfs = make_tmpfs_fsmount();
        assert_se(host_tmpfs >= 0);

        r = RET_NERRNO(openat(host_fd1, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0666));
        have_tmpfile = r >= 0;
        if (have_tmpfile)
                safe_close(r);
        else {
                ASSERT_ERROR(r, EOPNOTSUPP);
                log_notice("O_TMPFILE is not supported here, skipping host directory checks.");
        }

        /* The client cannot create a file in the host directory for the whiteout check. */
        safe_close(ASSERT_OK_ERRNO(openat(host_fd1, "white", O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0644)));

        userns_fd = userns_acquire("0 0 1", "0 0 1", /* setgroups_deny= */ true);
        if (userns_fd < 0)
                return log_error_errno(userns_fd, "Failed to make user namespace: %m");

        r = userns_restrict_put_by_fd(
                        obj,
                        userns_fd,
                        /* replace= */ true,
                        /* mount_fds= */ NULL,
                        /* n_mount_fds= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to restrict user namespace: %m");

        afd = eventfd(0, EFD_CLOEXEC);
        bfd = eventfd(0, EFD_CLOEXEC);

        assert_se(afd >= 0 && bfd >= 0);

        r = safe_fork("(test)", FORK_DEATHSIG_SIGKILL, &pid);
        assert_se(r >= 0);
        if (r == 0) {
                _cleanup_close_ int private_tmpfs = -EBADF;

                assert_se(setns(userns_fd, CLONE_NEWUSER) >= 0);
                assert_se(unshare(CLONE_NEWNS) >= 0);

                /* Allocate tmpfs locally */
                private_tmpfs = make_tmpfs_fsmount();

                /* These two host mounts should be inaccessible */
                test_fails_reg(host_fd1, "test");
                test_fails_reg(host_tmpfs, "xxx");
                test_fails_dir(host_fd1, "test2");
                test_fails_dir(host_tmpfs, "xxx2");

                /* But this mount created locally should be fine */
                test_works_reg(private_tmpfs, "yyy");
                test_works_dir(private_tmpfs, "yyy2");

                if (have_tmpfile) {
                        ASSERT_ERROR_ERRNO(openat(host_fd1, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0666), EPERM);
                        ASSERT_ERROR_ERRNO(openat(host_fd1, ".", O_TMPFILE|O_EXCL|O_RDWR|O_CLOEXEC, 0666), EPERM);
                }
                ASSERT_ERROR_ERRNO(openat(host_tmpfs, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(openat(host_tmpfs, ".", O_TMPFILE|O_EXCL|O_RDWR|O_CLOEXEC, 0666), EPERM);

                _cleanup_close_ int tmpfile_fd = -EBADF;
                tmpfile_fd = ASSERT_OK_ERRNO(openat(private_tmpfs, ".", O_TMPFILE|O_RDWR|O_CLOEXEC, 0666));
                ASSERT_OK(link_fd(tmpfile_fd, private_tmpfs, "ccc"));

                safe_close(ASSERT_OK_ERRNO(openat(private_tmpfs, ".", O_TMPFILE|O_EXCL|O_RDWR|O_CLOEXEC, 0666)));

                /* The whiteout RENAME_WHITEOUT leaves behind is owned by us too. */
                ASSERT_ERROR_ERRNO(renameat2(host_fd1, "white", host_fd1, "white2", RENAME_WHITEOUT), EPERM);
                ASSERT_OK_ERRNO(renameat2(private_tmpfs, "ccc", private_tmpfs, "ccc2", RENAME_WHITEOUT));

                /* Let's sync with the parent, so that it allowlists more stuff for us */
                assert_se(eventfd_write(afd, 1) >= 0);
                uint64_t x;
                assert_se(eventfd_read(bfd, &x) >= 0);

                /* And now we should also have access to the host tmpfs */
                test_works_reg(host_tmpfs, "zzz");
                test_works_reg(private_tmpfs, "aaa");
                test_works_dir(host_tmpfs, "zzz2");
                test_works_dir(private_tmpfs, "aaa2");

                /* But this one should still fail */
                test_fails_reg(host_fd1, "bbb");
                test_fails_dir(host_fd1, "bbb2");

                /* Sync again, to get more stuff allowlisted */
                assert_se(eventfd_write(afd, 1) >= 0);
                assert_se(eventfd_read(bfd, &x) >= 0);

                /* Everything should now be allowed */
                test_works_reg(host_tmpfs, "ccc");
                test_works_reg(host_fd1, "ddd");
                test_works_reg(private_tmpfs, "eee");
                test_works_dir(host_tmpfs, "ccc2");
                test_works_reg(host_fd1, "ddd2");
                test_works_dir(private_tmpfs, "eee2");

                _exit(EXIT_SUCCESS);
        }

        uint64_t x;
        assert_se(eventfd_read(afd, &x) >= 0);

        r = userns_restrict_put_by_fd(
                        obj,
                        userns_fd,
                        /* replace= */ false,
                        &host_tmpfs,
                        1);
        if (r < 0)
                return log_error_errno(r, "Failed to loosen user namespace: %m");

        assert_se(eventfd_write(bfd, 1) >= 0);

        assert_se(eventfd_read(afd, &x) >= 0);

        r = userns_restrict_put_by_fd(
                        obj,
                        userns_fd,
                        /* replace= */ false,
                        &host_fd1,
                        1);
        if (r < 0)
                return log_error_errno(r, "Failed to loosen user namespace: %m");

        assert_se(eventfd_write(bfd, 1) >= 0);

        assert_se(wait_for_terminate_and_check("(test)", pid, WAIT_LOG) >= 0);

        test_userns_restrict_btrfs(obj);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
