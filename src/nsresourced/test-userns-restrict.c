/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/eventfd.h>

#include "fd-util.h"
#include "main-func.h"
#include "missing_mount.h"
#include "missing_syscall.h"
#include "namespace-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "tmpfile-util.h"
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

static int run(int argc, char *argv[]) {
        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *obj = NULL;
        _cleanup_close_ int userns_fd = -EBADF, host_fd1 = -EBADF, host_tmpfs = -EBADF, afd = -EBADF, bfd = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
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

        userns_fd = userns_acquire("0 0 1", "0 0 1");
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

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
