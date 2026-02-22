/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "namespace-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "userns-restrict.h"

static int make_tmpfs_fsmount(void) {
        _cleanup_close_ int fsfd = -EBADF, mntfd = -EBADF;

        fsfd = ASSERT_OK_ERRNO(fsopen("tmpfs", FSOPEN_CLOEXEC));
        ASSERT_OK_ERRNO(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0));

        mntfd = ASSERT_OK_ERRNO(fsmount(fsfd, FSMOUNT_CLOEXEC, 0));

        return TAKE_FD(mntfd);
}

static struct userns_restrict_bpf *bpf_obj = NULL;
STATIC_DESTRUCTOR_REGISTER(bpf_obj, userns_restrict_bpf_freep);

static int intro(void) {
        int r;

        r = userns_restrict_install(/* pin= */ false, &bpf_obj);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("LSM-BPF logic not supported");
        if (ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped("Lacking privileges");
        ASSERT_OK(r);

        return 0;
}

TEST(userns_restrict) {
        _cleanup_close_ int userns_fd = -EBADF, host_fd1 = -EBADF, host_tmpfs = -EBADF, afd = -EBADF, bfd = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc(NULL, &t));

        host_fd1 = ASSERT_OK_ERRNO(open(t, O_DIRECTORY|O_CLOEXEC));
        host_tmpfs = ASSERT_OK(make_tmpfs_fsmount());
        userns_fd = ASSERT_OK(userns_acquire("0 0 1", "0 0 1", /* setgroups_deny= */ true));

        ASSERT_OK(userns_restrict_put_by_fd(
                        bpf_obj,
                        userns_fd,
                        /* replace= */ true,
                        /* mount_fds= */ NULL,
                        /* n_mount_fds= */ 0));

        afd = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));
        bfd = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));

        r = ASSERT_OK(pidref_safe_fork("(test)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                _cleanup_close_ int private_tmpfs = -EBADF;

                ASSERT_OK_ERRNO(setns(userns_fd, CLONE_NEWUSER));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));

                /* Allocate tmpfs locally */
                private_tmpfs = make_tmpfs_fsmount();

                /* These two host mounts should be inaccessible */
                ASSERT_ERROR_ERRNO(openat(host_fd1, "test", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(openat(host_tmpfs, "xxx", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(host_fd1, "test2", 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(host_tmpfs, "xxx2", 0666), EPERM);

                /* But this mount created locally should be fine */
                safe_close(ASSERT_OK_ERRNO(openat(private_tmpfs, "yyy", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                ASSERT_OK_ERRNO(mkdirat(private_tmpfs, "yyy2", 0666));

                /* Let's sync with the parent, so that it allowlists more stuff for us */
                ASSERT_OK_ERRNO(eventfd_write(afd, 1));
                uint64_t x;
                ASSERT_OK_ERRNO(eventfd_read(bfd, &x));

                /* And now we should also have access to the host tmpfs */
                safe_close(ASSERT_OK_ERRNO(openat(host_tmpfs, "zzz", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                safe_close(ASSERT_OK_ERRNO(openat(private_tmpfs, "aaa", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                ASSERT_OK_ERRNO(mkdirat(host_tmpfs, "zzz2", 0666));
                ASSERT_OK_ERRNO(mkdirat(private_tmpfs, "aaa2", 0666));

                /* But this one should still fail */
                ASSERT_ERROR_ERRNO(openat(host_fd1, "bbb", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(host_fd1, "bbb2", 0666), EPERM);

                /* Sync again, to get more stuff allowlisted */
                ASSERT_OK_ERRNO(eventfd_write(afd, 1));
                ASSERT_OK_ERRNO(eventfd_read(bfd, &x));

                /* Everything should now be allowed */
                safe_close(ASSERT_OK_ERRNO(openat(host_tmpfs, "ccc", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                safe_close(ASSERT_OK_ERRNO(openat(host_fd1, "ddd", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                safe_close(ASSERT_OK_ERRNO(openat(private_tmpfs, "eee", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                ASSERT_OK_ERRNO(mkdirat(host_tmpfs, "ccc2", 0666));
                safe_close(ASSERT_OK_ERRNO(openat(host_fd1, "ddd2", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                ASSERT_OK_ERRNO(mkdirat(private_tmpfs, "eee2", 0666));

                _exit(EXIT_SUCCESS);
        }

        uint64_t x;
        ASSERT_OK_ERRNO(eventfd_read(afd, &x));

        ASSERT_OK(userns_restrict_put_by_fd(
                        bpf_obj,
                        userns_fd,
                        /* replace= */ false,
                        &host_tmpfs,
                        1));

        ASSERT_OK_ERRNO(eventfd_write(bfd, 1));
        ASSERT_OK_ERRNO(eventfd_read(afd, &x));

        ASSERT_OK(userns_restrict_put_by_fd(
                        bpf_obj,
                        userns_fd,
                        /* replace= */ false,
                        &host_fd1,
                        1));

        ASSERT_OK_ERRNO(eventfd_write(bfd, 1));

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test)", &pidref, WAIT_LOG));
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
