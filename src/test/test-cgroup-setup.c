/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "virt.h"

TEST(cg_create) {
        int r;

        _cleanup_free_ char *here = NULL;
        ASSERT_OK(cg_pid_get_path_shifted(/* pid= */ 0, /* cached_root= */ NULL, &here));

        /* cg_* will use path_simplify(), so use it here too otherwise when running in a container at the
         * root it asserts with "/test-b != //test-b" */
        _cleanup_free_ char *test_a = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-a"))),
                            *test_b = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b"))),
                            *test_c = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b/test-c"))),
                            *test_d = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b/test-d")));
        char *path;

        log_info("Paths for test:\n%s\n%s", test_a, test_b);

        /* Possibly clean up left-overs from aborted previous runs */
        (void) cg_trim(test_a, /* delete_root= */ true);
        (void) cg_trim(test_b, /* delete_root= */ true);

        r = cg_create(test_a);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(r) || r == -ENOENT)
                return (void) log_tests_skipped_errno(r, "%s: Failed to create cgroup %s", __func__, test_a);

        ASSERT_OK_EQ(r, 1);
        ASSERT_OK_ZERO(cg_create(test_a));
        ASSERT_OK_EQ(cg_create(test_b), 1);
        ASSERT_OK_EQ(cg_create(test_c), 1);
        ASSERT_OK_ZERO(cg_create_and_attach(test_b, /* pid= */ 0));

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_STREQ(path, test_b);
        free(path);

        ASSERT_OK_ZERO(cg_attach(test_a, /* pid= */ 0));

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_a));
        free(path);

        ASSERT_OK_EQ(cg_create_and_attach(test_d, /* pid= */ 0), 1);

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_d));
        free(path);

        ASSERT_OK_ZERO(cg_get_path(test_d, /* suffix= */ NULL, &path));
        log_debug("test_d: %s", path);
        ASSERT_TRUE(path_equal(path, strjoina("/sys/fs/cgroup", test_d)));
        free(path);

        ASSERT_OK_POSITIVE(cg_is_empty(test_a));
        ASSERT_OK_ZERO(cg_is_empty(test_b));

        ASSERT_OK_ZERO(cg_kill_recursive(test_a, /* sig= */ 0, /* flags= */ 0, /* killed_pids= */ NULL, /* log_kill= */ NULL, /* userdata= */ NULL));
        ASSERT_OK_POSITIVE(cg_kill_recursive(test_b, /* sig= */ 0, /* flags= */ 0, /* killed_pids= */ NULL, /* log_kill= */ NULL, /* userdata= */ NULL));

        ASSERT_OK(cg_trim(test_a, /* delete_root= */ true));
        ASSERT_ERROR(cg_trim(test_b, /* delete_root= */ true), EBUSY);

        ASSERT_OK_ZERO(cg_attach(here, /* pid= */ 0));
        ASSERT_OK(cg_trim(test_b, /* delete_root= */ true));
}

TEST(cg_pin_attribute) {
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("running in chroot");

        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_close_ int tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &tmp));
        _cleanup_close_ int file = ASSERT_OK(xopenat_full(tfd, "file", O_CREAT|O_EXCL|O_WRONLY, /* xopen_flags= */ 0, 0600));
        _cleanup_close_ int pinned = ASSERT_OK(cg_pin_attribute(tfd, "file"));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(file, pinned));

        ASSERT_OK_ERRNO(symlinkat("file", tfd, "link"));
        ASSERT_OK_ERRNO(mkdirat(tfd, "dir", 0755));
        ASSERT_OK_ERRNO(mkfifoat(tfd, "fifo", 0600));
        ASSERT_ERROR(cg_pin_attribute(tfd, "link"), ELOOP);
        ASSERT_ERROR(cg_pin_attribute(tfd, "dir"), EISDIR);
        ASSERT_ERROR(cg_pin_attribute(tfd, "fifo"), EBADFD);
        ASSERT_ERROR(cg_pin_attribute(tfd, "missing"), ENOENT);

        _cleanup_close_ int cg = ASSERT_OK(cg_path_open("/"));
        _cleanup_close_ int procs = ASSERT_OK(cg_pin_attribute(cg, "cgroup.procs"));
        ASSERT_OK_POSITIVE(fd_is_opath(procs));

        _cleanup_close_ int root = ASSERT_OK(xopenat(AT_FDCWD, "/", O_PATH|O_DIRECTORY));
        ASSERT_ERROR(cg_pin_attribute(root, "proc"), EXDEV);

        /* A bind mount of a file onto itself keeps both its device and inode number. Only the mount changes. */
        int r = pidref_safe_fork(
                        "(cg-pin-attribute)",
                        FORK_CLOSE_ALL_FDS|FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REOPEN_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        /* ret= */ NULL);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Cannot test a private bind mount");
        ASSERT_OK(r);
        if (r == 0) {
                ASSERT_OK(mount_nofollow("/proc/version", "/proc/version", /* filesystemtype= */ NULL, MS_BIND, /* data= */ NULL));

                _cleanup_close_ int proc = ASSERT_OK(xopenat(AT_FDCWD, "/proc", O_PATH|O_DIRECTORY));
                ASSERT_ERROR(cg_pin_attribute(proc, "version"), EXDEV);
                _exit(EXIT_SUCCESS);
        }
}

static int intro(void) {
        if (cg_is_available() <= 0)
                return log_tests_skipped("cgroupfs v2 is not mounted");

        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
