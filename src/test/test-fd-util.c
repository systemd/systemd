/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "seccomp-util.h"
#include "serialize.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(close_many) {
        int fds[3];
        _cleanup_(unlink_tempfilep) char name0[] = "/tmp/test-close-many.XXXXXX";
        _cleanup_(unlink_tempfilep) char name1[] = "/tmp/test-close-many.XXXXXX";
        _cleanup_(unlink_tempfilep) char name2[] = "/tmp/test-close-many.XXXXXX";

        fds[0] = mkostemp_safe(name0);
        fds[1] = mkostemp_safe(name1);
        fds[2] = mkostemp_safe(name2);

        close_many(fds, 2);

        assert_se(fd_validate(fds[0]) == -EBADF);
        assert_se(fd_validate(fds[1]) == -EBADF);
        assert_se(fd_validate(fds[2]) >= 0);

        safe_close(fds[2]);
}

TEST(close_nointr) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);
        assert_se(close_nointr(fd) < 0);
}

TEST(fd_validate) {
        assert_se(fd_validate(-EINVAL) == -EBADF);
        assert_se(fd_validate(-EBADF) == -EBADF);

        _cleanup_close_ int b = -EBADF;
        assert_se((b = open("/dev/null", O_RDONLY|O_CLOEXEC)) >= 0);

        assert_se(fd_validate(b) == 0);
        safe_close(b);
        assert_se(fd_validate(b) == -EBADF);
        TAKE_FD(b);
}

TEST(same_fd) {
        _cleanup_close_pair_ int p[2];
        _cleanup_close_ int a, b, c, d, e;

        assert_se(pipe2(p, O_CLOEXEC) >= 0);
        assert_se((a = fcntl(p[0], F_DUPFD, 3)) >= 0);
        assert_se((b = open("/bin/sh", O_RDONLY|O_CLOEXEC)) >= 0);
        assert_se((c = fcntl(a, F_DUPFD, 3)) >= 0);
        assert_se((d = open("/bin/sh", O_RDONLY|O_CLOEXEC|O_PATH)) >= 0); /* O_PATH changes error returns in F_DUPFD_QUERY, let's test explicitly */
        assert_se((e = fcntl(d, F_DUPFD, 3)) >= 0);

        assert_se(same_fd(p[0], p[0]) > 0);
        assert_se(same_fd(p[1], p[1]) > 0);
        assert_se(same_fd(a, a) > 0);
        assert_se(same_fd(b, b) > 0);

        assert_se(same_fd(a, p[0]) > 0);
        assert_se(same_fd(p[0], a) > 0);
        assert_se(same_fd(c, p[0]) > 0);
        assert_se(same_fd(p[0], c) > 0);
        assert_se(same_fd(a, c) > 0);
        assert_se(same_fd(c, a) > 0);

        assert_se(same_fd(p[0], p[1]) == 0);
        assert_se(same_fd(p[1], p[0]) == 0);
        assert_se(same_fd(p[0], b) == 0);
        assert_se(same_fd(b, p[0]) == 0);
        assert_se(same_fd(p[1], a) == 0);
        assert_se(same_fd(a, p[1]) == 0);
        assert_se(same_fd(p[1], b) == 0);
        assert_se(same_fd(b, p[1]) == 0);

        assert_se(same_fd(a, b) == 0);
        assert_se(same_fd(b, a) == 0);

        assert_se(same_fd(a, d) == 0);
        assert_se(same_fd(d, a) == 0);
        assert_se(same_fd(d, d) > 0);
        assert_se(same_fd(d, e) > 0);
        assert_se(same_fd(e, d) > 0);

        /* Let's now compare with a valid fd nr, that is definitely closed, and verify it returns the right error code */
        safe_close(d);
        assert_se(same_fd(d, d) == -EBADF);
        assert_se(same_fd(e, d) == -EBADF);
        assert_se(same_fd(d, e) == -EBADF);
        assert_se(same_fd(e, e) > 0);
        TAKE_FD(d);
}

TEST(open_serialization_fd) {
        _cleanup_close_ int fd = -EBADF;

        fd = open_serialization_fd("test");
        assert_se(fd >= 0);

        assert_se(write(fd, "test\n", 5) == 5);

        assert_se(finish_serialization_fd(fd) >= 0);
}

TEST(open_serialization_file) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        r = open_serialization_file("test", &f);
        assert_se(r >= 0);
        assert_se(f);

        assert_se(fwrite("test\n", 1, 5, f) == 5);

        assert_se(finish_serialization_file(f) >= 0);
}

TEST(fd_move_above_stdio) {
        int original_stdin, new_fd;

        original_stdin = fcntl(0, F_DUPFD, 3);
        assert_se(original_stdin >= 3);
        assert_se(close_nointr(0) != EBADF);

        new_fd = open("/dev/null", O_RDONLY);
        assert_se(new_fd == 0);

        new_fd = fd_move_above_stdio(new_fd);
        assert_se(new_fd >= 3);

        assert_se(dup(original_stdin) == 0);
        assert_se(close_nointr(original_stdin) != EBADF);
        assert_se(close_nointr(new_fd) != EBADF);
}

TEST(rearrange_stdio) {
        pid_t pid;
        int r;

        r = safe_fork("rearrange", FORK_WAIT|FORK_LOG, &pid);
        assert_se(r >= 0);

        if (r == 0) {
                _cleanup_free_ char *path = NULL;
                int pipe_read_fd, pair[2];
                char buffer[10];

                /* Child */

                safe_close(STDERR_FILENO); /* Let's close an fd < 2, to make it more interesting */

                assert_se(rearrange_stdio(-EBADF, -EBADF, -EBADF) >= 0);
                /* Reconfigure logging after rearranging stdout/stderr, so we still log to somewhere if the
                 * following tests fail, making it slightly less annoying to debug */
                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                log_open();

                assert_se(fd_get_path(STDIN_FILENO, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                assert_se(fd_get_path(STDOUT_FILENO, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                assert_se(fd_get_path(STDOUT_FILENO, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                safe_close(STDIN_FILENO);
                safe_close(STDOUT_FILENO);
                safe_close(STDERR_FILENO);

                assert_se(pipe(pair) >= 0);
                assert_se(pair[0] == 0);
                assert_se(pair[1] == 1);
                pipe_read_fd = fd_move_above_stdio(0);
                assert_se(pipe_read_fd >= 3);

                assert_se(open("/dev/full", O_WRONLY|O_CLOEXEC) == 0);
                assert_se(memfd_new_and_seal_string("data", "foobar") == 2);

                assert_se(rearrange_stdio(2, 0, 1) >= 0);

                assert_se(write(1, "x", 1) < 0 && errno == ENOSPC);
                assert_se(write(2, "z", 1) == 1);
                assert_se(read(pipe_read_fd, buffer, sizeof(buffer)) == 1);
                assert_se(buffer[0] == 'z');
                assert_se(read(0, buffer, sizeof(buffer)) == 6);
                assert_se(memcmp(buffer, "foobar", 6) == 0);

                assert_se(rearrange_stdio(-EBADF, 1, 2) >= 0);
                assert_se(write(1, "a", 1) < 0 && errno == ENOSPC);
                assert_se(write(2, "y", 1) == 1);
                assert_se(read(pipe_read_fd, buffer, sizeof(buffer)) == 1);
                assert_se(buffer[0] == 'y');

                assert_se(fd_get_path(0, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                _exit(EXIT_SUCCESS);
        }
}

TEST(read_nr_open) {
        log_info("nr-open: %i", read_nr_open());
}

static size_t validate_fds(
                bool opened,
                const int *fds,
                size_t n_fds) {

        size_t c = 0;

        /* Validates that fds in the specified array are one of the following three:
         *
         *  1. < 0 (test is skipped) or
         *  2. opened (if 'opened' param is true) or
         *  3. closed (if 'opened' param is false)
         */

        for (size_t i = 0; i < n_fds; i++) {
                if (fds[i] < 0)
                        continue;

                if (opened)
                        assert_se(fd_validate(fds[i]) >= 0);
                else
                        assert_se(fd_validate(fds[i]) == -EBADF);

                c++;
        }

        return c; /* Return number of fds >= 0 in the array */
}

static void test_close_all_fds_inner(void) {
        _cleanup_free_ int *fds = NULL, *keep = NULL;
        size_t n_fds, n_keep;
        int max_fd;

        log_info("/* %s */", __func__);

        rlimit_nofile_bump(-1);

        max_fd = get_max_fd();
        assert_se(max_fd > 10);

        if (max_fd > 7000) {
                /* If the worst fallback is activated we need to iterate through all possible fds, hence,
                 * let's lower the limit a small bit, so that we don't run for too long. Yes, this undoes the
                 * rlimit_nofile_bump() call above partially. */

                (void) setrlimit_closest(RLIMIT_NOFILE, &(struct rlimit) { 7000, 7000 });
                max_fd = 7000;
        }

        /* Try to use 5000 fds, but when we can't bump the rlimit to make that happen use the whole limit minus 10 */
        n_fds = MIN(((size_t) max_fd & ~1U) - 10U, 5000U);
        assert_se((n_fds & 1U) == 0U); /* make sure even number of fds */

        /* Allocate the determined number of fds, always two at a time */
        assert_se(fds = new(int, n_fds));
        for (size_t i = 0; i < n_fds; i += 2)
                assert_se(pipe2(fds + i, O_CLOEXEC) >= 0);

        /* Validate this worked */
        assert_se(validate_fds(true, fds, n_fds) == n_fds);

        /* Randomized number of fds to keep, but at most every second */
        n_keep = (random_u64() % (n_fds / 2));

        /* Now randomly select a number of fds from the array above to keep */
        assert_se(keep = new(int, n_keep));
        for (size_t k = 0; k < n_keep; k++) {
                for (;;) {
                        size_t p;

                        p = random_u64() % n_fds;
                        if (fds[p] >= 0) {
                                keep[k] = TAKE_FD(fds[p]);
                                break;
                        }
                }
        }

        /* Check that all fds from both arrays are still open, and test how many in each are >= 0 */
        assert_se(validate_fds(true, fds, n_fds) == n_fds - n_keep);
        assert_se(validate_fds(true, keep, n_keep) == n_keep);

        /* Close logging fd first, so that we don't confuse it by closing its fd */
        log_close();
        log_set_open_when_needed(true);
        log_settle_target();

        /* Close all but the ones to keep */
        assert_se(close_all_fds(keep, n_keep) >= 0);

        assert_se(validate_fds(false, fds, n_fds) == n_fds - n_keep);
        assert_se(validate_fds(true, keep, n_keep) == n_keep);

        /* Close everything else too! */
        assert_se(close_all_fds(NULL, 0) >= 0);

        assert_se(validate_fds(false, fds, n_fds) == n_fds - n_keep);
        assert_se(validate_fds(false, keep, n_keep) == n_keep);

        log_set_open_when_needed(false);
        log_open();
}

static int seccomp_prohibit_close_range(void) {
#if HAVE_SECCOMP && defined(__SNR_close_range)
        _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
        int r;

        r = seccomp_init_for_arch(&seccomp, SCMP_ARCH_NATIVE, SCMP_ACT_ALLOW);
        if (r < 0)
                return log_warning_errno(r, "Failed to acquire seccomp context, ignoring: %m");

        r = seccomp_rule_add_exact(
                        seccomp,
                        SCMP_ACT_ERRNO(EPERM),
                        SCMP_SYS(close_range),
                        0);
        if (r < 0)
                return log_warning_errno(r, "Failed to add close_range() rule, ignoring: %m");

        r = seccomp_load(seccomp);
        if (r < 0)
                return log_warning_errno(r, "Failed to apply close_range() restrictions, ignoring: %m");

        return 0;
#else
        return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Seccomp support or close_range() syscall definition not available.");
#endif
}

TEST(close_all_fds) {
        int r;

        /* Runs the test four times. Once as is. Once with close_range() syscall blocked via seccomp, once
         * with /proc/ overmounted, and once with the combination of both. This should trigger all fallbacks
         * in the close_range_all() function. */

        r = safe_fork("(caf-plain)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        if (r == 0) {
                test_close_all_fds_inner();
                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);

        if (geteuid() != 0)
                return (void) log_tests_skipped("Lacking privileges for test with close_range() blocked and /proc/ overmounted");

        r = safe_fork("(caf-noproc)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, NULL);
        if (r == 0) {
                r = mount_nofollow_verbose(LOG_WARNING, "tmpfs", "/proc", "tmpfs", 0, NULL);
                if (r < 0)
                        log_notice("Overmounting /proc/ didn't work, skipping close_all_fds() with masked /proc/.");
                else
                        test_close_all_fds_inner();
                _exit(EXIT_SUCCESS);
        }
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped("Lacking privileges for test in namespace with /proc/ overmounted");
        assert_se(r >= 0);

        if (!is_seccomp_available())
                return (void) log_tests_skipped("Seccomp not available");

        r = safe_fork("(caf-seccomp)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        if (r == 0) {
                r = seccomp_prohibit_close_range();
                if (r < 0)
                        log_notice("Applying seccomp filter didn't work, skipping close_all_fds() test with masked close_range().");
                else
                        test_close_all_fds_inner();

                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);

        r = safe_fork("(caf-scnp)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, NULL);
        if (r == 0) {
                r = seccomp_prohibit_close_range();
                if (r < 0)
                        log_notice("Applying seccomp filter didn't work, skipping close_all_fds() test with masked close_range().");
                else {
                        r = mount_nofollow_verbose(LOG_WARNING, "tmpfs", "/proc", "tmpfs", 0, NULL);
                        if (r < 0)
                                log_notice("Overmounting /proc/ didn't work, skipping close_all_fds() with masked /proc/.");
                        else
                                test_close_all_fds_inner();
                }

                test_close_all_fds_inner();
                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);
}

TEST(format_proc_fd_path) {
        ASSERT_STREQ(FORMAT_PROC_FD_PATH(0), "/proc/self/fd/0");
        ASSERT_STREQ(FORMAT_PROC_FD_PATH(1), "/proc/self/fd/1");
        ASSERT_STREQ(FORMAT_PROC_FD_PATH(2), "/proc/self/fd/2");
        ASSERT_STREQ(FORMAT_PROC_FD_PATH(3), "/proc/self/fd/3");
        ASSERT_STREQ(FORMAT_PROC_FD_PATH(2147483647), "/proc/self/fd/2147483647");
}

TEST(fd_reopen) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;
        struct stat st1, st2;
        int fl;

        /* Test this with a directory */
        fd1 = open("/proc", O_DIRECTORY|O_PATH|O_CLOEXEC);
        assert_se(fd1 >= 0);

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        assert_se(S_ISDIR(st1.st_mode));

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        /* fd_reopen() with O_NOFOLLOW will systematically fail, since it is implemented via a symlink in /proc/self/fd/ */
        assert_se(fd_reopen(fd1, O_RDONLY|O_CLOEXEC|O_NOFOLLOW) == -ELOOP);
        assert_se(fd_reopen(fd1, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW) == -ELOOP);

        fd2 = fd_reopen(fd1, O_RDONLY|O_DIRECTORY|O_CLOEXEC);  /* drop the O_PATH */
        assert_se(fd2 >= 0);

        ASSERT_OK_ERRNO(fstat(fd2, &st2));
        assert_se(S_ISDIR(st2.st_mode));
        assert_se(stat_inode_same(&st1, &st2));

        fl = fcntl(fd2, F_GETFL);
        assert_se(fl >= 0);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(!FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        fd1 = fd_reopen(fd2, O_DIRECTORY|O_PATH|O_CLOEXEC);  /* reacquire the O_PATH */
        assert_se(fd1 >= 0);

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        assert_se(S_ISDIR(st1.st_mode));
        assert_se(stat_inode_same(&st1, &st2));

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        /* And now, test this with a file. */
        fd1 = open("/proc/version", O_PATH|O_CLOEXEC);
        assert_se(fd1 >= 0);

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        assert_se(S_ISREG(st1.st_mode));

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(!FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        assert_se(fd_reopen(fd1, O_RDONLY|O_DIRECTORY|O_CLOEXEC) == -ENOTDIR);
        fd2 = fd_reopen(fd1, O_RDONLY|O_CLOEXEC);  /* drop the O_PATH */
        assert_se(fd2 >= 0);

        ASSERT_OK_ERRNO(fstat(fd2, &st2));
        assert_se(S_ISREG(st2.st_mode));
        assert_se(stat_inode_same(&st1, &st2));

        fl = fcntl(fd2, F_GETFL);
        assert_se(fl >= 0);
        assert_se(!FLAGS_SET(fl, O_DIRECTORY));
        assert_se(!FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        assert_se(fd_reopen(fd2, O_DIRECTORY|O_PATH|O_CLOEXEC) == -ENOTDIR);
        fd1 = fd_reopen(fd2, O_PATH|O_CLOEXEC);  /* reacquire the O_PATH */
        assert_se(fd1 >= 0);

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        assert_se(S_ISREG(st1.st_mode));
        assert_se(stat_inode_same(&st1, &st2));

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(!FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        /* Also check the right error is generated if the fd is already closed */
        safe_close(fd1);
        assert_se(fd_reopen(fd1, O_RDONLY|O_CLOEXEC) == -EBADF);
        fd1 = -EBADF;

        /* Validate what happens if we reopen a symlink */
        fd1 = open("/proc/self", O_PATH|O_CLOEXEC|O_NOFOLLOW);
        assert_se(fd1 >= 0);
        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        assert_se(S_ISLNK(st1.st_mode));

        fd2 = fd_reopen(fd1, O_PATH|O_CLOEXEC);
        assert_se(fd2 >= 0);
        ASSERT_OK_ERRNO(fstat(fd2, &st2));
        assert_se(S_ISLNK(st2.st_mode));
        assert_se(stat_inode_same(&st1, &st2));
        fd2 = safe_close(fd2);

        /* So here's the thing: if we have an O_PATH fd to a symlink, we *cannot* convert it to a regular fd
         * with that. i.e. you cannot have the VFS follow a symlink pinned via an O_PATH fd. */
        assert_se(fd_reopen(fd1, O_RDONLY|O_CLOEXEC) == -ELOOP);
}

TEST(fd_reopen_condition) {
        _cleanup_close_ int fd1 = -EBADF, fd3 = -EBADF;
        int fd2, fl;

        /* Open without O_PATH */
        fd1 = open("/usr/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        assert_se(fd1 >= 0);

        fl = fcntl(fd1, F_GETFL);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(!FLAGS_SET(fl, O_PATH));

        fd2 = fd_reopen_condition(fd1, O_DIRECTORY, O_DIRECTORY|O_PATH, &fd3);
        assert_se(fd2 == fd1);
        assert_se(fd3 < 0);

        /* Switch on O_PATH */
        fd2 = fd_reopen_condition(fd1, O_DIRECTORY|O_PATH, O_DIRECTORY|O_PATH, &fd3);
        assert_se(fd2 != fd1);
        assert_se(fd3 == fd2);

        fl = fcntl(fd2, F_GETFL);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        close_and_replace(fd1, fd3);

        fd2 = fd_reopen_condition(fd1, O_DIRECTORY|O_PATH, O_DIRECTORY|O_PATH, &fd3);
        assert_se(fd2 == fd1);
        assert_se(fd3 < 0);

        /* Switch off O_PATH again */
        fd2 = fd_reopen_condition(fd1, O_DIRECTORY, O_DIRECTORY|O_PATH, &fd3);
        assert_se(fd2 != fd1);
        assert_se(fd3 == fd2);

        fl = fcntl(fd2, F_GETFL);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(!FLAGS_SET(fl, O_PATH));

        close_and_replace(fd1, fd3);

        fd2 = fd_reopen_condition(fd1, O_DIRECTORY, O_DIRECTORY|O_PATH, &fd3);
        assert_se(fd2 == fd1);
        assert_se(fd3 < 0);
}

TEST(take_fd) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;
        int array[2] = EBADF_PAIR, i = 0;

        assert_se(fd1 == -EBADF);
        assert_se(fd2 == -EBADF);

        fd1 = eventfd(0, EFD_CLOEXEC);
        assert_se(fd1 >= 0);

        fd2 = TAKE_FD(fd1);
        assert_se(fd1 == -EBADF);
        assert_se(fd2 >= 0);

        assert_se(array[0] == -EBADF);
        assert_se(array[1] == -EBADF);

        array[0] = TAKE_FD(fd2);
        assert_se(fd1 == -EBADF);
        assert_se(fd2 == -EBADF);
        assert_se(array[0] >= 0);
        assert_se(array[1] == -EBADF);

        array[1] = TAKE_FD(array[i]);
        assert_se(array[0] == -EBADF);
        assert_se(array[1] >= 0);

        i = 1 - i;
        array[0] = TAKE_FD(*(array + i));
        assert_se(array[0] >= 0);
        assert_se(array[1] == -EBADF);

        i = 1 - i;
        fd1 = TAKE_FD(array[i]);
        assert_se(fd1 >= 0);
        assert_se(array[0] == -EBADF);
        assert_se(array[1] == -EBADF);
}

TEST(dir_fd_is_root) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert_se(dir_fd_is_root_or_cwd(AT_FDCWD) > 0);

        assert_se((fd = open("/", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW)) >= 0);
        assert_se(dir_fd_is_root(fd) > 0);
        assert_se(dir_fd_is_root_or_cwd(fd) > 0);

        fd = safe_close(fd);

        assert_se((fd = open("/usr", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW)) >= 0);
        assert_se(dir_fd_is_root(fd) == 0);
        assert_se(dir_fd_is_root_or_cwd(fd) == 0);

        r = detach_mount_namespace();
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to detach mount namespace");

        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *x = NULL, *y = NULL;

        assert_se(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp) >= 0);
        assert_se(x = path_join(tmp, "x"));
        assert_se(y = path_join(tmp, "x/y"));
        assert_se(mkdir_p(y, 0755) >= 0);
        assert_se(mount_nofollow_verbose(LOG_DEBUG, x, y, NULL, MS_BIND, NULL) >= 0);

        fd = safe_close(fd);

        assert_se((fd = open(tmp, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW)) >= 0);
        assert_se(dir_fd_is_root(fd) == 0);
        assert_se(dir_fd_is_root_or_cwd(fd) == 0);

        fd = safe_close(fd);

        assert_se((fd = open(x, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW)) >= 0);
        assert_se(dir_fd_is_root(fd) == 0);
        assert_se(dir_fd_is_root_or_cwd(fd) == 0);

        fd = safe_close(fd);

        assert_se((fd = open(y, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW)) >= 0);
        assert_se(dir_fd_is_root(fd) == 0);
        assert_se(dir_fd_is_root_or_cwd(fd) == 0);
}

TEST(fds_are_same_mount) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF, fd3 = -EBADF, fd4 = -EBADF;

        fd1 = open("/sys", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        fd2 = open("/proc", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        fd3 = open("/proc", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        fd4 = open("/", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);

        if (fd1 < 0 || fd2 < 0 || fd3 < 0 || fd4 < 0)
                return (void) log_tests_skipped_errno(errno, "Failed to open /sys or /proc or /");

        if (fds_are_same_mount(fd1, fd4) > 0 && fds_are_same_mount(fd2, fd4) > 0)
                return (void) log_tests_skipped("Cannot test fds_are_same_mount() as /sys and /proc are not mounted");

        assert_se(fds_are_same_mount(fd1, fd2) == 0);
        assert_se(fds_are_same_mount(fd2, fd3) > 0);
}

TEST(fd_get_path) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL, *q = NULL, *saved_cwd = NULL;

        tfd = mkdtemp_open(NULL, O_PATH, &t);
        assert_se(tfd >= 0);
        assert_se(fd_get_path(tfd, &p) >= 0);
        ASSERT_STREQ(p, t);

        p = mfree(p);

        assert_se(safe_getcwd(&saved_cwd) >= 0);
        assert_se(chdir(t) >= 0);

        assert_se(fd_get_path(AT_FDCWD, &p) >= 0);
        ASSERT_STREQ(p, t);

        p = mfree(p);

        assert_se(q = path_join(t, "regular"));
        assert_se(touch(q) >= 0);
        assert_se(mkdirat_parents(tfd, "subdir/symlink", 0755) >= 0);
        assert_se(symlinkat("../regular", tfd, "subdir/symlink") >= 0);
        assert_se(symlinkat("subdir", tfd, "symdir") >= 0);

        fd = openat(tfd, "regular", O_CLOEXEC|O_PATH);
        assert_se(fd >= 0);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(AT_FDCWD, "regular", O_CLOEXEC|O_PATH);
        assert_se(fd >= 0);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(tfd, "subdir/symlink", O_CLOEXEC|O_PATH);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) >= 0);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(AT_FDCWD, "subdir/symlink", O_CLOEXEC|O_PATH);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) >= 0);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(tfd, "symdir//./symlink", O_CLOEXEC|O_PATH);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) >= 0);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(AT_FDCWD, "symdir//./symlink", O_CLOEXEC|O_PATH);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) >= 0);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        q = mfree(q);
        fd = safe_close(fd);

        assert_se(q = path_join(t, "subdir/symlink"));
        fd = openat(tfd, "subdir/symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) == -ELOOP);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(AT_FDCWD, "subdir/symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) == -ELOOP);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(tfd, "symdir//./symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) == -ELOOP);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = openat(AT_FDCWD, "symdir//./symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) == -ELOOP);
        assert_se(fd_get_path(fd, &p) >= 0);
        ASSERT_STREQ(p, q);

        assert_se(chdir(saved_cwd) >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
