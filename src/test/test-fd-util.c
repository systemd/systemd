/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "alloc-util.h"
#include "data-fd-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "mount-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rlimit-util.h"
#include "seccomp-util.h"
#include "serialize.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(close_many) {
        int fds[3];
        char name0[] = "/tmp/test-close-many.XXXXXX";
        char name1[] = "/tmp/test-close-many.XXXXXX";
        char name2[] = "/tmp/test-close-many.XXXXXX";

        fds[0] = mkostemp_safe(name0);
        fds[1] = mkostemp_safe(name1);
        fds[2] = mkostemp_safe(name2);

        close_many(fds, 2);

        assert_se(fcntl(fds[0], F_GETFD) == -1);
        assert_se(fcntl(fds[1], F_GETFD) == -1);
        assert_se(fcntl(fds[2], F_GETFD) >= 0);

        safe_close(fds[2]);

        unlink(name0);
        unlink(name1);
        unlink(name2);
}

TEST(close_nointr) {
        char name[] = "/tmp/test-test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);
        assert_se(close_nointr(fd) < 0);

        unlink(name);
}

TEST(same_fd) {
        _cleanup_close_pair_ int p[2] = { -1, -1 };
        _cleanup_close_ int a = -1, b = -1, c = -1;

        assert_se(pipe2(p, O_CLOEXEC) >= 0);
        assert_se((a = fcntl(p[0], F_DUPFD, 3)) >= 0);
        assert_se((b = open("/dev/null", O_RDONLY|O_CLOEXEC)) >= 0);
        assert_se((c = fcntl(a, F_DUPFD, 3)) >= 0);

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
}

TEST(open_serialization_fd) {
        _cleanup_close_ int fd = -1;

        fd = open_serialization_fd("test");
        assert_se(fd >= 0);

        assert_se(write(fd, "test\n", 5) == 5);
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
                char buffer[10];

                /* Child */

                safe_close(STDERR_FILENO); /* Let's close an fd < 2, to make it more interesting */

                assert_se(rearrange_stdio(-1, -1, -1) >= 0);

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

                {
                        int pair[2];
                        assert_se(pipe(pair) >= 0);
                        assert_se(pair[0] == 0);
                        assert_se(pair[1] == 1);
                        assert_se(fd_move_above_stdio(0) == 3);
                }
                assert_se(open("/dev/full", O_WRONLY|O_CLOEXEC) == 0);
                assert_se(acquire_data_fd("foobar", 6, 0) == 2);

                assert_se(rearrange_stdio(2, 0, 1) >= 0);

                assert_se(write(1, "x", 1) < 0 && errno == ENOSPC);
                assert_se(write(2, "z", 1) == 1);
                assert_se(read(3, buffer, sizeof(buffer)) == 1);
                assert_se(buffer[0] == 'z');
                assert_se(read(0, buffer, sizeof(buffer)) == 6);
                assert_se(memcmp(buffer, "foobar", 6) == 0);

                assert_se(rearrange_stdio(-1, 1, 2) >= 0);
                assert_se(write(1, "a", 1) < 0 && errno == ENOSPC);
                assert_se(write(2, "y", 1) == 1);
                assert_se(read(3, buffer, sizeof(buffer)) == 1);
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
                        assert_se(fcntl(fds[i], F_GETFD) >= 0);
                else
                        assert_se(fcntl(fds[i], F_GETFD) < 0 && errno == EBADF);

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
         * with /proc overmounted, and once with the combination of both. This should trigger all fallbacks in
         * the close_range_all() function. */

        r = safe_fork("(caf-plain)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
        if (r == 0) {
                test_close_all_fds_inner();
                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);

        if (geteuid() != 0) {
                log_notice("Lacking privileges, skipping running tests with blocked close_range() and with /proc/ overnmounted.");
                return;
        }

        r = safe_fork("(caf-noproc)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, NULL);
        if (r == 0) {
                r = mount_nofollow_verbose(LOG_WARNING, "tmpfs", "/proc", "tmpfs", 0, NULL);
                if (r < 0)
                        log_notice("Overmounting /proc didn#t work, skipping close_all_fds() with masked /proc/.");
                else
                        test_close_all_fds_inner();
                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping seccomp tests in %s", __func__);
                return;
        }

        r = safe_fork("(caf-seccomp)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
        if (r == 0) {
                r = seccomp_prohibit_close_range();
                if (r < 0)
                        log_notice("Applying seccomp filter didn't work, skipping close_all_fds() test with masked close_range().");
                else
                        test_close_all_fds_inner();

                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);

        r = safe_fork("(caf-scnp)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, NULL);
        if (r == 0) {
                r = seccomp_prohibit_close_range();
                if (r < 0)
                        log_notice("Applying seccomp filter didn't work, skipping close_all_fds() test with masked close_range().");
                else {
                        r = mount_nofollow_verbose(LOG_WARNING, "tmpfs", "/proc", "tmpfs", 0, NULL);
                        if (r < 0)
                                log_notice("Overmounting /proc didn#t work, skipping close_all_fds() with masked /proc/.");
                        else
                                test_close_all_fds_inner();
                }

                test_close_all_fds_inner();
                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);
}

TEST(format_proc_fd_path) {
        assert_se(streq_ptr(FORMAT_PROC_FD_PATH(0), "/proc/self/fd/0"));
        assert_se(streq_ptr(FORMAT_PROC_FD_PATH(1), "/proc/self/fd/1"));
        assert_se(streq_ptr(FORMAT_PROC_FD_PATH(2), "/proc/self/fd/2"));
        assert_se(streq_ptr(FORMAT_PROC_FD_PATH(3), "/proc/self/fd/3"));
        assert_se(streq_ptr(FORMAT_PROC_FD_PATH(2147483647), "/proc/self/fd/2147483647"));
}

TEST(fd_reopen) {
        _cleanup_close_ int fd1 = -1, fd2 = -1;
        struct stat st1, st2;
        int fl;

        /* Test this with a directory */
        fd1 = open("/proc", O_DIRECTORY|O_PATH|O_CLOEXEC);
        assert_se(fd1 >= 0);

        assert_se(fstat(fd1, &st1) >= 0);
        assert_se(S_ISDIR(st1.st_mode));

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        fd2 = fd_reopen(fd1, O_RDONLY|O_DIRECTORY|O_CLOEXEC);  /* drop the O_PATH */
        assert_se(fd2 >= 0);

        assert_se(fstat(fd2, &st2) >= 0);
        assert_se(S_ISDIR(st2.st_mode));
        assert_se(st1.st_ino == st2.st_ino);
        assert_se(st1.st_rdev == st2.st_rdev);

        fl = fcntl(fd2, F_GETFL);
        assert_se(fl >= 0);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(!FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        fd1 = fd_reopen(fd2, O_DIRECTORY|O_PATH|O_CLOEXEC);  /* reacquire the O_PATH */
        assert_se(fd1 >= 0);

        assert_se(fstat(fd1, &st1) >= 0);
        assert_se(S_ISDIR(st1.st_mode));
        assert_se(st1.st_ino == st2.st_ino);
        assert_se(st1.st_rdev == st2.st_rdev);

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        /* And now, test this with a file. */
        fd1 = open("/proc/version", O_PATH|O_CLOEXEC);
        assert_se(fd1 >= 0);

        assert_se(fstat(fd1, &st1) >= 0);
        assert_se(S_ISREG(st1.st_mode));

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(!FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        assert_se(fd_reopen(fd1, O_RDONLY|O_DIRECTORY|O_CLOEXEC) == -ENOTDIR);
        fd2 = fd_reopen(fd1, O_RDONLY|O_CLOEXEC);  /* drop the O_PATH */
        assert_se(fd2 >= 0);

        assert_se(fstat(fd2, &st2) >= 0);
        assert_se(S_ISREG(st2.st_mode));
        assert_se(st1.st_ino == st2.st_ino);
        assert_se(st1.st_rdev == st2.st_rdev);

        fl = fcntl(fd2, F_GETFL);
        assert_se(fl >= 0);
        assert_se(!FLAGS_SET(fl, O_DIRECTORY));
        assert_se(!FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        assert_se(fd_reopen(fd2, O_DIRECTORY|O_PATH|O_CLOEXEC) == -ENOTDIR);
        fd1 = fd_reopen(fd2, O_PATH|O_CLOEXEC);  /* reacquire the O_PATH */
        assert_se(fd1 >= 0);

        assert_se(fstat(fd1, &st1) >= 0);
        assert_se(S_ISREG(st1.st_mode));
        assert_se(st1.st_ino == st2.st_ino);
        assert_se(st1.st_rdev == st2.st_rdev);

        fl = fcntl(fd1, F_GETFL);
        assert_se(fl >= 0);
        assert_se(!FLAGS_SET(fl, O_DIRECTORY));
        assert_se(FLAGS_SET(fl, O_PATH));

        /* Also check the right error is generated if the fd is already closed */
        safe_close(fd1);
        assert_se(fd_reopen(fd1, O_RDONLY|O_CLOEXEC) == -EBADF);
        fd1 = -1;
}

TEST(take_fd) {
        _cleanup_close_ int fd1 = -1, fd2 = -1;
        int array[2] = { -1, -1 }, i = 0;

        assert_se(fd1 == -1);
        assert_se(fd2 == -1);

        fd1 = eventfd(0, EFD_CLOEXEC);
        assert_se(fd1 >= 0);

        fd2 = TAKE_FD(fd1);
        assert_se(fd1 == -1);
        assert_se(fd2 >= 0);

        assert_se(array[0] == -1);
        assert_se(array[1] == -1);

        array[0] = TAKE_FD(fd2);
        assert_se(fd1 == -1);
        assert_se(fd2 == -1);
        assert_se(array[0] >= 0);
        assert_se(array[1] == -1);

        array[1] = TAKE_FD(array[i]);
        assert_se(array[0] == -1);
        assert_se(array[1] >= 0);

        i = 1 - i;
        array[0] = TAKE_FD(*(array + i));
        assert_se(array[0] >= 0);
        assert_se(array[1] == -1);

        i = 1 - i;
        fd1 = TAKE_FD(array[i]);
        assert_se(fd1 >= 0);
        assert_se(array[0] == -1);
        assert_se(array[1] == -1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
