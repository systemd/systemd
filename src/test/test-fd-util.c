/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "memfd-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "serialize.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(fdname_is_valid) {
        static const struct {
                const char *value;
                bool name_valid;
                bool glob_valid;
        } cases[] = {
                { NULL,           false, false },
                { "",             true,  false },
                { "1",            true,  true  },
                { "*",            true,  true  },
                { "test-?",       true,  true  },
                { "test-[ab]",    true,  true  },
                { "test-[0-9]",   true,  true  },
                { "[[:digit:]]",  false, false },
                { "test-\\*",     true,  true  },
                { "test:name",    false, false },
                { "*:*",          false, false },
                { "test name",    true,  true  },
                { "test\tname",   false, false },
                { "test\nname",   false, false },
                { "test\177name", false, false },
                { "test\200name", false, false },
        };

        FOREACH_ELEMENT(c, cases) {
                ASSERT_EQ(fdname_is_valid(c->value), c->name_valid);
                ASSERT_EQ(fdname_glob_is_valid(c->value), c->glob_valid);
        }

        _cleanup_free_ char *long_name = strrep("x", FDNAME_MAX + 1);
        ASSERT_NOT_NULL(long_name);
        ASSERT_FALSE(fdname_is_valid(long_name));
        ASSERT_FALSE(fdname_glob_is_valid(long_name));
        long_name[FDNAME_MAX] = 0;
        ASSERT_TRUE(fdname_is_valid(long_name));
        ASSERT_TRUE(fdname_glob_is_valid(long_name));
}

TEST(close_many) {
        int fds[3];
        _cleanup_(unlink_tempfilep) char name0[] = "/tmp/test-close-many.XXXXXX";
        _cleanup_(unlink_tempfilep) char name1[] = "/tmp/test-close-many.XXXXXX";
        _cleanup_(unlink_tempfilep) char name2[] = "/tmp/test-close-many.XXXXXX";

        fds[0] = mkostemp_safe(name0);
        fds[1] = mkostemp_safe(name1);
        fds[2] = mkostemp_safe(name2);

        close_many(fds, 2);

        ASSERT_ERROR(fd_validate(fds[0]), EBADF);
        ASSERT_ERROR(fd_validate(fds[1]), EBADF);
        ASSERT_OK(fd_validate(fds[2]));

        safe_close(fds[2]);
}

TEST(close_nointr) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-test-close_nointr.XXXXXX";
        int fd;

        fd = ASSERT_OK(mkostemp_safe(name));
        ASSERT_OK(close_nointr(fd));
        ASSERT_FAIL(close_nointr(fd));
}

TEST(fd_validate) {
        ASSERT_ERROR(fd_validate(-EINVAL), EBADF);
        ASSERT_ERROR(fd_validate(-EBADF), EBADF);

        _cleanup_close_ int b = -EBADF;
        b = ASSERT_OK_ERRNO(open("/dev/null", O_RDONLY|O_CLOEXEC));

        ASSERT_OK_ZERO(fd_validate(b));
        safe_close(b);
        ASSERT_ERROR(fd_validate(b), EBADF);
        TAKE_FD(b);
}

TEST(same_fd) {
        _cleanup_close_pair_ int p[2];
        _cleanup_close_ int a, b, c, d, e;

        ASSERT_OK_ERRNO(pipe2(p, O_CLOEXEC));
        a = ASSERT_OK_ERRNO(fcntl(p[0], F_DUPFD, 3));
        b = ASSERT_OK_ERRNO(open("/bin/sh", O_RDONLY|O_CLOEXEC));
        c = ASSERT_OK_ERRNO(fcntl(a, F_DUPFD, 3));
        d = ASSERT_OK_ERRNO(open("/bin/sh", O_RDONLY|O_CLOEXEC|O_PATH)); /* O_PATH changes error returns in F_DUPFD_QUERY, let's test explicitly */
        e = ASSERT_OK_ERRNO(fcntl(d, F_DUPFD, 3));

        ASSERT_OK_POSITIVE(same_fd(p[0], p[0]));
        ASSERT_OK_POSITIVE(same_fd(p[1], p[1]));
        ASSERT_OK_POSITIVE(same_fd(a, a));
        ASSERT_OK_POSITIVE(same_fd(b, b));

        ASSERT_OK_POSITIVE(same_fd(a, p[0]));
        ASSERT_OK_POSITIVE(same_fd(p[0], a));
        ASSERT_OK_POSITIVE(same_fd(c, p[0]));
        ASSERT_OK_POSITIVE(same_fd(p[0], c));
        ASSERT_OK_POSITIVE(same_fd(a, c));
        ASSERT_OK_POSITIVE(same_fd(c, a));

        ASSERT_OK_EQ(same_fd(p[0], p[1]), 0);
        ASSERT_OK_EQ(same_fd(p[1], p[0]), 0);
        ASSERT_OK_EQ(same_fd(p[0], b), 0);
        ASSERT_OK_EQ(same_fd(b, p[0]), 0);
        ASSERT_OK_EQ(same_fd(p[1], a), 0);
        ASSERT_OK_EQ(same_fd(a, p[1]), 0);
        ASSERT_OK_EQ(same_fd(p[1], b), 0);
        ASSERT_OK_EQ(same_fd(b, p[1]), 0);

        ASSERT_OK_EQ(same_fd(a, b), 0);
        ASSERT_OK_EQ(same_fd(b, a), 0);

        ASSERT_OK_EQ(same_fd(a, d), 0);
        ASSERT_OK_EQ(same_fd(d, a), 0);
        ASSERT_OK_POSITIVE(same_fd(d, d));
        ASSERT_OK_POSITIVE(same_fd(d, e));
        ASSERT_OK_POSITIVE(same_fd(e, d));

        /* Let's now compare with a valid fd nr, that is definitely closed, and verify it returns the right error code */
        safe_close(d);
        ASSERT_ERROR(same_fd(d, d), EBADF);
        ASSERT_ERROR(same_fd(e, d), EBADF);
        ASSERT_ERROR(same_fd(d, e), EBADF);
        ASSERT_OK_POSITIVE(same_fd(e, e));
        TAKE_FD(d);
}

TEST(open_serialization_fd) {
        _cleanup_close_ int fd = -EBADF;

        fd = ASSERT_OK(open_serialization_fd("test"));

        ASSERT_OK_EQ_ERRNO(write(fd, "test\n", 5), 5);

        ASSERT_OK(finish_serialization_fd(fd));
}

TEST(open_serialization_file) {
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_OK(open_serialization_file("test", &f));
        ASSERT_NOT_NULL(f);

        ASSERT_EQ(fwrite("test\n", 1, 5, f), 5U);

        ASSERT_OK(finish_serialization_file(f));
}

TEST(fd_move_above_stdio) {
        int original_stdin, new_fd;

        original_stdin = fcntl(0, F_DUPFD, 3);
        ASSERT_GE(original_stdin, 3);
        ASSERT_OK(close_nointr(/* fd= */ 0));

        new_fd = ASSERT_OK_ZERO_ERRNO(open("/dev/null", O_RDONLY));

        new_fd = fd_move_above_stdio(new_fd);
        ASSERT_GE(new_fd, 3);

        ASSERT_OK_ZERO_ERRNO(fcntl(original_stdin, F_DUPFD, 0));
        ASSERT_OK(close_nointr(original_stdin));
        ASSERT_OK(close_nointr(new_fd));
}

TEST(rearrange_stdio) {
        int r;

        r = ASSERT_OK(pidref_safe_fork("rearrange", FORK_WAIT|FORK_LOG, /* ret= */ NULL));

        if (r == 0) {
                _cleanup_free_ char *path = NULL;
                int pipe_read_fd, pair[2];
                char buffer[10];

                /* Child */

                safe_close(STDERR_FILENO); /* Let's close an fd < 2, to make it more interesting */

                ASSERT_OK(rearrange_stdio(-EBADF, -EBADF, -EBADF));
                /* Reconfigure logging after rearranging stdout/stderr, so we still log to somewhere if the
                 * following tests fail, making it slightly less annoying to debug */
                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                log_open();

                ASSERT_OK(fd_get_path(STDIN_FILENO, &path));
                ASSERT_PATH_EQ(path, "/dev/null");
                path = mfree(path);

                ASSERT_OK(fd_get_path(STDOUT_FILENO, &path));
                ASSERT_PATH_EQ(path, "/dev/null");
                path = mfree(path);

                ASSERT_OK(fd_get_path(STDOUT_FILENO, &path));
                ASSERT_PATH_EQ(path, "/dev/null");
                path = mfree(path);

                safe_close(STDIN_FILENO);
                safe_close(STDOUT_FILENO);
                safe_close(STDERR_FILENO);

                ASSERT_OK_ERRNO(pipe(pair));
                ASSERT_EQ(pair[0], 0);
                ASSERT_EQ(pair[1], 1);
                pipe_read_fd = fd_move_above_stdio(/* fd= */ 0);
                ASSERT_GE(pipe_read_fd, 3);

                ASSERT_OK_ZERO_ERRNO(open("/dev/full", O_WRONLY|O_CLOEXEC));
                ASSERT_OK_EQ(memfd_new_and_seal_string("data", "foobar"), 2);

                ASSERT_OK(rearrange_stdio(2, /* original_output_fd= */ 0, 1));

                ASSERT_ERROR_ERRNO(write(1, "x", 1), ENOSPC);
                ASSERT_OK_EQ_ERRNO(write(2, "z", 1), 1);
                ASSERT_OK_EQ_ERRNO(read(pipe_read_fd, buffer, sizeof(buffer)), 1);
                ASSERT_EQ(buffer[0], 'z');
                ASSERT_OK_EQ_ERRNO(read(0, buffer, sizeof(buffer)), 6);
                ASSERT_EQ(memcmp(buffer, "foobar", 6), 0);

                ASSERT_OK(rearrange_stdio(-EBADF, 1, 2));
                ASSERT_ERROR_ERRNO(write(1, "a", 1), ENOSPC);
                ASSERT_OK_EQ_ERRNO(write(2, "y", 1), 1);
                ASSERT_OK_EQ_ERRNO(read(pipe_read_fd, buffer, sizeof(buffer)), 1);
                ASSERT_EQ(buffer[0], 'y');

                ASSERT_OK(fd_get_path(/* fd= */ 0, &path));
                ASSERT_PATH_EQ(path, "/dev/null");
                path = mfree(path);

                _exit(EXIT_SUCCESS);
        }
}

TEST(read_nr_open) {
        log_info("nr-open: %u", read_nr_open());
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
                        ASSERT_OK(fd_validate(fds[i]));
                else
                        ASSERT_ERROR(fd_validate(fds[i]), EBADF);

                c++;
        }

        return c; /* Return number of fds >= 0 in the array */
}

static void test_close_all_fds_inner(int (*func)(const int except[], size_t n_except)) {
        _cleanup_free_ int *fds = NULL, *keep = NULL;
        size_t n_fds, n_keep;
        int max_fd;

        log_info("/* %s */", __func__);

        rlimit_nofile_bump(-1);

        max_fd = get_max_fd();
        ASSERT_GT(max_fd, 10);

        if (max_fd > 7000) {
                /* If the worst fallback is activated we need to iterate through all possible fds, hence,
                 * let's lower the limit a small bit, so that we don't run for too long. Yes, this undoes the
                 * rlimit_nofile_bump() call above partially. */

                (void) setrlimit_closest(RLIMIT_NOFILE, &(struct rlimit) { 7000, 7000 });
                max_fd = 7000;
        }

        /* Try to use 5000 fds, but when we can't bump the rlimit to make that happen use the whole limit minus 10 */
        n_fds = MIN(((size_t) max_fd & ~1U) - 10U, 5000U);
        ASSERT_EQ(n_fds & 1U, 0U); /* make sure even number of fds */

        /* Allocate the determined number of fds, always two at a time */
        ASSERT_NOT_NULL(fds = new(int, n_fds));
        for (size_t i = 0; i < n_fds; i += 2)
                ASSERT_OK_ERRNO(pipe2(fds + i, O_CLOEXEC));

        /* Validate this worked */
        ASSERT_EQ(validate_fds(/* opened= */ true, fds, n_fds), n_fds);

        /* Randomized number of fds to keep, but at most every second */
        n_keep = (random_u64() % (n_fds / 2));

        /* Now randomly select a number of fds from the array above to keep */
        ASSERT_NOT_NULL(keep = new(int, n_keep));
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
        ASSERT_EQ(validate_fds(/* opened= */ true, fds, n_fds), n_fds - n_keep);
        ASSERT_EQ(validate_fds(/* opened= */ true, keep, n_keep), n_keep);

        /* Close logging fd first, so that we don't confuse it by closing its fd */
        log_close();
        log_set_open_when_needed(true);
        log_settle_target();

        /* Close all but the ones to keep */
        ASSERT_OK(func(keep, n_keep));

        ASSERT_EQ(validate_fds(/* opened= */ false, fds, n_fds), n_fds - n_keep);
        ASSERT_EQ(validate_fds(/* opened= */ true, keep, n_keep), n_keep);

        /* Close everything else too! */
        ASSERT_OK(func(NULL, 0));

        ASSERT_EQ(validate_fds(/* opened= */ false, fds, n_fds), n_fds - n_keep);
        ASSERT_EQ(validate_fds(/* opened= */ false, keep, n_keep), n_keep);

        log_set_open_when_needed(false);
        log_open();
}

TEST(close_all_fds) {
        ForkFlags flags = FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT;
        int r;

        r = ASSERT_OK(pidref_safe_fork("(caf-plain)", flags, /* ret= */ NULL));
        if (r == 0) {
                test_close_all_fds_inner(close_all_fds);
                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("(caf-nomalloc)", flags, /* ret= */ NULL));
        if (r == 0) {
                test_close_all_fds_inner(close_all_fds_without_malloc);
                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("(caf-frugal)", flags, /* ret= */ NULL));
        if (r == 0) {
                test_close_all_fds_inner(close_all_fds_frugal);
                _exit(EXIT_SUCCESS);
        }
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
        fd1 = ASSERT_OK_ERRNO(open("/proc", O_DIRECTORY|O_PATH|O_CLOEXEC));

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        ASSERT_TRUE(S_ISDIR(st1.st_mode));

        fl = ASSERT_OK_ERRNO(fcntl(fd1, F_GETFL));
        ASSERT_TRUE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_TRUE(FLAGS_SET(fl, O_PATH));

        /* fd_reopen() with O_NOFOLLOW will systematically fail, since it is implemented via a symlink in /proc/self/fd/ */
        ASSERT_ERROR(fd_reopen(fd1, O_RDONLY|O_CLOEXEC|O_NOFOLLOW), ELOOP);
        ASSERT_ERROR(fd_reopen(fd1, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW), ELOOP);

        fd2 = ASSERT_OK(fd_reopen(fd1, O_RDONLY|O_DIRECTORY|O_CLOEXEC));  /* drop the O_PATH */

        ASSERT_OK_ERRNO(fstat(fd2, &st2));
        ASSERT_TRUE(S_ISDIR(st2.st_mode));
        ASSERT_TRUE(stat_inode_same(&st1, &st2));

        fl = ASSERT_OK_ERRNO(fcntl(fd2, F_GETFL));
        ASSERT_TRUE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_FALSE(FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        fd1 = ASSERT_OK(fd_reopen(fd2, O_DIRECTORY|O_PATH|O_CLOEXEC));  /* reacquire the O_PATH */

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        ASSERT_TRUE(S_ISDIR(st1.st_mode));
        ASSERT_TRUE(stat_inode_same(&st1, &st2));

        fl = ASSERT_OK_ERRNO(fcntl(fd1, F_GETFL));
        ASSERT_TRUE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_TRUE(FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        /* And now, test this with a file. */
        fd1 = ASSERT_OK_ERRNO(open("/proc/version", O_PATH|O_CLOEXEC));

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        ASSERT_TRUE(S_ISREG(st1.st_mode));

        fl = ASSERT_OK_ERRNO(fcntl(fd1, F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_TRUE(FLAGS_SET(fl, O_PATH));

        ASSERT_ERROR(fd_reopen(fd1, O_RDONLY|O_DIRECTORY|O_CLOEXEC), ENOTDIR);
        fd2 = ASSERT_OK(fd_reopen(fd1, O_RDONLY|O_CLOEXEC));  /* drop the O_PATH */

        ASSERT_OK_ERRNO(fstat(fd2, &st2));
        ASSERT_TRUE(S_ISREG(st2.st_mode));
        ASSERT_TRUE(stat_inode_same(&st1, &st2));

        fl = ASSERT_OK_ERRNO(fcntl(fd2, F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_FALSE(FLAGS_SET(fl, O_PATH));

        safe_close(fd1);

        ASSERT_ERROR(fd_reopen(fd2, O_DIRECTORY|O_PATH|O_CLOEXEC), ENOTDIR);
        fd1 = ASSERT_OK(fd_reopen(fd2, O_PATH|O_CLOEXEC));  /* reacquire the O_PATH */

        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        ASSERT_TRUE(S_ISREG(st1.st_mode));
        ASSERT_TRUE(stat_inode_same(&st1, &st2));

        fl = ASSERT_OK_ERRNO(fcntl(fd1, F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_TRUE(FLAGS_SET(fl, O_PATH));

        /* Also check the right error is generated if the fd is already closed */
        safe_close(fd1);
        ASSERT_ERROR(fd_reopen(fd1, O_RDONLY|O_CLOEXEC), EBADF);
        fd1 = -EBADF;

        /* Validate what happens if we reopen a symlink */
        fd1 = ASSERT_OK_ERRNO(open("/proc/self", O_PATH|O_CLOEXEC|O_NOFOLLOW));
        ASSERT_OK_ERRNO(fstat(fd1, &st1));
        ASSERT_TRUE(S_ISLNK(st1.st_mode));

        fd2 = ASSERT_OK(fd_reopen(fd1, O_PATH|O_CLOEXEC));
        ASSERT_OK_ERRNO(fstat(fd2, &st2));
        ASSERT_TRUE(S_ISLNK(st2.st_mode));
        ASSERT_TRUE(stat_inode_same(&st1, &st2));
        fd2 = safe_close(fd2);

        /* So here's the thing: if we have an O_PATH fd to a symlink, we *cannot* convert it to a regular fd
         * with that. i.e. you cannot have the VFS follow a symlink pinned via an O_PATH fd. */
        ASSERT_ERROR(fd_reopen(fd1, O_RDONLY|O_CLOEXEC), ELOOP);
}

TEST(fd_dup_or_reopen_stdio_nonblock) {
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/test-fd-dup-or-reopen-stdio-nonblock.XXXXXX";
        _cleanup_close_ int fd = -EBADF, nfd = -EBADF;
        _cleanup_close_pair_ int p[2] = EBADF_PAIR;
        char buf[4] = {};
        int fl;

        ASSERT_OK(fd = mkostemp_safe(path));
        ASSERT_OK(nfd = fd_dup_or_reopen_stdio_nonblock(fd, O_WRONLY));
        ASSERT_OK_EQ_ERRNO(write(nfd, "hello", 5), (ssize_t) 5);
        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_CUR), (off_t) 5);
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_NONBLOCK));
        ASSERT_OK_ERRNO(fl = fcntl(nfd, F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_NONBLOCK));
        nfd = safe_close(nfd);
        fd = safe_close(fd);

        ASSERT_OK_ERRNO(fd = open(path, O_WRONLY|O_APPEND|O_CLOEXEC));
        ASSERT_OK(nfd = fd_dup_or_reopen_stdio_nonblock(fd, O_WRONLY));
        ASSERT_OK_ERRNO(fl = fcntl(nfd, F_GETFL));
        ASSERT_TRUE(FLAGS_SET(fl, O_APPEND));
        nfd = safe_close(nfd);
        fd = safe_close(fd);

        /* Reading ahead must not move the offset of the original fd */
        ASSERT_OK_ERRNO(fd = open(path, O_RDONLY|O_CLOEXEC));
        ASSERT_OK_EQ_ERRNO(lseek(fd, 2, SEEK_SET), (off_t) 2);
        ASSERT_OK(nfd = fd_dup_or_reopen_stdio_nonblock(fd, O_RDONLY));
        ASSERT_OK_EQ_ERRNO(read(nfd, buf, sizeof(buf) - 1), (ssize_t) 3);
        ASSERT_STREQ(buf, "llo");
        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_CUR), (off_t) 2);
        ASSERT_OK_ERRNO(fl = fcntl(nfd, F_GETFL));
        ASSERT_TRUE(FLAGS_SET(fl, O_NONBLOCK));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_NONBLOCK));
        nfd = safe_close(nfd);
        fd = safe_close(fd);

        ASSERT_OK_ERRNO(pipe2(p, O_CLOEXEC));
        ASSERT_OK(nfd = fd_dup_or_reopen_stdio_nonblock(p[0], O_RDONLY));
        ASSERT_OK_ERRNO(fl = fcntl(nfd, F_GETFL));
        ASSERT_TRUE(FLAGS_SET(fl, O_NONBLOCK));
        ASSERT_OK_ERRNO(fl = fcntl(p[0], F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_NONBLOCK));
        nfd = safe_close(nfd);

        ASSERT_OK(nfd = fd_dup_or_reopen_stdio_nonblock(p[1], O_WRONLY));
        ASSERT_OK_ERRNO(fl = fcntl(nfd, F_GETFL));
        ASSERT_TRUE(FLAGS_SET(fl, O_NONBLOCK));
        ASSERT_OK_ERRNO(fl = fcntl(p[1], F_GETFL));
        ASSERT_FALSE(FLAGS_SET(fl, O_NONBLOCK));
}

TEST(fd_reopen_condition) {
        _cleanup_close_ int fd1 = -EBADF, fd3 = -EBADF;
        int fd2, fl;

        /* Open without O_PATH */
        fd1 = ASSERT_OK_ERRNO(open("/usr/", O_RDONLY|O_DIRECTORY|O_CLOEXEC));

        fl = fcntl(fd1, F_GETFL);
        ASSERT_TRUE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_FALSE(FLAGS_SET(fl, O_PATH));

        fd2 = fd_reopen_condition(fd1, O_DIRECTORY, O_DIRECTORY|O_PATH, &fd3);
        ASSERT_EQ(fd2, fd1);
        ASSERT_LT(fd3, 0);

        /* Switch on O_PATH */
        fd2 = fd_reopen_condition(fd1, O_DIRECTORY|O_PATH, O_DIRECTORY|O_PATH, &fd3);
        ASSERT_NE(fd2, fd1);
        ASSERT_EQ(fd3, fd2);

        fl = fcntl(fd2, F_GETFL);
        ASSERT_TRUE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_TRUE(FLAGS_SET(fl, O_PATH));

        close_and_replace(fd1, fd3);

        fd2 = fd_reopen_condition(fd1, O_DIRECTORY|O_PATH, O_DIRECTORY|O_PATH, &fd3);
        ASSERT_EQ(fd2, fd1);
        ASSERT_LT(fd3, 0);

        /* Switch off O_PATH again */
        fd2 = fd_reopen_condition(fd1, O_DIRECTORY, O_DIRECTORY|O_PATH, &fd3);
        ASSERT_NE(fd2, fd1);
        ASSERT_EQ(fd3, fd2);

        fl = fcntl(fd2, F_GETFL);
        ASSERT_TRUE(FLAGS_SET(fl, O_DIRECTORY));
        ASSERT_FALSE(FLAGS_SET(fl, O_PATH));

        close_and_replace(fd1, fd3);

        fd2 = fd_reopen_condition(fd1, O_DIRECTORY, O_DIRECTORY|O_PATH, &fd3);
        ASSERT_EQ(fd2, fd1);
        ASSERT_LT(fd3, 0);
}

TEST(take_fd) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;
        int array[2] = EBADF_PAIR, i = 0;

        ASSERT_EQ(fd1, -EBADF);
        ASSERT_EQ(fd2, -EBADF);

        fd1 = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));

        fd2 = TAKE_FD(fd1);
        ASSERT_EQ(fd1, -EBADF);
        ASSERT_OK(fd2);

        ASSERT_EQ(array[0], -EBADF);
        ASSERT_EQ(array[1], -EBADF);

        array[0] = TAKE_FD(fd2);
        ASSERT_EQ(fd1, -EBADF);
        ASSERT_EQ(fd2, -EBADF);
        ASSERT_OK(array[0]);
        ASSERT_EQ(array[1], -EBADF);

        array[1] = TAKE_FD(array[i]);
        ASSERT_EQ(array[0], -EBADF);
        ASSERT_OK(array[1]);

        i = 1 - i;
        array[0] = TAKE_FD(*(array + i));
        ASSERT_OK(array[0]);
        ASSERT_EQ(array[1], -EBADF);

        i = 1 - i;
        fd1 = ASSERT_OK(TAKE_FD(array[i]));
        ASSERT_EQ(array[0], -EBADF);
        ASSERT_EQ(array[1], -EBADF);
}

TEST(dir_fd_is_root) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        ASSERT_OK_POSITIVE(dir_fd_is_root_or_cwd(AT_FDCWD));

        fd = ASSERT_OK_ERRNO(open("/", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW));
        ASSERT_OK_POSITIVE(dir_fd_is_root(fd));
        ASSERT_OK_POSITIVE(dir_fd_is_root_or_cwd(fd));

        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(open("/usr", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW));
        ASSERT_OK_EQ(dir_fd_is_root(fd), 0);
        ASSERT_OK_EQ(dir_fd_is_root_or_cwd(fd), 0);

        r = detach_mount_namespace();
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to detach mount namespace");

        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *x = NULL, *y = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp));
        ASSERT_NOT_NULL(x = path_join(tmp, "x"));
        ASSERT_NOT_NULL(y = path_join(tmp, "x/y"));
        ASSERT_OK(mkdir_p(y, 0755));
        ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, x, y, /* fstype= */ NULL, MS_BIND, /* options= */ NULL));

        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(open(tmp, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW));
        ASSERT_OK_EQ(dir_fd_is_root(fd), 0);
        ASSERT_OK_EQ(dir_fd_is_root_or_cwd(fd), 0);

        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(open(x, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW));
        ASSERT_OK_EQ(dir_fd_is_root(fd), 0);
        ASSERT_OK_EQ(dir_fd_is_root_or_cwd(fd), 0);

        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(open(y, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW));
        ASSERT_OK_EQ(dir_fd_is_root(fd), 0);
        ASSERT_OK_EQ(dir_fd_is_root_or_cwd(fd), 0);
}

static void test_path_is_root_at_one(bool expected) {
        ASSERT_OK_POSITIVE(path_is_root("/"));
        ASSERT_OK_POSITIVE(path_is_root("/."));
        ASSERT_OK_EQ(path_is_root("/./.."), expected);
        ASSERT_OK_EQ(path_is_root("/.."), expected);
        ASSERT_OK_EQ(path_is_root("/../"), expected);
        ASSERT_OK_EQ(path_is_root("/../."), expected);
        ASSERT_OK_EQ(path_is_root("/../.."), expected);

        ASSERT_OK_ZERO(path_is_root("/usr"));
        ASSERT_OK_ZERO(path_is_root("/./usr"));
        ASSERT_OK_ZERO(path_is_root("/../usr"));
        ASSERT_OK_ZERO(path_is_root("/.././usr"));
        ASSERT_OK_ZERO(path_is_root("/../../usr"));

        _cleanup_close_ int fd = -EBADF;
        ASSERT_OK_ERRNO(fd = open("/", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW));

        ASSERT_OK_POSITIVE(path_is_root_at(fd, /* path= */ NULL));
        ASSERT_OK_POSITIVE(path_is_root_at(fd, ""));
        ASSERT_OK_POSITIVE(path_is_root_at(fd, "."));
        ASSERT_OK_EQ(path_is_root_at(fd, "./../"), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "../"), expected);
        ASSERT_OK_POSITIVE(path_is_root_at(fd, "/"));
        ASSERT_OK_POSITIVE(path_is_root_at(fd, "/."));
        ASSERT_OK_EQ(path_is_root_at(fd, "/./.."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/.."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/../"), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/../."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/../.."), expected);

        ASSERT_OK_ZERO(path_is_root_at(fd, "usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "./usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "../usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/./usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/../usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/.././usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/../../usr"));

        safe_close(fd);
        ASSERT_OK_ERRNO(fd = open("/../", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW));

        ASSERT_OK_EQ(path_is_root_at(fd, /* path= */ NULL), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, ""), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "./.."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "../"), expected);
        ASSERT_OK_POSITIVE(path_is_root_at(fd, "/"));
        ASSERT_OK_POSITIVE(path_is_root_at(fd, "/."));
        ASSERT_OK_EQ(path_is_root_at(fd, "/./.."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/.."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/../"), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/../."), expected);
        ASSERT_OK_EQ(path_is_root_at(fd, "/../.."), expected);

        ASSERT_OK_ZERO(path_is_root_at(fd, "usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "./usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "../usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/./usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/../usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/.././usr"));
        ASSERT_OK_ZERO(path_is_root_at(fd, "/../../usr"));
}

TEST(path_is_root_at) {
        int r;

        test_path_is_root_at_one(/* expected= */ true);

        r = detach_mount_namespace();
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to detach mount namespace");

        /* Interestingly, even after bind mount a path on "/", still "/" points to the previous root
         * directory, but "/../" points to the new root directory. Hence, path_is_root("/") is true but
         * path_is_root("/../") is false. Such spurious situation is resolved after chroot()ing to the new
         * root directory. */
        ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, "/", "/", /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL));
        log_debug("/* %s: bind mount(\"/\", \"/\") */", __func__);
        test_path_is_root_at_one(/* expected= */ false);

        /* chroot("/") does not change anything. */
        ASSERT_OK_ERRNO(chroot("/"));
        log_debug("/* %s: chroot(\"/\") */", __func__);
        test_path_is_root_at_one(/* expected= */ false);

        /* chdir("/") neither change anything. */
        ASSERT_OK_ERRNO(chdir("/"));
        log_debug("/* %s: chdir(\"/\") */", __func__);
        test_path_is_root_at_one(/* expected= */ false);

        /* chdir("/../") neither change anything. */
        ASSERT_OK_ERRNO(chdir("/../"));
        log_debug("/* %s: chdir(\"/../\") */", __func__);
        test_path_is_root_at_one(/* expected= */ false);

        /* After chroot("/../"), both "/" and "/../" point to the new root directory. */
        ASSERT_OK_ERRNO(chroot("/../"));
        log_debug("/* %s: chroot(\"/../\") */", __func__);
        test_path_is_root_at_one(/* expected= */ true);

        /* chdir("/../") does not change anything. */
        ASSERT_OK_ERRNO(chdir("/../"));
        log_debug("/* %s: chdir(\"/../\") again */", __func__);
        test_path_is_root_at_one(/* expected= */ true);

        /* bind mounting to non-root directory has no problem, of course. */
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-path_is_root-XXXXXX", &tmp));
        ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, "/", tmp, /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL));
        log_debug("/* %s: bind mount(\"/\", \"%s\") */", __func__, tmp);
        test_path_is_root_at_one(/* expected= */ true);

        ASSERT_OK_ERRNO(chdir(tmp));
        log_debug("/* %s: chdir(\"%s\") */", __func__, tmp);
        test_path_is_root_at_one(/* expected= */ true);

        ASSERT_OK_ERRNO(chroot(tmp));
        log_debug("/* %s: chroot(\"%s\") */", __func__, tmp);
        test_path_is_root_at_one(/* expected= */ true);

        ASSERT_OK_ERRNO(chdir(tmp));
        log_debug("/* %s: chdir(\"%s\") again */", __func__, tmp);
        test_path_is_root_at_one(/* expected= */ true);
}

TEST(fds_inode_and_mount_same) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF, fd3 = -EBADF, fd4 = -EBADF;

        fd1 = open("/sys", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        fd2 = open("/proc", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        fd3 = open("/proc", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        fd4 = open("/", O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);

        if (fd1 < 0 || fd2 < 0 || fd3 < 0 || fd4 < 0)
                return (void) log_tests_skipped_errno(errno, "Failed to open /sys or /proc or /");

        ASSERT_OK_EQ(fds_inode_and_mount_same(fd1, fd2), 0);
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd2, fd3));
}

TEST(fd_get_path) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL, *q = NULL, *saved_cwd = NULL;

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, O_PATH, &t));
        ASSERT_OK(fd_get_path(tfd, &p));
        ASSERT_STREQ(p, t);

        p = mfree(p);

        ASSERT_OK(safe_getcwd(&saved_cwd));
        ASSERT_OK_ERRNO(chdir(t));

        ASSERT_OK(fd_get_path(AT_FDCWD, &p));
        ASSERT_STREQ(p, t);

        p = mfree(p);

        ASSERT_NOT_NULL(q = path_join(t, "regular"));
        ASSERT_OK(touch(q));
        ASSERT_OK(mkdirat_parents(tfd, "subdir/symlink", 0755));
        ASSERT_OK_ERRNO(symlinkat("../regular", tfd, "subdir/symlink"));
        ASSERT_OK_ERRNO(symlinkat("subdir", tfd, "symdir"));

        fd = ASSERT_OK_ERRNO(openat(tfd, "regular", O_CLOEXEC|O_PATH));
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(AT_FDCWD, "regular", O_CLOEXEC|O_PATH));
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(tfd, "subdir/symlink", O_CLOEXEC|O_PATH));
        ASSERT_OK(fd_verify_regular(fd));
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(AT_FDCWD, "subdir/symlink", O_CLOEXEC|O_PATH));
        ASSERT_OK(fd_verify_regular(fd));
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(tfd, "symdir//./symlink", O_CLOEXEC|O_PATH));
        ASSERT_OK(fd_verify_regular(fd));
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(AT_FDCWD, "symdir//./symlink", O_CLOEXEC|O_PATH));
        ASSERT_OK(fd_verify_regular(fd));
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        q = mfree(q);
        fd = safe_close(fd);

        ASSERT_NOT_NULL(q = path_join(t, "subdir/symlink"));
        fd = ASSERT_OK_ERRNO(openat(tfd, "subdir/symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW));
        ASSERT_ERROR(fd_verify_regular(fd), ELOOP);
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(AT_FDCWD, "subdir/symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW));
        ASSERT_ERROR(fd_verify_regular(fd), ELOOP);
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(tfd, "symdir//./symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW));
        ASSERT_ERROR(fd_verify_regular(fd), ELOOP);
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        p = mfree(p);
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(AT_FDCWD, "symdir//./symlink", O_CLOEXEC|O_PATH|O_NOFOLLOW));
        ASSERT_ERROR(fd_verify_regular(fd), ELOOP);
        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_STREQ(p, q);

        ASSERT_OK_ERRNO(chdir(saved_cwd));
}

TEST(fd_vet_accmode) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fd-accmode.XXXXXX";
        _cleanup_close_ int fd_rw = -EBADF, fd_ro = -EBADF, fd_wo = -EBADF, fd_opath = -EBADF;

        ASSERT_OK(fd_rw = mkostemp_safe(name));
        ASSERT_OK_ZERO(fd_vet_accmode(fd_rw, O_RDONLY));
        ASSERT_OK_ZERO(fd_vet_accmode(fd_rw, O_WRONLY));
        ASSERT_OK_POSITIVE(fd_vet_accmode(fd_rw, O_RDWR));

        ASSERT_OK_ERRNO(fd_ro = open(name, O_RDONLY | O_CLOEXEC));
        ASSERT_OK_POSITIVE(fd_vet_accmode(fd_ro, O_RDONLY));
        ASSERT_ERROR(fd_vet_accmode(fd_ro, O_WRONLY), EPROTOTYPE);
        ASSERT_ERROR(fd_vet_accmode(fd_ro, O_RDWR), EPROTOTYPE);

        ASSERT_OK_ERRNO(fd_wo = open(name, O_WRONLY | O_CLOEXEC));
        ASSERT_ERROR(fd_vet_accmode(fd_wo, O_RDONLY), EPROTOTYPE);
        ASSERT_OK_POSITIVE(fd_vet_accmode(fd_wo, O_WRONLY));
        ASSERT_ERROR(fd_vet_accmode(fd_wo, O_RDWR), EPROTOTYPE);

        ASSERT_OK_ERRNO(fd_opath = open(name, O_PATH | O_CLOEXEC));
        ASSERT_ERROR(fd_vet_accmode(fd_opath, O_RDONLY), EBADFD);
        ASSERT_ERROR(fd_vet_accmode(fd_opath, O_WRONLY), EBADFD);
        ASSERT_ERROR(fd_vet_accmode(fd_opath, O_RDWR), EBADFD);
}

TEST(fd_is_writable) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fd-writable.XXXXXX";
        _cleanup_close_ int fd_ro = -EBADF, fd_wo = -EBADF, fd_rw = -EBADF, fd_path = -EBADF;

        ASSERT_OK(fd_rw = mkostemp_safe(name));
        ASSERT_OK_POSITIVE(fd_is_writable(fd_rw));

        ASSERT_OK(fd_ro = open(name, O_RDONLY | O_CLOEXEC));
        ASSERT_OK_ZERO(fd_is_writable(fd_ro));

        ASSERT_OK(fd_wo = open(name, O_WRONLY | O_CLOEXEC));
        ASSERT_OK_POSITIVE(fd_is_writable(fd_wo));

        ASSERT_OK(fd_path = open(name, O_PATH | O_CLOEXEC));
        ASSERT_OK_ZERO(fd_is_writable(fd_path));

        ASSERT_SIGNAL(fd_is_writable(-1), SIGABRT);

        safe_close(fd_ro);
        ASSERT_ERROR(fd_is_writable(fd_ro), EBADF);
        TAKE_FD(fd_ro);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
