/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rlimit-util.h"
#include "serialize.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_close_many(void) {
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

static void test_close_nointr(void) {
        char name[] = "/tmp/test-test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);
        assert_se(close_nointr(fd) < 0);

        unlink(name);
}

static void test_same_fd(void) {
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

static void test_open_serialization_fd(void) {
        _cleanup_close_ int fd = -1;

        fd = open_serialization_fd("test");
        assert_se(fd >= 0);

        assert_se(write(fd, "test\n", 5) == 5);
}

static void test_acquire_data_fd_one(unsigned flags) {
        char wbuffer[196*1024 - 7];
        char rbuffer[sizeof(wbuffer)];
        int fd;

        fd = acquire_data_fd("foo", 3, flags);
        assert_se(fd >= 0);

        zero(rbuffer);
        assert_se(read(fd, rbuffer, sizeof(rbuffer)) == 3);
        assert_se(streq(rbuffer, "foo"));

        fd = safe_close(fd);

        fd = acquire_data_fd("", 0, flags);
        assert_se(fd >= 0);

        zero(rbuffer);
        assert_se(read(fd, rbuffer, sizeof(rbuffer)) == 0);
        assert_se(streq(rbuffer, ""));

        fd = safe_close(fd);

        random_bytes(wbuffer, sizeof(wbuffer));

        fd = acquire_data_fd(wbuffer, sizeof(wbuffer), flags);
        assert_se(fd >= 0);

        zero(rbuffer);
        assert_se(read(fd, rbuffer, sizeof(rbuffer)) == sizeof(rbuffer));
        assert_se(memcmp(rbuffer, wbuffer, sizeof(rbuffer)) == 0);

        fd = safe_close(fd);
}

static void test_acquire_data_fd(void) {

        test_acquire_data_fd_one(0);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL);
        test_acquire_data_fd_one(ACQUIRE_NO_MEMFD);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_MEMFD);
        test_acquire_data_fd_one(ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_MEMFD|ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_MEMFD|ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_MEMFD|ACQUIRE_NO_PIPE|ACQUIRE_NO_TMPFILE);
}

static void test_fd_move_above_stdio(void) {
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

static void test_rearrange_stdio(void) {
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

static void assert_equal_fd(int fd1, int fd2) {

        for (;;) {
                uint8_t a[4096], b[4096];
                ssize_t x, y;

                x = read(fd1, a, sizeof(a));
                assert_se(x >= 0);

                y = read(fd2, b, sizeof(b));
                assert_se(y >= 0);

                assert_se(x == y);

                if (x == 0)
                        break;

                assert_se(memcmp(a, b, x) == 0);
        }
}

static void test_fd_duplicate_data_fd(void) {
        _cleanup_close_ int fd1 = -1, fd2 = -1;
        _cleanup_(close_pairp) int sfd[2] = { -1, -1 };
        _cleanup_(sigkill_waitp) pid_t pid = -1;
        uint64_t i, j;
        int r;

        fd1 = open("/etc/fstab", O_RDONLY|O_CLOEXEC);
        if (fd1 >= 0) {

                fd2 = fd_duplicate_data_fd(fd1);
                assert_se(fd2 >= 0);

                assert_se(lseek(fd1, 0, SEEK_SET) == 0);
                assert_equal_fd(fd1, fd2);
        }

        fd1 = safe_close(fd1);
        fd2 = safe_close(fd2);

        fd1 = acquire_data_fd("hallo", 6,  0);
        assert_se(fd1 >= 0);

        fd2 = fd_duplicate_data_fd(fd1);
        assert_se(fd2 >= 0);

        safe_close(fd1);
        fd1 = acquire_data_fd("hallo", 6,  0);
        assert_se(fd1 >= 0);

        assert_equal_fd(fd1, fd2);

        fd1 = safe_close(fd1);
        fd2 = safe_close(fd2);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, sfd) >= 0);

        r = safe_fork("(sd-pipe)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        assert_se(r >= 0);

        if (r == 0) {
                /* child */

                sfd[0] = safe_close(sfd[0]);

                for (i = 0; i < 1536*1024 / sizeof(uint64_t); i++)
                        assert_se(write(sfd[1], &i, sizeof(i)) == sizeof(i));

                sfd[1] = safe_close(sfd[1]);

                _exit(EXIT_SUCCESS);
        }

        sfd[1] = safe_close(sfd[1]);

        fd2 = fd_duplicate_data_fd(sfd[0]);
        assert_se(fd2 >= 0);

        for (i = 0; i < 1536*1024 / sizeof(uint64_t); i++) {
                assert_se(read(fd2, &j, sizeof(j)) == sizeof(j));
                assert_se(i == j);
        }

        assert_se(read(fd2, &j, sizeof(j)) == 0);
}

static void test_read_nr_open(void) {
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

static void test_close_all_fds(void) {
        _cleanup_free_ int *fds = NULL, *keep = NULL;
        struct rlimit rl;
        size_t n_fds, n_keep;

        log_info("/* %s */", __func__);

        rlimit_nofile_bump(-1);

        assert_se(getrlimit(RLIMIT_NOFILE, &rl) >= 0);
        assert_se(rl.rlim_cur > 10);

        /* Try to use 5000 fds, but when we can't bump the rlimit to make that happen use the whole limit minus 10 */
        n_fds = MIN((rl.rlim_cur & ~1U) - 10U, 5000U);
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

int main(int argc, char *argv[]) {

        test_setup_logging(LOG_DEBUG);

        test_close_many();
        test_close_nointr();
        test_same_fd();
        test_open_serialization_fd();
        test_acquire_data_fd();
        test_fd_move_above_stdio();
        test_rearrange_stdio();
        test_fd_duplicate_data_fd();
        test_read_nr_open();
        test_close_all_fds();

        return 0;
}
