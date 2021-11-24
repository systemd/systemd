/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "data-fd-util.h"
#include "fd-util.h"
#include "memory-util.h"
#include "process-util.h"
#include "tests.h"
#include "random-util.h"

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

TEST(acquire_data_fd) {
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

TEST(copy_data_fd) {
        _cleanup_close_ int fd1 = -1, fd2 = -1;
        _cleanup_(close_pairp) int sfd[2] = { -1, -1 };
        _cleanup_(sigkill_waitp) pid_t pid = -1;
        int r;

        fd1 = open("/etc/fstab", O_RDONLY|O_CLOEXEC);
        if (fd1 >= 0) {

                fd2 = copy_data_fd(fd1);
                assert_se(fd2 >= 0);

                assert_se(lseek(fd1, 0, SEEK_SET) == 0);
                assert_equal_fd(fd1, fd2);
        }

        fd1 = safe_close(fd1);
        fd2 = safe_close(fd2);

        fd1 = acquire_data_fd("hallo", 6,  0);
        assert_se(fd1 >= 0);

        fd2 = copy_data_fd(fd1);
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

                for (uint64_t i = 0; i < 1536*1024 / sizeof(uint64_t); i++)
                        assert_se(write(sfd[1], &i, sizeof(i)) == sizeof(i));

                sfd[1] = safe_close(sfd[1]);

                _exit(EXIT_SUCCESS);
        }

        sfd[1] = safe_close(sfd[1]);

        fd2 = copy_data_fd(sfd[0]);
        assert_se(fd2 >= 0);

        uint64_t j;
        for (uint64_t i = 0; i < 1536*1024 / sizeof(uint64_t); i++) {
                assert_se(read(fd2, &j, sizeof(j)) == sizeof(j));
                assert_se(i == j);
        }

        assert_se(read(fd2, &j, sizeof(j)) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
