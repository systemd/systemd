/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "data-fd-util.h"
#include "fd-util.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "process-util.h"
#include "random-util.h"
#include "tests.h"

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
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;
        _cleanup_close_pair_ int sfd[2] = EBADF_PAIR;
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

        fd1 = memfd_new_and_seal_string("data", "hallo");
        assert_se(fd1 >= 0);

        fd2 = copy_data_fd(fd1);
        assert_se(fd2 >= 0);

        safe_close(fd1);
        fd1 = memfd_new_and_seal_string("data", "hallo");
        assert_se(fd1 >= 0);

        assert_equal_fd(fd1, fd2);

        fd1 = safe_close(fd1);
        fd2 = safe_close(fd2);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, sfd) >= 0);

        r = safe_fork("(sd-pipe)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pid);
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
