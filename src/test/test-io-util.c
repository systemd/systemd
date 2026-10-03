/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include "fd-util.h"
#include "io-util.h"
#include "signal-util.h"
#include "tests.h"

static void test_sparse_write_one(int fd, const char *buffer, size_t n) {
        char check[n];

        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_SET), 0);
        ASSERT_OK_ERRNO(ftruncate(fd, 0));
        ASSERT_OK(sparse_write(fd, buffer, n, 4));

        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_CUR), (off_t) n);
        ASSERT_OK_ERRNO(ftruncate(fd, n));

        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_SET), 0);
        ASSERT_OK_EQ_ERRNO(read(fd, check, n), (ssize_t) n);

        ASSERT_EQ(memcmp(buffer, check, n), 0);
}

TEST(sparse_write) {
        const char test_a[] = "test";
        const char test_b[] = "\0\0\0\0test\0\0\0\0";
        const char test_c[] = "\0\0test\0\0\0\0";
        const char test_d[] = "\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0\0\0\0";
        const char test_e[] = "test\0\0\0\0test";
        _cleanup_close_ int fd = -EBADF;
        char fn[] = "/tmp/sparseXXXXXX";

        ASSERT_OK_ERRNO(fd = mkostemp(fn, O_CLOEXEC));
        (void) unlink(fn);

        test_sparse_write_one(fd, test_a, sizeof(test_a));
        test_sparse_write_one(fd, test_b, sizeof(test_b));
        test_sparse_write_one(fd, test_c, sizeof(test_c));
        test_sparse_write_one(fd, test_d, sizeof(test_d));
        test_sparse_write_one(fd, test_e, sizeof(test_e));
}

TEST(sparse_write_rlimit) {
        const uint8_t data[] = {
                '1', '2', '3', '4', '5', '6', '7', '8',
                0, 0, 0, 0, 0,
                'a', 'b', 'c', 'd',
        };
        _cleanup_close_ int fd = -EBADF;
        struct sigaction old_sa;
        struct rlimit old_rlimit, new_rlimit;
        char fn[] = "/tmp/sparseXXXXXX";

        ASSERT_OK_ERRNO(fd = mkostemp(fn, O_CLOEXEC));
        (void) unlink(fn);

        ASSERT_OK_ERRNO(getrlimit(RLIMIT_FSIZE, &old_rlimit));
        if (old_rlimit.rlim_max < 4)
                return (void) log_tests_skipped("RLIMIT_FSIZE hard limit is too low");

        ASSERT_OK_ERRNO(sigaction(SIGXFSZ, &sigaction_ignore, &old_sa));

        new_rlimit = old_rlimit;
        new_rlimit.rlim_cur = 4;
        ASSERT_OK_ERRNO(setrlimit(RLIMIT_FSIZE, &new_rlimit));

        ASSERT_ERROR(sparse_write(fd, data, sizeof(data), 4), EFBIG);

        ASSERT_OK_ERRNO(setrlimit(RLIMIT_FSIZE, &old_rlimit));
        ASSERT_OK_ERRNO(sigaction(SIGXFSZ, &old_sa, NULL));
}

DEFINE_TEST_MAIN(LOG_INFO);
