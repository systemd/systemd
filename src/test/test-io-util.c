/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "macro.h"
#include "tests.h"

static void test_sparse_write_one(int fd, const char *buffer, size_t n) {
        char check[n];

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(sparse_write(fd, buffer, n, 4) == (ssize_t) n);

        assert_se(lseek(fd, 0, SEEK_CUR) == (off_t) n);
        assert_se(ftruncate(fd, n) >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(read(fd, check, n) == (ssize_t) n);

        assert_se(memcmp(buffer, check, n) == 0);
}

TEST(sparse_write) {
        const char test_a[] = "test";
        const char test_b[] = "\0\0\0\0test\0\0\0\0";
        const char test_c[] = "\0\0test\0\0\0\0";
        const char test_d[] = "\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0\0\0\0";
        const char test_e[] = "test\0\0\0\0test";
        _cleanup_close_ int fd = -1;
        char fn[] = "/tmp/sparseXXXXXX";

        fd = mkostemp(fn, O_CLOEXEC);
        assert_se(fd >= 0);
        unlink(fn);

        test_sparse_write_one(fd, test_a, sizeof(test_a));
        test_sparse_write_one(fd, test_b, sizeof(test_b));
        test_sparse_write_one(fd, test_c, sizeof(test_c));
        test_sparse_write_one(fd, test_d, sizeof(test_d));
        test_sparse_write_one(fd, test_e, sizeof(test_e));
}

DEFINE_TEST_MAIN(LOG_INFO);
