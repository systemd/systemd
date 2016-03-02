/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "macro.h"

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

static void test_sparse_write(void) {
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

int main(void) {
        test_sparse_write();

        return 0;
}
