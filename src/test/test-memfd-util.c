/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "memfd-util.h"
#include "missing_mman.h"
#include "string-util.h"
#include "tests.h"

TEST(memfd_get_sealed) {
#define TEST_TEXT "this is some random test text we are going to write to a memfd"
        _cleanup_close_ int fd = -EBADF;

        fd = memfd_new_full("test-memfd-get-sealed", MFD_ALLOW_SEALING);
        if (fd < 0) {
                assert_se(ERRNO_IS_NOT_SUPPORTED(fd));
                return;
        }

        assert_se(write(fd, TEST_TEXT, strlen(TEST_TEXT)) == strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        assert_se(memfd_get_sealed(fd) == 0);
        assert_se(memfd_set_sealed(fd) >= 0);
        assert_se(memfd_get_sealed(fd) > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
