/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "memfd-util.h"
#include "tests.h"

TEST(memfd_get_sealed) {
#define TEST_TEXT "this is some random test text we are going to write to a memfd"
        _cleanup_close_ int fd = memfd_new_full("test-memfd-get-sealed", MFD_ALLOW_SEALING);
        if (fd < 0) {
                ASSERT_TRUE(ERRNO_IS_NOT_SUPPORTED(fd));
                return (void) log_tests_skipped_errno(fd, "Failed to create new memfd");
        }
        ASSERT_OK_EQ_ERRNO(write(fd, TEST_TEXT, strlen(TEST_TEXT)), (ssize_t) strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        uint64_t size, new_size;
        ASSERT_OK(memfd_get_size(fd, &size));
        ASSERT_GE(size, (uint64_t) strlen(TEST_TEXT));

        ASSERT_OK(memfd_set_size(fd, size * 2));
        ASSERT_OK(memfd_get_size(fd, &new_size));
        ASSERT_EQ(new_size, size * 2);

        ASSERT_OK(memfd_set_size(fd, new_size / 2));
        ASSERT_OK(memfd_get_size(fd, &size));
        ASSERT_EQ(size, new_size / 2);

        ASSERT_OK_ZERO(memfd_get_sealed(fd));
        ASSERT_OK(memfd_set_sealed(fd));
        ASSERT_OK_POSITIVE(memfd_get_sealed(fd));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
