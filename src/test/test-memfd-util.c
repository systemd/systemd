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
                ASSERT_TRUE(ERRNO_IS_NOT_SUPPORTED(fd));
                return;
        }
        unsigned int seals;

        ASSERT_EQ(memfd_get_seals(fd, &seals), 0);

        ASSERT_OK_POSITIVE(write(fd, TEST_TEXT, strlen(TEST_TEXT)) == strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        ASSERT_EQ(memfd_get_sealed(fd), 0);
        ASSERT_OK(memfd_set_sealed(fd) >= 0);
        ASSERT_OK_POSITIVE(memfd_get_sealed(fd) > 0);
}

TEST(memfd_new_and_seal) {
        _cleanup_close_ int fd = -EBADF;

        int data[] = { 1, 2, 3 };
        const int dataN = sizeof( data ) / sizeof( *data );
        const int dt_size = sizeof data / sizeof(int);
        unsigned long data_size = (unsigned long) (unsigned int) dt_size;

        fd = memfd_new_full("test-memfd-get-sealed", MFD_ALLOW_SEALING);
        if (fd < 0) {
                ASSERT_TRUE(ERRNO_IS_NOT_SUPPORTED(fd));
                return;
        }
        ASSERT_OK_POSITIVE(memfd_new_full("test-memfd-get-sealed", MFD_ALLOW_SEALING));
        ASSERT_EQ(memfd_set_sealed(fd), 0);

        ASSERT_EQ(dt_size, dataN);
        ASSERT_LE(data_size, SIZE_MAX);

        ASSERT_OK(memfd_set_sealed(fd) >= 0);

        uint64_t ret = 0;
        int bit = 7;
        int value = 1;

        if (value) {
                ret |= ((uint64_t)1 << bit);
        } else {
                ret &= ~((uint64_t)1 << bit);
        }

        ASSERT_EQ(memfd_get_size(fd, &ret), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
