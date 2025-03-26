/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "memfd-util.h"
#include "missing_mman.h"
#include "tests.h"

static int memfd_get_seals(int fd, unsigned *ret_seals);

TEST(memfd_get_sealed) {
#define TEST_TEXT "this is some random test text we are going to write to a memfd"
        int r;
        unsigned seals;

        _cleanup_close_ int fd = memfd_new_full("test-memfd-get-sealed", MFD_ALLOW_SEALING);
        if (fd < 0) {
                ASSERT_TRUE(ERRNO_IS_NOT_SUPPORTED(fd));
                return (void) log_tests_skipped_errno(fd, "Failed to create new memfd");
        }

        ASSERT_OK(memfd_get_seals(fd, &seals));
        r = memfd_get_seals(fd, &seals);

        ASSERT_OK(r);
        ASSERT_OK(seals > 0);

        ASSERT_OK_EQ_ERRNO(write(fd, TEST_TEXT, strlen(TEST_TEXT)), (ssize_t) strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        ASSERT_OK(memfd_set_sealed(fd) >= 0);
        ASSERT_OK(memfd_get_sealed(fd) > 0);

        uint64_t size = 137;
        ASSERT_EQ(memfd_get_size(fd, &size), 0);
        ASSERT_OK(memfd_set_size(fd, size));
        size = 32;
        ASSERT_EQ(memfd_get_size(fd, &size), 0);

}

static int memfd_get_seals(int fd, unsigned *ret_seals) {
        int r;

        assert(fd >= 0);

        r = RET_NERRNO(fcntl(fd, F_GET_SEALS));
        if (r < 0)
                return r;

        if (ret_seals)
                *ret_seals = r;
        return 0;
}

DEFINE_TEST_MAIN(LOG_DEBUG);
