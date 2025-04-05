/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <inttypes.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "memfd-util.h"
#include "missing_mman.h"
#include "string-util.h"
#include "tests.h"

TEST(memfd_get_sealed) {
#define TEST_TEXT "this is some random test text we are going to write to a memfd"
        _cleanup_close_ int fd = memfd_new_full("test-memfd-get-sealed", MFD_ALLOW_SEALING);
        if (fd < 0) {
                ASSERT_TRUE(ERRNO_IS_NOT_SUPPORTED(fd));
                return (void) log_tests_skipped_errno(fd, "Failed to create new memfd");
        }

        int r;
        unsigned seals;
        ASSERT_OK(memfd_get_seals(fd, &seals));
        r = memfd_get_seals(fd, &seals);
        log_info("r: %d\n", r);
        log_info("seals: %u\n", seals);
        if (r < 0)
                return (void) log_error_errno(r, "memfd_get_seals function failed: %m");

        ASSERT_OK(r);
        ASSERT_OK(seals > 0);

        ASSERT_OK_EQ_ERRNO(write(fd, TEST_TEXT, strlen(TEST_TEXT)), (ssize_t) strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        ASSERT_OK(memfd_set_sealed(fd));
        ASSERT_OK_POSITIVE(memfd_get_sealed(fd));

        uint64_t size = 137;
        ASSERT_EQ(memfd_get_size(fd, &size), 0);
        log_info("size value - 1: %"PRIu64"\n", size);
        ASSERT_OK(memfd_set_size(fd, size));
        log_info("size value - 2: %"PRIu64"\n", size);
        size = 32;
        ASSERT_EQ(memfd_get_size(fd, &size), 0);
        log_info("size value - 3: %"PRIu64"\n", size);
}

DEFINE_TEST_MAIN(LOG_DEBUG);