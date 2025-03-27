/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>
#include <inttypes.h>
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
        if (ERRNO_IS_NOT_SUPPORTED(fd)) {
                return (void) log_tests_skipped("memfd is not supported");
        }
        ASSERT_OK(fd);

        int r;
        unsigned seals;
        r = memfd_get_seals(fd, &seals);
        if (r < 0)
                return (void) log_error_errno(r, "memfd_get_seals function failed: %m");

        ASSERT_OK(r);
        ASSERT_EQ((int) seals, 0);
        ASSERT_OK_EQ_ERRNO(write(fd, TEST_TEXT, strlen(TEST_TEXT)), (long int) strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        ASSERT_OK_ZERO(memfd_get_sealed(fd));

        uint64_t size = 0;
        int bit = 7;
        int value = 1;

        if (value) {
                size |= ((uint64_t)1 << bit);
        } else {
                size &= ~((uint64_t)1 << bit);
        }

        uint64_t sizeof_size = sizeof(size);

        log_info("size value: %"PRIu64"\n", size);
        log_info("sizeof_size value: %"PRIu64"\n", sizeof_size);

        ASSERT_OK(memfd_get_size(fd, &size) == 0);
        ASSERT_OK(ftruncate(fd, sizeof_size) == 0);
        ASSERT_OK(memfd_set_size(fd, sizeof_size) == 0);
}
DEFINE_TEST_MAIN(LOG_DEBUG);
