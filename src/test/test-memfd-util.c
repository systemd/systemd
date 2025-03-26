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
                return;
        }
        if (ERRNO_IS_NOT_SUPPORTED(fd))
                return (void) log_tests_skipped_errno(fd, "Could not make new %s : %m", "test-memfd-get-sealed");
        ASSERT_OK(fd);

        int r;
        unsigned seals;
        r = memfd_get_seals(fd, &seals);
        log_info("r: %d\n", r);
        if (r < 0)
                return (void) log_error_errno(r, "memfd_get_seals function failed: %m");

        ASSERT_OK(r);
        ASSERT_GT(seals, (unsigned) 0);
        log_info("seals: %u\n", seals);

        ASSERT_OK(write(fd, TEST_TEXT, strlen(TEST_TEXT)) == strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        int memfd_set_res = memfd_set_sealed(fd);
        log_info("memfd_set_res: %d\n", memfd_set_res);
        ASSERT_EQ(memfd_set_res, 0);

        int memfd_get_res = memfd_get_sealed(fd);
        log_info("memfd_get_res: %d\n", memfd_get_res);
        ASSERT_GE(memfd_get_res, 0);

        uint64_t size = 0;
        uint64_t sizeof_size = sizeof(size);
        log_info("size => before set: %"PRIu64"\n", size);
        ASSERT_OK(size > 0);
        ASSERT_EQ(memfd_get_size(fd, &size), 0);
        log_info("size => after set: %"PRIu64"\n", size);
        log_info("sizeof_size: %"PRIu64"\n", sizeof_size);
        ASSERT_LT(memfd_set_size(fd, sizeof_size), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
