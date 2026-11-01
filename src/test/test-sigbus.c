/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#include "fd-util.h"
#include "fs-util.h"
#include "memory-util.h"
#include "sigbus.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_close_ int fd = -EBADF;
        char template[] = "/tmp/sigbus-test-XXXXXX";
        void *addr = NULL;
        uint8_t *p;

        test_setup_logging(LOG_INFO);

#if HAS_FEATURE_ADDRESS_SANITIZER
        return log_tests_skipped("address-sanitizer is enabled");
#endif
#if HAVE_VALGRIND_VALGRIND_H
        if (RUNNING_ON_VALGRIND)
                return log_tests_skipped("This test cannot run on valgrind");
#endif

        sigbus_install();

        ASSERT_OK_EQ(sigbus_pop(&addr), 0);

        fd = ASSERT_OK_ERRNO(mkostemp(template, O_RDWR|O_CREAT|O_EXCL));
        ASSERT_OK_ERRNO(unlink(template));
        ASSERT_OK(posix_fallocate_loop(fd, /* offset= */ 0, page_size() * 8)); /* NOLINT (posix-return) */

        p = mmap(NULL, page_size() * 16, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        ASSERT_TRUE(p != MAP_FAILED);

        ASSERT_OK_EQ(sigbus_pop(&addr), 0);

        p[0] = 0xFF;
        ASSERT_OK_EQ(sigbus_pop(&addr), 0);

        p[page_size()] = 0xFF;
        ASSERT_OK_EQ(sigbus_pop(&addr), 0);

        p[page_size()*8] = 0xFF;
        p[page_size()*8+1] = 0xFF;
        p[page_size()*10] = 0xFF;
        ASSERT_OK_POSITIVE(sigbus_pop(&addr));
        ASSERT_PTR_EQ(addr, p + page_size() * 8);
        ASSERT_OK_POSITIVE(sigbus_pop(&addr));
        ASSERT_PTR_EQ(addr, p + page_size() * 10);
        ASSERT_OK_EQ(sigbus_pop(&addr), 0);

        sigbus_reset();
}
