/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/mman.h>

#include "fd-util.h"
#include "sigbus.h"
#include "util.h"
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

int main(int argc, char *argv[]) {
        _cleanup_close_ int fd = -1;
        char template[] = "/tmp/sigbus-test-XXXXXX";
        void *addr = NULL;
        uint8_t *p;

#if HAVE_VALGRIND_VALGRIND_H
        if (RUNNING_ON_VALGRIND) {
                puts("This test cannot run on valgrind, skipping tests.");
                return EXIT_TEST_SKIP;
        }
#endif

#ifdef __SANITIZE_ADDRESS__
        puts("Address sanitization is enabled, skipping tests.");
        return EXIT_TEST_SKIP;
#endif
        sigbus_install();

        assert_se(sigbus_pop(&addr) == 0);

        assert_se((fd = mkostemp(template, O_RDWR|O_CREAT|O_EXCL)) >= 0);
        assert_se(unlink(template) >= 0);
        assert_se(posix_fallocate(fd, 0, page_size() * 8) >= 0);

        p = mmap(NULL, page_size() * 16, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        assert_se(p != MAP_FAILED);

        assert_se(sigbus_pop(&addr) == 0);

        p[0] = 0xFF;
        assert_se(sigbus_pop(&addr) == 0);

        p[page_size()] = 0xFF;
        assert_se(sigbus_pop(&addr) == 0);

        p[page_size()*8] = 0xFF;
        p[page_size()*8+1] = 0xFF;
        p[page_size()*10] = 0xFF;
        assert_se(sigbus_pop(&addr) > 0);
        assert_se(addr == p + page_size() * 8);
        assert_se(sigbus_pop(&addr) > 0);
        assert_se(addr == p + page_size() * 10);
        assert_se(sigbus_pop(&addr) == 0);

        sigbus_reset();
}
