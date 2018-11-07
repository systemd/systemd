/* SPDX-License-Identifier: LGPL-2.1+ */

#include "hexdecoct.h"
#include "random-util.h"
#include "log.h"
#include "tests.h"

static void test_genuine_random_bytes(bool high_quality_required) {
        uint8_t buf[16] = {};
        unsigned i;

        log_info("/* %s */", __func__);

        for (i = 1; i < sizeof buf; i++) {
                assert_se(genuine_random_bytes(buf, i, high_quality_required) == 0);
                if (i + 1 < sizeof buf)
                        assert_se(buf[i] == 0);

                hexdump(stdout, buf, i);
        }
}

static void test_pseudo_random_bytes(void) {
        uint8_t buf[16] = {};
        unsigned i;

        log_info("/* %s */", __func__);

        for (i = 1; i < sizeof buf; i++) {
                pseudo_random_bytes(buf, i);
                if (i + 1 < sizeof buf)
                        assert_se(buf[i] == 0);

                hexdump(stdout, buf, i);
        }
}

static void test_rdrand64(void) {
        int r, i;

        for (i = 0; i < 10; i++) {
                uint64_t x = 0;

                r = rdrand64(&x);
                if (r < 0) {
                        log_error_errno(r, "RDRAND failed: %m");
                        return;
                }

                printf("%" PRIx64 "\n", x);
        }
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_genuine_random_bytes(false);
        test_genuine_random_bytes(true);

        test_pseudo_random_bytes();

        test_rdrand64();

        return 0;
}
