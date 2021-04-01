/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-util.h"
#include "tests.h"

static void test_log_device_full(void) {
        int r;

        log_info("/* %s */", __func__);

        for (int level = LOG_ERR; level <= LOG_DEBUG; level++) {
                log_device_full(NULL, level, "test level=%d: %m", level);

                r = log_device_full_errno(NULL, level, EUCLEAN, "test level=%d errno=EUCLEAN: %m", level);
                assert_se(r == -EUCLEAN);

                r = log_device_full_errno(NULL, level, 0, "test level=%d errno=0: %m", level);
                assert_se(r == 0);

                r = log_device_full_errno(NULL, level, SYNTHETIC_ERRNO(ENODATA), "test level=%d errno=S(ENODATA): %m", level);
                assert_se(r == -ENODATA);
        }
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_log_device_full();
        return 0;
}
