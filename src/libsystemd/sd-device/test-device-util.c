/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-util.h"
#include "tests.h"

TEST(log_device_full) {
        int r;

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

DEFINE_TEST_MAIN(LOG_INFO);
