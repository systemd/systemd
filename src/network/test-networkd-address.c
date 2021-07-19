/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-address.h"
#include "tests.h"

static void test_FORMAT_LIFETIME_one(uint32_t lifetime, const char *expected) {
        const char *t = FORMAT_LIFETIME(lifetime);

        log_debug("%"PRIu32 " → \"%s\" (expected \"%s\")", lifetime, t, expected);
        assert_se(streq(t, expected));
}

static void test_FORMAT_LIFETIME(void) {
        log_info("/* %s */", __func__);

        test_FORMAT_LIFETIME_one(0, "for 0");
        test_FORMAT_LIFETIME_one(1, "for 1s");
        test_FORMAT_LIFETIME_one(3 * (USEC_PER_WEEK/USEC_PER_SEC), "for 3w");
        test_FORMAT_LIFETIME_one(CACHE_INFO_INFINITY_LIFE_TIME, "forever");
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_FORMAT_LIFETIME();

        return 0;
}
