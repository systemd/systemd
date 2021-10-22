/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-address.h"
#include "tests.h"
#include "time-util.h"

static void test_FORMAT_LIFETIME_one(usec_t lifetime, const char *expected) {
        const char *t = FORMAT_LIFETIME(lifetime);

        log_debug(USEC_FMT " → \"%s\" (expected \"%s\")", lifetime, t, expected);
        assert_se(streq(t, expected));
}

static void test_FORMAT_LIFETIME(void) {
        usec_t now_usec;

        log_info("/* %s */", __func__);

        now_usec = now(clock_boottime_or_monotonic());

        test_FORMAT_LIFETIME_one(now_usec, "for 0");
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 2 * USEC_PER_SEC - 1), "for 1s");
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 3 * USEC_PER_WEEK + USEC_PER_SEC - 1), "for 3w");
        test_FORMAT_LIFETIME_one(USEC_INFINITY, "forever");
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_FORMAT_LIFETIME();

        return 0;
}
