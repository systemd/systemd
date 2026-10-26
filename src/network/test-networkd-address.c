/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "networkd-address.h"
#include "tests.h"
#include "time-util.h"

static void test_FORMAT_LIFETIME_one(usec_t lifetime, const char *expected) {
        const char *t = FORMAT_LIFETIME(lifetime);

        log_debug(USEC_FMT " → \"%s\" (expected \"%s\")", lifetime, t, strna(expected));
        if (expected)
                ASSERT_STREQ(t, expected);
}

TEST(FORMAT_LIFETIME) {
        usec_t now_usec;

        now_usec = now(CLOCK_BOOTTIME);

        test_FORMAT_LIFETIME_one(now_usec, "for 0");
        test_FORMAT_LIFETIME_one(USEC_INFINITY, "forever");

        /* These two are necessarily racy, especially for slow test environment. */
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 2 * USEC_PER_SEC - 1), NULL);
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 3 * USEC_PER_WEEK + USEC_PER_SEC - 1), NULL);
}

TEST(address_limit_from_env) {
        const char *name = "SYSTEMD_TEST_NETWORKD_ADDRESS_LIMIT";
        uint64_t cached = 0;

        ASSERT_OK_ERRNO(unsetenv(name));
        ASSERT_EQ(address_limit_from_env(name, 123, &cached), 123U);

        cached = 0;
        ASSERT_OK_ERRNO(setenv(name, "42", /* overwrite= */ true));
        ASSERT_EQ(address_limit_from_env(name, 123, &cached), 42U);

        /* Changing the environment after first use must not change the cached limit. */
        ASSERT_OK_ERRNO(setenv(name, "0", /* overwrite= */ true));
        ASSERT_EQ(address_limit_from_env(name, 123, &cached), 42U);

        cached = 0;
        ASSERT_EQ(address_limit_from_env(name, 123, &cached), 123U);

        cached = 0;
        ASSERT_OK_ERRNO(setenv(name, "invalid", /* overwrite= */ true));
        ASSERT_EQ(address_limit_from_env(name, 123, &cached), 123U);
        ASSERT_OK_ERRNO(setenv(name, "43", /* overwrite= */ true));
        ASSERT_EQ(address_limit_from_env(name, 123, &cached), 123U);

        cached = 0;
        ASSERT_OK_ERRNO(setenv(name, "18446744073709551616", /* overwrite= */ true));
        ASSERT_EQ(address_limit_from_env(name, 123, &cached), 123U);

        ASSERT_OK_ERRNO(unsetenv(name));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
