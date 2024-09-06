/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exit-status.h"
#include "string-util.h"
#include "tests.h"

TEST(exit_status_to_string) {
        for (int i = -1; i <= 256; i++) {
                const char *s, *class;

                s = exit_status_to_string(i, EXIT_STATUS_FULL);
                class = exit_status_class(i);
                log_info("%d: %s%s%s%s",
                         i, s ?: "-",
                         class ? " (" : "", strempty(class), class ? ")" : "");

                if (s)
                        assert_se(exit_status_from_string(s) == i);
        }
}

TEST(exit_status_from_string) {
        assert_se(exit_status_from_string("11") == 11);
        assert_se(exit_status_from_string("-1") == -ERANGE);
        assert_se(exit_status_from_string("256") == -ERANGE);
        assert_se(exit_status_from_string("foo") == -EINVAL);
        assert_se(exit_status_from_string("SUCCESS") == 0);
        assert_se(exit_status_from_string("FAILURE") == 1);
}

TEST(exit_status_NUMA_POLICY) {
        ASSERT_STREQ(exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_FULL), "NUMA_POLICY");
        ASSERT_STREQ(exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_SYSTEMD), "NUMA_POLICY");
        assert_se(!exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_BSD));
        assert_se(!exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_LSB));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
