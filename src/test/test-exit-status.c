/* SPDX-License-Identifier: LGPL-2.1+ */

#include "exit-status.h"
#include "string-util.h"
#include "tests.h"

static void test_exit_status_to_string(void) {
        log_info("/* %s */", __func__);

        for (int i = -1; i <= 256; i++) {
                const char *s, *class;

                s = exit_status_to_string(i, EXIT_STATUS_FULL);
                class = exit_status_class(i);
                log_info("%d: %s%s%s%s",
                         i, s ?: "-",
                         class ? " (" : "", class ?: "", class ? ")" : "");

                if (s)
                        assert_se(exit_status_from_string(s) == i);
        }
}

static void test_exit_status_from_string(void) {
        log_info("/* %s */", __func__);

        assert_se(exit_status_from_string("11") == 11);
        assert_se(exit_status_from_string("-1") == -ERANGE);
        assert_se(exit_status_from_string("256") == -ERANGE);
        assert_se(exit_status_from_string("foo") == -EINVAL);
        assert_se(exit_status_from_string("SUCCESS") == 0);
        assert_se(exit_status_from_string("FAILURE") == 1);
}

static void test_exit_status_NUMA_POLICY(void) {
        log_info("/* %s */", __func__);

        assert_se(streq(exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_FULL), "NUMA_POLICY"));
        assert_se(streq(exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_SYSTEMD), "NUMA_POLICY"));
        assert_se(!exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_BSD));
        assert_se(!exit_status_to_string(EXIT_NUMA_POLICY, EXIT_STATUS_LSB));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_exit_status_to_string();
        test_exit_status_from_string();
        test_exit_status_NUMA_POLICY();

        return 0;
}
