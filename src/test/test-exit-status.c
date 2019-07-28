/* SPDX-License-Identifier: LGPL-2.1+ */

#include "exit-status.h"
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
        }
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_exit_status_to_string();

        return 0;
}
