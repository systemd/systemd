/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/prctl.h>

#include "tests.h"

#define PR_THP_DISABLE_NOT_SET 0
#define PR_THP_DISABLE 1

static const char *arg_mode = NULL;

static int intro(void) {
        int r;

        r = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
        if (streq_ptr(arg_mode, "no-disable")) {
                /* Test case: THPs should not be disabled */
                if (r != PR_THP_DISABLE_NOT_SET) {
                        log_error("THPs disabled for the process r = %d: %m", r);
                        return EXIT_FAILURE;
                }
        } else if (streq_ptr(arg_mode, "disable")) {
                /* Test case: THPs should be completely disabled */
                if (r == PR_THP_DISABLE_NOT_SET)
                        return log_tests_skipped("Disabling THPs completely for the process not supported");

                if (r != PR_THP_DISABLE) {
                        log_error("THPs not completely disabled for the process r = %d: %m", r);
                        return EXIT_FAILURE;
                }
        } else if (streq_ptr(arg_mode, "madvise")) {
                /* Test case: THPs should be only enabled on a madvise basis */
                if (r == PR_THP_DISABLE_NOT_SET)
                        return log_tests_skipped("Disabling THPs except for madvise not supported");

                if (r != (PR_THP_DISABLE | PR_THP_DISABLE_EXCEPT_ADVISED)) {
                        log_error("THPs (except madvise) not completely disabled for the process r = %d: %m", r);
                        return EXIT_FAILURE;
                }
        } else {
                log_error("Invalid mode: %s (expected: no-disable, disable, or madvise)", strna(arg_mode));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        if (argc != 2) {
                log_error("Invalid number of args passed to the test %d", argc);
                return EXIT_FAILURE;
        }
        arg_mode = argv[1];
        test_setup_logging(LOG_DEBUG);
        return intro();
}
