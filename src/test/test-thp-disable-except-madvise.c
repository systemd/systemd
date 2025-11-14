/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "test-thp-util.h"

static int intro(void) {
        int r = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);

        if (r == PR_THP_DISABLE_NOT_SET)
                return log_tests_skipped("Disabling THPs except for the process not supported");

        if (r != (PR_THP_DISABLE | PR_THP_DISABLE_EXCEPT_ADVISED)){
                log_error("THPs (except madvise) not completely disabled for the process r = %d: %m", r);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
