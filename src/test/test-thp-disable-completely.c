/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "tests.h"

#define PR_THP_DISABLE_NOT_SET 0
#define PR_THP_DISABLE 1

static int intro(void) {
        int r = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);

        if (r == PR_THP_DISABLE_NOT_SET)
                return log_tests_skipped("Disabling THPs completely for the process not supported");

        if (r != PR_THP_DISABLE) {
                log_error("THPs not completely disabled for the process r = %d: %m", r);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
