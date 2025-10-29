/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "tests.h"

#define PR_THP_DISABLE 1

static int intro(void) {
        int res = prctl(PR_GET_THP_DISABLE, NULL, NULL, NULL, NULL);

        if (res == 0)
                return log_tests_skipped("Disabling THPs completely for the process not supported");

        if (res != PR_THP_DISABLE)
                return log_error_errno(errno,
                        "THPs not completely disabled for the process res = %d: %m", res);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
