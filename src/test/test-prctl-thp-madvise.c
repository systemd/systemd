/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "tests.h"

static int intro(void) {

        if (prctl(PR_GET_THP_DISABLE, NULL, NULL, NULL, NULL) == 0)
                return log_tests_skipped("PR_THP_DISABLE_EXCEPT_ADVISED flag for PR_SET_THP_DISABLE not supported");

        if (prctl(PR_GET_THP_DISABLE, NULL, NULL, NULL, NULL) != 3)
                return log_error_errno(errno,
                        "PR_THP_DISABLE_EXCEPT_ADVISED flag for PR_SET_THP_DISABLE is not set: %m");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
