/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "test-thp-util.h"

static int intro(void) {
        int r = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);

        if (r != PR_THP_DISABLE_NOT_SET) {
                log_error("THPs disabled for the process r = %d: %m", r);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
