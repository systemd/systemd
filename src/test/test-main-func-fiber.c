/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "main-func.h"
#include "tests.h"

static int run(int argc, char *argv[]) {
        ASSERT_GE(argc, 1);
        ASSERT_NOT_NULL(argv);
        ASSERT_NOT_NULL(argv[0]);
        ASSERT_NULL(argv[argc]);

        /* A positive result means success, so this has to exit zero. */
        return 23;
}

DEFINE_MAIN_FUNCTION_FIBER(run);
