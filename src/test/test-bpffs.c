/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "mountpoint-util.h"
#include "tests.h"

static int intro(void) {
        return fsconfig_bpffs_supported() ? EXIT_SUCCESS : EXIT_FAILURE;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
