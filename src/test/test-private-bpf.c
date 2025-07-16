/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "namespace.h"
#include "tests.h"

static int intro(void) {
        int r;

        r = private_bpf_supported();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
