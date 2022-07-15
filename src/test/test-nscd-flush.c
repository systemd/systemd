/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "main-func.h"
#include "nscd-flush.h"
#include "strv.h"
#include "tests.h"

static int run(int argc, char *argv[]) {
        int r;

        test_setup_logging(LOG_DEBUG);

        r = nscd_flush_cache(STRV_MAKE("group", "passwd", "hosts"));
        if (r < 0)
                return log_error_errno(r, "Failed to flush NSCD cache");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
