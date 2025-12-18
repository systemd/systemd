/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "main-func.h"
#include "time-util.h"

static int run(int argc, char *argv[]) {
        usec_t usec = USEC_INFINITY;
        int r;

        if (argc > 1) {
                r = parse_sec(argv[1], &usec);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse timespan '%s': %m", argv[1]);
        }

        r = usleep_safe(usec);
        if (r < 0)
                return log_error_errno(r, "Failed to sleep: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
