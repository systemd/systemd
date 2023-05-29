/* SPDX-License-Identifier: LGPL-1.1-or-later */

#include "log.h"
#include "main-func.h"
#include "sleep-config.h"

static int run(int argc, char *argv[]) {
    int r;

    log_parse_environment();
    log_open();

    r = battery_is_discharging_and_low();
    if (r < 0)
        return log_error_errno(r, "Failed to check battery status: %m");

    if (r > 0)
        log_emergency("Battery level critically low. Halting boot process.");

    return r == 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
