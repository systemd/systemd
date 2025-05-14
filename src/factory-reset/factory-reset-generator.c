/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "factory-reset.h"
#include "generator.h"
#include "log.h"
#include "special.h"

/* This generator pulls factory-reset-now.target into the initial transaction the kernel command line's
 * systemd.factor_reset= variable, or the FactoryResetRequest EFI variable say so. */

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        assert(dest_early);

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to determine factory reset mode: %m");
        if (f != FACTORY_RESET_ON) {
                log_debug("Not in factory reset mode, skipping.");
                return 0;
        }

        log_debug("Detected factory reset mode, pulling in factory-reset-now.target.");

        /* We pull this in from basic.target so that it ends up in all "regular" boot ups, but not in
         * rescue.target or even emergency.target. */
        return generator_add_symlink(dest_early, SPECIAL_BASIC_TARGET, "wants", "factory-reset-now.target");
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
