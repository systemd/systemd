/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "factory-reset.h"
#include "generator.h"
#include "special.h"

/* This generator pulls systemd-bless-boot.service into the initial transaction if the "LoaderBootCountPath"
 * EFI variable is set, i.e. the system boots up with boot counting in effect, which means we should mark the
 * boot as "good" if we manage to boot up far enough. */

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        assert(dest_early);

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to determine factory reset mode: %m");
        if (f != FACTORY_RESET_ON) {
                log_debug("Not in factory reset mode, skipping.");
                return EXIT_SUCCESS;
        }

        log_debug("Detected factory reset mode, pulling in factory-reset-now.target.");

        /* We pull this in from basic.target so that it ends up in all "regular" boot ups, but not in
         * rescue.target or even emergency.target. */
        return generator_add_symlink(dest_early, SPECIAL_BASIC_TARGET, "wants", "factory-reset-now.target");
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
