/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "efi-loader.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "special.h"
#include "string-util.h"
#include "virt.h"

/* This generator pulls systemd-bless-boot.service into the initial transaction if the "LoaderBootCountPath"
 * EFI variable is set, i.e. the system boots up with boot counting in effect, which means we should mark the
 * boot as "good" if we manage to boot up far enough. */

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        assert(dest_early);

        if (in_initrd()) {
                log_debug("Skipping generator, running in the initrd.");
                return EXIT_SUCCESS;
        }

        if (detect_container() > 0) {
                log_debug("Skipping generator, running in a container.");
                return 0;
        }

        if (!is_efi_boot()) {
                log_debug("Skipping generator, not an EFI boot.");
                return 0;
        }

        if (access(EFIVAR_PATH(EFI_LOADER_VARIABLE_STR("LoaderBootCountPath")), F_OK) < 0) {
                if (errno == ENOENT) {
                        log_debug_errno(errno, "Skipping generator, not booted with boot counting in effect.");
                        return 0;
                }

                return log_error_errno(errno, "Failed to check if LoaderBootCountPath EFI variable exists: %m");
        }

        /* We pull this in from basic.target so that it ends up in all "regular" boot ups, but not in
         * rescue.target or even emergency.target. */
        return generator_add_symlink(dest_early, SPECIAL_BASIC_TARGET, "wants", "systemd-bless-boot.service");
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
