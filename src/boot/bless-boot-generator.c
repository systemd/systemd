/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "efi-loader.h"
#include "generator.h"
#include "log.h"
#include "mkdir.h"
#include "special.h"
#include "string-util.h"
#include "virt.h"

/* This generator pulls systemd-bless-boot.service into the initial transaction if the "LoaderBootCountPath"
 * EFI variable is set, i.e. the system boots up with boot counting in effect, which means we should mark the
 * boot as "good" if we manage to boot up far enough. */

static int run(const char *dest, const char *dest_early, const char *dest_late) {

        if (in_initrd() > 0) {
                log_debug("Skipping generator, running in the initrd.");
                return 0;
        }

        if (detect_container() > 0) {
                log_debug("Skipping generator, running in a container.");
                return 0;
        }

        if (!is_efi_boot()) {
                log_debug("Skipping generator, not an EFI boot.");
                return 0;
        }

        if (access(EFIVAR_PATH(EFI_LOADER_VARIABLE(LoaderBootCountPath)), F_OK) < 0) {

                if (errno == ENOENT) {
                        log_debug_errno(errno, "Skipping generator, not booted with boot counting in effect.");
                        return 0;
                }

                return log_error_errno(errno, "Failed to check if LoaderBootCountPath EFI variable exists: %m");
        }

        /* We pull this in from basic.target so that it ends up in all "regular" boot ups, but not in
         * rescue.target or even emergency.target. */
        const char *p = strjoina(dest_early, "/" SPECIAL_BASIC_TARGET ".wants/systemd-bless-boot.service");
        (void) mkdir_parents(p, 0755);
        if (symlink(SYSTEM_DATA_UNIT_DIR "/systemd-bless-boot.service", p) < 0)
                return log_error_errno(errno, "Failed to create symlink '%s': %m", p);

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
