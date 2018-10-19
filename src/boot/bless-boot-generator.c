/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "efivars.h"
#include "log.h"
#include "mkdir.h"
#include "special.h"
#include "string-util.h"
#include "util.h"
#include "virt.h"

/* This generator pulls systemd-bless-boot.service into the initial transaction if the "LoaderBootCountPath" EFI
 * variable is set, i.e. the system boots up with boot counting in effect, which means we should mark the boot as
 * "good" if we manage to boot up far enough. */

static const char *arg_dest = "/tmp";

int main(int argc, char *argv[]) {
        const char *p;

        log_set_prohibit_ipc(true);
        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[2];

        if (in_initrd() > 0) {
                log_debug("Skipping generator, running in the initrd.");
                return EXIT_SUCCESS;
        }

        if (detect_container() > 0) {
                log_debug("Skipping generator, running in a container.");
                return EXIT_SUCCESS;
        }

        if (!is_efi_boot()) {
                log_debug("Skipping generator, not an EFI boot.");
                return EXIT_SUCCESS;
        }

        if (access("/sys/firmware/efi/efivars/LoaderBootCountPath-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f", F_OK) < 0) {

                if (errno == ENOENT) {
                        log_debug_errno(errno, "Skipping generator, not booted with boot counting in effect.");
                        return EXIT_SUCCESS;
                }

                log_error_errno(errno, "Failed to check if LoaderBootCountPath EFI variable exists: %m");
                return EXIT_FAILURE;
        }

        /* We pull this in from basic.target so that it ends up in all "regular" boot ups, but not in rescue.target or
         * even emergency.target. */
        p = strjoina(arg_dest, "/" SPECIAL_BASIC_TARGET ".wants/systemd-bless-boot.service");
        (void) mkdir_parents(p, 0755);
        if (symlink(SYSTEM_DATA_UNIT_PATH "/systemd-bless-boot.service", p) < 0) {
                log_error_errno(errno, "Failed to create symlink '%s': %m", p);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
