/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "env-util.h"
#include "errno-util.h"
#include "initrd-util.h"
#include "log.h"

static int saved_in_initrd = -1;

bool in_initrd(void) {
        int r;

        if (saved_in_initrd >= 0)
                return saved_in_initrd;

        /* If /etc/initrd-release exists, we're in an initrd.
         * This can be overridden by setting SYSTEMD_IN_INITRD=0|1.
         */

        r = secure_getenv_bool("SYSTEMD_IN_INITRD");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");

        if (r >= 0)
                saved_in_initrd = r > 0;
        else {
                r = RET_NERRNO(access("/etc/initrd-release", F_OK));
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to check if /etc/initrd-release exists, assuming it does not: %m");
                saved_in_initrd = r >= 0;
        }

        return saved_in_initrd;
}

void in_initrd_force(bool value) {
        saved_in_initrd = value;
}

static int saved_in_first_boot = -1;

bool in_first_boot(void) {
        int r;

        if (saved_in_first_boot >= 0)
                return saved_in_first_boot;

        /* If /run/systemd/first-boot exists, we're in first-boot mode.
         * This can be overridden by setting SYSTEMD_FIRST_BOOT=0|1.
         */

        r = secure_getenv_bool("SYSTEMD_FIRST_BOOT");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_FIRST_BOOT, ignoring: %m");

        if (r >= 0)
                saved_in_first_boot = r > 0;
        else {
                r = RET_NERRNO(access("/run/systemd/first-boot", F_OK));
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to check if /run/systemd/first-boot exists, assuming no: %m");
                saved_in_first_boot = r >= 0;
        }

        return saved_in_first_boot;
}

void in_first_boot_force(bool value) {
        saved_in_first_boot = value;
}
