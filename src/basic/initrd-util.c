/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "env-util.h"
#include "initrd-util.h"
#include "parse-util.h"
#include "stat-util.h"
#include "string-util.h"

static int saved_in_initrd = -1;

bool in_initrd(void) {
        int r;

        if (saved_in_initrd >= 0)
                return saved_in_initrd;

        /* We make two checks here:
         *
         * 1. the flag file /etc/initrd-release must exist
         * 2. the root file system must be a memory file system
         *
         * The second check is extra paranoia, since misdetecting an
         * initrd can have bad consequences due the initrd
         * emptying when transititioning to the main systemd.
         */

        r = getenv_bool_secure("SYSTEMD_IN_INITRD");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");

        if (r >= 0)
                saved_in_initrd = r > 0;
        else
                saved_in_initrd = access("/etc/initrd-release", F_OK) >= 0 &&
                                  path_is_temporary_fs("/") > 0;

        return saved_in_initrd;
}

void in_initrd_force(bool value) {
        saved_in_initrd = value;
}
