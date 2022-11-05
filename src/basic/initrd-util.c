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
        const char *e;
        bool lenient = false;

        if (saved_in_initrd >= 0)
                return saved_in_initrd;

        /* We have two checks here:
         *
         * 1. the flag file /etc/initrd-release must exist
         * 2. the root file system must be a memory file system
         *
         * The second check is extra paranoia, since misdetecting an
         * initrd can have bad consequences due the initrd
         * emptying when transititioning to the main systemd.
         *
         * If env var $SYSTEMD_IN_INITRD is not set or set to "auto",
         * both checks are used. If it's set to "lenient", only check
         * 1 is used. If set to a boolean value, then the boolean
         * value is returned.
         */

        e = secure_getenv("SYSTEMD_IN_INITRD");
        if (e) {
                if (streq(e, "lenient"))
                        lenient = true;
                else if (!streq(e, "auto")) {
                        r = parse_boolean(e);
                        if (r >= 0) {
                                saved_in_initrd = r > 0;
                                return saved_in_initrd;
                        }
                        log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");
                }
        }

        if (!lenient) {
                r = path_is_temporary_fs("/");
                if (r < 0)
                        log_debug_errno(r, "Couldn't determine if / is a temporary file system: %m");

                saved_in_initrd = r > 0;
        }

        r = access("/etc/initrd-release", F_OK);
        if (r >= 0) {
                if (saved_in_initrd == 0)
                        log_debug("/etc/initrd-release exists, but it's not an initrd.");
                else
                        saved_in_initrd = 1;
        } else {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to test if /etc/initrd-release exists: %m");
                saved_in_initrd = 0;
        }

        return saved_in_initrd;
}

void in_initrd_force(bool value) {
        saved_in_initrd = value;
}
