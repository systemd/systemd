/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "initrd-util.h"
#include "log.h"
#include "path-util.h"

static int saved_in_initrd = -1;

bool in_initrd_root(const char *root) {
        int r;

        if (saved_in_initrd >= 0 && root == NULL)
                return saved_in_initrd;

        /* If /etc/initrd-release exists, we're in an initrd.
         * This can be overridden by setting SYSTEMD_IN_INITRD=0|1.
         */

        r = secure_getenv_bool("SYSTEMD_IN_INITRD");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");

        if (r >= 0) {
                if (root)
                        return r > 0;

                saved_in_initrd = r > 0;
        } else {
                _cleanup_free_ char *release_file = NULL;

                release_file = path_join(root, "/etc/initrd-release");
                if (!release_file)
                        return log_oom();

                r = RET_NERRNO(access(release_file, F_OK));
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to check if /etc/initrd-release exists, assuming it does not: %m");

                if (root)
                        return r >= 0;

                saved_in_initrd = r >= 0;
        }

        return saved_in_initrd;
}

bool in_initrd(void) {
        return in_initrd_root(NULL);
}

void in_initrd_force(bool value) {
        saved_in_initrd = value;
}
