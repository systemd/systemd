/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <unistd.h>

#include "fs-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "util.h"

/*
 * Implements the logic described in systemd.offline-updates(7).
 */

static const char *arg_dest = "/tmp";

static int generate_symlink(void) {
        const char *p = NULL;

        if (laccess("/system-update", F_OK) < 0) {
                if (errno == ENOENT)
                        return 0;

                log_error_errno(errno, "Failed to check for system update: %m");
                return -EINVAL;
        }

        p = strjoina(arg_dest, "/" SPECIAL_DEFAULT_TARGET);
        if (symlink(SYSTEM_DATA_UNIT_PATH "/system-update.target", p) < 0)
                return log_error_errno(errno, "Failed to create symlink %s: %m", p);

        return 1;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        assert(key);

        /* Check if a run level is specified on the kernel command line. The
         * command line has higher priority than any on-disk configuration, so
         * it'll make any symlink we create moot.
         */

        if (streq(key, "systemd.unit") && !proc_cmdline_value_missing(key, value))
                log_warning("Offline system update overriden by kernel command line systemd.unit= setting");
        else if (!value && runlevel_to_target(key))
                log_warning("Offline system update overriden by runlevel \"%s\" on the kernel command line", key);

        return 0;
}

int main(int argc, char *argv[]) {
        int r, k;

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[2];

        log_set_target(LOG_TARGET_SAFE);
        log_parse_environment();
        log_open();

        umask(0022);

        r = generate_symlink();

        if (r > 0) {
                k = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
                if (k < 0)
                        log_warning_errno(k, "Failed to parse kernel command line, ignoring: %m");
        }

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
