/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include "fileio.h"
#include "fileio-label.h"
#include "fs-util.h"
#include "log.h"
#include "selinux-util.h"
#include "string-util.h"
#include "util.h"

int main(int argc, char*argv[]) {
        int r, k;

        if (argc != 2) {
                log_error("This program requires one argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        mac_selinux_init();

        if (streq(argv[1], "start")) {
                r = unlink_or_warn("/run/nologin");
                k = unlink_or_warn("/etc/nologin");
                if (k < 0 && r >= 0)
                        r = k;

        } else if (streq(argv[1], "stop"))
                r = create_shutdown_run_nologin_or_warn();
        else {
                log_error("Unknown verb '%s'.", argv[1]);
                r = -EINVAL;
        }

        mac_selinux_finish();
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
