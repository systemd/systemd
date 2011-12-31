/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <string.h>

#include "logind-acl.h"
#include "util.h"
#include "log.h"
#include "sd-daemon.h"
#include "sd-login.h"

int main(int argc, char *argv[]) {
        int r;
        const char *path = NULL, *seat;
        bool changed_acl = false;
        uid_t uid;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc < 2 || argc > 3) {
                log_error("This program expects one or two arguments.");
                r = -EINVAL;
                goto finish;
        }

        /* Make sure we don't muck around with ACLs the system is not
         * running systemd. */
        if (!sd_booted())
                return 0;

        path = argv[1];
        seat = argc < 3 || isempty(argv[2]) ? "seat0" : argv[2];

        r = sd_seat_get_active(seat, NULL, &uid);
        if (r == -ENOENT) {
                /* No active session on this seat */
                r = 0;
                goto finish;
        } else if (r < 0) {
                log_error("Failed to determine active user on seat %s.", seat);
                goto finish;
        }

        r = devnode_acl(path, true, false, 0, true, uid);
        if (r < 0) {
                log_error("Failed to apply ACL on %s: %s", path, strerror(-r));
                goto finish;
        }

        changed_acl = true;
        r = 0;

finish:
        if (path && !changed_acl) {
                int k;
                /* Better be safe that sorry and reset ACL */

                k = devnode_acl(path, true, false, 0, false, 0);
                if (k < 0) {
                        log_error("Failed to apply ACL on %s: %s", path, strerror(-k));
                        if (r >= 0)
                                r = k;
                }
        }

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
