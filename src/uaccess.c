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

int main(int argc, char *argv[]) {
        int r;
        const char *path, *seat;
        char *p, *active_uid = NULL;
        unsigned long ul;
        bool changed_acl = false;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc < 2 || argc > 3) {
                log_error("This program expects one or two arguments.");
                r = -EINVAL;
                goto finish;
        }

        path = argv[1];
        seat = argc >= 3 ? argv[2] : "seat0";

        p = strappend("/run/systemd/seats/", seat);
        if (!p) {
                log_error("Out of memory.");
                goto finish;
        }

        r = parse_env_file(p, NEWLINE,
                           "ACTIVE_UID", &active_uid,
                           NULL);
        free(p);

        if (r < 0) {
                if (errno == ENOENT) {
                        r = 0;
                        goto finish;
                }

                log_error("Failed to read seat data for %s: %s", seat, strerror(-r));
                goto finish;
        }

        if (active_uid) {
                r = safe_atolu(active_uid, &ul);
                if (r < 0) {
                        log_error("Failed to parse active UID value %s: %s", active_uid, strerror(-r));
                        goto finish;
                }

                r = devnode_acl(path, true, false, 0, true, (uid_t) ul);
                if (r < 0) {
                        log_error("Failed to apply ACL on %s: %s", path, strerror(-r));
                        goto finish;
                }

                changed_acl = true;
        }

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

        free(active_uid);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
