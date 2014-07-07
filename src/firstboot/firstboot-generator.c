/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "util.h"
#include "mkdir.h"

static const char *arg_dest = "/tmp";

static bool is_first_boot(void) {
        const char *e;

        e = getenv("SYSTEMD_FIRST_BOOT");
        if (!e)
                return false;

        return parse_boolean(e) > 0;
}

int main(int argc, char *argv[]) {
        int r;

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

        if (is_first_boot()) {
                const char *t;

                t = strappenda(arg_dest, "/default.target.wants/systemd-firstboot.service");

                mkdir_parents(t, 0755);
                if (symlink(SYSTEM_DATA_UNIT_PATH "/systemd-firstboot.service", t) < 0 && errno != EEXIST) {
                        log_error("Failed to create firstboot service symlinks %s: %m", t);
                        r = -errno;
                        goto finish;
                }
        }

        r = 0;

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
