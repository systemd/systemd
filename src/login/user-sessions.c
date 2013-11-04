/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "util.h"
#include "fileio.h"

int main(int argc, char*argv[]) {

        if (argc != 2) {
                log_error("This program requires one argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (streq(argv[1], "start")) {
                int r = 0;

                if (unlink("/run/nologin") < 0 && errno != ENOENT) {
                        log_error("Failed to remove /run/nologin file: %m");
                        r = -errno;
                }

                if (unlink("/etc/nologin") < 0 && errno != ENOENT) {
                        /* If the file doesn't exist and /etc simply
                         * was read-only (in which case unlink()
                         * returns EROFS even if the file doesn't
                         * exist), don't complain */

                        if (errno != EROFS || access("/etc/nologin", F_OK) >= 0) {
                                log_error("Failed to remove /etc/nologin file: %m");
                                return EXIT_FAILURE;
                        }
                }

                if (r < 0)
                        return EXIT_FAILURE;

        } else if (streq(argv[1], "stop")) {
                int r;

                r = write_string_file_atomic("/run/nologin", "System is going down.");
                if (r < 0) {
                        log_error("Failed to create /run/nologin: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

        } else {
                log_error("Unknown verb %s.", argv[1]);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
