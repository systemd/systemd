/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "util.h"
#include "cgroup-util.h"

int main(int argc, char*argv[]) {
        int ret = EXIT_FAILURE;

        if (argc != 2) {
                log_error("This program requires one argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (streq(argv[1], "start")) {
                int q = 0, r = 0;

                if (unlink("/var/run/nologin") < 0 && errno != ENOENT) {
                        log_error("Failed to remove /var/run/nologin file: %m");
                        r = -errno;
                }

                if (unlink("/etc/nologin") < 0 && errno != ENOENT) {
                        log_error("Failed to remove /etc/nologin file: %m");
                        q = -errno;
                }

                if (r < 0 || q < 0)
                        goto finish;

        } else if (streq(argv[1], "stop")) {
                int r, q;
                char *cgroup_user_tree = NULL;

                if ((r = write_one_line_file("/var/run/nologin", "System is going down.")) < 0)
                        log_error("Failed to create /var/run/nologin: %s", strerror(-r));

                if ((q = cg_get_user_path(&cgroup_user_tree)) < 0) {
                        log_error("Failed to determine use path: %s", strerror(-q));
                        goto finish;
                }

                q = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, cgroup_user_tree, true);
                free(cgroup_user_tree);

                if (q < 0) {
                        log_error("Failed to kill sessions: %s", strerror(-q));
                        goto finish;
                }

                if (r < 0)
                        goto finish;

        } else {
                log_error("Unknown verb %s.", argv[1]);
                goto finish;
        }

        ret = EXIT_SUCCESS;

finish:
        return ret;
}
