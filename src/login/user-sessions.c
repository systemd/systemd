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
#include "cgroup-util.h"
#include "fileio.h"

static int kill_all_users(void) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        d = opendir("/run/systemd/users");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/users: %m");
                return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *cgroup = NULL;
                char *a;
                int k;

                if (!dirent_is_file(de))
                        continue;

                a = strappenda("/run/systemd/users/", de->d_name);

                k = parse_env_file(a, NEWLINE, "CGROUP", &cgroup, NULL);
                if (k < 0) {
                        if (k != -ENOENT) {
                                log_error("Failed to read user data: %s", strerror(-k));
                                r = k;
                        }

                        continue;
                }

                if (!cgroup) {
                        log_error("User data did not contain cgroup field.");
                        r = -ENOENT;
                        continue;
                }

                k = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, cgroup, true);
                if (k < 0) {
                        log_error("Failed to kill cgroup %s: %s", cgroup, strerror(-k));
                        r = k;
                }
        }

        return r;
}

static int kill_all_sessions(void) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        d = opendir("/run/systemd/sessions");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/sessions: %m");
                return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *cgroup = NULL;
                char *a;
                int k;

                if (!dirent_is_file(de))
                        continue;

                a = strappenda("/run/systemd/sessions/", de->d_name);

                k = parse_env_file(a, NEWLINE, "CGROUP", &cgroup, NULL);
                if (k < 0) {
                        if (k != -ENOENT) {
                                log_error("Failed to read session data: %s", strerror(-k));
                                r = k;
                        }

                        continue;
                }

                if (!cgroup) {
                        log_error("Session data did not contain cgroup field.");
                        r = -ENOENT;
                        continue;
                }

                k = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, cgroup, true);
                if (k < 0) {
                        log_error("Failed to kill cgroup %s: %s", cgroup, strerror(-k));
                        r = k;
                }
        }

        return r;
}

int main(int argc, char*argv[]) {
        int ret = EXIT_FAILURE;

        if (argc != 2) {
                log_error("This program requires one argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (streq(argv[1], "start")) {
                int q = 0, r = 0;

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
                                q = -errno;
                        }
                }

                if (r < 0 || q < 0)
                        goto finish;

        } else if (streq(argv[1], "stop")) {
                int r, q;

                r = write_string_file_atomic("/run/nologin", "System is going down.");
                if (r < 0)
                        log_error("Failed to create /run/nologin: %s", strerror(-r));

                q = kill_all_users();
                if (q < 0 && r >= 0)
                        r = q;

                q = kill_all_sessions();
                if (q < 0 && r >= 0)
                        r = q;

        } else {
                log_error("Unknown verb %s.", argv[1]);
                goto finish;
        }

        ret = EXIT_SUCCESS;

finish:
        return ret;
}
