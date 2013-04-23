/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2011 Michal Schmidt

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
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "mkdir.h"

#ifndef RC_LOCAL_SCRIPT_PATH_START
#define RC_LOCAL_SCRIPT_PATH_START "/etc/rc.d/rc.local"
#endif

#ifndef RC_LOCAL_SCRIPT_PATH_STOP
#define RC_LOCAL_SCRIPT_PATH_STOP "/sbin/halt.local"
#endif

const char *arg_dest = "/tmp";

static int add_symlink(const char *service, const char *where) {
        char *from = NULL, *to = NULL;
        int r;

        assert(service);

        asprintf(&from, SYSTEM_DATA_UNIT_PATH "/%s", service);
        asprintf(&to, "%s/%s.wants/%s", arg_dest, where, service);

        if (!from || !to) {
                r = log_oom();
                goto finish;
        }

        mkdir_parents_label(to, 0755);

        r = symlink(from, to);
        if (r < 0) {
                if (errno == EEXIST)
                        r = 0;
                else {
                        log_error("Failed to create symlink %s: %m", to);
                        r = -errno;
                }
        }

finish:
        free(from);
        free(to);

        return r;
}

static bool file_is_executable(const char *f) {
        struct stat st;

        if (stat(f, &st) < 0)
                return false;

        return S_ISREG(st.st_mode) && (st.st_mode & 0111);
}

int main(int argc, char *argv[]) {
        int r = EXIT_SUCCESS;

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[1];

        log_set_target(LOG_TARGET_SAFE);
        log_parse_environment();
        log_open();

        umask(0022);

        if (file_is_executable(RC_LOCAL_SCRIPT_PATH_START)) {
                log_debug("Automatically adding rc-local.service.");

                if (add_symlink("rc-local.service", "multi-user.target") < 0)
                        r = EXIT_FAILURE;
        }

        if (file_is_executable(RC_LOCAL_SCRIPT_PATH_STOP)) {
                log_debug("Automatically adding halt-local.service.");

                if (add_symlink("halt-local.service", "final.target") < 0)
                        r = EXIT_FAILURE;
        }

        return r;
}
