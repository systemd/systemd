/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2011 Michal Schmidt

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
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "mkdir.h"

#if defined(TARGET_FEDORA) || defined(TARGET_MANDRIVA) || defined(TARGET_MAGEIA)
#define SCRIPT_PATH "/etc/rc.d/rc.local"
#elif defined(TARGET_SUSE)
#define SCRIPT_PATH "/etc/init.d/boot.local"
#endif

const char *arg_dest = "/tmp";

static int add_symlink(const char *service) {
        char *from = NULL, *to = NULL;
        int r;

        assert(service);

        asprintf(&from, SYSTEM_DATA_UNIT_PATH "/%s", service);
        asprintf(&to, "%s/multi-user.target.wants/%s", arg_dest, service);

        if (!from || !to) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        mkdir_parents(to, 0755);

        r = symlink(from, to);
        if (r < 0) {
                if (errno == EEXIST)
                        r = 0;
                else {
                        log_error("Failed to create symlink from %s to %s: %m", from, to);
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

        if (argc > 2) {
                log_error("This program takes one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc > 1)
                arg_dest = argv[1];

        if (file_is_executable(SCRIPT_PATH)) {
                log_debug("Automatically adding rc-local.service.");

                if (add_symlink("rc-local.service") < 0)
                        r = EXIT_FAILURE;

        }

        return r;
}
