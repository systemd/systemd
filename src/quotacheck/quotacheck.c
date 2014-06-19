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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "util.h"
#include "fileio.h"

static bool arg_skip = false;
static bool arg_force = false;

static int parse_proc_cmdline_item(const char *key, const char *value) {

        if (streq(key, "quotacheck.mode") && value) {

                if (streq(value, "auto"))
                        arg_force = arg_skip = false;
                else if (streq(value, "force"))
                        arg_force = true;
                else if (streq(value, "skip"))
                        arg_skip = true;
                else
                        log_warning("Invalid quotacheck.mode= parameter '%s'. Ignoring.", value);
        }

#ifdef HAVE_SYSV_COMPAT
        else if (streq(key, "forcequotacheck") && !value) {
                log_warning("Please use 'quotacheck.mode=force' rather than 'forcequotacheck' on the kernel command line.");
                arg_force = true;
        }
#endif

        return 0;
}

static void test_files(void) {

#ifdef HAVE_SYSV_COMPAT
        if (access("/forcequotacheck", F_OK) >= 0) {
                log_error("Please pass 'quotacheck.mode=force' on the kernel command line rather than creating /forcequotacheck on the root file system.");
                arg_force = true;
        }
#endif
}

int main(int argc, char *argv[]) {

        static const char * const cmdline[] = {
                QUOTACHECK,
                "-anug",
                NULL
        };

        pid_t pid;

        if (argc > 1) {
                log_error("This program takes no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        parse_proc_cmdline(parse_proc_cmdline_item);
        test_files();

        if (!arg_force) {
                if (arg_skip)
                        return EXIT_SUCCESS;

                if (access("/run/systemd/quotacheck", F_OK) < 0)
                        return EXIT_SUCCESS;
        }

        pid = fork();
        if (pid < 0) {
                log_error("fork(): %m");
                return EXIT_FAILURE;
        } else if (pid == 0) {
                /* Child */
                execv(cmdline[0], (char**) cmdline);
                _exit(1); /* Operational error */
        }

        return wait_for_terminate_and_warn("quotacheck", pid) >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
