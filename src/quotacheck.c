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
#include "virt.h"

static bool arg_skip = false;
static bool arg_force = false;

static int parse_proc_cmdline(void) {
        char *line, *w, *state;
        int r;
        size_t l;

        if (detect_container(NULL) > 0)
                return 0;

        if ((r = read_one_line_file("/proc/cmdline", &line)) < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {

                if (strneq(w, "quotacheck.mode=auto", l))
                        arg_force = arg_skip = false;
                else if (strneq(w, "quotacheck.mode=force", l))
                        arg_force = true;
                else if (strneq(w, "quotacheck.mode=skip", l))
                        arg_skip = true;
                else if (startswith(w, "quotacheck.mode"))
                        log_warning("Invalid quotacheck.mode= parameter. Ignoring.");
#if defined(TARGET_FEDORA) || defined(TARGET_MANDRIVA) || defined(TARGET_MAGEIA)
                else if (strneq(w, "forcequotacheck", l))
                        arg_force = true;
#endif
        }

        free(line);
        return 0;
}

static void test_files(void) {
#if defined(TARGET_FEDORA) || defined(TARGET_MANDRIVA) || defined(TARGET_MAGEIA)
        /* This exists only on Fedora, Mandriva or Mageia */
        if (access("/forcequotacheck", F_OK) >= 0)
                arg_force = true;
#endif
}

int main(int argc, char *argv[]) {
        static const char * const cmdline[] = {
                "/sbin/quotacheck",
                "-anug",
                NULL
        };

        int r = EXIT_FAILURE;
        pid_t pid;

        if (argc > 1) {
                log_error("This program takes no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        parse_proc_cmdline();
        test_files();

        if (!arg_force) {
                if (arg_skip)
                        return 0;

                if (access("/run/systemd/quotacheck", F_OK) < 0)
                        return 0;
        }

        if ((pid = fork()) < 0) {
                log_error("fork(): %m");
                goto finish;
        } else if (pid == 0) {
                /* Child */
                execv(cmdline[0], (char**) cmdline);
                _exit(1); /* Operational error */
        }

        r = wait_for_terminate_and_warn("quotacheck", pid) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

finish:
        return r;
}
