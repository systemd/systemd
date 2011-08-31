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
#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "unit-name.h"

const char *arg_dest = "/tmp";

static int add_symlink(const char *fservice, const char *tservice) {
        char *from = NULL, *to = NULL;
        int r;

        assert(fservice);
        assert(tservice);

        asprintf(&from, SYSTEM_DATA_UNIT_PATH "/%s", fservice);
        asprintf(&to, "%s/getty.target.wants/%s", arg_dest, tservice);

        if (!from || !to) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        mkdir_parents(to, 0755);

        r = symlink(from, to);
        if (r < 0) {
                if (errno == EEXIST)
                        /* In case console=hvc0 is passed this will very likely result in EEXIST */
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

static int add_serial_getty(const char *tty) {
        char *n;
        int r;

        assert(tty);

        log_debug("Automatically adding serial getty for /dev/%s.", tty);

        n = unit_name_replace_instance("serial-getty@.service", tty);
        if (!n) {
                log_error("Out of memory");
                return -ENOMEM;
        }

        r = add_symlink("serial-getty@.service", n);
        free(n);

        return r;
}

int main(int argc, char *argv[]) {

        static const char virtualization_consoles[] =
                "hvc0\0"
                "xvc0\0"
                "hvsi0\0";

        int r = EXIT_SUCCESS;
        char *active;
        const char *j;

        if (argc > 2) {
                log_error("This program takes one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc > 1)
            arg_dest = argv[1];

        if (detect_container(NULL) > 0) {
                log_debug("Automatically adding console shell.");

                if (add_symlink("console-shell.service", "console-shell.service") < 0)
                        r = EXIT_FAILURE;

                /* Don't add any further magic if we are in a container */
                goto finish;
        }

        if (read_one_line_file("/sys/class/tty/console/active", &active) >= 0) {
                const char *tty;

                tty = strrchr(active, ' ');
                if (tty)
                        tty ++;
                else
                        tty = active;

                /* Automatically add in a serial getty on the kernel
                 * console */
                if (tty_is_vc(tty))
                        free(active);
                else {
                        int k;

                        /* We assume that gettys on virtual terminals are
                         * started via manual configuration and do this magic
                         * only for non-VC terminals. */

                        k = add_serial_getty(tty);
                        free(active);

                        if (k < 0) {
                                r = EXIT_FAILURE;
                                goto finish;
                        }
                }
        }

        /* Automatically add in a serial getty on the first
         * virtualizer console */
        NULSTR_FOREACH(j, virtualization_consoles) {
                char *p;
                int k;

                if (asprintf(&p, "/sys/class/tty/%s", j) < 0) {
                        log_error("Out of memory");
                        r = EXIT_FAILURE;
                        goto finish;
                }

                k = access(p, F_OK);
                free(p);

                if (k < 0)
                        continue;

                k = add_serial_getty(j);
                if (k < 0) {
                        r = EXIT_FAILURE;
                        goto finish;
                }
        }

finish:
        return r;
}
