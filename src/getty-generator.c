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

        asprintf(&from, SYSTEM_DATA_UNIT_PATH "/%s", fservice);
        asprintf(&to, "%s/getty.target.wants/%s", arg_dest, tservice);

        if (!from || !to) {
                log_error("Out of memory");
                r = -ENOMEM;
                goto finish;
        }

        mkdir_parents(to, 0755);

        if ((r = symlink(from, to)) < 0) {
                log_error("Failed to create symlink from %s to %s: %m", from, to);
                r = -errno;
        }

finish:

        free(from);
        free(to);

        return r;
}

int main(int argc, char *argv[]) {
        int r = EXIT_SUCCESS;
        char *active;

        if (argc > 2) {
                log_error("This program takes one or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
            arg_dest = argv[1];

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        umask(0022);

        if (detect_container(NULL) > 0) {
                log_debug("Automatically adding console shell.");

                if (add_symlink("console-shell.service", "console-shell.service") < 0)
                        r = EXIT_FAILURE;

                /* Don't add any further magic if we are in a container */
                goto finish;
        }

        if (read_one_line_file("/sys/class/tty/console/active", &active) >= 0) {
                const char *tty;

                if ((tty = strrchr(active, ' ')))
                        tty ++;
                else
                        tty = active;

                /* Automatically add in a serial getty on the kernel
                 * console */
                if (!tty_is_vc(tty)) {
                        char *n;

                        /* We assume that gettys on virtual terminals are
                         * started via manual configuration and do this magic
                         * only for non-VC terminals. */

                        log_debug("Automatically adding serial getty for /dev/%s.", tty);

                        if (!(n = unit_name_replace_instance("serial-getty@.service", tty)) ||
                            add_symlink("serial-getty@.service", n) < 0)
                                r = EXIT_FAILURE;

                        free(n);
                }

                free(active);
        }

        /* Automatically add in a serial getty on the first
         * virtualizer console */
        if (access("/sys/class/tty/hvc0", F_OK) == 0) {
                log_debug("Automatically adding serial getty for hvc0.");

                if (add_symlink("serial-getty@.service", "serial-getty@hvc0.service") < 0)
                        r = EXIT_FAILURE;

        }

        if (access("/sys/class/tty/xvc0", F_OK) == 0) {
                log_debug("Automatically adding serial getty for xvc0.");

                if (add_symlink("serial-getty@.service", "serial-getty@xvc0.service") < 0)
                        r = EXIT_FAILURE;
        }

finish:
        return r;
}
