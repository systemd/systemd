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
#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "mkdir.h"
#include "unit-name.h"
#include "virt.h"
#include "fileio.h"

static const char *arg_dest = "/tmp";

static int add_symlink(const char *fservice, const char *tservice) {
        _cleanup_free_ char *from = NULL, *to = NULL;
        int r;

        assert(fservice);
        assert(tservice);

        from = strappend(SYSTEM_DATA_UNIT_PATH "/", fservice);
        if (!from)
                return log_oom();

        to = strjoin(arg_dest,"/getty.target.wants/", tservice, NULL);
        if (!to)
                return log_oom();

        mkdir_parents_label(to, 0755);

        r = symlink(from, to);
        if (r < 0) {
                if (errno == EEXIST)
                        /* In case console=hvc0 is passed this will very likely result in EEXIST */
                        return 0;
                else {
                        log_error("Failed to create symlink %s: %m", to);
                        return -errno;
                }
        }

        return 0;
}

static int add_serial_getty(const char *tty) {
        _cleanup_free_ char *n = NULL;

        assert(tty);

        log_debug("Automatically adding serial getty for /dev/%s.", tty);

        n = unit_name_replace_instance("serial-getty@.service", tty);
        if (!n)
                return log_oom();

        return add_symlink("serial-getty@.service", n);
}

int main(int argc, char *argv[]) {

        static const char virtualization_consoles[] =
                "hvc0\0"
                "xvc0\0"
                "hvsi0\0";

        _cleanup_free_ char *active = NULL;
        const char *j;

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

        if (detect_container(NULL) > 0) {
                log_debug("Automatically adding console shell.");

                if (add_symlink("console-getty.service", "console-getty.service") < 0)
                        return EXIT_FAILURE;

                /* Don't add any further magic if we are in a container */
                return EXIT_SUCCESS;
        }

        if (read_one_line_file("/sys/class/tty/console/active", &active) >= 0) {
                char *w, *state;
                size_t l;

                /* Automatically add in a serial getty on all active
                 * kernel consoles */
                FOREACH_WORD(w, l, active, state) {
                        _cleanup_free_ char *tty = NULL;

                        tty = strndup(w, l);
                        if (!tty) {
                                log_oom();
                                return EXIT_FAILURE;
                        }

                        if (isempty(tty) || tty_is_vc(tty))
                                continue;

                        /* We assume that gettys on virtual terminals are
                         * started via manual configuration and do this magic
                         * only for non-VC terminals. */

                        if (add_serial_getty(tty) < 0)
                                return EXIT_FAILURE;
                }
        }

        /* Automatically add in a serial getty on the first
         * virtualizer console */
        NULSTR_FOREACH(j, virtualization_consoles) {
                _cleanup_free_ char *p = NULL;

                p = strappend("/sys/class/tty/", j);
                if (!p) {
                        log_oom();
                        return EXIT_FAILURE;
                }

                if (access(p, F_OK) < 0)
                        continue;

                if (add_serial_getty(j) < 0)
                        return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
