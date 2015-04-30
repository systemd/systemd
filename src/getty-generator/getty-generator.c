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
#include <fcntl.h>

#include "log.h"
#include "util.h"
#include "mkdir.h"
#include "unit-name.h"
#include "virt.h"
#include "fileio.h"
#include "path-util.h"
#include "process-util.h"
#include "terminal-util.h"

static const char *arg_dest = "/tmp";

static int add_symlink(const char *fservice, const char *tservice) {
        char *from, *to;
        int r;

        assert(fservice);
        assert(tservice);

        from = strjoina(SYSTEM_DATA_UNIT_PATH "/", fservice);
        to = strjoina(arg_dest, "/getty.target.wants/", tservice);

        mkdir_parents_label(to, 0755);

        r = symlink(from, to);
        if (r < 0) {
                /* In case console=hvc0 is passed this will very likely result in EEXIST */
                if (errno == EEXIST)
                        return 0;

                return log_error_errno(errno, "Failed to create symlink %s: %m", to);
        }

        return 0;
}

static int add_serial_getty(const char *tty) {
        _cleanup_free_ char *n = NULL;
        int r;

        assert(tty);

        log_debug("Automatically adding serial getty for /dev/%s.", tty);

        r = unit_name_from_path_instance("serial-getty", tty, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate service name: %m");

        return add_symlink("serial-getty@.service", n);
}

static int add_container_getty(const char *tty) {
        _cleanup_free_ char *n = NULL;
        int r;

        assert(tty);

        log_debug("Automatically adding container getty for /dev/pts/%s.", tty);

        r = unit_name_from_path_instance("container-getty", tty, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate service name: %m");

        return add_symlink("container-getty@.service", n);
}

static int verify_tty(const char *name) {
        _cleanup_close_ int fd = -1;
        const char *p;

        /* Some TTYs are weird and have been enumerated but don't work
         * when you try to use them, such as classic ttyS0 and
         * friends. Let's check that and open the device and run
         * isatty() on it. */

        p = strjoina("/dev/", name);

        /* O_NONBLOCK is essential here, to make sure we don't wait
         * for DCD */
        fd = open(p, O_RDWR|O_NONBLOCK|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        errno = 0;
        if (isatty(fd) <= 0)
                return errno ? -errno : -EIO;

        return 0;
}

int main(int argc, char *argv[]) {

        static const char virtualization_consoles[] =
                "hvc0\0"
                "xvc0\0"
                "hvsi0\0"
                "sclp_line0\0"
                "ttysclp0\0"
                "3270!tty1\0";

        _cleanup_free_ char *active = NULL;
        const char *j;
        int r;

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
                _cleanup_free_ char *container_ttys = NULL;

                log_debug("Automatically adding console shell.");

                if (add_symlink("console-getty.service", "console-getty.service") < 0)
                        return EXIT_FAILURE;

                /* When $container_ttys is set for PID 1, spawn
                 * gettys on all ptys named therein. Note that despite
                 * the variable name we only support ptys here. */

                r = getenv_for_pid(1, "container_ttys", &container_ttys);
                if (r > 0) {
                        const char *word, *state;
                        size_t l;

                        FOREACH_WORD(word, l, container_ttys, state) {
                                const char *t;
                                char tty[l + 1];

                                memcpy(tty, word, l);
                                tty[l] = 0;

                                /* First strip off /dev/ if it is specified */
                                t = path_startswith(tty, "/dev/");
                                if (!t)
                                        t = tty;

                                /* Then, make sure it's actually a pty */
                                t = path_startswith(t, "pts/");
                                if (!t)
                                        continue;

                                if (add_container_getty(t) < 0)
                                        return EXIT_FAILURE;
                        }
                }

                /* Don't add any further magic if we are in a container */
                return EXIT_SUCCESS;
        }

        if (read_one_line_file("/sys/class/tty/console/active", &active) >= 0) {
                const char *word, *state;
                size_t l;

                /* Automatically add in a serial getty on all active
                 * kernel consoles */
                FOREACH_WORD(word, l, active, state) {
                        _cleanup_free_ char *tty = NULL;

                        tty = strndup(word, l);
                        if (!tty) {
                                log_oom();
                                return EXIT_FAILURE;
                        }

                        if (isempty(tty) || tty_is_vc(tty))
                                continue;

                        if (verify_tty(tty) < 0)
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
                char *p;

                p = strjoina("/sys/class/tty/", j);
                if (access(p, F_OK) < 0)
                        continue;

                if (add_serial_getty(j) < 0)
                        return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
