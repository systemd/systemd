/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "util.h"
#include "strv.h"
#include "unit-name.h"
#include "mkdir.h"

static const char *arg_dest = "/tmp";
static char **arg_mask = NULL;
static bool arg_debug_shell = false;

static int parse_proc_cmdline_item(const char *key, const char *value) {
        int r;

        if (streq(key, "systemd.mask")) {

                if (!value)
                        log_error("Missing argument for systemd.mask= kernel command line parameter.");
                else {
                        char *n;

                        n = strdup(value);
                        if (!n)
                                return log_oom();

                        r = strv_consume(&arg_mask, n);
                        if (r < 0)
                                return log_oom();
                }
        } else if (streq(key, "systemd.debug-shell")) {

                if (value) {
                        r = parse_boolean(value);
                        if (r < 0)
                                log_error("Failed to parse systemd.debug-shell= argument '%s', ignoring.", value);
                        else
                                arg_debug_shell = r;
                } else
                        arg_debug_shell = true;
        }

        return 0;
}

static int generate_mask_symlinks(void) {
        char **u;
        int r = 0;

        if (strv_isempty(arg_mask))
                return 0;

        STRV_FOREACH(u, arg_mask) {
                _cleanup_free_ char *m = NULL, *p = NULL;

                m = unit_name_mangle(*u, MANGLE_NOGLOB);
                if (!m)
                        return log_oom();

                p = strjoin(arg_dest, "/", m, NULL);
                if (!p)
                        return log_oom();

                if (symlink("/dev/null", p) < 0) {
                        log_error("Failed to create mask symlink %s: %m", p);
                        r = -errno;
                }
        }

        return r;
}

static int generate_debug_shell_symlink(void) {
        const char *p;

        if (!arg_debug_shell)
                return 0;

        p = strappenda(arg_dest, "/default.target.wants/debug-shell.service");

        mkdir_parents_label(p, 0755);

        if (symlink(SYSTEM_DATA_UNIT_PATH "/debug-shell.service", p) < 0) {
                log_error("Failed to create %s symlink: %m", p);
                return -errno;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        int r, q;

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[2];

        log_set_target(LOG_TARGET_SAFE);
        log_parse_environment();
        log_open();

        umask(0022);

        if (parse_proc_cmdline(parse_proc_cmdline_item) < 0)
                return EXIT_FAILURE;

        r = generate_mask_symlinks();

        q = generate_debug_shell_symlink();
        if (q < 0)
                r = q;

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

}
