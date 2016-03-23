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

#include <getopt.h>

#include "alloc-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "process-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "util.h"

static char *arg_default_unit = NULL;
static const char *arg_dest = "/tmp";
static char **arg_mask = NULL;
static char **arg_wants = NULL;
static bool arg_debug_shell = false;

static int parse_proc_cmdline_item(const char *key, const char *value) {
        int r;

        assert(key);

        if (streq(key, "systemd.mask")) {

                if (!value)
                        log_error("Missing argument for systemd.mask= kernel command line parameter.");
                else {
                        char *n;

                        r = unit_name_mangle(value, UNIT_NAME_NOGLOB, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to glob unit name: %m");

                        r = strv_consume(&arg_mask, n);
                        if (r < 0)
                                return log_oom();
                }

        } else if (streq(key, "systemd.wants")) {

                if (!value)
                        log_error("Missing argument for systemd.want= kernel command line parameter.");
                else {
                        char *n;

                        r = unit_name_mangle(value, UNIT_NAME_NOGLOB, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to glob unit name: %m");

                        r = strv_consume(&arg_wants, n);
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
        } else if (streq(key, "systemd.unit")) {

                if (!value)
                        log_error("Missing argument for systemd.unit= kernel command line parameter.");
                else {
                        r = free_and_strdup(&arg_default_unit, value);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set default unit %s: %m", value);
                }
        } else if (!value) {
                const char *target;

                target = runlevel_to_target(key);
                if (target) {
                        r = free_and_strdup(&arg_default_unit, target);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set default unit %s: %m", target);
                }
        }

        return 0;
}

static int generate_mask_symlinks(void) {
        char **u;
        int r = 0;

        if (strv_isempty(arg_mask))
                return 0;

        STRV_FOREACH(u, arg_mask) {
                _cleanup_free_ char *p = NULL;

                p = strjoin(arg_dest, "/", *u, NULL);
                if (!p)
                        return log_oom();

                if (symlink("/dev/null", p) < 0)
                        r = log_error_errno(errno,
                                            "Failed to create mask symlink %s: %m",
                                            p);
        }

        return r;
}

static int generate_wants_symlinks(void) {
        char **u;
        int r = 0;

        if (strv_isempty(arg_wants))
                return 0;

        STRV_FOREACH(u, arg_wants) {
                _cleanup_free_ char *p = NULL, *f = NULL;

                p = strjoin(arg_dest, "/", arg_default_unit, ".wants/", *u, NULL);
                if (!p)
                        return log_oom();

                f = strappend(SYSTEM_DATA_UNIT_PATH "/", *u);
                if (!f)
                        return log_oom();

                mkdir_parents_label(p, 0755);

                if (symlink(f, p) < 0)
                        r = log_error_errno(errno,
                                            "Failed to create wants symlink %s: %m",
                                            p);
        }

        return r;
}

static int parse_proc_1_cmdline(void) {
        int c, r;
        unsigned proc_1_argc;
        _cleanup_free_ char *proc_1_cmdline = NULL;
        _cleanup_strv_free_ char **proc_1_argv = NULL;
        enum {
                ARG_UNIT = 0x100,
        };
        static const struct option options[] = {
                { "unit", required_argument, NULL, ARG_UNIT },
        };

        r = get_process_cmdline(1, 0, false, &proc_1_cmdline);
        if (r < 0)
                return log_error_errno(r, "Failed to get /proc/1/cmdline: %m");

        r = strv_split_extract(&proc_1_argv, proc_1_cmdline, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
        if (r < 0)
                return log_error_errno(r, "Failed to split /proc/1/cmdline: %m");

        opterr = 0;
        proc_1_argc = strv_length(proc_1_argv);
        while ((c = getopt_long(proc_1_argc, proc_1_argv, "", options, NULL)) >= 0) {
                switch (c) {
                case ARG_UNIT:
                        r = free_and_strdup(&arg_default_unit, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set default unit %s: %m", optarg);
                        break;

                case '?':
                        break;

                default:
                        assert_not_reached("Unhandled option code.");

                }
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

        r = free_and_strdup(&arg_default_unit, SPECIAL_DEFAULT_TARGET);
        if (r < 0) {
                log_error_errno(r, "Failed to set default unit %s: %m", SPECIAL_DEFAULT_TARGET);
                goto finish;
        }

        r = parse_proc_cmdline(parse_proc_cmdline_item);
        if (r == -ENOMEM)
                goto finish;
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        r = parse_proc_1_cmdline();
        if (r == -ENOMEM)
                goto finish;
        if (r < 0)
                log_warning_errno(r, "Failed to parse /proc/1/cmdline, ignoring: %m");

        if (arg_debug_shell) {
                r = strv_extend(&arg_wants, "debug-shell.service");
                if (r < 0) {
                        r = log_oom();
                        goto finish;
                }
        }

        r = generate_mask_symlinks();

        q = generate_wants_symlinks();
        if (q < 0)
                r = q;

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

}
