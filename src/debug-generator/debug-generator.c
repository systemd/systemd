/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "mkdir.h"
#include "parse-util.h"
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

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (streq(key, "systemd.mask")) {
                char *n;

                if (in_initrd())
                        return 0;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = unit_name_mangle(value, UNIT_NAME_MANGLE_WARN, &n);
                if (r < 0)
                        return log_error_errno(r, "Failed to glob unit name: %m");

                r = strv_consume(&arg_mask, n);
                if (r < 0)
                        return log_oom();

        } else if (streq(key, "systemd.wants")) {
                char *n;

                if (in_initrd())
                        return 0;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = unit_name_mangle(value, UNIT_NAME_MANGLE_WARN, &n);
                if (r < 0)
                        return log_error_errno(r, "Failed to glob unit name: %m");

                r = strv_consume(&arg_wants, n);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.debug_shell")) {

                if (value) {
                        r = parse_boolean(value);
                        if (r < 0)
                                log_error("Failed to parse systemd.debug_shell= argument '%s', ignoring.", value);
                        else
                                arg_debug_shell = r;
                } else
                        arg_debug_shell = true;

        } else if (streq(key, "systemd.unit")) {

                if (in_initrd())
                        return 0;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_default_unit, value);
                if (r < 0)
                        return log_error_errno(r, "Failed to set default unit %s: %m", value);

        } else if (!value) {
                const char *target;

                if (in_initrd())
                        return 0;

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

                p = strjoin(arg_dest, "/", *u);
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
                const char *target = arg_default_unit ?: SPECIAL_DEFAULT_TARGET;

                p = strjoin(arg_dest, "/", target, ".wants/", *u);
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

int main(int argc, char *argv[]) {
        int r, q;

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[2];

        log_set_prohibit_ipc(true);
        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

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
        arg_default_unit = mfree(arg_default_unit);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
