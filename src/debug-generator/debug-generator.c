/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "creds-util.h"
#include "dropin.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "initrd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "recurse-dir.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-file.h"
#include "unit-name.h"

typedef enum BreakpointType {
        BREAKPOINT_PRE_UDEV,
        BREAKPOINT_PRE_SYSROOT_MOUNT,
        BREAKPOINT_PRE_SWITCH_ROOT,
        _BREAKPOINT_TYPE_MAX,
        _BREAKPOINT_TYPE_INVALID = -EINVAL,
} BreakpointType;

static const char *arg_dest = NULL;
static char *arg_default_unit = NULL;
static char **arg_mask = NULL;
static char **arg_wants = NULL;
static bool arg_debug_shell = false;
static char *arg_debug_tty = NULL;
static char *arg_default_debug_tty = NULL;
static BreakpointType arg_breakpoint = _BREAKPOINT_TYPE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_default_unit, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mask, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_wants, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_debug_tty, freep);
STATIC_DESTRUCTOR_REGISTER(arg_default_debug_tty, freep);

static const char* const breakpoint_type_table[_BREAKPOINT_TYPE_MAX] = {
        [BREAKPOINT_PRE_UDEV] = "pre-udev",
        [BREAKPOINT_PRE_SYSROOT_MOUNT] = "pre-mount",
        [BREAKPOINT_PRE_SWITCH_ROOT] = "pre-switch-root",
};

static BreakpointType breakpoint_type_from_string(const char *s);
static const char* breakpoint_type_to_string(BreakpointType t);

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(breakpoint_type, BreakpointType);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (streq(key, "systemd.mask")) {
                char *n;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = unit_name_mangle(value, UNIT_NAME_MANGLE_WARN, &n);
                if (r < 0)
                        return log_error_errno(r, "Failed to glob unit name: %m");

                if (strv_consume(&arg_mask, n) < 0)
                        return log_oom();

        } else if (streq(key, "systemd.wants")) {
                char *n;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = unit_name_mangle(value, UNIT_NAME_MANGLE_WARN, &n);
                if (r < 0)
                        return log_error_errno(r, "Failed to glob unit name: %m");

                if (strv_consume(&arg_wants, n) < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.debug_shell")) {

                r = value ? parse_boolean(value) : 1;
                arg_debug_shell = r != 0;
                if (r >= 0)
                        return 0;

                return free_and_strdup_warn(&arg_debug_tty, skip_dev_prefix(value));

        } else if (proc_cmdline_key_streq(key, "systemd.default_debug_tty")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_default_debug_tty, skip_dev_prefix(value));

        } else if (streq(key, "systemd.unit")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_default_unit, value);

        } else if (streq(key, "systemd.break")) {

                if (value) {
                        arg_breakpoint = breakpoint_type_from_string(value);
                        if (arg_breakpoint < 0)
                                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                         "Invalid breakpoint value '%s'",
                                                         value);
                        else if (!in_initrd() && IN_SET(arg_breakpoint,
                                                        BREAKPOINT_PRE_SYSROOT_MOUNT,
                                                        BREAKPOINT_PRE_SWITCH_ROOT)) {
                                log_warning("Breakpoint '%s' only valid in the initrd, ignoring.", value);
                                arg_breakpoint = _BREAKPOINT_TYPE_INVALID;
                        }
                } else if (in_initrd())
                        arg_breakpoint = BREAKPOINT_PRE_SWITCH_ROOT;
                else
                        log_warning("No default breakpoint defined in the main system, ignoring.");

                arg_debug_shell = arg_breakpoint != _BREAKPOINT_TYPE_INVALID;

        } else if (!value) {
                const char *target;

                target = runlevel_to_target(key);
                if (target)
                        return free_and_strdup_warn(&arg_default_unit, target);
        }

        return 0;
}

static int generate_mask_symlinks(void) {
        int r = 0;

        STRV_FOREACH(u, arg_mask) {
                _cleanup_free_ char *p = NULL;

                p = path_join(arg_dest, *u);
                if (!p)
                        return log_oom();

                if (symlink("/dev/null", p) < 0)
                        RET_GATHER(r, log_error_errno(errno, "Failed to create mask symlink '%s': %m", p));
        }

        return r;
}

static int generate_wants_symlinks(void) {
        int r = 0;

        STRV_FOREACH(u, arg_wants) {
                _cleanup_free_ char *f = NULL;
                const char *target;

                /* This should match what do_queue_default_job() in core/main.c does. */
                if (arg_default_unit)
                        target = arg_default_unit;
                else if (in_initrd())
                        target = SPECIAL_INITRD_TARGET;
                else
                        target = SPECIAL_DEFAULT_TARGET;

                f = path_join(SYSTEM_DATA_UNIT_DIR, *u);
                if (!f)
                        return log_oom();

                RET_GATHER(r, generator_add_symlink(arg_dest, target, "wants", f));
        }

        return r;
}

static int install_debug_shell_dropin(void) {
        const char *tty = arg_debug_tty ?: arg_default_debug_tty;
        int r;

        if (arg_breakpoint != _BREAKPOINT_TYPE_INVALID) {
                switch (arg_breakpoint) {
                case BREAKPOINT_PRE_UDEV:
                        r = write_drop_in_format(arg_dest, "debug-shell.service", 60, "breakpoint",
                                                 "# Automatically generated by systemd-debug-generator\n\n"
                                                 "[Unit]\n"
                                                 "Wants=systemd-journald.socket\n"
                                                 "After=systemd-journald.socket\n"
                                                 "Before=systemd-udevd.service systemd-udev-trigger.service\n"
                                                 "\n[Service]\n"
                                                 "Environment=PS1=\"%s:$PWD# \"\n"
                                                 "Type=oneshot\n"
                                                 "Restart=no\n",
                                                 breakpoint_type_to_string(arg_breakpoint));
                        break;

                case BREAKPOINT_PRE_SYSROOT_MOUNT:
                        assert(in_initrd());
                        r = write_drop_in_format(arg_dest, "debug-shell.service", 60, "breakpoint",
                                                 "# Automatically generated by systemd-debug-generator\n\n"
                                                 "[Unit]\n"
                                                 "After=sysinit.target\n"
                                                 "Before=initrd-root-fs.target sysroot.mount systemd-fsck-root.service\n"
                                                 "\n[Service]\n"
                                                 "Environment=PS1=\"%s:$PWD# \"\n"
                                                 "Type=oneshot\n"
                                                 "Restart=no\n",
                                                 breakpoint_type_to_string(arg_breakpoint));
                        break;

                case BREAKPOINT_PRE_SWITCH_ROOT:
                        assert(in_initrd());
                        r = write_drop_in_format(arg_dest, "debug-shell.service", 60, "breakpoint",
                                                 "# Automatically generated by systemd-debug-generator\n\n"
                                                 "[Unit]\n"
                                                 "Wants=remote-fs.target\n"
                                                 "After=initrd.target initrd-parse-etc.service sysroot.mount remote-fs.target\n"
                                                 "Before=initrd-cleanup.service\n"
                                                 "\n[Service]\n"
                                                 "Environment=PS1=\"%s:$PWD# \"\n"
                                                 "Type=oneshot\n"
                                                 "Restart=no\n",
                                                 breakpoint_type_to_string(arg_breakpoint));
                        break;

                default:
                        assert_not_reached();
                }

                if (r < 0)
                        return log_warning_errno(r, "Failed to write drop-in for debug-shell.service: %m");
        }

        if (!tty || path_equal(tty, skip_dev_prefix(DEBUGTTY)))
                return 0;

        r = write_drop_in_format(arg_dest, "debug-shell.service", 50, "tty",
                                 "# Automatically generated by systemd-debug-generator\n\n"
                                 "[Unit]\n"
                                 "Description=Early root shell on /dev/%s FOR DEBUGGING ONLY\n"
                                 "ConditionPathExists=\n"
                                 "\n[Service]\n"
                                 "TTYPath=/dev/%s\n",
                                 tty, tty);
        if (r < 0)
                return log_warning_errno(r, "Failed to write drop-in for debug-shell.service: %m");

        return 1;
}

static int process_unit_credentials(const char *credentials_dir) {
        _cleanup_free_ DirectoryEntries *des = NULL;
        int r;

        assert(credentials_dir);

        r = readdir_all_at(AT_FDCWD, credentials_dir, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &des);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate credentials from credentials directory '%s': %m", credentials_dir);

        FOREACH_ARRAY(i, des->entries, des->n_entries) {
                struct dirent *de = *i;
                const char *unit, *dropin;

                if (de->d_type != DT_REG)
                        continue;

                unit = startswith(de->d_name, "systemd.extra-unit.");
                dropin = startswith(de->d_name, "systemd.unit-dropin.");

                if (!unit && !dropin)
                        continue;

                _cleanup_free_ char *d = NULL;

                r = read_credential_with_decryption(de->d_name, (void**) &d, NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read credential '%s', ignoring: %m", de->d_name);
                        continue;
                }

                if (unit) {
                        _cleanup_free_ char *p = NULL;

                        if (!unit_name_is_valid(unit, UNIT_NAME_ANY)) {
                                log_warning("Invalid unit name '%s' in credential '%s', ignoring.",
                                            unit, de->d_name);
                                continue;
                        }

                        p = path_join(arg_dest, unit);
                        if (!p)
                                return log_oom();

                        r = write_string_file(p, d, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755|WRITE_STRING_FILE_LABEL);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to write unit file '%s' from credential '%s', ignoring: %m",
                                                  unit, de->d_name);
                                continue;
                        }

                        log_debug("Wrote unit file '%s' from credential '%s'", unit, de->d_name);

                } else if (dropin) {
                        _cleanup_free_ char *dropin_unit = NULL;
                        const char *tilde, *dropin_name;

                        tilde = strchrnul(dropin, '~');
                        dropin_unit = strndup(dropin, tilde - dropin);
                        if (!dropin_unit)
                                return log_oom();

                        if (!unit_name_is_valid(dropin_unit, UNIT_NAME_ANY)) {
                                log_warning("Invalid unit name '%s' in credential '%s', ignoring.",
                                            dropin_unit, de->d_name);
                                continue;
                        }

                        dropin_name = isempty(tilde) ? "50-credential" : tilde + 1;
                        if (isempty(dropin_name)) {
                                log_warning("Empty drop-in name for unit '%s' in credential '%s', ignoring.",
                                            dropin_unit, de->d_name);
                                continue;
                        }

                        r = write_drop_in(arg_dest, dropin_unit, /* level = */ UINT_MAX, dropin_name, d);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to write drop-in '%s' for unit '%s' from credential '%s', ignoring: %m",
                                                  dropin_name, dropin_unit, de->d_name);
                                continue;
                        }

                        log_debug("Wrote drop-in '%s' for unit '%s' from credential '%s'", dropin_name, dropin_unit, de->d_name);
                } else
                        assert_not_reached();
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        const char *credentials_dir;
        int r;

        assert_se(arg_dest = dest_early);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_RD_STRICT | PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (arg_debug_shell) {
                if (strv_extend(&arg_wants, "debug-shell.service") < 0)
                        return log_oom();

                RET_GATHER(r, install_debug_shell_dropin());
        }

        if (get_credentials_dir(&credentials_dir) >= 0)
                RET_GATHER(r, process_unit_credentials(credentials_dir));

        if (get_encrypted_credentials_dir(&credentials_dir) >= 0)
                RET_GATHER(r, process_unit_credentials(credentials_dir));

        RET_GATHER(r, generate_mask_symlinks());
        RET_GATHER(r, generate_wants_symlinks());

        return r;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
