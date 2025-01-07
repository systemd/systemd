/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "bitfield.h"
#include "creds-util.h"
#include "dropin.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "initrd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "recurse-dir.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "unit-file.h"
#include "unit-name.h"

static const char *arg_dest = NULL;
static char *arg_default_unit = NULL;
static char **arg_mask = NULL;
static char **arg_wants = NULL;
static bool arg_debug_shell = false;
static char *arg_debug_tty = NULL;
static char *arg_default_debug_tty = NULL;
static uint32_t arg_breakpoints = 0;

STATIC_DESTRUCTOR_REGISTER(arg_default_unit, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mask, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_wants, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_debug_tty, freep);
STATIC_DESTRUCTOR_REGISTER(arg_default_debug_tty, freep);

typedef enum BreakpointType {
        BREAKPOINT_PRE_UDEV,
        BREAKPOINT_PRE_BASIC,
        BREAKPOINT_PRE_SYSROOT_MOUNT,
        BREAKPOINT_PRE_SWITCH_ROOT,
        _BREAKPOINT_TYPE_MAX,
        _BREAKPOINT_TYPE_INVALID = -EINVAL,
} BreakpointType;

typedef enum BreakpointValidity {
        BREAKPOINT_DEFAULT   = 1 << 0,
        BREAKPOINT_IN_INITRD = 1 << 1,
        BREAKPOINT_ON_HOST   = 1 << 2,
} BreakpointValidity;

typedef struct BreakpointInfo {
        BreakpointType type;
        const char *name;
        const char *unit;
        BreakpointValidity validity;
} BreakpointInfo;

static const struct BreakpointInfo breakpoint_info_table[_BREAKPOINT_TYPE_MAX] = {
        { BREAKPOINT_PRE_UDEV,          "pre-udev",        "breakpoint-pre-udev.service",        BREAKPOINT_IN_INITRD | BREAKPOINT_ON_HOST },
        { BREAKPOINT_PRE_BASIC,         "pre-basic",       "breakpoint-pre-basic.service",       BREAKPOINT_IN_INITRD | BREAKPOINT_ON_HOST },
        { BREAKPOINT_PRE_SYSROOT_MOUNT, "pre-mount",       "breakpoint-pre-mount.service",       BREAKPOINT_IN_INITRD                      },
        { BREAKPOINT_PRE_SWITCH_ROOT,   "pre-switch-root", "breakpoint-pre-switch-root.service", BREAKPOINT_IN_INITRD | BREAKPOINT_DEFAULT },
};

static bool breakpoint_applies(const BreakpointInfo *info, int log_level) {
        assert(info);

        if (in_initrd() && !FLAGS_SET(info->validity, BREAKPOINT_IN_INITRD))
                log_full(log_level, "Breakpoint '%s' not valid in the initrd, ignoring.", info->name);
        else if (!in_initrd() && !FLAGS_SET(info->validity, BREAKPOINT_ON_HOST))
                log_full(log_level, "Breakpoint '%s' not valid on the host, ignoring.", info->name);
        else
                return true;

        return false;
}

static BreakpointType parse_breakpoint_from_string_one(const char *s) {
        assert(s);

        FOREACH_ELEMENT(i, breakpoint_info_table)
                if (streq(i->name, s))
                        return i->type;

        return _BREAKPOINT_TYPE_INVALID;
}

static int parse_breakpoint_from_string(const char *s, uint32_t *ret_breakpoints) {
        uint32_t breakpoints = 0;
        int r;

        assert(ret_breakpoints);

        /* Empty value? set default breakpoint */
        if (isempty(s)) {
                bool found_default = false;

                FOREACH_ELEMENT(i, breakpoint_info_table)
                        if (FLAGS_SET(i->validity, BREAKPOINT_DEFAULT) && breakpoint_applies(i, INT_MAX)) {
                                breakpoints |= 1 << i->type;
                                found_default = true;
                                break;
                        }

                if (!found_default)
                        log_warning("No default breakpoint defined %s, ignoring.",
                                    in_initrd() ? "in the initrd" : "on the host");
        } else
                for (;;) {
                        _cleanup_free_ char *t = NULL;
                        BreakpointType tt;

                        r = extract_first_word(&s, &t, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        tt = parse_breakpoint_from_string_one(t);
                        if (tt < 0) {
                                log_warning("Invalid breakpoint value '%s', ignoring.", t);
                                continue;
                        }

                        if (breakpoint_applies(&breakpoint_info_table[tt], LOG_WARNING))
                                breakpoints |= 1 << tt;
                }

        *ret_breakpoints = breakpoints;

        return 0;
}

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
                uint32_t breakpoints = 0;

                r = parse_breakpoint_from_string(value, &breakpoints);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse breakpoint value '%s': %m", value);

                arg_breakpoints |= breakpoints;

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

        BIT_FOREACH(i, arg_breakpoints)
                if (strv_extend(&arg_wants, breakpoint_info_table[i].unit) < 0)
                        return log_oom();

        if (get_credentials_dir(&credentials_dir) >= 0)
                RET_GATHER(r, process_unit_credentials(credentials_dir));

        if (get_encrypted_credentials_dir(&credentials_dir) >= 0)
                RET_GATHER(r, process_unit_credentials(credentials_dir));

        RET_GATHER(r, generate_mask_symlinks());
        RET_GATHER(r, generate_wants_symlinks());

        return r;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
