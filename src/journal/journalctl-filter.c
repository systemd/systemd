/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "chase.h"
#include "devnum-util.h"
#include "fileio.h"
#include "glob-util.h"
#include "journal-internal.h"
#include "journalctl.h"
#include "journalctl-filter.h"
#include "journalctl-util.h"
#include "logs-show.h"
#include "missing_sched.h"
#include "path-util.h"
#include "unit-name.h"

static int add_invocation(sd_journal *j) {
        int r;

        assert(j);

        if (!arg_invocation)
                return 0;

        assert(!sd_id128_is_null(arg_invocation_id));

        r = add_matches_for_invocation_id(j, arg_invocation_id);
        if (r < 0)
                return r;

        return sd_journal_add_conjunction(j);
}

static int add_boot(sd_journal *j) {
        int r;

        assert(j);

        if (!arg_boot)
                return 0;

        assert(!sd_id128_is_null(arg_boot_id));

        r = add_match_boot_id(j, arg_boot_id);
        if (r < 0)
                return r;

        return sd_journal_add_conjunction(j);
}

static int add_dmesg(sd_journal *j) {
        int r;

        assert(j);

        if (!arg_dmesg)
                return 0;

        r = sd_journal_add_match(j, "_TRANSPORT=kernel", SIZE_MAX);
        if (r < 0)
                return r;

        return sd_journal_add_conjunction(j);
}

static int add_units(sd_journal *j) {
        _cleanup_strv_free_ char **patterns = NULL;
        bool added = false;
        MatchUnitFlag flags = MATCH_UNIT_ALL;
        int r;

        assert(j);

        if (strv_isempty(arg_system_units) && strv_isempty(arg_user_units))
                return 0;

        /* When --directory/-D, --root, --file/-i, or --machine/-M is specified, the opened journal file may
         * be external, and the uid of the systemd-coredump user that generates the coredump entries may be
         * different from the one in the current host. Let's relax the filter condition in such cases. */
        if (arg_directory || arg_root || arg_file_stdin || arg_file || arg_machine)
                flags &= ~MATCH_UNIT_COREDUMP_UID;

        STRV_FOREACH(i, arg_system_units) {
                _cleanup_free_ char *u = NULL;

                r = unit_name_mangle(*i, UNIT_NAME_MANGLE_GLOB | (arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN), &u);
                if (r < 0)
                        return r;

                if (string_is_glob(u)) {
                        r = strv_consume(&patterns, TAKE_PTR(u));
                        if (r < 0)
                                return r;
                } else {
                        r = add_matches_for_unit_full(j, flags, u);
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        added = true;
                }
        }

        if (!strv_isempty(patterns)) {
                _cleanup_set_free_ Set *units = NULL;
                char *u;

                r = get_possible_units(j, SYSTEM_UNITS_FULL, patterns, &units);
                if (r < 0)
                        return r;

                SET_FOREACH(u, units) {
                        r = add_matches_for_unit_full(j, flags, u);
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        added = true;
                }
        }

        patterns = strv_free(patterns);

        STRV_FOREACH(i, arg_user_units) {
                _cleanup_free_ char *u = NULL;

                r = unit_name_mangle(*i, UNIT_NAME_MANGLE_GLOB | (arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN), &u);
                if (r < 0)
                        return r;

                if (string_is_glob(u)) {
                        r = strv_consume(&patterns, TAKE_PTR(u));
                        if (r < 0)
                                return r;
                } else {
                        r = add_matches_for_user_unit_full(j, flags, u);
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        added = true;
                }
        }

        if (!strv_isempty(patterns)) {
                _cleanup_set_free_ Set *units = NULL;
                char *u;

                r = get_possible_units(j, USER_UNITS_FULL, patterns, &units);
                if (r < 0)
                        return r;

                SET_FOREACH(u, units) {
                        r = add_matches_for_user_unit_full(j, flags, u);
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        added = true;
                }
        }

        /* Complain if the user request matches but nothing whatsoever was found, since otherwise everything
         * would be matched. */
        if (!added)
                return -ENODATA;

        return sd_journal_add_conjunction(j);
}

static int add_syslog_identifier(sd_journal *j) {
        int r;

        assert(j);

        if (strv_isempty(arg_syslog_identifier))
                return 0;

        STRV_FOREACH(i, arg_syslog_identifier) {
                r = journal_add_match_pair(j, "SYSLOG_IDENTIFIER", *i);
                if (r < 0)
                        return r;
                r = sd_journal_add_disjunction(j);
                if (r < 0)
                        return r;
        }

        return sd_journal_add_conjunction(j);
}

static int add_exclude_identifier(sd_journal *j) {
        _cleanup_set_free_ Set *excludes = NULL;
        int r;

        assert(j);

        r = set_put_strdupv(&excludes, arg_exclude_identifier);
        if (r < 0)
                return r;

        return set_free_and_replace(j->exclude_syslog_identifiers, excludes);
}

static int add_priorities(sd_journal *j) {
        int r;

        assert(j);

        if (arg_priorities == 0)
                return 0;

        for (int i = LOG_EMERG; i <= LOG_DEBUG; i++)
                if (arg_priorities & (1 << i)) {
                        r = journal_add_matchf(j, "PRIORITY=%d", i);
                        if (r < 0)
                                return r;
                }

        return sd_journal_add_conjunction(j);
}

static int add_facilities(sd_journal *j) {
        int r;

        assert(j);

        if (set_isempty(arg_facilities))
                return 0;

        void *p;
        SET_FOREACH(p, arg_facilities) {
                r = journal_add_matchf(j, "SYSLOG_FACILITY=%d", PTR_TO_INT(p));
                if (r < 0)
                        return r;
        }

        return sd_journal_add_conjunction(j);
}

static int add_matches_for_executable(sd_journal *j, const char *path) {
        _cleanup_free_ char *interpreter = NULL;
        int r;

        assert(j);
        assert(path);

        if (script_get_shebang_interpreter(path, &interpreter) >= 0) {
                _cleanup_free_ char *comm = NULL;

                r = path_extract_filename(path, &comm);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename of '%s': %m", path);

                r = journal_add_match_pair(j, "_COMM", strshorten(comm, TASK_COMM_LEN-1));
                if (r < 0)
                        return log_error_errno(r, "Failed to add match: %m");

                /* Append _EXE only if the interpreter is not a link. Otherwise, it might be outdated often. */
                if (is_symlink(interpreter) > 0)
                        return 0;

                path = interpreter;
        }

        r = journal_add_match_pair(j, "_EXE", path);
        if (r < 0)
                return log_error_errno(r, "Failed to add match: %m");

        return 0;
}

static int add_matches_for_device(sd_journal *j, const char *devpath) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        int r;

        assert(j);
        assert(devpath);

        r = sd_device_new_from_devname(&device, devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to get device '%s': %m", devpath);

        for (sd_device *d = device; d; ) {
                const char *subsys, *sysname;

                r = sd_device_get_subsystem(d, &subsys);
                if (r < 0)
                        goto get_parent;

                r = sd_device_get_sysname(d, &sysname);
                if (r < 0)
                        goto get_parent;

                r = journal_add_matchf(j, "_KERNEL_DEVICE=+%s:%s", subsys, sysname);
                if (r < 0)
                        return log_error_errno(r, "Failed to add match: %m");

                dev_t devnum;
                if (sd_device_get_devnum(d, &devnum) >= 0) {
                        r = journal_add_matchf(j, "_KERNEL_DEVICE=%c" DEVNUM_FORMAT_STR,
                                               streq(subsys, "block") ? 'b' : 'c',
                                               DEVNUM_FORMAT_VAL(devnum));
                        if (r < 0)
                                return log_error_errno(r, "Failed to add match: %m");
                }

get_parent:
                if (sd_device_get_parent(d, &d) < 0)
                        break;
        }

        return add_match_boot_id(j, SD_ID128_NULL);
}

static int add_matches_for_path(sd_journal *j, const char *path) {
        _cleanup_free_ char *p = NULL;
        struct stat st;
        int r;

        assert(j);
        assert(path);

        if (arg_root || arg_machine)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "An extra path in match filter is currently not supported with --root, --image, or -M/--machine.");

        r = chase_and_stat(path, NULL, 0, &p, &st);
        if (r < 0)
                return log_error_errno(r, "Couldn't canonicalize path '%s': %m", path);

        if (S_ISREG(st.st_mode) && (0111 & st.st_mode))
                return add_matches_for_executable(j, p);

        if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
                return add_matches_for_device(j, p);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File is neither a device node nor executable: %s", p);
}

static int add_matches(sd_journal *j, char **args) {
        bool have_term = false;
        int r;

        assert(j);

        if (strv_isempty(args))
                return 0;

        STRV_FOREACH(i, args)
                if (streq(*i, "+")) {
                        if (!have_term)
                                break;

                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add disjunction: %m");

                        have_term = false;

                } else if (path_is_absolute(*i)) {
                        r = add_matches_for_path(j, *i);
                        if (r < 0)
                                return r;
                        have_term = true;

                } else {
                        r = sd_journal_add_match(j, *i, SIZE_MAX);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add match '%s': %m", *i);
                        have_term = true;
                }

        if (!have_term)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "\"+\" can only be used between terms.");

        return 0;
}

int add_filters(sd_journal *j, char **matches) {
        int r;

        assert(j);

        /* First, search boot or invocation ID, as that may set and flush matches and seek journal. */
        r = journal_acquire_boot(j);
        if (r < 0)
                return r;

        r = journal_acquire_invocation(j);
        if (r < 0)
                return r;

        /* Clear unexpected matches for safety. */
        sd_journal_flush_matches(j);

        /* Then, add filters in the below. */
        if (arg_invocation) {
                /* If an invocation ID is found, then it is not necessary to add matches for boot and units. */
                r = add_invocation(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to add filter for invocation: %m");
        } else {
                r = add_boot(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to add filter for boot: %m");

                r = add_units(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to add filter for units: %m");
        }

        r = add_dmesg(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add filter for dmesg: %m");

        r = add_syslog_identifier(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add filter for syslog identifiers: %m");

        r = add_exclude_identifier(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add exclude filter for syslog identifiers: %m");

        r = add_priorities(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add filter for priorities: %m");

        r = add_facilities(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add filter for facilities: %m");

        r = add_matches(j, matches);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *filter = NULL;

                filter = journal_make_match_string(j);
                if (!filter)
                        return log_oom();

                log_debug("Journal filter: %s", filter);
        }

        return 0;
}
