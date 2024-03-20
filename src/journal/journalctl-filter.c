/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "chase.h"
#include "devnum-util.h"
#include "fileio.h"
#include "glob-util.h"
#include "journal-internal.h"
#include "journalctl.h"
#include "journalctl-filter.h"
#include "logs-show.h"
#include "missing_sched.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "unit-name.h"

static int add_boot(sd_journal *j) {
        int r;

        assert(j);

        if (!arg_boot)
                return 0;

        /* Take a shortcut and use the current boot_id, which we can do very quickly.
         * We can do this only when we logs are coming from the current machine,
         * so take the slow path if log location is specified. */
        if (arg_boot_offset == 0 && sd_id128_is_null(arg_boot_id) &&
            !arg_directory && !arg_file && !arg_root)
                return add_match_this_boot(j, arg_machine);

        if (sd_id128_is_null(arg_boot_id)) {
                r = journal_find_boot_by_offset(j, arg_boot_offset, &arg_boot_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to find journal entry from the specified boot offset (%+i): %m",
                                               arg_boot_offset);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                               "No journal boot entry found from the specified boot offset (%+i).",
                                               arg_boot_offset);
        } else {
                r = journal_find_boot_by_id(j, arg_boot_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to find journal entry from the specified boot ID (%s): %m",
                                               SD_ID128_TO_STRING(arg_boot_id));
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                               "No journal boot entry found from the specified boot ID (%s).",
                                               SD_ID128_TO_STRING(arg_boot_id));
        }

        r = add_match_boot_id(j, arg_boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to add match: %m");

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add conjunction: %m");

        return 0;
}

static int add_dmesg(sd_journal *j) {
        int r;
        assert(j);

        if (!arg_dmesg)
                return 0;

        r = sd_journal_add_match(j, "_TRANSPORT=kernel",
                                 STRLEN("_TRANSPORT=kernel"));
        if (r < 0)
                return log_error_errno(r, "Failed to add match: %m");

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add conjunction: %m");

        return 0;
}

static int get_possible_units(
                sd_journal *j,
                const char *fields,
                char **patterns,
                Set **units) {

        _cleanup_set_free_free_ Set *found = NULL;
        int r;

        found = set_new(&string_hash_ops);
        if (!found)
                return -ENOMEM;

        NULSTR_FOREACH(field, fields) {
                const void *data;
                size_t size;

                r = sd_journal_query_unique(j, field);
                if (r < 0)
                        return r;

                SD_JOURNAL_FOREACH_UNIQUE(j, data, size) {
                        char *eq;
                        size_t prefix;
                        _cleanup_free_ char *u = NULL;

                        eq = memchr(data, '=', size);
                        if (eq)
                                prefix = eq - (char*) data + 1;
                        else
                                prefix = 0;

                        u = strndup((char*) data + prefix, size - prefix);
                        if (!u)
                                return -ENOMEM;

                        STRV_FOREACH(pattern, patterns)
                                if (fnmatch(*pattern, u, FNM_NOESCAPE) == 0) {
                                        log_debug("Matched %s with pattern %s=%s", u, field, *pattern);

                                        r = set_consume(found, u);
                                        u = NULL;
                                        if (r < 0 && r != -EEXIST)
                                                return r;

                                        break;
                                }
                }
        }

        *units = TAKE_PTR(found);

        return 0;
}

/* This list is supposed to return the superset of unit names
 * possibly matched by rules added with add_matches_for_unit... */
#define SYSTEM_UNITS                 \
        "_SYSTEMD_UNIT\0"            \
        "COREDUMP_UNIT\0"            \
        "UNIT\0"                     \
        "OBJECT_SYSTEMD_UNIT\0"      \
        "_SYSTEMD_SLICE\0"

/* ... and add_matches_for_user_unit */
#define USER_UNITS                   \
        "_SYSTEMD_USER_UNIT\0"       \
        "USER_UNIT\0"                \
        "COREDUMP_USER_UNIT\0"       \
        "OBJECT_SYSTEMD_USER_UNIT\0" \
        "_SYSTEMD_USER_SLICE\0"

static int add_units(sd_journal *j) {
        _cleanup_strv_free_ char **patterns = NULL;
        int r, count = 0;

        assert(j);

        STRV_FOREACH(i, arg_system_units) {
                _cleanup_free_ char *u = NULL;

                r = unit_name_mangle(*i, UNIT_NAME_MANGLE_GLOB | (arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN), &u);
                if (r < 0)
                        return r;

                if (string_is_glob(u)) {
                        r = strv_push(&patterns, u);
                        if (r < 0)
                                return r;
                        u = NULL;
                } else {
                        r = add_matches_for_unit(j, u);
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        count++;
                }
        }

        if (!strv_isempty(patterns)) {
                _cleanup_set_free_free_ Set *units = NULL;
                char *u;

                r = get_possible_units(j, SYSTEM_UNITS, patterns, &units);
                if (r < 0)
                        return r;

                SET_FOREACH(u, units) {
                        r = add_matches_for_unit(j, u);
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        count++;
                }
        }

        patterns = strv_free(patterns);

        STRV_FOREACH(i, arg_user_units) {
                _cleanup_free_ char *u = NULL;

                r = unit_name_mangle(*i, UNIT_NAME_MANGLE_GLOB | (arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN), &u);
                if (r < 0)
                        return r;

                if (string_is_glob(u)) {
                        r = strv_push(&patterns, u);
                        if (r < 0)
                                return r;
                        u = NULL;
                } else {
                        r = add_matches_for_user_unit(j, u, getuid());
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        count++;
                }
        }

        if (!strv_isempty(patterns)) {
                _cleanup_set_free_free_ Set *units = NULL;
                char *u;

                r = get_possible_units(j, USER_UNITS, patterns, &units);
                if (r < 0)
                        return r;

                SET_FOREACH(u, units) {
                        r = add_matches_for_user_unit(j, u, getuid());
                        if (r < 0)
                                return r;
                        r = sd_journal_add_disjunction(j);
                        if (r < 0)
                                return r;
                        count++;
                }
        }

        /* Complain if the user request matches but nothing whatsoever was
         * found, since otherwise everything would be matched. */
        if (!(strv_isempty(arg_system_units) && strv_isempty(arg_user_units)) && count == 0)
                return -ENODATA;

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return r;

        return 0;
}

static int add_syslog_identifier(sd_journal *j) {
        int r;

        assert(j);

        STRV_FOREACH(i, arg_syslog_identifier) {
                _cleanup_free_ char *u = NULL;

                u = strjoin("SYSLOG_IDENTIFIER=", *i);
                if (!u)
                        return -ENOMEM;
                r = sd_journal_add_match(j, u, 0);
                if (r < 0)
                        return r;
                r = sd_journal_add_disjunction(j);
                if (r < 0)
                        return r;
        }

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return r;

        return 0;
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
        char match[] = "PRIORITY=0";
        int i, r;
        assert(j);

        if (arg_priorities == 0xFF)
                return 0;

        for (i = LOG_EMERG; i <= LOG_DEBUG; i++)
                if (arg_priorities & (1 << i)) {
                        match[sizeof(match)-2] = '0' + i;

                        r = sd_journal_add_match(j, match, strlen(match));
                        if (r < 0)
                                return log_error_errno(r, "Failed to add match: %m");
                }

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add conjunction: %m");

        return 0;
}

static int add_facilities(sd_journal *j) {
        void *p;
        int r;

        SET_FOREACH(p, arg_facilities) {
                char match[STRLEN("SYSLOG_FACILITY=") + DECIMAL_STR_MAX(int)];

                xsprintf(match, "SYSLOG_FACILITY=%d", PTR_TO_INT(p));

                r = sd_journal_add_match(j, match, strlen(match));
                if (r < 0)
                        return log_error_errno(r, "Failed to add match: %m");
        }

        return 0;
}

static int add_matches_for_device(sd_journal *j, const char *devpath) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        sd_device *d = NULL;
        struct stat st;
        int r;

        assert(j);
        assert(devpath);

        if (!path_startswith(devpath, "/dev/"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Devpath does not start with /dev/");

        if (stat(devpath, &st) < 0)
                return log_error_errno(errno, "Couldn't stat file: %m");

        r = sd_device_new_from_stat_rdev(&device, &st);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from devnum " DEVNUM_FORMAT_STR ": %m", DEVNUM_FORMAT_VAL(st.st_rdev));

        for (d = device; d; ) {
                _cleanup_free_ char *match = NULL;
                const char *subsys, *sysname, *devnode;
                sd_device *parent;

                r = sd_device_get_subsystem(d, &subsys);
                if (r < 0)
                        goto get_parent;

                r = sd_device_get_sysname(d, &sysname);
                if (r < 0)
                        goto get_parent;

                match = strjoin("_KERNEL_DEVICE=+", subsys, ":", sysname);
                if (!match)
                        return log_oom();

                r = sd_journal_add_match(j, match, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to add match: %m");

                if (sd_device_get_devname(d, &devnode) >= 0) {
                        _cleanup_free_ char *match1 = NULL;

                        r = stat(devnode, &st);
                        if (r < 0)
                                return log_error_errno(r, "Failed to stat() device node \"%s\": %m", devnode);

                        r = asprintf(&match1, "_KERNEL_DEVICE=%c" DEVNUM_FORMAT_STR, S_ISBLK(st.st_mode) ? 'b' : 'c', DEVNUM_FORMAT_VAL(st.st_rdev));
                        if (r < 0)
                                return log_oom();

                        r = sd_journal_add_match(j, match1, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add match: %m");
                }

get_parent:
                if (sd_device_get_parent(d, &parent) < 0)
                        break;

                d = parent;
        }

        r = add_match_this_boot(j, arg_machine);
        if (r < 0)
                return log_error_errno(r, "Failed to add match for the current boot: %m");

        return 0;
}

static int add_matches(sd_journal *j, char **args) {
        bool have_term = false;

        assert(j);

        STRV_FOREACH(i, args) {
                int r;

                if (streq(*i, "+")) {
                        if (!have_term)
                                break;
                        r = sd_journal_add_disjunction(j);
                        have_term = false;

                } else if (path_is_absolute(*i)) {
                        _cleanup_free_ char *p = NULL, *t = NULL, *t2 = NULL, *interpreter = NULL;
                        struct stat st;

                        r = chase(*i, NULL, CHASE_TRAIL_SLASH, &p, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Couldn't canonicalize path: %m");

                        if (lstat(p, &st) < 0)
                                return log_error_errno(errno, "Couldn't stat file: %m");

                        if (S_ISREG(st.st_mode) && (0111 & st.st_mode)) {
                                if (executable_is_script(p, &interpreter) > 0) {
                                        _cleanup_free_ char *comm = NULL;

                                        r = path_extract_filename(p, &comm);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to extract filename of '%s': %m", p);

                                        t = strjoin("_COMM=", strshorten(comm, TASK_COMM_LEN-1));
                                        if (!t)
                                                return log_oom();

                                        /* Append _EXE only if the interpreter is not a link.
                                           Otherwise, it might be outdated often. */
                                        if (lstat(interpreter, &st) == 0 && !S_ISLNK(st.st_mode)) {
                                                t2 = strjoin("_EXE=", interpreter);
                                                if (!t2)
                                                        return log_oom();
                                        }
                                } else {
                                        t = strjoin("_EXE=", p);
                                        if (!t)
                                                return log_oom();
                                }

                                r = sd_journal_add_match(j, t, 0);

                                if (r >=0 && t2)
                                        r = sd_journal_add_match(j, t2, 0);

                        } else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
                                r = add_matches_for_device(j, p);
                                if (r < 0)
                                        return r;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "File is neither a device node, nor regular file, nor executable: %s",
                                                       *i);

                        have_term = true;
                } else {
                        r = sd_journal_add_match(j, *i, 0);
                        have_term = true;
                }

                if (r < 0)
                        return log_error_errno(r, "Failed to add match '%s': %m", *i);
        }

        if (!strv_isempty(args) && !have_term)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "\"+\" can only be used between terms");

        return 0;
}

int add_filters(sd_journal *j, char **matches) {
        int r;

        assert(j);

        /* add_boot() must be called first!
         * It may need to seek the journal to find parent boot IDs. */
        r = add_boot(j);
        if (r < 0)
                return r;

        r = add_dmesg(j);
        if (r < 0)
                return r;

        r = add_units(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add filter for units: %m");

        r = add_syslog_identifier(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add filter for syslog identifiers: %m");

        r = add_exclude_identifier(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add exclude filter for syslog identifiers: %m");

        r = add_priorities(j);
        if (r < 0)
                return r;

        r = add_facilities(j);
        if (r < 0)
                return r;

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
