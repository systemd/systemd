/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dirent-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "journal-internal.h"
#include "journal-verify.h"
#include "journalctl.h"
#include "journalctl-misc.h"
#include "journalctl-util.h"
#include "logs-show.h"
#include "syslog-util.h"

int action_print_header(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(arg_action == ACTION_PRINT_HEADER);

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        journal_print_header(j);
        return 0;
}

int action_verify(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(arg_action == ACTION_VERIFY);

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        log_show_color(true);

        JournalFile *f;
        ORDERED_HASHMAP_FOREACH(f, j->files) {
                int k;
                usec_t first = 0, validated = 0, last = 0;

#if HAVE_GCRYPT
                if (!arg_verify_key && JOURNAL_HEADER_SEALED(f->header))
                        log_notice("Journal file %s has sealing enabled but verification key has not been passed using --verify-key=.", f->path);
#endif

                k = journal_file_verify(f, arg_verify_key, &first, &validated, &last, /* show_progress = */ !arg_quiet);
                if (k == -EINVAL)
                        /* If the key was invalid give up right-away. */
                        return k;
                if (k < 0)
                        r = log_warning_errno(k, "FAIL: %s (%m)", f->path);
                else {
                        char a[FORMAT_TIMESTAMP_MAX], b[FORMAT_TIMESTAMP_MAX];
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "PASS: %s", f->path);

                        if (arg_verify_key && JOURNAL_HEADER_SEALED(f->header)) {
                                if (validated > 0) {
                                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                                 "=> Validated from %s to %s, final %s entries not sealed.",
                                                 format_timestamp_maybe_utc(a, sizeof(a), first),
                                                 format_timestamp_maybe_utc(b, sizeof(b), validated),
                                                 FORMAT_TIMESPAN(last > validated ? last - validated : 0, 0));
                                } else if (last > 0)
                                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                                 "=> No sealing yet, %s of entries not sealed.",
                                                 FORMAT_TIMESPAN(last - first, 0));
                                else
                                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                                 "=> No sealing yet, no entries in file.");
                        }
                }
        }

        return r;
}

int action_disk_usage(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        uint64_t bytes = 0;
        int r;

        assert(arg_action == ACTION_DISK_USAGE);

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        r = sd_journal_get_usage(j, &bytes);
        if (r < 0)
                return log_error_errno(r, "Failed to get disk usage: %m");

        printf("Archived and active journals take up %s in the file system.\n", FORMAT_BYTES(bytes));
        return 0;
}

static int show_log_ids(const LogId *ids, size_t n_ids, const char *name) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(ids);
        assert(n_ids > 0);
        assert((uint64_t) INT64_MAX - n_ids > 0);
        assert(name);

        table = table_new("idx", name, "first entry", "last entry");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        r = table_set_json_field_name(table, 0, "index");
        if (r < 0)
                return log_error_errno(r, "Failed to set JSON field name of column 0: %m");

        (void) table_set_sort(table, (size_t) 0);
        (void) table_set_reverse(table, 0, arg_reverse);

        for (size_t i = 0; i < n_ids; i++) {
                int64_t index;

                if (arg_lines_needs_seek_end())
                        /* With --lines=N, we only know the negative index, and the older ID is located earlier. */
                        index = - (int64_t) i;
                else if (arg_lines >= 0)
                        /* With --lines=+N, we only know the positive index, and the newer ID is located earlier. */
                        index = i + 1;
                else
                        /* Otherwise, show negative index. Note, in this case, newer ID is located earlier. */
                        index = (int64_t) (i + 1) - (int64_t) n_ids;

                r = table_add_many(table,
                                   TABLE_INT64, index,
                                   TABLE_SET_ALIGN_PERCENT, 100,
                                   TABLE_ID128, ids[i].id,
                                   TABLE_TIMESTAMP, ids[i].first_usec,
                                   TABLE_TIMESTAMP, ids[i].last_usec);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, !arg_quiet);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

int action_list_boots(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ LogId *ids = NULL;
        size_t n_ids;
        int r;

        assert(arg_action == ACTION_LIST_BOOTS);

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        r = journal_get_boots(
                        j,
                        /* advance_older = */ arg_lines_needs_seek_end(),
                        /* max_ids = */ arg_lines >= 0 ? (size_t) arg_lines : SIZE_MAX,
                        &ids, &n_ids);
        if (r < 0)
                return log_error_errno(r, "Failed to determine boots: %m");
        if (r == 0)
                return log_full_errno(arg_quiet ? LOG_DEBUG : LOG_ERR, SYNTHETIC_ERRNO(ENODATA),
                                      "No boot found.");

        return show_log_ids(ids, n_ids, "boot id");
}

int action_list_fields(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r, n_shown = 0;

        assert(arg_action == ACTION_LIST_FIELDS);
        assert(arg_field);

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        if (!journal_boot_has_effect(j))
                return 0;

        r = sd_journal_set_data_threshold(j, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to unset data size threshold: %m");

        r = sd_journal_query_unique(j, arg_field);
        if (r < 0)
                return log_error_errno(r, "Failed to query unique data objects: %m");

        const void *data;
        size_t size;
        SD_JOURNAL_FOREACH_UNIQUE(j, data, size) {
                const void *eq;

                if (arg_lines >= 0 && n_shown >= arg_lines)
                        break;

                eq = memchr(data, '=', size);
                if (eq)
                        printf("%.*s\n", (int) (size - ((const uint8_t*) eq - (const uint8_t*) data + 1)), (const char*) eq + 1);
                else
                        printf("%.*s\n", (int) size, (const char*) data);

                n_shown++;
        }

        return 0;
}

int action_list_field_names(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(arg_action == ACTION_LIST_FIELD_NAMES);

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        const char *field;
        SD_JOURNAL_FOREACH_FIELD(j, field)
                printf("%s\n", field);

        return 0;
}

int action_list_invocations(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ LogId *ids = NULL;
        size_t n_ids;
        LogIdType type;
        const char *unit;
        int r;

        assert(arg_action == ACTION_LIST_INVOCATIONS);

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        r = acquire_unit(j, "--list-invocations", &unit, &type);
        if (r < 0)
                return r;

        r = journal_acquire_boot(j);
        if (r < 0)
                return r;

        r = journal_get_log_ids(
                        j, type,
                        /* boot_id = */ arg_boot_id, /* unit = */ unit,
                        /* advance_older = */ arg_lines_needs_seek_end(),
                        /* max_ids = */ arg_lines >= 0 ? (size_t) arg_lines : SIZE_MAX,
                        &ids, &n_ids);
        if (r < 0)
                return log_error_errno(r, "Failed to list invocation id for %s: %m", unit);
        if (r == 0)
                return log_full_errno(arg_quiet ? LOG_DEBUG : LOG_ERR, SYNTHETIC_ERRNO(ENODATA),
                                      "No invocation ID for %s found.", unit);

        return show_log_ids(ids, n_ids, "invocation id");
}

int action_list_namespaces(void) {
        _cleanup_(table_unrefp) Table *table = NULL;
        sd_id128_t machine;
        int r;

        assert(arg_action == ACTION_LIST_NAMESPACES);

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine ID: %m");

        table = table_new("namespace");
        if (!table)
                return log_oom();

        (void) table_set_sort(table, (size_t) 0);

        FOREACH_STRING(dir, "/var/log/journal", "/run/log/journal") {
                _cleanup_free_ char *path = NULL;
                _cleanup_closedir_ DIR *dirp = NULL;

                path = path_join(arg_root, dir);
                if (!path)
                        return log_oom();

                dirp = opendir(path);
                if (!dirp) {
                        log_debug_errno(errno, "Failed to open directory %s, ignoring: %m", path);
                        continue;
                }

                FOREACH_DIRENT(de, dirp, return log_error_errno(errno, "Failed to iterate through %s: %m", path)) {

                        const char *e = strchr(de->d_name, '.');
                        if (!e)
                                continue;

                        _cleanup_free_ char *ids = strndup(de->d_name, e - de->d_name);
                        if (!ids)
                                return log_oom();

                        sd_id128_t id;
                        r = sd_id128_from_string(ids, &id);
                        if (r < 0)
                                continue;

                        if (!sd_id128_equal(machine, id))
                                continue;

                        e++;

                        if (!log_namespace_name_valid(e))
                                continue;

                        r = table_add_cell(table, NULL, TABLE_STRING, e);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        if (table_isempty(table) && !sd_json_format_enabled(arg_json_format_flags)) {
                if (!arg_quiet)
                        log_notice("No namespaces found.");
        } else {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, !arg_quiet);
                if (r < 0)
                        return r;
        }

        return 0;
}
