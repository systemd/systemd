/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-journal.h"
#include "sd-messages.h"

#include "ansi-color.h"
#include "coredumpctl.h"
#include "coredumpctl-info.h"
#include "coredumpctl-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-table.h"
#include "fs-util.h"
#include "json-util.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "user-util.h"

static int print_field(FILE *file, sd_journal *j) {
        const void *d;
        size_t l;

        assert(file);
        assert(j);

        assert(arg_field);

        /* A (user-specified) field may appear more than once for a given entry. We will print all of the
         * occurrences. This is different below for fields that systemd-coredump uses, because they cannot
         * meaningfully appear more than once. */
        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                _cleanup_free_ char *value = NULL;
                int r;

                r = retrieve(d, l, arg_field, &value);
                if (r < 0)
                        return r;
                if (r > 0)
                        fprintf(file, "%s\n", value);
        }

        return 0;
}

static void analyze_coredump_file(
                const char *path,
                const char **ret_state,
                const char **ret_color,
                uint64_t *ret_size) {

        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(path);
        assert(ret_state);
        assert(ret_color);
        assert(ret_size);

        fd = open(path, O_PATH|O_CLOEXEC);
        if (fd < 0) {
                if (errno == ENOENT) {
                        *ret_state = "missing";
                        *ret_color = ansi_grey();
                        *ret_size = UINT64_MAX;
                        return;
                }

                r = -errno;
        } else
                r = access_fd(fd, R_OK);
        if (r < 0) {
                if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                        *ret_state = "inaccessible";
                        *ret_color = ansi_highlight_yellow();
                        *ret_size = UINT64_MAX;
                        return;
                }
                goto error;
        }

        if (fstat(fd, &st) < 0)
                goto error;

        if (!S_ISREG(st.st_mode))
                goto error;

        *ret_state = "present";
        *ret_color = NULL;
        *ret_size = st.st_size;
        return;

error:
        *ret_state = "error";
        *ret_color = ansi_highlight_red();
        *ret_size = UINT64_MAX;
}

#define RETRIEVE(d, l, name, arg)                    \
        {                                            \
                int _r = retrieve(d, l, name, &arg); \
                if (_r < 0)                          \
                        return _r;                   \
                if (_r > 0)                          \
                        continue;                    \
        }

static int print_list(FILE *file, sd_journal *j, Table *t) {
        _cleanup_free_ char
                *mid = NULL, *cid = NULL, *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL, *comm = NULL,
                *filename = NULL, *truncated = NULL;
        const void *d;
        size_t l;
        usec_t ts;
        int r, signal_as_int = 0;
        const char *present = NULL, *color = NULL;
        uint64_t size = UINT64_MAX;
        bool normal_coredump, has_inline_coredump;
        sd_id128_t coredump_id = SD_ID128_NULL;
        uid_t uid_as_int = UID_INVALID;
        gid_t gid_as_int = GID_INVALID;
        pid_t pid_as_int = 0;

        assert(file);
        assert(j);
        assert(t);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                RETRIEVE(d, l, "MESSAGE_ID", mid);
                RETRIEVE(d, l, "COREDUMP_ID", cid);
                RETRIEVE(d, l, "COREDUMP_PID", pid);
                RETRIEVE(d, l, "COREDUMP_UID", uid);
                RETRIEVE(d, l, "COREDUMP_GID", gid);
                RETRIEVE(d, l, "COREDUMP_SIGNAL", sgnl);
                RETRIEVE(d, l, "COREDUMP_EXE", exe);
                RETRIEVE(d, l, "COREDUMP_COMM", comm);
                RETRIEVE(d, l, "COREDUMP_FILENAME", filename);
                RETRIEVE(d, l, "COREDUMP_TRUNCATED", truncated);
        }

        /* Check for an inline coredump without copying the (potentially large) payload to heap. */
        has_inline_coredump = sd_journal_get_data(j, "COREDUMP", /* ret_data= */ NULL, /* ret_size= */ NULL) >= 0;

        if (!pid || !uid || !gid || !sgnl || !comm) {
                log_warning("Found a coredump entry without mandatory fields (PID=%s, UID=%s, GID=%s, SIGNAL=%s, COMM=%s), ignoring.",
                            strna(pid), strna(uid), strna(gid), strna(sgnl), strna(comm));
                return 0;
        }

        if (cid)
                (void) sd_id128_from_string(cid, &coredump_id);
        (void) parse_uid(uid, &uid_as_int);
        (void) parse_gid(gid, &gid_as_int);
        (void) parse_pid(pid, &pid_as_int);
        signal_as_int = signal_from_string(sgnl);

        r = sd_journal_get_realtime_usec(j, &ts);
        if (r < 0)
                return log_error_errno(r, "Failed to get realtime timestamp: %m");

        normal_coredump = streq_ptr(mid, SD_MESSAGE_COREDUMP_STR);

        if (filename) {
                r = resolve_filename(arg_root, &filename);
                if (r < 0)
                        return r;

                analyze_coredump_file(filename, &present, &color, &size);
        } else if (has_inline_coredump)
                present = "journal";
        else if (normal_coredump) {
                present = "none";
                color = ansi_grey();
        } else
                present = NULL;

        if (STRPTR_IN_SET(present, "present", "journal") && truncated && parse_boolean(truncated) > 0)
                present = "truncated";

        if (sd_id128_is_null(coredump_id))
                r = table_add_cell(t, /* ret_cell= */ NULL, TABLE_EMPTY, /* data= */ NULL);
        else
                r = table_add_cell(t, /* ret_cell= */ NULL, TABLE_ID128, &coredump_id);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_many(
                        t,
                        TABLE_TIMESTAMP, ts,
                        TABLE_PID, pid_as_int,
                        TABLE_UID, uid_as_int,
                        TABLE_GID, gid_as_int,
                        TABLE_SIGNAL, normal_coredump ? signal_as_int : 0,
                        TABLE_STRING, present,
                        TABLE_SET_COLOR, color,
                        TABLE_STRING, exe ?: comm,
                        TABLE_SIZE, size);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

typedef enum CoredumpField {
        COREDUMP_FIELD_MID,
        COREDUMP_FIELD_ID,
        COREDUMP_FIELD_PID,
        COREDUMP_FIELD_UID,
        COREDUMP_FIELD_GID,
        COREDUMP_FIELD_SGNL,
        COREDUMP_FIELD_CODE,
        COREDUMP_FIELD_EXE,
        COREDUMP_FIELD_COMM,
        COREDUMP_FIELD_CMDLINE,
        COREDUMP_FIELD_HOSTNAME,
        COREDUMP_FIELD_UNIT,
        COREDUMP_FIELD_USER_UNIT,
        COREDUMP_FIELD_SESSION,
        COREDUMP_FIELD_OWNER_UID,
        COREDUMP_FIELD_SLICE,
        COREDUMP_FIELD_CGROUP,
        COREDUMP_FIELD_TIMESTAMP,
        COREDUMP_FIELD_FILENAME,
        COREDUMP_FIELD_TRUNCATED,
        COREDUMP_FIELD_PKGMETA_NAME,
        COREDUMP_FIELD_PKGMETA_VERSION,
        COREDUMP_FIELD_PKGMETA_JSON,
        COREDUMP_FIELD_TID,
        COREDUMP_FIELD_THREAD_NAME,
        COREDUMP_FIELD_BOOT_ID,
        COREDUMP_FIELD_MACHINE_ID,
        COREDUMP_FIELD_MESSAGE,
        _COREDUMP_FIELD_MAX,
} CoredumpField;

static const char* const coredump_field_table[_COREDUMP_FIELD_MAX] = {
        [COREDUMP_FIELD_MID]              = "MESSAGE_ID",
        [COREDUMP_FIELD_ID]               = "COREDUMP_ID",
        [COREDUMP_FIELD_PID]              = "COREDUMP_PID",
        [COREDUMP_FIELD_UID]              = "COREDUMP_UID",
        [COREDUMP_FIELD_GID]              = "COREDUMP_GID",
        [COREDUMP_FIELD_SGNL]             = "COREDUMP_SIGNAL",
        [COREDUMP_FIELD_CODE]             = "COREDUMP_CODE",
        [COREDUMP_FIELD_EXE]              = "COREDUMP_EXE",
        [COREDUMP_FIELD_COMM]             = "COREDUMP_COMM",
        [COREDUMP_FIELD_CMDLINE]          = "COREDUMP_CMDLINE",
        [COREDUMP_FIELD_HOSTNAME]         = "COREDUMP_HOSTNAME",
        [COREDUMP_FIELD_UNIT]             = "COREDUMP_UNIT",
        [COREDUMP_FIELD_USER_UNIT]        = "COREDUMP_USER_UNIT",
        [COREDUMP_FIELD_SESSION]          = "COREDUMP_SESSION",
        [COREDUMP_FIELD_OWNER_UID]        = "COREDUMP_OWNER_UID",
        [COREDUMP_FIELD_SLICE]            = "COREDUMP_SLICE",
        [COREDUMP_FIELD_CGROUP]           = "COREDUMP_CGROUP",
        [COREDUMP_FIELD_TIMESTAMP]        = "COREDUMP_TIMESTAMP",
        [COREDUMP_FIELD_FILENAME]         = "COREDUMP_FILENAME",
        [COREDUMP_FIELD_TRUNCATED]        = "COREDUMP_TRUNCATED",
        [COREDUMP_FIELD_PKGMETA_NAME]     = "COREDUMP_PACKAGE_NAME",
        [COREDUMP_FIELD_PKGMETA_VERSION]  = "COREDUMP_PACKAGE_VERSION",
        [COREDUMP_FIELD_PKGMETA_JSON]     = "COREDUMP_PACKAGE_JSON",
        [COREDUMP_FIELD_TID]              = "COREDUMP_TID",
        [COREDUMP_FIELD_THREAD_NAME]      = "COREDUMP_THREAD_NAME",
        [COREDUMP_FIELD_BOOT_ID]          = "_BOOT_ID",
        [COREDUMP_FIELD_MACHINE_ID]       = "_MACHINE_ID",
        [COREDUMP_FIELD_MESSAGE]          = "MESSAGE",
};

typedef struct CoredumpFields {
        char *fields[_COREDUMP_FIELD_MAX];

        sd_id128_t coredump_id;
        bool normal_coredump;
        const char *storage_state;  /* points to a static string, not owned */
        const char *storage_color;  /* points to a static string, not owned */
        uint64_t disk_size;
        sd_json_variant *package_json;
} CoredumpFields;

static void coredump_fields_done(CoredumpFields *f) {
        assert(f);

        free_many_charp(f->fields, _COREDUMP_FIELD_MAX);
        sd_json_variant_unref(f->package_json);
}

static int coredump_fields_load(sd_journal *j, CoredumpFields *f) {
        const void *d;
        size_t l;
        int r;

        assert(j);
        assert(f);

        (void) sd_journal_set_data_threshold(j, 0);

        SD_JOURNAL_FOREACH_DATA(j, d, l)
                for (CoredumpField i = 0; i < _COREDUMP_FIELD_MAX; i++) {
                        r = retrieve(d, l, coredump_field_table[i], &f->fields[i]);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                break;
                }

        f->normal_coredump = streq_ptr(f->fields[COREDUMP_FIELD_MID], SD_MESSAGE_COREDUMP_STR);

        if (f->fields[COREDUMP_FIELD_ID]) {
                r = sd_id128_from_string(f->fields[COREDUMP_FIELD_ID], &f->coredump_id);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse coredump ID '%s', ignoring: %m", f->fields[COREDUMP_FIELD_ID]);
        }

        if (f->fields[COREDUMP_FIELD_FILENAME]) {
                r = resolve_filename(arg_root, &f->fields[COREDUMP_FIELD_FILENAME]);
                if (r < 0)
                        return r;

                analyze_coredump_file(f->fields[COREDUMP_FIELD_FILENAME], &f->storage_state, &f->storage_color, &f->disk_size);

                if (STRPTR_IN_SET(f->storage_state, "present", "journal") &&
                    f->fields[COREDUMP_FIELD_TRUNCATED] &&
                    parse_boolean(f->fields[COREDUMP_FIELD_TRUNCATED]) > 0)
                        f->storage_state = "truncated";

        } else if (sd_journal_get_data(j, "COREDUMP", /* ret_data= */ NULL, /* ret_size= */ NULL) >= 0)
                f->storage_state = "journal";
        else
                f->storage_state = "none";

        if (f->fields[COREDUMP_FIELD_PKGMETA_JSON]) {
                r = sd_json_parse(f->fields[COREDUMP_FIELD_PKGMETA_JSON],
                                  SD_JSON_PARSE_MUST_BE_OBJECT,
                                  &f->package_json,
                                  /* reterr_line= */ NULL,
                                  /* reterr_column= */ NULL);
                if (r < 0) {
                        _cleanup_free_ char *esc = cescape(f->fields[COREDUMP_FIELD_PKGMETA_JSON]);
                        log_warning_errno(r, "Failed to parse COREDUMP_PACKAGE_JSON \"%s\", ignoring: %m", strnull(esc));
                }
        }

        return 0;
}

static int table_add_string_field_full(Table *table, const char *field, const char *color, const char *value) {
        int r;

        assert(table);
        assert(field);

        if (isempty(value))
                return 0;

        r = table_add_many(table,
                           TABLE_FIELD, field,
                           TABLE_STRING, value,
                           TABLE_SET_COLOR, color);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int table_add_string_field(Table *table, const char *field, const char *value) {
        return table_add_string_field_full(table, field, /* color= */ NULL, value);
}

_printf_(4, 5)
static int table_add_string_fieldf_full(Table *table, const char *field, const char *color, const char *format, ...) {
        _cleanup_free_ char *value = NULL;
        va_list ap;
        int r;

        assert(table);
        assert(field);
        assert(format);

        va_start(ap, format);
        r = vasprintf(&value, format, ap);
        va_end(ap);
        if (r < 0)
                return log_oom();

        return table_add_string_field_full(table, field, color, value);
}

#define table_add_string_fieldf(table, field, format, ...) \
        table_add_string_fieldf_full(table, field, /* color= */ NULL, format, __VA_ARGS__)

static int table_add_string_field2_full(Table *table, const char *field, const char *color, const char *value, const char *supp) {
        if (isempty(supp))
                return table_add_string_field_full(table, field, color, value);

        return table_add_string_fieldf_full(table, field, color, "%s (%s)", value, supp);
}

static int table_add_string_field2(Table *table, const char *field, const char *value, const char *supp) {
        return table_add_string_field2_full(table, field, /* color= */ NULL, value, supp);
}

static int print_info(FILE *file, sd_journal *j, bool need_space) {
        _cleanup_(coredump_fields_done) CoredumpFields f = {
                .disk_size = UINT64_MAX,
        };
        int r;

        assert(file);
        assert(j);

        r = coredump_fields_load(j, &f);
        if (r < 0)
                return r;

        _cleanup_(table_unrefp) Table *table = table_new_vertical();
        if (!table)
                return log_oom();

        if (!sd_id128_is_null(f.coredump_id)) {
                r = table_add_string_field(table, "ID", SD_ID128_TO_STRING(f.coredump_id));
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_COMM])
                r = table_add_string_fieldf(table, "PID", "%s%s%s (%s)",
                                            ansi_highlight(), strna(f.fields[COREDUMP_FIELD_PID]), ansi_normal(),
                                            f.fields[COREDUMP_FIELD_COMM]);
        else
                r = table_add_string_field_full(table, "PID", ansi_highlight(), strna(f.fields[COREDUMP_FIELD_PID]));
        if (r < 0)
                return r;

        if (f.fields[COREDUMP_FIELD_TID]) {
                r = table_add_string_field2(table, "TID", f.fields[COREDUMP_FIELD_TID], f.fields[COREDUMP_FIELD_THREAD_NAME]);
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_UID]) {
                _cleanup_free_ char *u = NULL;
                uid_t n;

                if (parse_uid(f.fields[COREDUMP_FIELD_UID], &n) >= 0)
                        u = uid_to_name(n);

                r = table_add_string_field2(table, "UID", f.fields[COREDUMP_FIELD_UID], u);
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_GID]) {
                _cleanup_free_ char *g = NULL;
                gid_t n;

                if (parse_gid(f.fields[COREDUMP_FIELD_GID], &n) >= 0)
                        g = gid_to_name(n);

                r = table_add_string_field2(table, "GID", f.fields[COREDUMP_FIELD_GID], g);
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_SGNL]) {
                int sig;
                const char *name = f.normal_coredump ? "Signal" : "Reason";

                if (f.normal_coredump && safe_atoi(f.fields[COREDUMP_FIELD_SGNL], &sig) >= 0) {
                        if (f.fields[COREDUMP_FIELD_CODE]) {
                                int n;
                                const char *s;

                                if (safe_atoi(f.fields[COREDUMP_FIELD_CODE], &n) >= 0)
                                        s = signal_code_to_string(sig, n);
                                else
                                        s = NULL;

                                r = table_add_string_fieldf(table, name, "%s (%s) si_code: %s",
                                                           f.fields[COREDUMP_FIELD_SGNL], signal_to_string(sig),
                                                           s ?: f.fields[COREDUMP_FIELD_CODE]);
                        } else
                                r = table_add_string_field2(table, name, f.fields[COREDUMP_FIELD_SGNL], signal_to_string(sig));
                } else
                        r = table_add_string_field(table, name, f.fields[COREDUMP_FIELD_SGNL]);
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_TIMESTAMP]) {
                usec_t u;

                if (safe_atou64(f.fields[COREDUMP_FIELD_TIMESTAMP], &u) >= 0)
                        r = table_add_string_field2(table, "Timestamp", FORMAT_TIMESTAMP(u), FORMAT_TIMESTAMP_RELATIVE(u));
                else
                        r = table_add_string_field(table, "Timestamp", f.fields[COREDUMP_FIELD_TIMESTAMP]);
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_CMDLINE]) {
                r = table_add_string_field(table, "Command Line", f.fields[COREDUMP_FIELD_CMDLINE]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_EXE]) {
                r = table_add_string_field_full(table, "Executable", ansi_highlight(), f.fields[COREDUMP_FIELD_EXE]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_CGROUP]) {
                r = table_add_string_field(table, "Control Group", f.fields[COREDUMP_FIELD_CGROUP]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_UNIT]) {
                r = table_add_string_field(table, "Unit", f.fields[COREDUMP_FIELD_UNIT]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_USER_UNIT]) {
                r = table_add_string_field(table, "User Unit", f.fields[COREDUMP_FIELD_USER_UNIT]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_SLICE]) {
                r = table_add_string_field(table, "Slice", f.fields[COREDUMP_FIELD_SLICE]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_SESSION]) {
                r = table_add_string_field(table, "Session", f.fields[COREDUMP_FIELD_SESSION]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_OWNER_UID]) {
                _cleanup_free_ char *u = NULL;
                uid_t n;

                if (parse_uid(f.fields[COREDUMP_FIELD_OWNER_UID], &n) >= 0)
                        u = uid_to_name(n);

                r = table_add_string_field2(table, "Owner UID", f.fields[COREDUMP_FIELD_OWNER_UID], u);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_BOOT_ID]) {
                r = table_add_string_field(table, "Boot ID", f.fields[COREDUMP_FIELD_BOOT_ID]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_MACHINE_ID]) {
                r = table_add_string_field(table, "Machine ID", f.fields[COREDUMP_FIELD_MACHINE_ID]);
                if (r < 0)
                        return r;
        }
        if (f.fields[COREDUMP_FIELD_HOSTNAME]) {
                r = table_add_string_field(table, "Hostname", f.fields[COREDUMP_FIELD_HOSTNAME]);
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_FILENAME]) {
                r = table_add_string_field2_full(table, "Storage", f.storage_color,
                                                 f.fields[COREDUMP_FIELD_FILENAME], f.storage_state);
                if (r < 0)
                        return r;

                if (f.disk_size != UINT64_MAX) {
                        r = table_add_string_field(table, "Size on Disk", FORMAT_BYTES(f.disk_size));
                        if (r < 0)
                                return r;
                }
        } else {
                r = table_add_string_field(table, "Storage", f.storage_state);
                if (r < 0)
                        return r;
        }

        if (f.fields[COREDUMP_FIELD_PKGMETA_NAME] && f.fields[COREDUMP_FIELD_PKGMETA_VERSION]) {
                r = table_add_string_fieldf(table, "Package", "%s/%s",
                                            f.fields[COREDUMP_FIELD_PKGMETA_NAME],
                                            f.fields[COREDUMP_FIELD_PKGMETA_VERSION]);
                if (r < 0)
                        return r;
        }

        /* Print out the build-id of the 'main' ELF module, by matching the JSON key
         * with the 'exe' field. */
        if (f.fields[COREDUMP_FIELD_EXE] && f.package_json) {
                const char *module_name;
                sd_json_variant *module_json;

                JSON_VARIANT_OBJECT_FOREACH(module_name, module_json, f.package_json) {
                        /* We only print the build-id for the 'main' ELF module */
                        if (!path_equal_filename(module_name, f.fields[COREDUMP_FIELD_EXE]))
                                continue;

                        r = table_add_string_field(
                                        table, "Build ID",
                                        sd_json_variant_string(sd_json_variant_by_key(module_json, "buildId")));
                        if (r < 0)
                                return r;

                        break;
                }
        }

        if (f.fields[COREDUMP_FIELD_MESSAGE]) {
                _cleanup_strv_free_ char **lines = strv_split_newlines(f.fields[COREDUMP_FIELD_MESSAGE]);
                if (lines) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Message",
                                           TABLE_STRV, lines);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        if (need_space)
                fputs("\n", file);

        r = table_print_full(table, file, /* flush= */ false);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int print_info_json(FILE *file, sd_journal *j) {
        _cleanup_(coredump_fields_done) CoredumpFields f = {
                .disk_size = UINT64_MAX,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        pid_t pid_as_int = 0, tid_as_int = 0;
        uid_t uid_as_int = UID_INVALID, owner_uid_as_int = UID_INVALID;
        gid_t gid_as_int = GID_INVALID;
        int sig_as_int = 0, code_as_int = 0;
        bool code_is_valid = false;
        usec_t ts = USEC_INFINITY;
        int r;

        assert(file);
        assert(j);

        r = coredump_fields_load(j, &f);
        if (r < 0)
                return r;

        if (f.fields[COREDUMP_FIELD_PID])
                (void) parse_pid(f.fields[COREDUMP_FIELD_PID], &pid_as_int);
        if (f.fields[COREDUMP_FIELD_TID])
                (void) parse_pid(f.fields[COREDUMP_FIELD_TID], &tid_as_int);
        if (f.fields[COREDUMP_FIELD_UID])
                (void) parse_uid(f.fields[COREDUMP_FIELD_UID], &uid_as_int);
        if (f.fields[COREDUMP_FIELD_GID])
                (void) parse_gid(f.fields[COREDUMP_FIELD_GID], &gid_as_int);
        if (f.fields[COREDUMP_FIELD_OWNER_UID])
                (void) parse_uid(f.fields[COREDUMP_FIELD_OWNER_UID], &owner_uid_as_int);
        if (f.normal_coredump && f.fields[COREDUMP_FIELD_SGNL])
                (void) safe_atoi(f.fields[COREDUMP_FIELD_SGNL], &sig_as_int);
        if (f.normal_coredump && f.fields[COREDUMP_FIELD_CODE])
                code_is_valid = safe_atoi(f.fields[COREDUMP_FIELD_CODE], &code_as_int) >= 0;
        if (f.fields[COREDUMP_FIELD_TIMESTAMP])
                (void) safe_atou64(f.fields[COREDUMP_FIELD_TIMESTAMP], &ts);

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(f.coredump_id), "ID", SD_JSON_BUILD_ID128(f.coredump_id)),
                SD_JSON_BUILD_PAIR_CONDITION(pid_is_valid(pid_as_int), "PID", SD_JSON_BUILD_UNSIGNED(pid_as_int)),
                SD_JSON_BUILD_PAIR_CONDITION(!pid_is_valid(pid_as_int) && !!f.fields[COREDUMP_FIELD_PID], "PID", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_PID])),
                SD_JSON_BUILD_PAIR_CONDITION(pid_is_valid(tid_as_int), "TID", SD_JSON_BUILD_UNSIGNED(tid_as_int)),
                SD_JSON_BUILD_PAIR_CONDITION(!pid_is_valid(tid_as_int) && !!f.fields[COREDUMP_FIELD_TID], "TID", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_TID])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_THREAD_NAME], "ThreadName", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_THREAD_NAME])),
                SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(uid_as_int), "UID", SD_JSON_BUILD_UNSIGNED(uid_as_int)),
                SD_JSON_BUILD_PAIR_CONDITION(!uid_is_valid(uid_as_int) && !!f.fields[COREDUMP_FIELD_UID], "UID", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_UID])),
                SD_JSON_BUILD_PAIR_CONDITION(gid_is_valid(gid_as_int), "GID", SD_JSON_BUILD_UNSIGNED(gid_as_int)),
                SD_JSON_BUILD_PAIR_CONDITION(!gid_is_valid(gid_as_int) && !!f.fields[COREDUMP_FIELD_GID], "GID", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_GID])),
                SD_JSON_BUILD_PAIR_CONDITION(f.normal_coredump && sig_as_int > 0, "Signal", SD_JSON_BUILD_INTEGER(sig_as_int)),
                SD_JSON_BUILD_PAIR_CONDITION(f.normal_coredump && sig_as_int > 0 && !!signal_to_string(sig_as_int), "SignalName", SD_JSON_BUILD_STRING(signal_to_string(sig_as_int))),
                SD_JSON_BUILD_PAIR_CONDITION(f.normal_coredump && sig_as_int <= 0 && !!f.fields[COREDUMP_FIELD_SGNL], "Signal", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_SGNL])),
                SD_JSON_BUILD_PAIR_CONDITION(f.normal_coredump && code_is_valid, "SignalCode", SD_JSON_BUILD_INTEGER(code_as_int)),
                SD_JSON_BUILD_PAIR_CONDITION(f.normal_coredump && !code_is_valid && !!f.fields[COREDUMP_FIELD_CODE], "SignalCode", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_CODE])),
                SD_JSON_BUILD_PAIR_CONDITION(!f.normal_coredump && !!f.fields[COREDUMP_FIELD_SGNL], "Reason", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_SGNL])),
                SD_JSON_BUILD_PAIR_CONDITION(ts != USEC_INFINITY, "Timestamp", SD_JSON_BUILD_UNSIGNED(ts)),
                SD_JSON_BUILD_PAIR_CONDITION(ts == USEC_INFINITY && !!f.fields[COREDUMP_FIELD_TIMESTAMP], "Timestamp", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_TIMESTAMP])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_EXE], "Executable", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_EXE])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_COMM], "Command", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_COMM])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_CMDLINE], "CommandLine", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_CMDLINE])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_CGROUP], "ControlGroup", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_CGROUP])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_UNIT], "Unit", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_UNIT])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_USER_UNIT], "UserUnit", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_USER_UNIT])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_SLICE], "Slice", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_SLICE])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_SESSION], "Session", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_SESSION])),
                SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(owner_uid_as_int), "OwnerUID", SD_JSON_BUILD_UNSIGNED(owner_uid_as_int)),
                SD_JSON_BUILD_PAIR_CONDITION(!uid_is_valid(owner_uid_as_int) && !!f.fields[COREDUMP_FIELD_OWNER_UID], "OwnerUID", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_OWNER_UID])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_BOOT_ID], "BootID", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_BOOT_ID])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_MACHINE_ID], "MachineID", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_MACHINE_ID])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_HOSTNAME], "Hostname", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_HOSTNAME])),
                SD_JSON_BUILD_PAIR("Storage", SD_JSON_BUILD_STRING(f.storage_state)),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_FILENAME], "Filename", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_FILENAME])),
                SD_JSON_BUILD_PAIR_CONDITION(f.disk_size != UINT64_MAX, "DiskSize", SD_JSON_BUILD_UNSIGNED(f.disk_size)),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_PKGMETA_NAME], "PackageName", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_PKGMETA_NAME])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_PKGMETA_VERSION], "PackageVersion", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_PKGMETA_VERSION])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.package_json, "Package", SD_JSON_BUILD_VARIANT(f.package_json)),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_MESSAGE], "Message", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_MESSAGE]))));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        r = sd_json_variant_dump(v, arg_json_format_flags, file, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump JSON object: %m");

        return 0;
}

int print_entry(FILE *f, sd_journal *j, bool need_space, Table *table) {
        assert(f);
        assert(j);

        if (table)
                return print_list(f, j, table);
        if (arg_field)
                return print_field(f, j);
        if (sd_json_format_enabled(arg_json_format_flags))
                return print_info_json(f, j);
        return print_info(f, j, need_space);
}
