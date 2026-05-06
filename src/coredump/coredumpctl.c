/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-journal.h"
#include "sd-json.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "chase.h"
#include "compress.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "help-util.h"
#include "image-policy.h"
#include "io-util.h"
#include "journal-internal.h"
#include "journal-util.h"
#include "json-util.h"
#include "log.h"
#include "logs-show.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "verbs.h"

#define SHORT_BUS_CALL_TIMEOUT_USEC (3 * USEC_PER_SEC)

static usec_t arg_since = USEC_INFINITY, arg_until = USEC_INFINITY;
static const char* arg_field = NULL;
static const char *arg_debugger = NULL;
static char **arg_debugger_args = NULL;
static const char *arg_directory = NULL;
static char *arg_root = NULL;
static char *arg_image = NULL;
static char **arg_file = NULL;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static int arg_legend = true;
static size_t arg_rows_max = SIZE_MAX;
static const char* arg_output = NULL;
static bool arg_reverse = false;
static bool arg_quiet = false;
static bool arg_all = false;
static ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_debugger_args, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_file, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

static int add_match(sd_journal *j, const char *match) {
        _cleanup_free_ char *p = NULL;
        const char *field;
        int r;

        if (strchr(match, '='))
                field = NULL;
        else if (is_path(match)) {
                r = path_make_absolute_cwd(match, &p);
                if (r < 0)
                        return log_error_errno(r, "path_make_absolute_cwd(\"%s\"): %m", match);

                match = p;
                field = "COREDUMP_EXE";
        } else if (parse_pid(match, NULL) >= 0)
                field = "COREDUMP_PID";
        else
                field = "COREDUMP_COMM";

        log_debug("Adding match: %s%s%s", strempty(field), field ? "=" : "", match);
        if (field)
                r = journal_add_match_pair(j, field, match);
        else
                r = sd_journal_add_match(j, match, SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to add match \"%s%s%s\": %m",
                                       strempty(field), field ? "=" : "", match);

        return 0;
}

static int add_matches(sd_journal *j, char **matches) {
        int r;

        r = sd_journal_add_match(j, "MESSAGE_ID=" SD_MESSAGE_COREDUMP_STR, SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to add match \"%s\": %m", "MESSAGE_ID=" SD_MESSAGE_COREDUMP_STR);

        r = sd_journal_add_match(j, "MESSAGE_ID=" SD_MESSAGE_BACKTRACE_STR, SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to add match \"%s\": %m", "MESSAGE_ID=" SD_MESSAGE_BACKTRACE_STR);

        STRV_FOREACH(match, matches) {
                r = add_match(j, *match);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int acquire_journal(sd_journal **ret, char **matches) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(ret);

        if (arg_directory) {
                r = sd_journal_open_directory(&j, arg_directory, SD_JOURNAL_ASSUME_IMMUTABLE);
                if (r < 0)
                        return log_error_errno(r, "Failed to open journals in directory: %s: %m", arg_directory);
        } else if (arg_root) {
                r = sd_journal_open_directory(&j, arg_root, SD_JOURNAL_OS_ROOT | SD_JOURNAL_ASSUME_IMMUTABLE);
                if (r < 0)
                        return log_error_errno(r, "Failed to open journals in root directory: %s: %m", arg_root);
        } else if (arg_file) {
                r = sd_journal_open_files(&j, (const char**)arg_file, SD_JOURNAL_ASSUME_IMMUTABLE);
                if (r < 0)
                        return log_error_errno(r, "Failed to open journal files: %m");
        } else {
                r = sd_journal_open(&j, arg_all ? 0 : SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE);
                if (r < 0)
                        return log_error_errno(r, "Failed to open journal: %m");
        }

        r = journal_access_check_and_warn(j, arg_quiet, true);
        if (r < 0)
                return r;

        r = add_matches(j, matches);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *filter = NULL;

                filter = journal_make_match_string(j);
                log_debug("Journal filter: %s", filter);
        }

        *ret = TAKE_PTR(j);

        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *verbs = NULL, *options = NULL;
        int r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        help_cmdline("[OPTIONS…] COMMAND …");
        help_abstract("List or retrieve coredumps from the journal.");

        help_section("Commands");
        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("coredumpctl", "1");
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_LONG("debugger", "DEBUGGER", "Use the given debugger"):
                        arg_debugger = opts.arg;
                        break;

                OPTION('A', "debugger-arguments", "…", "Pass the given arguments to the debugger"): {
                        _cleanup_strv_free_ char **l = NULL;
                        r = strv_split_full(&l, opts.arg, WHITESPACE, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse debugger arguments '%s': %m", opts.arg);
                        strv_free_and_replace(arg_debugger_args, l);
                        break;
                }

                OPTION_LONG("file", "PATH", "Use journal file"):
                        r = glob_extend(&arg_file, opts.arg, GLOB_NOCHECK);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add paths: %m");
                        break;

                OPTION('o', "output", "FILE", "Write output to FILE"):
                        if (arg_output)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot set output more than once.");

                        arg_output = opts.arg;
                        break;

                OPTION('S', "since", "DATE", "Only print coredumps since the date"):
                        r = parse_timestamp(opts.arg, &arg_since);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", opts.arg);
                        break;

                OPTION('U', "until", "DATE", "Only print coredumps until the date"):
                        r = parse_timestamp(opts.arg, &arg_until);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", opts.arg);
                        break;

                OPTION('F', "field", "FIELD", "List all values a certain field takes"):
                        if (arg_field)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot use --field/-F more than once.");
                        arg_field = opts.arg;
                        break;

                OPTION_SHORT('1', NULL, "Show information about most recent entry only"):
                        arg_rows_max = 1;
                        arg_reverse = true;
                        break;

                OPTION_SHORT('n', "INT", "Show at most this many rows"): {
                        unsigned n;

                        r = safe_atou(opts.arg, &n);
                        if (r < 0 || n < 1)
                                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid numeric parameter to -n: %s", opts.arg);

                        arg_rows_max = n;
                        break;
                }

                OPTION('D', "directory", "DIR", "Use journal files from directory"):
                        arg_directory = opts.arg;
                        break;

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION('r', "reverse", NULL, "Show the newest entries first"):
                        arg_reverse = true;
                        break;

                OPTION('q', "quiet", NULL, "Do not show info messages and privilege warning"):
                        arg_quiet = true;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("all", NULL, "Look at all journal files instead of local ones"):
                        arg_all = true;
                        break;
                }

        if (arg_since != USEC_INFINITY && arg_until != USEC_INFINITY &&
            arg_since > arg_until)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--since= must be before --until=.");

        if ((!!arg_directory + !!arg_image + !!arg_root) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root=, --image= or -D/--directory=, the combination of these options is not supported.");

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

static int retrieve(const void *data,
                    size_t len,
                    const char *name,
                    char **var) {

        size_t ident;
        char *v;

        assert(var);

        ident = strlen(name) + 1; /* name + "=" */

        if (len < ident)
                return 0;

        if (memcmp(data, name, ident - 1) != 0)
                return 0;

        if (((const char*) data)[ident - 1] != '=')
                return 0;

        v = strndup((const char*)data + ident, len - ident);
        if (!v)
                return log_oom();

        free_and_replace(*var, v);
        return 1;
}

static int print_field(FILE* file, sd_journal *j) {
        const void *d;
        size_t l;

        assert(file);
        assert(j);

        assert(arg_field);

        /* A (user-specified) field may appear more than once for a given entry.
         * We will print all of the occurrences.
         * This is different below for fields that systemd-coredump uses,
         * because they cannot meaningfully appear more than once.
         */
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

#define RETRIEVE(d, l, name, arg)                    \
        {                                            \
                int _r = retrieve(d, l, name, &arg); \
                if (_r < 0)                          \
                        return _r;                   \
                if (_r > 0)                          \
                        continue;                    \
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
                if (ERRNO_IS_PRIVILEGE(r)) {
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

static int resolve_filename(const char *root, char **p) {
        char *resolved = NULL;
        int r;

        assert(p);

        if (!*p)
                return 0;

        r = chase(*p, root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &resolved, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve \"%s%s\": %m", strempty(root), *p);

        free_and_replace(*p, resolved);

        /* chase() with flag CHASE_NONEXISTENT will return 0 if the file doesn't exist and 1 if it does.
         * Return that to the caller
         */
        return r;
}

static int print_list(FILE* file, sd_journal *j, Table *t) {
        _cleanup_free_ char
                *mid = NULL, *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL, *comm = NULL,
                *filename = NULL, *truncated = NULL;
        const void *d;
        size_t l;
        usec_t ts;
        int r, signal_as_int = 0;
        const char *present = NULL, *color = NULL;
        uint64_t size = UINT64_MAX;
        bool normal_coredump, has_inline_coredump;
        uid_t uid_as_int = UID_INVALID;
        gid_t gid_as_int = GID_INVALID;
        pid_t pid_as_int = 0;

        assert(file);
        assert(j);
        assert(t);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                RETRIEVE(d, l, "MESSAGE_ID", mid);
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
        has_inline_coredump = sd_journal_get_data(j, "COREDUMP", NULL, NULL) >= 0;

        if (!pid || !uid || !gid || !sgnl || !comm) {
                log_warning("Found a coredump entry without mandatory fields (PID=%s, UID=%s, GID=%s, SIGNAL=%s, COMM=%s), ignoring.",
                            strna(pid), strna(uid), strna(gid), strna(sgnl), strna(comm));
                return 0;
        }

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

static int print_info(FILE *file, sd_journal *j, bool need_space) {
        _cleanup_free_ char
                *mid = NULL, *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL, *comm = NULL, *cmdline = NULL,
                *unit = NULL, *user_unit = NULL, *session = NULL,
                *boot_id = NULL, *machine_id = NULL, *hostname = NULL,
                *slice = NULL, *cgroup = NULL, *owner_uid = NULL,
                *message = NULL, *timestamp = NULL, *filename = NULL,
                *truncated = NULL,
                *pkgmeta_name = NULL, *pkgmeta_version = NULL, *pkgmeta_json = NULL,
                *tid = NULL, *thread_name = NULL;
        const void *d;
        size_t l;
        bool normal_coredump, has_inline_coredump;
        int r;

        assert(file);
        assert(j);

        (void) sd_journal_set_data_threshold(j, 0);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                RETRIEVE(d, l, "MESSAGE_ID", mid);
                RETRIEVE(d, l, "COREDUMP_PID", pid);
                RETRIEVE(d, l, "COREDUMP_UID", uid);
                RETRIEVE(d, l, "COREDUMP_GID", gid);
                RETRIEVE(d, l, "COREDUMP_SIGNAL", sgnl);
                RETRIEVE(d, l, "COREDUMP_EXE", exe);
                RETRIEVE(d, l, "COREDUMP_COMM", comm);
                RETRIEVE(d, l, "COREDUMP_CMDLINE", cmdline);
                RETRIEVE(d, l, "COREDUMP_HOSTNAME", hostname);
                RETRIEVE(d, l, "COREDUMP_UNIT", unit);
                RETRIEVE(d, l, "COREDUMP_USER_UNIT", user_unit);
                RETRIEVE(d, l, "COREDUMP_SESSION", session);
                RETRIEVE(d, l, "COREDUMP_OWNER_UID", owner_uid);
                RETRIEVE(d, l, "COREDUMP_SLICE", slice);
                RETRIEVE(d, l, "COREDUMP_CGROUP", cgroup);
                RETRIEVE(d, l, "COREDUMP_TIMESTAMP", timestamp);
                RETRIEVE(d, l, "COREDUMP_FILENAME", filename);
                RETRIEVE(d, l, "COREDUMP_TRUNCATED", truncated);
                RETRIEVE(d, l, "COREDUMP_PACKAGE_NAME", pkgmeta_name);
                RETRIEVE(d, l, "COREDUMP_PACKAGE_VERSION", pkgmeta_version);
                RETRIEVE(d, l, "COREDUMP_PACKAGE_JSON", pkgmeta_json);
                RETRIEVE(d, l, "COREDUMP_TID", tid);
                RETRIEVE(d, l, "COREDUMP_THREAD_NAME", thread_name);
                RETRIEVE(d, l, "_BOOT_ID", boot_id);
                RETRIEVE(d, l, "_MACHINE_ID", machine_id);
                RETRIEVE(d, l, "MESSAGE", message);
        }

        /* Check for an inline coredump without copying the (potentially large) payload to heap. */
        has_inline_coredump = sd_journal_get_data(j, "COREDUMP", NULL, NULL) >= 0;

        if (need_space)
                fputs("\n", file);

        normal_coredump = streq_ptr(mid, SD_MESSAGE_COREDUMP_STR);

        if (comm)
                fprintf(file,
                        "           PID: %s%s%s (%s)\n",
                        ansi_highlight(), strna(pid), ansi_normal(), comm);
        else
                fprintf(file,
                        "           PID: %s%s%s\n",
                        ansi_highlight(), strna(pid), ansi_normal());

        if (tid) {
                if (thread_name)
                        fprintf(file, "           TID: %s (%s)\n", tid, thread_name);
                else
                        fprintf(file, "           TID: %s\n", tid);
        }

        if (uid) {
                uid_t n;

                if (parse_uid(uid, &n) >= 0) {
                        _cleanup_free_ char *u = NULL;

                        u = uid_to_name(n);
                        fprintf(file,
                                "           UID: %s (%s)\n",
                                uid, u);
                } else {
                        fprintf(file,
                                "           UID: %s\n",
                                uid);
                }
        }

        if (gid) {
                gid_t n;

                if (parse_gid(gid, &n) >= 0) {
                        _cleanup_free_ char *g = NULL;

                        g = gid_to_name(n);
                        fprintf(file,
                                "           GID: %s (%s)\n",
                                gid, g);
                } else {
                        fprintf(file,
                                "           GID: %s\n",
                                gid);
                }
        }

        if (sgnl) {
                int sig;
                const char *name = normal_coredump ? "Signal" : "Reason";

                if (normal_coredump && safe_atoi(sgnl, &sig) >= 0)
                        fprintf(file, "        %s: %s (%s)\n", name, sgnl, signal_to_string(sig));
                else
                        fprintf(file, "        %s: %s\n", name, sgnl);
        }

        if (timestamp) {
                usec_t u;

                r = safe_atou64(timestamp, &u);
                if (r >= 0)
                        fprintf(file, "     Timestamp: %s (%s)\n",
                                FORMAT_TIMESTAMP(u), FORMAT_TIMESTAMP_RELATIVE(u));

                else
                        fprintf(file, "     Timestamp: %s\n", timestamp);
        }

        if (cmdline)
                fprintf(file, "  Command Line: %s\n", cmdline);
        if (exe)
                fprintf(file, "    Executable: %s%s%s\n", ansi_highlight(), exe, ansi_normal());
        if (cgroup)
                fprintf(file, " Control Group: %s\n", cgroup);
        if (unit)
                fprintf(file, "          Unit: %s\n", unit);
        if (user_unit)
                fprintf(file, "     User Unit: %s\n", user_unit);
        if (slice)
                fprintf(file, "         Slice: %s\n", slice);
        if (session)
                fprintf(file, "       Session: %s\n", session);
        if (owner_uid) {
                uid_t n;

                if (parse_uid(owner_uid, &n) >= 0) {
                        _cleanup_free_ char *u = NULL;

                        u = uid_to_name(n);
                        fprintf(file,
                                "     Owner UID: %s (%s)\n",
                                owner_uid, u);
                } else {
                        fprintf(file,
                                "     Owner UID: %s\n",
                                owner_uid);
                }
        }
        if (boot_id)
                fprintf(file, "       Boot ID: %s\n", boot_id);
        if (machine_id)
                fprintf(file, "    Machine ID: %s\n", machine_id);
        if (hostname)
                fprintf(file, "      Hostname: %s\n", hostname);

        if (filename) {
                r = resolve_filename(arg_root, &filename);
                if (r < 0)
                        return r;

                const char *state = NULL, *color = NULL;
                uint64_t size = UINT64_MAX;

                analyze_coredump_file(filename, &state, &color, &size);

                if (STRPTR_IN_SET(state, "present", "journal") && truncated && parse_boolean(truncated) > 0)
                        state = "truncated";

                fprintf(file,
                        "       Storage: %s%s (%s)%s\n",
                        strempty(color),
                        filename,
                        state,
                        ansi_normal());

                if (size != UINT64_MAX)
                        fprintf(file, "  Size on Disk: %s\n", FORMAT_BYTES(size));

        } else if (has_inline_coredump)
                fprintf(file, "       Storage: journal\n");
        else
                fprintf(file, "       Storage: none\n");

        if (pkgmeta_name && pkgmeta_version)
                fprintf(file, "       Package: %s/%s\n", pkgmeta_name, pkgmeta_version);

        /* Print out the build-id of the 'main' ELF module, by matching the JSON key
         * with the 'exe' field. */
        if (exe && pkgmeta_json) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = sd_json_parse(pkgmeta_json, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
                if (r < 0) {
                        _cleanup_free_ char *esc = cescape(pkgmeta_json);
                        log_warning_errno(r, "json_parse on \"%s\" failed, ignoring: %m", strnull(esc));
                } else {
                        const char *module_name;
                        sd_json_variant *module_json;

                        JSON_VARIANT_OBJECT_FOREACH(module_name, module_json, v) {
                                sd_json_variant *build_id;

                                /* We only print the build-id for the 'main' ELF module */
                                if (!path_equal_filename(module_name, exe))
                                        continue;

                                build_id = sd_json_variant_by_key(module_json, "buildId");
                                if (build_id)
                                        fprintf(file, "      build-id: %s\n", sd_json_variant_string(build_id));

                                break;
                        }
                }
        }

        if (message) {
                _cleanup_free_ char *m = NULL;

                m = strreplace(message, "\n", "\n                ");

                fprintf(file, "       Message: %s\n", strstrip(m ?: message));
        }

        return 0;
}

static int focus(sd_journal *j) {
        int r;

        r = sd_journal_seek_tail(j);
        if (r == 0)
                r = sd_journal_previous(j);
        if (r < 0)
                return log_error_errno(r, "Failed to search journal: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "No match found.");
        return r;
}

static int print_entry(
                sd_journal *j,
                size_t n_found,
                Table *t) {

        assert(j);

        if (t)
                return print_list(stdout, j, t);
        else if (arg_field)
                return print_field(stdout, j);
        else
                return print_info(stdout, j, n_found > 0);
}

VERB(verb_dump_list, "list", "[MATCHES…]", VERB_ANY, VERB_ANY, VERB_DEFAULT,
     "List available coredumps");
VERB(verb_dump_list, "info", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
     "Show detailed information about one or more coredumps");
static int verb_dump_list(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        size_t n_found = 0;
        bool verb_is_info;
        int r;

        verb_is_info = argc >= 1 && streq(argv[0], "info");

        r = acquire_journal(&j, strv_skip(argv, 1));
        if (r < 0)
                return r;

        /* The coredumps are likely compressed, and for just listing them we don't need to decompress them,
         * so let's pick a fairly low data threshold here */
        (void) sd_journal_set_data_threshold(j, 4096);

        if (!verb_is_info && !arg_field) {
                t = table_new("time", "pid", "uid", "gid", "sig", "corefile", "exe", "size");
                if (!t)
                        return log_oom();

                (void) table_set_align_percent(t, TABLE_HEADER_CELL(1), 100);
                (void) table_set_align_percent(t, TABLE_HEADER_CELL(2), 100);
                (void) table_set_align_percent(t, TABLE_HEADER_CELL(3), 100);
                (void) table_set_align_percent(t, TABLE_HEADER_CELL(7), 100);

                table_set_ersatz_string(t, TABLE_ERSATZ_DASH);
        } else
                pager_open(arg_pager_flags);

        /* "info" without pattern implies "-1" */
        if ((arg_rows_max == 1 && arg_reverse) || (verb_is_info && argc == 1)) {
                r = focus(j);
                if (r < 0)
                        return r;

                r = print_entry(j, 0, t);
                if (r < 0)
                        return r;
        } else {
                if (arg_since != USEC_INFINITY && !arg_reverse)
                        r = sd_journal_seek_realtime_usec(j, arg_since);
                else if (arg_until != USEC_INFINITY && arg_reverse)
                        r = sd_journal_seek_realtime_usec(j, arg_until);
                else if (arg_reverse)
                        r = sd_journal_seek_tail(j);
                else
                        r = sd_journal_seek_head(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to date: %m");

                for (;;) {
                        if (!arg_reverse)
                                r = sd_journal_next(j);
                        else
                                r = sd_journal_previous(j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to iterate through journal: %m");
                        if (r == 0)
                                break;

                        if (arg_until != USEC_INFINITY && !arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine timestamp: %m");
                                if (usec > arg_until)
                                        continue;
                        }

                        if (arg_since != USEC_INFINITY && arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine timestamp: %m");
                                if (usec < arg_since)
                                        continue;
                        }

                        r = print_entry(j, n_found++, t);
                        if (r < 0)
                                return r;

                        if (arg_rows_max != SIZE_MAX && n_found >= arg_rows_max)
                                break;
                }

                if (!arg_field && n_found <= 0) {
                        if (!arg_quiet)
                                log_notice("No coredumps found.");
                        return -ESRCH;
                }
        }

        if (t) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int save_core(sd_journal *j, FILE *file, char **path, bool *unlink_temp) {
        const char *data;
        _cleanup_free_ char *filename = NULL;
        size_t len;
        int r, fd;
        _cleanup_close_ int fdt = -EBADF;
        char *temp = NULL;

        assert(!(file && path));         /* At most one can be specified */
        assert(!!path == !!unlink_temp); /* Those must be specified together */

        /* Look for a coredump on disk first. */
        r = sd_journal_get_data(j, "COREDUMP_FILENAME", (const void**) &data, &len);
        if (r == 0) {
                _cleanup_free_ char *resolved = NULL;

                r = retrieve(data, len, "COREDUMP_FILENAME", &filename);
                if (r < 0)
                        return r;
                assert(r > 0);

                r = chase_and_access(filename, arg_root, CHASE_PREFIX_ROOT, F_OK, &resolved);
                if (r < 0)
                        return log_error_errno(r, "Cannot access \"%s%s\": %m", strempty(arg_root), filename);

                free_and_replace(filename, resolved);

                if (path && !ENDSWITH_SET(filename, ".xz", ".lz4", ".zst")) {
                        *path = TAKE_PTR(filename);

                        return 0;
                }

        } else {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to retrieve COREDUMP_FILENAME field: %m");
                /* Check that we can have a COREDUMP field. We still haven't set a high
                 * data threshold, so we'll get a few kilobytes at most.
                 */

                r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
                if (r == -ENOENT)
                        return log_error_errno(r, "Coredump entry has no core attached (neither internally in the journal nor externally on disk).");
                if (r < 0)
                        return log_error_errno(r, "Failed to retrieve COREDUMP field: %m");
        }

        if (path) {
                const char *vt;

                /* Create a temporary file to write the uncompressed core to. */

                r = var_tmp_dir(&vt);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire temporary directory path: %m");

                temp = path_join(vt, "coredump-XXXXXX");
                if (!temp)
                        return log_oom();

                fdt = mkostemp_safe(temp);
                if (fdt < 0)
                        return log_error_errno(fdt, "Failed to create temporary file: %m");
                log_debug("Created temporary file %s", temp);

                fd = fdt;
        } else {
                /* If neither path or file are specified, we will write to stdout. Let's now check
                 * if stdout is connected to a tty. We checked that the file exists, or that the
                 * core might be stored in the journal. In this second case, if we found the entry,
                 * in all likelihood we will be able to access the COREDUMP= field.  In either case,
                 * we stop before doing any "real" work, i.e. before starting decompression or
                 * reading from the file or creating temporary files.
                 */
                if (!file) {
                        if (on_tty())
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                                       "Refusing to dump core to tty"
                                                       " (use shell redirection or specify --output).");
                        file = stdout;
                }

                fd = fileno(file);
        }

        if (filename) {
#if HAVE_COMPRESSION
                _cleanup_close_ int fdf = -EBADF;

                fdf = open(filename, O_RDONLY | O_CLOEXEC);
                if (fdf < 0) {
                        r = log_error_errno(errno, "Failed to open %s: %m", filename);
                        goto error;
                }

                r = decompress_stream_by_filename(filename, fdf, fd, -1);
                if (r < 0) {
                        log_error_errno(r, "Failed to decompress %s: %m", filename);
                        goto error;
                }
#else
                r = log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                    "Cannot decompress file. Compiled without compression support.");
                goto error;
#endif
        } else {
                /* We want full data, nothing truncated. */
                sd_journal_set_data_threshold(j, 0);

                r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
                if (r < 0)
                        return log_error_errno(r, "Failed to retrieve COREDUMP field: %m");

                assert(len >= 9);
                data += 9;
                len -= 9;

                r = loop_write(fd, data, len);
                if (r < 0) {
                        log_error_errno(r, "Failed to write output: %m");
                        goto error;
                }
        }

        if (temp) {
                *path = temp;
                *unlink_temp = true;
        }
        return 0;

error:
        if (temp) {
                (void) unlink(temp);
                log_debug("Removed temporary file %s", temp);
        }
        return r;
}

VERB(verb_dump_core, "dump", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
     "Print first matching coredump to stdout");
static int verb_dump_core(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (arg_field)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --field/-F only makes sense with list");

        r = acquire_journal(&j, strv_skip(argv, 1));
        if (r < 0)
                return r;

        r = focus(j);
        if (r < 0)
                return r;

        if (arg_output) {
                f = fopen(arg_output, "we");
                if (!f)
                        return log_error_errno(errno, "Failed to open \"%s\" for writing: %m", arg_output);
        }

        print_info(f ? stdout : stderr, j, false);

        r = save_core(j, f, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_journal_previous(j);
        if (r > 0 && !arg_quiet)
                log_notice("More than one entry matches, ignoring rest.");

        return 0;
}

VERB(verb_run_debug, "debug", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
     "Start a debugger for the first matching coredump");
VERB(verb_run_debug, "gdb", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
     /* help= */ NULL);
static int verb_run_debug(int argc, char *argv[], uintptr_t _data, void *userdata) {
        static const struct sigaction sa = {
                .sa_sigaction = sigterm_process_group_handler,
                .sa_flags = SA_SIGINFO,
        };

        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *exe = NULL, *path = NULL;
        _cleanup_strv_free_ char **debugger_call = NULL;
        bool unlink_path = false;
        const char *data, *fork_name;
        size_t len;
        int r;

        if (!arg_debugger) {
                char *env_debugger;

                env_debugger = getenv("SYSTEMD_DEBUGGER");
                if (env_debugger)
                        arg_debugger = env_debugger;
                else
                        arg_debugger = "gdb";
        }

        r = strv_extend(&debugger_call, arg_debugger);
        if (r < 0)
                return log_oom();

        r = strv_extend_strv(&debugger_call, arg_debugger_args, false);
        if (r < 0)
                return log_oom();

        if (arg_field)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --field/-F only makes sense with list");

        r = acquire_journal(&j, strv_skip(argv, 1));
        if (r < 0)
                return r;

        r = focus(j);
        if (r < 0)
                return r;

        if (!arg_quiet) {
                print_info(stdout, j, false);
                fputs("\n", stdout);
        }

        r = sd_journal_get_data(j, "COREDUMP_EXE", (const void**) &data, &len);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve COREDUMP_EXE field: %m");

        assert(len > STRLEN("COREDUMP_EXE="));
        data += STRLEN("COREDUMP_EXE=");
        len -= STRLEN("COREDUMP_EXE=");

        exe = strndup(data, len);
        if (!exe)
                return log_oom();

        if (endswith(exe, " (deleted)"))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Binary already deleted.");

        if (!path_is_absolute(exe))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Binary is not an absolute path.");

        r = resolve_filename(arg_root, &exe);
        if (r < 0)
                return r;

        r = save_core(j, NULL, &path, &unlink_path);
        if (r < 0)
                return r;

        r = strv_extend_many(&debugger_call, exe, "-c", path);
        if (r < 0)
                return log_oom();

        if (arg_root) {
                if (streq(arg_debugger, "gdb")) {
                        const char *sysroot_cmd;
                        sysroot_cmd = strjoina("set sysroot ", arg_root);

                        r = strv_extend_many(&debugger_call, "-iex", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                } else if (streq(arg_debugger, "lldb")) {
                        const char *sysroot_cmd;
                        sysroot_cmd = strjoina("platform select --sysroot ", arg_root, " host");

                        r = strv_extend_many(&debugger_call, "-O", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                }
        }

        /* Don't interfere with gdb and its handling of SIGINT. */
        (void) ignore_signals(SIGINT);
        (void) sigaction(SIGTERM, &sa, NULL);

        fork_name = strjoina("(", debugger_call[0], ")");

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        fork_name,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG|FORK_FLUSH_STDIO,
                        &pidref);
        if (r < 0)
                goto finish;
        if (r == 0) {
                execvp(debugger_call[0], debugger_call);
                log_open();
                log_error_errno(errno, "Failed to invoke %s: %m", debugger_call[0]);
                _exit(EXIT_FAILURE);
        }

        r = pidref_wait_for_terminate_and_check(debugger_call[0], &pidref, WAIT_LOG_ABNORMAL);

finish:
        (void) default_signals(SIGINT, SIGTERM);

        if (unlink_path) {
                log_debug("Removed temporary file %s", path);
                (void) unlink(path);
        }

        return r;
}

static int check_units_active(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int c = 0, r;
        const char *id, *state, *substate;

        if (arg_quiet)
                return false;

        r = sd_bus_default_system(&bus);
        if (r == -ENOENT) {
                log_debug("D-Bus is not running, skipping active unit check");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to acquire bus: %m");

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitsByPatterns");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, NULL);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, STRV_MAKE("systemd-coredump@*.service"));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, SHORT_BUS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to check if any systemd-coredump@.service units are running: %s",
                                       bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(
                                reply, "(ssssssouso)",
                                &id,  NULL,  NULL,  &state,  &substate,
                                NULL,  NULL,  NULL,  NULL,  NULL)) > 0) {
                bool found = !STR_IN_SET(state, "inactive", "dead", "failed");
                log_debug("Unit %s is %s/%s, %scounting it.", id, state, substate, found ? "" : "not ");
                c += found;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return c;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        char **args = NULL;
        int r, units_active;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        journal_browse_prepare();

        units_active = check_units_active(); /* error is treated the same as 0 */

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }

        r = dispatch_verb_with_args(args, NULL);

        if (units_active > 0)
                printf("%s-- Notice: %d systemd-coredump@.service %s, output may be incomplete.%s\n",
                       ansi_highlight_red(),
                       units_active, units_active == 1 ? "unit is running" : "units are running",
                       ansi_normal());

        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
