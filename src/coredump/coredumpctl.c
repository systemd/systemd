/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
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
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "pretty-print.h"
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
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("coredumpctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sList or retrieve coredumps from the journal.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  list [MATCHES...]  List available coredumps (default)\n"
               "  info [MATCHES...]  Show detailed information about one or more coredumps\n"
               "  dump [MATCHES...]  Print first matching coredump to stdout\n"
               "  debug [MATCHES...] Start a debugger for the first matching coredump\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                    Show this help\n"
               "     --version                 Print version string\n"
               "     --no-pager                Do not pipe output into a pager\n"
               "     --no-legend               Do not print the column headers\n"
               "     --json=pretty|short|off   Generate JSON output\n"
               "     --debugger=DEBUGGER       Use the given debugger\n"
               "  -A --debugger-arguments=ARGS Pass the given arguments to the debugger\n"
               "  -n INT                       Show maximum number of rows\n"
               "  -1                           Show information about most recent entry only\n"
               "  -S --since=DATE              Only print coredumps since the date\n"
               "  -U --until=DATE              Only print coredumps until the date\n"
               "  -r --reverse                 Show the newest entries first\n"
               "  -F --field=FIELD             List all values a certain field takes\n"
               "  -o --output=FILE             Write output to FILE\n"
               "     --file=PATH               Use journal file\n"
               "  -D --directory=DIR           Use journal files from directory\n\n"
               "  -q --quiet                   Do not show info messages and privilege warning\n"
               "     --all                     Look at all journal files instead of local ones\n"
               "     --root=PATH               Operate on an alternate filesystem root\n"
               "     --image=PATH              Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY     Specify disk image dissection policy\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int verb_help(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return help();
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_JSON,
                ARG_DEBUGGER,
                ARG_FILE,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_ALL,
        };

        int c, r;

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'              },
                { "version" ,           no_argument,       NULL, ARG_VERSION      },
                { "no-pager",           no_argument,       NULL, ARG_NO_PAGER     },
                { "no-legend",          no_argument,       NULL, ARG_NO_LEGEND    },
                { "debugger",           required_argument, NULL, ARG_DEBUGGER     },
                { "debugger-arguments", required_argument, NULL, 'A'              },
                { "output",             required_argument, NULL, 'o'              },
                { "field",              required_argument, NULL, 'F'              },
                { "file",               required_argument, NULL, ARG_FILE         },
                { "directory",          required_argument, NULL, 'D'              },
                { "reverse",            no_argument,       NULL, 'r'              },
                { "since",              required_argument, NULL, 'S'              },
                { "until",              required_argument, NULL, 'U'              },
                { "quiet",              no_argument,       NULL, 'q'              },
                { "json",               required_argument, NULL, ARG_JSON         },
                { "root",               required_argument, NULL, ARG_ROOT         },
                { "image",              required_argument, NULL, ARG_IMAGE        },
                { "image-policy",       required_argument, NULL, ARG_IMAGE_POLICY },
                { "all",                no_argument,       NULL, ARG_ALL          },
                {}
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hA:o:F:1D:rS:U:qn:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_DEBUGGER:
                        arg_debugger = optarg;
                        break;

                case 'A': {
                        _cleanup_strv_free_ char **l = NULL;
                        r = strv_split_full(&l, optarg, WHITESPACE, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse debugger arguments '%s': %m", optarg);
                        strv_free_and_replace(arg_debugger_args, l);
                        break;
                }

                case ARG_FILE:
                        r = glob_extend(&arg_file, optarg, GLOB_NOCHECK);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add paths: %m");
                        break;

                case 'o':
                        if (arg_output)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot set output more than once.");

                        arg_output = optarg;
                        break;

                case 'S':
                        r = parse_timestamp(optarg, &arg_since);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", optarg);
                        break;

                case 'U':
                        r = parse_timestamp(optarg, &arg_until);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", optarg);
                        break;

                case 'F':
                        if (arg_field)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot use --field/-F more than once.");
                        arg_field = optarg;
                        break;

                case '1':
                        arg_rows_max = 1;
                        arg_reverse = true;
                        break;

                case 'n': {
                        unsigned n;

                        r = safe_atou(optarg, &n);
                        if (r < 0 || n < 1)
                                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid numeric parameter to -n: %s", optarg);

                        arg_rows_max = n;
                        break;
                }

                case 'D':
                        arg_directory = optarg;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case 'r':
                        arg_reverse = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_ALL:
                        arg_all = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_since != USEC_INFINITY && arg_until != USEC_INFINITY &&
            arg_since > arg_until)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--since= must be before --until=.");

        if ((!!arg_directory + !!arg_image + !!arg_root) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root=, --image= or -D/--directory=, the combination of these options is not supported.");

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

typedef enum CoredumpField {
        COREDUMP_FIELD_MID,
        COREDUMP_FIELD_PID,
        COREDUMP_FIELD_UID,
        COREDUMP_FIELD_GID,
        COREDUMP_FIELD_SGNL,
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
        [COREDUMP_FIELD_PID]              = "COREDUMP_PID",
        [COREDUMP_FIELD_UID]              = "COREDUMP_UID",
        [COREDUMP_FIELD_GID]              = "COREDUMP_GID",
        [COREDUMP_FIELD_SGNL]             = "COREDUMP_SIGNAL",
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

static int coredump_fields_load(sd_journal *j, CoredumpFields *ret) {
        const void *d;
        size_t l;
        int r;

        assert(j);
        assert(ret);

        (void) sd_journal_set_data_threshold(j, 0);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                for (CoredumpField i = 0; i < _COREDUMP_FIELD_MAX; i++) {
                        int k = retrieve(d, l, coredump_field_table[i], &ret->fields[i]);
                        if (k < 0)
                                return k;
                        if (k > 0)
                                break;
                }
        }

        ret->normal_coredump = streq_ptr(ret->fields[COREDUMP_FIELD_MID], SD_MESSAGE_COREDUMP_STR);

        if (ret->fields[COREDUMP_FIELD_FILENAME]) {
                r = resolve_filename(arg_root, &ret->fields[COREDUMP_FIELD_FILENAME]);
                if (r < 0)
                        return r;

                analyze_coredump_file(ret->fields[COREDUMP_FIELD_FILENAME], &ret->storage_state, &ret->storage_color, &ret->disk_size);

                if (STRPTR_IN_SET(ret->storage_state, "present", "journal") && ret->fields[COREDUMP_FIELD_TRUNCATED] && parse_boolean(ret->fields[COREDUMP_FIELD_TRUNCATED]) > 0)
                        ret->storage_state = "truncated";
        } else if (sd_journal_get_data(j, "COREDUMP", NULL, NULL) >= 0)
                ret->storage_state = "journal";
        else
                ret->storage_state = "none";

        if (ret->fields[COREDUMP_FIELD_PKGMETA_JSON]) {
                r = sd_json_parse(ret->fields[COREDUMP_FIELD_PKGMETA_JSON], SD_JSON_PARSE_MUST_BE_OBJECT, &ret->package_json, NULL, NULL);
                if (r < 0) {
                        _cleanup_free_ char *esc = cescape(ret->fields[COREDUMP_FIELD_PKGMETA_JSON]);
                        log_warning_errno(r, "Failed to parse COREDUMP_PACKAGE_JSON \"%s\", ignoring: %m", strnull(esc));
                }
        }

        return 0;
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

        if (need_space)
                fputs("\n", file);

        if (f.fields[COREDUMP_FIELD_COMM])
                fprintf(file,
                        "           PID: %s%s%s (%s)\n",
                        ansi_highlight(), strna(f.fields[COREDUMP_FIELD_PID]), ansi_normal(), f.fields[COREDUMP_FIELD_COMM]);
        else
                fprintf(file,
                        "           PID: %s%s%s\n",
                        ansi_highlight(), strna(f.fields[COREDUMP_FIELD_PID]), ansi_normal());

        if (f.fields[COREDUMP_FIELD_TID]) {
                if (f.fields[COREDUMP_FIELD_THREAD_NAME])
                        fprintf(file, "           TID: %s (%s)\n", f.fields[COREDUMP_FIELD_TID], f.fields[COREDUMP_FIELD_THREAD_NAME]);
                else
                        fprintf(file, "           TID: %s\n", f.fields[COREDUMP_FIELD_TID]);
        }

        if (f.fields[COREDUMP_FIELD_UID]) {
                uid_t n;

                if (parse_uid(f.fields[COREDUMP_FIELD_UID], &n) >= 0) {
                        _cleanup_free_ char *u = NULL;

                        u = uid_to_name(n);
                        fprintf(file,
                                "           UID: %s (%s)\n",
                                f.fields[COREDUMP_FIELD_UID], u);
                } else
                        fprintf(file,
                                "           UID: %s\n",
                                f.fields[COREDUMP_FIELD_UID]);
        }

        if (f.fields[COREDUMP_FIELD_GID]) {
                gid_t n;

                if (parse_gid(f.fields[COREDUMP_FIELD_GID], &n) >= 0) {
                        _cleanup_free_ char *g = NULL;

                        g = gid_to_name(n);
                        fprintf(file,
                                "           GID: %s (%s)\n",
                                f.fields[COREDUMP_FIELD_GID], g);
                } else
                        fprintf(file,
                                "           GID: %s\n",
                                f.fields[COREDUMP_FIELD_GID]);
        }

        if (f.fields[COREDUMP_FIELD_SGNL]) {
                int sig;
                const char *name = f.normal_coredump ? "Signal" : "Reason";

                if (f.normal_coredump && safe_atoi(f.fields[COREDUMP_FIELD_SGNL], &sig) >= 0)
                        fprintf(file, "        %s: %s (%s)\n", name, f.fields[COREDUMP_FIELD_SGNL], signal_to_string(sig));
                else
                        fprintf(file, "        %s: %s\n", name, f.fields[COREDUMP_FIELD_SGNL]);
        }

        if (f.fields[COREDUMP_FIELD_TIMESTAMP]) {
                usec_t u;

                r = safe_atou64(f.fields[COREDUMP_FIELD_TIMESTAMP], &u);
                if (r >= 0)
                        fprintf(file, "     Timestamp: %s (%s)\n",
                                FORMAT_TIMESTAMP(u), FORMAT_TIMESTAMP_RELATIVE(u));
                else
                        fprintf(file, "     Timestamp: %s\n", f.fields[COREDUMP_FIELD_TIMESTAMP]);
        }

        if (f.fields[COREDUMP_FIELD_CMDLINE])
                fprintf(file, "  Command Line: %s\n", f.fields[COREDUMP_FIELD_CMDLINE]);
        if (f.fields[COREDUMP_FIELD_EXE])
                fprintf(file, "    Executable: %s%s%s\n", ansi_highlight(), f.fields[COREDUMP_FIELD_EXE], ansi_normal());
        if (f.fields[COREDUMP_FIELD_CGROUP])
                fprintf(file, " Control Group: %s\n", f.fields[COREDUMP_FIELD_CGROUP]);
        if (f.fields[COREDUMP_FIELD_UNIT])
                fprintf(file, "          Unit: %s\n", f.fields[COREDUMP_FIELD_UNIT]);
        if (f.fields[COREDUMP_FIELD_USER_UNIT])
                fprintf(file, "     User Unit: %s\n", f.fields[COREDUMP_FIELD_USER_UNIT]);
        if (f.fields[COREDUMP_FIELD_SLICE])
                fprintf(file, "         Slice: %s\n", f.fields[COREDUMP_FIELD_SLICE]);
        if (f.fields[COREDUMP_FIELD_SESSION])
                fprintf(file, "       Session: %s\n", f.fields[COREDUMP_FIELD_SESSION]);
        if (f.fields[COREDUMP_FIELD_OWNER_UID]) {
                uid_t n;

                if (parse_uid(f.fields[COREDUMP_FIELD_OWNER_UID], &n) >= 0) {
                        _cleanup_free_ char *u = NULL;

                        u = uid_to_name(n);
                        fprintf(file,
                                "     Owner UID: %s (%s)\n",
                                f.fields[COREDUMP_FIELD_OWNER_UID], u);
                } else
                        fprintf(file,
                                "     Owner UID: %s\n",
                                f.fields[COREDUMP_FIELD_OWNER_UID]);
        }
        if (f.fields[COREDUMP_FIELD_BOOT_ID])
                fprintf(file, "       Boot ID: %s\n", f.fields[COREDUMP_FIELD_BOOT_ID]);
        if (f.fields[COREDUMP_FIELD_MACHINE_ID])
                fprintf(file, "    Machine ID: %s\n", f.fields[COREDUMP_FIELD_MACHINE_ID]);
        if (f.fields[COREDUMP_FIELD_HOSTNAME])
                fprintf(file, "      Hostname: %s\n", f.fields[COREDUMP_FIELD_HOSTNAME]);

        if (f.fields[COREDUMP_FIELD_FILENAME]) {
                fprintf(file,
                        "       Storage: %s%s (%s)%s\n",
                        strempty(f.storage_color),
                        f.fields[COREDUMP_FIELD_FILENAME],
                        f.storage_state,
                        ansi_normal());

                if (f.disk_size != UINT64_MAX)
                        fprintf(file, "  Size on Disk: %s\n", FORMAT_BYTES(f.disk_size));
        } else
                fprintf(file, "       Storage: %s\n", f.storage_state);

        if (f.fields[COREDUMP_FIELD_PKGMETA_NAME] && f.fields[COREDUMP_FIELD_PKGMETA_VERSION])
                fprintf(file, "       Package: %s/%s\n", f.fields[COREDUMP_FIELD_PKGMETA_NAME], f.fields[COREDUMP_FIELD_PKGMETA_VERSION]);

        /* Print out the build-id of the 'main' ELF module, by matching the JSON key
         * with the 'exe' field. */
        if (f.fields[COREDUMP_FIELD_EXE] && f.package_json) {
                const char *module_name;
                sd_json_variant *module_json;

                JSON_VARIANT_OBJECT_FOREACH(module_name, module_json, f.package_json) {
                        sd_json_variant *build_id;

                        /* We only print the build-id for the 'main' ELF module */
                        if (!path_equal_filename(module_name, f.fields[COREDUMP_FIELD_EXE]))
                                continue;

                        build_id = sd_json_variant_by_key(module_json, "buildId");
                        if (build_id)
                                fprintf(file, "      build-id: %s\n", sd_json_variant_string(build_id));

                        break;
                }
        }

        if (f.fields[COREDUMP_FIELD_MESSAGE]) {
                _cleanup_free_ char *m = NULL;

                m = strreplace(f.fields[COREDUMP_FIELD_MESSAGE], "\n", "\n                ");

                fprintf(file, "       Message: %s\n", strstrip(m ?: f.fields[COREDUMP_FIELD_MESSAGE]));
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

static int print_info_json(FILE *file, sd_journal *j) {
        _cleanup_(coredump_fields_done) CoredumpFields f = {
                .disk_size = UINT64_MAX,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        pid_t pid_as_int = 0, tid_as_int = 0;
        uid_t uid_as_int = UID_INVALID, owner_uid_as_int = UID_INVALID;
        gid_t gid_as_int = GID_INVALID;
        int sig_as_int = 0;
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
        if (f.fields[COREDUMP_FIELD_TIMESTAMP])
                (void) safe_atou64(f.fields[COREDUMP_FIELD_TIMESTAMP], &ts);

        r = sd_json_build(&v, SD_JSON_BUILD_OBJECT(
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
                SD_JSON_BUILD_PAIR_CONDITION(f.normal_coredump && sig_as_int <= 0 && !!f.fields[COREDUMP_FIELD_SGNL], "Signal", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_SGNL])),
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
                SD_JSON_BUILD_PAIR_CONDITION(!!f.storage_state, "Storage", SD_JSON_BUILD_STRING(f.storage_state)),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_FILENAME], "Filename", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_FILENAME])),
                SD_JSON_BUILD_PAIR_CONDITION(f.disk_size != UINT64_MAX, "DiskSize", SD_JSON_BUILD_UNSIGNED(f.disk_size)),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_PKGMETA_NAME], "PackageName", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_PKGMETA_NAME])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_PKGMETA_VERSION], "PackageVersion", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_PKGMETA_VERSION])),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.package_json, "Package", SD_JSON_BUILD_VARIANT(f.package_json)),
                SD_JSON_BUILD_PAIR_CONDITION(!!f.fields[COREDUMP_FIELD_MESSAGE], "Message", SD_JSON_BUILD_STRING(f.fields[COREDUMP_FIELD_MESSAGE]))));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        r = sd_json_variant_dump(v, arg_json_format_flags, file, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump JSON object: %m");

        return 0;
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
        else if (sd_json_format_enabled(arg_json_format_flags))
                return print_info_json(stdout, j);
        else
                return print_info(stdout, j, n_found > 0);
}

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
        } else if (!sd_json_format_enabled(arg_json_format_flags))
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

                r = decompress_stream(filename, fdf, fd, -1);
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

static int coredumpctl_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "list",  VERB_ANY, VERB_ANY, VERB_DEFAULT, verb_dump_list },
                { "info",  VERB_ANY, VERB_ANY, 0,            verb_dump_list },
                { "dump",  VERB_ANY, VERB_ANY, 0,            verb_dump_core },
                { "debug", VERB_ANY, VERB_ANY, 0,            verb_run_debug },
                { "gdb",   VERB_ANY, VERB_ANY, 0,            verb_run_debug },
                { "help",  VERB_ANY, 1,        0,            verb_help      },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r, units_active;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv);
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

        r = coredumpctl_main(argc, argv);

        if (units_active > 0)
                printf("%s-- Notice: %d systemd-coredump@.service %s, output may be incomplete.%s\n",
                       ansi_highlight_red(),
                       units_active, units_active == 1 ? "unit is running" : "units are running",
                       ansi_normal());

        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
