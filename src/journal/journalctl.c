/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>

#include "sd-journal.h"
#include "sd-varlink.h"

#include "build.h"
#include "dissect-image.h"
#include "extract-word.h"
#include "format-table.h"
#include "glob-util.h"
#include "help-util.h"
#include "id128-print.h"
#include "image-policy.h"
#include "journalctl.h"
#include "journalctl-authenticate.h"
#include "journalctl-catalog.h"
#include "journalctl-misc.h"
#include "journalctl-show.h"
#include "journalctl-varlink.h"
#include "journalctl-varlink-server.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "options.h"
#include "output-mode.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pcre2-util.h"
#include "runtime-scope.h"
#include "set.h"
#include "static-destruct.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "varlink-io.systemd.JournalAccess.h"
#include "varlink-util.h"

#define DEFAULT_FSS_INTERVAL_USEC (15*USEC_PER_MINUTE)

enum {
        /* Special values for arg_lines */
        ARG_LINES_DEFAULT = -2,
        ARG_LINES_ALL = -1,
};

JournalctlAction arg_action = ACTION_SHOW;
OutputMode arg_output = OUTPUT_SHORT;
sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
PagerFlags arg_pager_flags = 0;
bool arg_utc = false;
bool arg_follow = false;
bool arg_full = true;
bool arg_all = false;
int arg_lines = ARG_LINES_DEFAULT;
bool arg_lines_oldest = false;
bool arg_no_tail = false;
bool arg_truncate_newline = false;
bool arg_quiet = false;
bool arg_merge = false;
int arg_boot = -1; /* tristate */
sd_id128_t arg_boot_id = {};
int arg_boot_offset = 0;
bool arg_dmesg = false;
bool arg_no_hostname = false;
char *arg_cursor = NULL;
char *arg_cursor_file = NULL;
char *arg_after_cursor = NULL;
bool arg_show_cursor = false;
char *arg_directory = NULL;
char **arg_file = NULL;
bool arg_file_stdin = false;
int arg_priorities = 0;
Set *arg_facilities = NULL;
char *arg_verify_key = NULL;
#if HAVE_GCRYPT
usec_t arg_interval = DEFAULT_FSS_INTERVAL_USEC;
bool arg_force = false;
#endif
usec_t arg_since = 0;
usec_t arg_until = 0;
bool arg_since_set = false;
bool arg_until_set = false;
char **arg_syslog_identifier = NULL;
char **arg_exclude_identifier = NULL;
char **arg_system_units = NULL;
char **arg_user_units = NULL;
bool arg_invocation = false;
sd_id128_t arg_invocation_id = SD_ID128_NULL;
int arg_invocation_offset = 0;
char *arg_field = NULL;
bool arg_catalog = false;
bool arg_reverse = false;
int arg_journal_type = 0;
int arg_journal_additional_open_flags = 0;
int arg_namespace_flags = 0;
char *arg_root = NULL;
char *arg_image = NULL;
char *arg_machine = NULL;
char *arg_namespace = NULL;
uint64_t arg_vacuum_size = 0;
uint64_t arg_vacuum_n_files = 0;
usec_t arg_vacuum_time = 0;
Set *arg_output_fields = NULL;
char *arg_pattern = NULL;
pcre2_code *arg_compiled_pattern = NULL;
PatternCompileCase arg_case = PATTERN_COMPILE_CASE_AUTO;
ImagePolicy *arg_image_policy = NULL;
bool arg_synchronize_on_exit = false;

static bool arg_varlink = false;
RuntimeScope arg_varlink_runtime_scope = _RUNTIME_SCOPE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_cursor, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cursor_file, freep);
STATIC_DESTRUCTOR_REGISTER(arg_after_cursor, freep);
STATIC_DESTRUCTOR_REGISTER(arg_directory, freep);
STATIC_DESTRUCTOR_REGISTER(arg_file, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_facilities, set_freep);
STATIC_DESTRUCTOR_REGISTER(arg_verify_key, erase_and_freep);
STATIC_DESTRUCTOR_REGISTER(arg_syslog_identifier, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_exclude_identifier, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_system_units, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_user_units, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_field, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_machine, freep);
STATIC_DESTRUCTOR_REGISTER(arg_namespace, freep);
STATIC_DESTRUCTOR_REGISTER(arg_output_fields, set_freep);
STATIC_DESTRUCTOR_REGISTER(arg_pattern, freep);
STATIC_DESTRUCTOR_REGISTER(arg_compiled_pattern, pcre2_code_freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

static int parse_id_descriptor(const char *x, sd_id128_t *ret_id, int *ret_offset) {
        sd_id128_t id = SD_ID128_NULL;
        int off = 0, r;

        assert(x);
        assert(ret_id);
        assert(ret_offset);

        if (streq(x, "all")) {
                *ret_id = SD_ID128_NULL;
                *ret_offset = 0;
                return 0;
        }

        if (strlen(x) >= SD_ID128_STRING_MAX - 1) {
                char *t;

                t = strndupa_safe(x, SD_ID128_STRING_MAX - 1);
                r = sd_id128_from_string(t, &id);
                if (r >= 0)
                        x += SD_ID128_STRING_MAX - 1;

                if (!IN_SET(*x, 0, '-', '+'))
                        return -EINVAL;

                if (*x != 0) {
                        r = safe_atoi(x, &off);
                        if (r < 0)
                                return r;
                }
        } else {
                r = safe_atoi(x, &off);
                if (r < 0)
                        return r;
        }

        *ret_id = id;
        *ret_offset = off;
        return 1;
}

static int parse_lines(const char *arg, bool graceful) {
        const char *l;
        int n, r;

        assert(arg || graceful);

        if (!arg)
                goto default_noarg;

        if (streq(arg, "all")) {
                arg_lines = ARG_LINES_ALL;
                return 1;
        }

        l = startswith(arg, "+");

        r = safe_atoi(l ?: arg, &n);
        if (r < 0 || n < 0) {
                if (graceful)
                        goto default_noarg;

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse --lines='%s'.", arg);
        }

        arg_lines = n;
        arg_lines_oldest = l;

        return 1;

default_noarg:
        arg_lines = 10;
        arg_lines_oldest = false;
        return 0;
}

static int help_facilities(void) {
        if (!arg_quiet)
                puts("Available facilities:");

        for (int i = 0; i < LOG_NFACILITIES; i++) {
                _cleanup_free_ char *t = NULL;

                if (log_facility_unshifted_to_string_alloc(i, &t) < 0)
                        return log_oom();
                puts(t);
        }

        return 0;
}

static int help(void) {
        static const char *const groups[] = {
                "Source Options",
                "Filtering Options",
                "Output Control Options",
                "Pager Control Options",
                "Forward Secure Sealing (FSS) Options",
                "Commands",
        };

        Table *tables[ELEMENTSOF(groups)] = {};
        CLEANUP_ELEMENTS(tables, table_unref_array_clear);
        int r;

        pager_open(arg_pager_flags);

        for (size_t i = 0; i < ELEMENTSOF(groups); i++) {
                r = option_parser_get_help_table_full("journalctl", groups[i], &tables[i]);
                if (r < 0)
                        return r;
        }

        assert_se(ELEMENTSOF(tables) == 6);
        (void) table_sync_column_widths(0, tables[0], tables[1], tables[2],
                                        tables[3], tables[4], tables[5]);

        help_cmdline("[OPTIONS…] [MATCHES…]");
        help_abstract("Query the journal.");

        for (size_t i = 0; i < ELEMENTSOF(groups); i++) {
                help_section(groups[i]);
                r = table_print_or_warn(tables[i]);
                if (r < 0)
                        return r;
        }

        help_man_page_reference("journalctl", "1");
        return 0;
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        r = varlink_server_new(&varlink_server, /* flags= */ 0, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_JournalAccess);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.JournalAccess.GetEntries", vl_method_get_entries);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0) {
                arg_varlink = true;

                OptionParser opts = { argc, argv, .namespace = "journalctl-varlink" };

                FOREACH_OPTION_OR_RETURN(c, &opts)
                        switch (c) {

                        OPTION_NAMESPACE("journalctl-varlink"): {}

                        OPTION_COMMON_SYSTEM:
                                arg_varlink_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                                break;

                        OPTION_COMMON_USER:
                                arg_varlink_runtime_scope = RUNTIME_SCOPE_USER;
                                break;
                        }

                if (arg_varlink_runtime_scope < 0)
                        return log_error_errno(arg_varlink_runtime_scope, "Cannot run in Varlink mode with no runtime scope specified.");

                if (option_parser_get_n_args(&opts) > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No arguments expected in Varlink mode.");

                *remaining_args = NULL;
                return 1;
        }

        OptionParser opts = { argc, argv, .namespace = "journalctl" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("journalctl"): {}

                OPTION_GROUP("Source Options"): {}

                OPTION_LONG("system", NULL, "Show the system journal"):
                        arg_journal_type |= SD_JOURNAL_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Show the user journal for the current user"):
                        arg_journal_type |= SD_JOURNAL_CURRENT_USER;
                        break;

                OPTION_COMMON_MACHINE:
                        r = free_and_strdup_warn(&arg_machine, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('m', "merge", NULL, "Show entries from all available journals"):
                        arg_merge = true;
                        break;

                OPTION('D', "directory", "PATH", "Show journal files from directory"):
                        r = free_and_strdup_warn(&arg_directory, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('i', "file", "PATH", "Show journal file"):
                        if (streq(opts.arg, "-"))
                                /* An undocumented feature: we can read journal files from STDIN. We don't document
                                 * this though, since after all we only support this for mmap-able, seekable files, and
                                 * not for example pipes which are probably the primary use case for reading things from
                                 * STDIN. To avoid confusion we hence don't document this feature. */
                                arg_file_stdin = true;
                        else {
                                r = glob_extend(&arg_file, opts.arg, GLOB_NOCHECK);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add paths: %m");
                        }
                        break;

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("namespace", "NAMESPACE",
                            "Show journal data from specified journal namespace"):
                        if (streq(opts.arg, "*")) {
                                arg_namespace_flags = SD_JOURNAL_ALL_NAMESPACES;
                                arg_namespace = mfree(arg_namespace);
                        } else if (startswith(opts.arg, "+")) {
                                arg_namespace_flags = SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE;
                                r = free_and_strdup_warn(&arg_namespace, opts.arg + 1);
                                if (r < 0)
                                        return r;
                        } else if (isempty(opts.arg)) {
                                arg_namespace_flags = 0;
                                arg_namespace = mfree(arg_namespace);
                        } else {
                                arg_namespace_flags = 0;
                                r = free_and_strdup_warn(&arg_namespace, opts.arg);
                                if (r < 0)
                                        return r;
                        }
                        break;

                OPTION_GROUP("Filtering Options"): {}

                OPTION('S', "since", "DATE", "Show entries not older than the specified date"):
                        r = parse_timestamp(opts.arg, &arg_since);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse timestamp: %s", opts.arg);
                        arg_since_set = true;
                        break;

                OPTION('U', "until", "DATE", "Show entries not newer than the specified date"):
                        r = parse_timestamp(opts.arg, &arg_until);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse timestamp: %s", opts.arg);
                        arg_until_set = true;
                        break;

                OPTION('c', "cursor", "CURSOR", "Show entries starting at the specified cursor"):
                        r = free_and_strdup_warn(&arg_cursor, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("after-cursor", "CURSOR", "Show entries after the specified cursor"):
                        r = free_and_strdup_warn(&arg_after_cursor, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("cursor-file", "FILE", "Show entries after cursor in FILE and update FILE"):
                        r = free_and_strdup_warn(&arg_cursor_file, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("this-boot", NULL, /* help= */ NULL):
                        arg_boot = true;
                        arg_boot_id = SD_ID128_NULL;
                        arg_boot_offset = 0;
                        break;

                OPTION_FULL(OPTION_OPTIONAL_ARG, 'b', "boot", "ID",
                            "Show current boot or the specified boot"):
                        arg_boot = true;
                        arg_boot_id = SD_ID128_NULL;
                        arg_boot_offset = 0;

                        if (opts.arg) {
                                r = parse_id_descriptor(opts.arg, &arg_boot_id, &arg_boot_offset);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse boot descriptor '%s'", opts.arg);

                                arg_boot = r;

                        } else {
                                /* Hmm, no argument? Maybe the next word on the command line is supposed to
                                 * be the argument? Let's see if there is one and is parsable as a boot
                                 * descriptor… */
                                char *peek = option_parser_peek_next_arg(&opts);
                                if (peek) {
                                        r = parse_id_descriptor(peek, &arg_boot_id, &arg_boot_offset);
                                        if (r >= 0) {
                                                arg_boot = r;
                                                (void) option_parser_consume_next_arg(&opts);
                                        }
                                }
                        }
                        break;

                OPTION('u', "unit", "UNIT", "Show logs from the specified unit"):
                        r = strv_extend(&arg_system_units, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_LONG("user-unit", "UNIT", "Show logs from the specified user unit"):
                        r = strv_extend(&arg_user_units, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_LONG("invocation", "ID", "Show logs from the matching invocation ID"):
                        r = parse_id_descriptor(opts.arg, &arg_invocation_id, &arg_invocation_offset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse invocation descriptor: %s", opts.arg);
                        arg_invocation = r;
                        break;

                OPTION_SHORT('I', NULL, "Show logs from the latest invocation of unit"):
                        /* Equivalent to --invocation=0 */
                        arg_invocation = true;
                        arg_invocation_id = SD_ID128_NULL;
                        arg_invocation_offset = 0;
                        break;

                OPTION('t', "identifier", "ID", "Show entries with the specified syslog identifier"):
                        r = strv_extend(&arg_syslog_identifier, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('T', "exclude-identifier", "ID",
                       "Hide entries with the specified syslog identifier"):
                        r = strv_extend(&arg_exclude_identifier, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('p', "priority", "RANGE", "Show entries within the specified priority range"): {

                        const char *dots = strstr(opts.arg, "..");
                        if (dots) {
                                /* a range */
                                _cleanup_free_ char *a = strndup(opts.arg, dots - opts.arg);
                                if (!a)
                                        return log_oom();

                                int from = log_level_from_string(a),
                                      to = log_level_from_string(dots + 2);

                                if (from < 0 || to < 0)
                                        return log_error_errno(from < 0 ? from : to,
                                                               "Failed to parse log level range %s", opts.arg);

                                arg_priorities = 0;
                                if (from < to)
                                        for (int i = from; i <= to; i++)
                                                arg_priorities |= 1 << i;
                                else
                                        for (int i = to; i <= from; i++)
                                                arg_priorities |= 1 << i;

                        } else {
                                int p = log_level_from_string(opts.arg);
                                if (p < 0)
                                        return log_error_errno(p, "Unknown log level %s", opts.arg);

                                arg_priorities = 0;
                                for (int i = 0; i <= p; i++)
                                        arg_priorities |= 1 << i;
                        }

                        break;
                }

                OPTION_LONG("facility", "FACILITY…", "Show entries with the specified facilities"):
                        for (const char *p = opts.arg;;) {
                                _cleanup_free_ char *fac = NULL;
                                int num;

                                r = extract_first_word(&p, &fac, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse facilities: %s", opts.arg);
                                if (r == 0)
                                        break;

                                if (streq(fac, "help")) {
                                        help_facilities();
                                        return 0;
                                }

                                num = log_facility_unshifted_from_string(fac);
                                if (num < 0)
                                        return log_error_errno(num, "Bad --facility= argument \"%s\".", fac);

                                if (set_ensure_put(&arg_facilities, NULL, INT_TO_PTR(num)) < 0)
                                        return log_oom();
                        }

                        break;

                OPTION('g', "grep", "PATTERN", "Show entries with MESSAGE matching PATTERN"):
                        r = free_and_strdup_warn(&arg_pattern, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "case-sensitive", "BOOL",
                                  "Force case sensitive or insensitive matching"):
                        if (opts.arg) {
                                r = parse_boolean(opts.arg);
                                if (r < 0)
                                        return log_error_errno(r, "Bad --case-sensitive= argument \"%s\": %m", opts.arg);
                                arg_case = r ? PATTERN_COMPILE_CASE_SENSITIVE : PATTERN_COMPILE_CASE_INSENSITIVE;
                        } else
                                arg_case = PATTERN_COMPILE_CASE_SENSITIVE;

                        break;

                OPTION('k', "dmesg", NULL, "Show kernel message log from the current boot"):
                        arg_dmesg = true;
                        break;

                OPTION_GROUP("Output Control Options"): {}

                OPTION('o', "output", "STRING",
                       "Change journal output mode (short, short-precise, short-iso, short-iso-precise, "
                       "short-full, short-monotonic, short-unix, verbose, export, json, json-pretty, "
                       "json-sse, json-seq, cat, with-unit)"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);

                        arg_output = output_mode_from_string(opts.arg);
                        if (arg_output < 0)
                                return log_error_errno(arg_output, "Unknown output format '%s'.", opts.arg);

                        if (IN_SET(arg_output, OUTPUT_EXPORT, OUTPUT_JSON, OUTPUT_JSON_PRETTY, OUTPUT_JSON_SSE, OUTPUT_JSON_SEQ, OUTPUT_CAT))
                                arg_quiet = true;

                        if (OUTPUT_MODE_IS_JSON(arg_output))
                                arg_json_format_flags = output_mode_to_json_format_flags(arg_output) | SD_JSON_FORMAT_COLOR_AUTO;
                        else
                                arg_json_format_flags = SD_JSON_FORMAT_OFF;

                        break;

                OPTION_LONG("output-fields", "LIST", "Select fields to print in verbose/export/json modes"): {
                        _cleanup_strv_free_ char **v = NULL;

                        v = strv_split(opts.arg, ",");
                        if (!v)
                                return log_oom();

                        r = set_put_strdupv(&arg_output_fields, v);
                        if (r < 0)
                                return log_oom();

                        break;
                }

                OPTION_FULL(OPTION_OPTIONAL_ARG, 'n', "lines", "[+]INTEGER",
                            "Number of journal entries to show"): {
                        const char *p = opts.arg ?: option_parser_peek_next_arg(&opts);

                        r = parse_lines(p, /* graceful= */ !opts.arg);
                        if (r < 0)
                                return r;
                        if (r > 0 && !opts.arg)
                                (void) option_parser_consume_next_arg(&opts);

                        break;
                }

                OPTION('r', "reverse", NULL, "Show the newest entries first"):
                        arg_reverse = true;
                        break;

                OPTION_LONG("show-cursor", NULL, "Print the cursor after all the entries"):
                        arg_show_cursor = true;
                        break;

                OPTION_LONG("utc", NULL, "Express time in Coordinated Universal Time (UTC)"):
                        arg_utc = true;
                        break;

                OPTION('x', "catalog", NULL, "Add message explanations where available"):
                        arg_catalog = true;
                        break;

                OPTION('W', "no-hostname", NULL, "Suppress output of hostname field"):
                        arg_no_hostname = true;
                        break;

                OPTION('l', "full", NULL, /* help= */ NULL):
                        arg_full = true;
                        break;

                OPTION_LONG("no-full", NULL, "Ellipsize fields"):
                        arg_full = false;
                        break;

                OPTION('a', "all", NULL, "Show all fields, including long and unprintable"):
                        arg_all = true;
                        break;

                OPTION('f', "follow", NULL, "Follow the journal"):
                        arg_follow = true;
                        break;

                OPTION_LONG("no-tail", NULL, "Show all lines, even in follow mode"):
                        arg_no_tail = true;
                        break;

                OPTION_LONG("truncate-newline", NULL, "Truncate entries by first newline character"):
                        arg_truncate_newline = true;
                        break;

                OPTION('q', "quiet", NULL, "Do not show info messages and privilege warning"):
                        arg_quiet = true;
                        break;

                OPTION_LONG("synchronize-on-exit", "BOOL",
                            "Wait for Journal synchronization before exiting"):
                        r = parse_boolean_argument("--synchronize-on-exit", opts.arg, &arg_synchronize_on_exit);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Pager Control Options"): {}

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION('e', "pager-end", NULL, "Immediately jump to the end in the pager"):
                        arg_pager_flags |= PAGER_JUMP_TO_END;
                        break;

                OPTION_GROUP("Forward Secure Sealing (FSS) Options"): {}

                OPTION_LONG("interval", "TIME", "Time interval for changing the FSS sealing key"):
#if HAVE_GCRYPT
                        r = parse_sec(opts.arg, &arg_interval);
                        if (r < 0 || arg_interval <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse sealing key change interval: %s", opts.arg);
                        break;
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Compiled without forward-secure sealing support.");
#endif

                OPTION_LONG("verify-key", "KEY", "Specify FSS verification key"):
#if HAVE_GCRYPT
                        erase_and_free(arg_verify_key);
                        arg_verify_key = strdup(opts.arg);
                        if (!arg_verify_key)
                                return log_oom();

                        /* Use memset not explicit_bzero() or similar so this doesn't look confusing
                         * in ps or htop output. We need to cast away the const to do this. */
                        memset((char*) opts.arg, 'x', strlen(opts.arg));

                        arg_action = ACTION_VERIFY;
                        arg_merge = false;
                        break;
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Compiled without forward-secure sealing support.");
#endif

                OPTION_LONG("force", NULL, "Override of the FSS key pair with --setup-keys"):
#if HAVE_GCRYPT
                        arg_force = true;
                        break;
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Compiled without forward-secure sealing support.");
#endif

                OPTION_GROUP("Commands"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('N', "fields", NULL, "List all field names currently used"):
                        arg_action = ACTION_LIST_FIELD_NAMES;
                        break;

                OPTION('F', "field", "FIELD", "List all values that a specified field takes"):
                        arg_action = ACTION_LIST_FIELDS;
                        r = free_and_strdup_warn(&arg_field, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("list-boots", NULL, "Show terse information about recorded boots"):
                        arg_action = ACTION_LIST_BOOTS;
                        break;

                OPTION_LONG("list-invocations", NULL, "Show invocation IDs of specified unit"):
                        arg_action = ACTION_LIST_INVOCATIONS;
                        break;

                OPTION_LONG("list-namespaces", NULL, "Show list of journal namespaces"):
                        arg_action = ACTION_LIST_NAMESPACES;
                        break;

                OPTION_LONG("disk-usage", NULL, "Show total disk usage of all journal files"):
                        arg_action = ACTION_DISK_USAGE;
                        break;

                OPTION_LONG("vacuum-size", "BYTES", "Reduce disk usage below specified size"):
                        r = parse_size(opts.arg, 1024, &arg_vacuum_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse vacuum size: %s", opts.arg);

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

                OPTION_LONG("vacuum-files", "INT", "Leave only the specified number of journal files"):
                        r = safe_atou64(opts.arg, &arg_vacuum_n_files);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse vacuum files: %s", opts.arg);

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

                OPTION_LONG("vacuum-time", "TIME", "Remove journal files older than specified time"):
                        r = parse_sec(opts.arg, &arg_vacuum_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse vacuum time: %s", opts.arg);

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

                OPTION_LONG("verify", NULL, "Verify journal file consistency"):
                        arg_action = ACTION_VERIFY;
                        break;

                OPTION_LONG("sync", NULL, "Synchronize unwritten journal messages to disk"):
                        arg_action = ACTION_SYNC;
                        break;

                OPTION_LONG("relinquish-var", NULL, "Stop logging to disk, log to temporary file system"):
                        arg_action = ACTION_RELINQUISH_VAR;
                        break;

                OPTION_LONG("smart-relinquish-var", NULL,
                            "Similar, but NOP if log directory is on root mount"):
                        arg_action = ACTION_SMART_RELINQUISH_VAR;
                        break;

                OPTION_LONG("flush", NULL, "Flush all journal data from /run into /var"):
                        arg_action = ACTION_FLUSH;
                        break;

                OPTION_LONG("rotate", NULL, "Request immediate rotation of the journal files"):
                        arg_action = arg_action == ACTION_VACUUM ? ACTION_ROTATE_AND_VACUUM : ACTION_ROTATE;
                        break;

                OPTION_LONG("header", NULL, "Show journal header information"):
                        arg_action = ACTION_PRINT_HEADER;
                        break;

                OPTION_LONG("list-catalog", NULL, "Show all message IDs in the catalog"):
                        arg_action = ACTION_LIST_CATALOG;
                        break;

                OPTION_LONG("dump-catalog", NULL, "Show entries in the message catalog"):
                        arg_action = ACTION_DUMP_CATALOG;
                        break;

                OPTION_LONG("update-catalog", NULL, "Update the message catalog database"):
                        arg_action = ACTION_UPDATE_CATALOG;
                        break;

                OPTION_LONG("setup-keys", NULL, "Generate a new FSS key pair"):
#if HAVE_GCRYPT
                        arg_action = ACTION_SETUP_KEYS;
                        break;
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Compiled without forward-secure sealing support.");
#endif

                OPTION_LONG("new-id128", NULL, /* help= */ NULL):
                        arg_action = ACTION_NEW_ID128;
                        break;
                }

        char **args = option_parser_get_args(&opts);
        size_t n_args = option_parser_get_n_args(&opts);

        if (arg_no_tail)
                arg_lines = ARG_LINES_ALL;

        if (arg_lines == ARG_LINES_DEFAULT) {
                if (arg_follow && !arg_since_set)
                        arg_lines = 10;
                else if (FLAGS_SET(arg_pager_flags, PAGER_JUMP_TO_END))
                        arg_lines = 1000;
        }

        if (arg_boot < 0)
                /* Show the current boot if -f/--follow, -k/--dmesg, or -e/--pager-end is specified unless
                 * -m/--merge is specified. */
                arg_boot = !arg_merge && (arg_follow || arg_dmesg || FLAGS_SET(arg_pager_flags, PAGER_JUMP_TO_END));
        if (!arg_boot) {
                /* Clear the boot ID and offset if -b/--boot is unspecified for safety. */
                arg_boot_id = SD_ID128_NULL;
                arg_boot_offset = 0;
        }

        if (!!arg_directory + !!arg_file + arg_file_stdin + !!arg_machine + !!arg_root + !!arg_image > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Please specify at most one of -D/--directory=, --file=, -M/--machine=, --root=, --image=.");

        if (arg_since_set && arg_until_set && arg_since > arg_until)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--since= must be before --until=.");

        if (!!arg_cursor + !!arg_after_cursor + !!arg_cursor_file + !!arg_since_set > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Please specify only one of --since=, --cursor=, --cursor-file=, and --after-cursor=.");

        if (arg_follow && arg_reverse)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Please specify either --reverse or --follow, not both.");

        if (arg_action == ACTION_SHOW && arg_lines >= 0 && arg_lines_oldest && (arg_reverse || arg_follow))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--lines=+N is unsupported when --reverse or --follow is specified.");

        if (!IN_SET(arg_action, ACTION_SHOW, ACTION_DUMP_CATALOG, ACTION_LIST_CATALOG) && n_args > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous arguments starting with '%s'",
                                       args[0]);

        if ((arg_boot || arg_action == ACTION_LIST_BOOTS) && arg_merge)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Using --boot or --list-boots with --merge is not supported.");

        if (!strv_isempty(arg_system_units) && arg_journal_type == SD_JOURNAL_CURRENT_USER) {
                /* Specifying --user and --unit= at the same time makes no sense (as the former excludes the user
                 * journal, but the latter excludes the system journal, thus resulting in empty output). Let's be nice
                 * to users, and automatically turn --unit= into --user-unit= if combined with --user. */
                r = strv_extend_strv(&arg_user_units, arg_system_units, true);
                if (r < 0)
                        return r;

                arg_system_units = strv_free(arg_system_units);
        }

        if (arg_pattern) {
                r = pattern_compile_and_log(arg_pattern, arg_case, &arg_compiled_pattern);
                if (r < 0)
                        return r;

                /* When --grep is used along with --lines without '+', i.e. when we start from the end of the
                 * journal, we don't know how many lines we can print. So we search backwards and count until
                 * enough lines have been printed or we hit the head.
                 * An exception is that --follow might set arg_lines, so let's not imply --reverse
                 * if that is specified. */
                if (arg_lines_needs_seek_end() && !arg_follow)
                        arg_reverse = true;
        }

        if (!arg_follow)
                arg_journal_additional_open_flags = SD_JOURNAL_ASSUME_IMMUTABLE;

        args = strv_copy(args);
        if (!args)
                return log_oom();

        *remaining_args = args;
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        _cleanup_strv_free_ char **args = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        if (arg_varlink)
                return vl_server();

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                (arg_action == ACTION_UPDATE_CATALOG ? DISSECT_IMAGE_FSCK|DISSECT_IMAGE_GROWFS : DISSECT_IMAGE_READ_ONLY) |
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

        switch (arg_action) {

        case ACTION_SHOW:
                return action_show(args);

        case ACTION_NEW_ID128:
                return id128_print_new(ID128_PRINT_PRETTY);

        case ACTION_SETUP_KEYS:
                return action_setup_keys();

        case ACTION_LIST_CATALOG:
        case ACTION_DUMP_CATALOG:
                return action_list_catalog(args);

        case ACTION_UPDATE_CATALOG:
                return action_update_catalog();

        case ACTION_PRINT_HEADER:
                return action_print_header();

        case ACTION_VERIFY:
                return action_verify();

        case ACTION_DISK_USAGE:
                return action_disk_usage();

        case ACTION_LIST_BOOTS:
                return action_list_boots();

        case ACTION_LIST_FIELDS:
                return action_list_fields();

        case ACTION_LIST_FIELD_NAMES:
                return action_list_field_names();

        case ACTION_LIST_INVOCATIONS:
                return action_list_invocations();

        case ACTION_LIST_NAMESPACES:
                return action_list_namespaces();

        case ACTION_FLUSH:
                return action_flush_to_var();

        case ACTION_SMART_RELINQUISH_VAR: {
                int root_mnt_id, log_mnt_id;

                /* Try to be smart about relinquishing access to /var/log/journal/ during shutdown:
                 * if it's on the same mount as the root file system there's no point in
                 * relinquishing access and we can leave journald write to it until the very last
                 * moment. */

                r = path_get_mnt_id("/", &root_mnt_id);
                if (r < 0)
                        log_debug_errno(r, "Failed to get root mount ID, ignoring: %m");
                else {
                        r = path_get_mnt_id("/var/log/journal/", &log_mnt_id);
                        if (r < 0)
                                log_debug_errno(r, "Failed to get journal directory mount ID, ignoring: %m");
                        else if (root_mnt_id == log_mnt_id) {
                                log_debug("/var/log/journal/ is on root file system, not relinquishing access to /var.");
                                return 0;
                        } else
                                log_debug("/var/log/journal/ is not on the root file system, relinquishing access to it.");
                }

                _fallthrough_;
        }

        case ACTION_RELINQUISH_VAR:
                return action_relinquish_var();

        case ACTION_SYNC:
                return action_sync();

        case ACTION_ROTATE:
                return action_rotate();

        case ACTION_VACUUM:
                return action_vacuum();

        case ACTION_ROTATE_AND_VACUUM:
                return action_rotate_and_vacuum();

        default:
                assert_not_reached();
        }
}

DEFINE_MAIN_FUNCTION(run);
