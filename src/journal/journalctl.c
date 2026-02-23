/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>

#include "sd-journal.h"
#include "sd-varlink.h"

#include "build.h"
#include "dissect-image.h"
#include "extract-word.h"
#include "glob-util.h"
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
#include "output-mode.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pcre2-util.h"
#include "pretty-print.h"
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
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("journalctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [MATCHES...]\n\n"
               "%5$sQuery the journal.%6$s\n\n"
               "%3$sSource Options:%4$s\n"
               "     --system                Show the system journal\n"
               "     --user                  Show the user journal for the current user\n"
               "  -M --machine=CONTAINER     Operate on local container\n"
               "  -m --merge                 Show entries from all available journals\n"
               "  -D --directory=PATH        Show journal files from directory\n"
               "  -i --file=PATH             Show journal file\n"
               "     --root=PATH             Operate on an alternate filesystem root\n"
               "     --image=PATH            Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY   Specify disk image dissection policy\n"
               "     --namespace=NAMESPACE   Show journal data from specified journal namespace\n"
               "\n%3$sFiltering Options:%4$s\n"
               "  -S --since=DATE            Show entries not older than the specified date\n"
               "  -U --until=DATE            Show entries not newer than the specified date\n"
               "  -c --cursor=CURSOR         Show entries starting at the specified cursor\n"
               "     --after-cursor=CURSOR   Show entries after the specified cursor\n"
               "     --cursor-file=FILE      Show entries after cursor in FILE and update FILE\n"
               "  -b --boot[=ID]             Show current boot or the specified boot\n"
               "  -u --unit=UNIT             Show logs from the specified unit\n"
               "     --user-unit=UNIT        Show logs from the specified user unit\n"
               "     --invocation=ID         Show logs from the matching invocation ID\n"
               "  -I                         Show logs from the latest invocation of unit\n"
               "  -t --identifier=STRING     Show entries with the specified syslog identifier\n"
               "  -T --exclude-identifier=STRING\n"
               "                             Hide entries with the specified syslog identifier\n"
               "  -p --priority=RANGE        Show entries within the specified priority range\n"
               "     --facility=FACILITY...  Show entries with the specified facilities\n"
               "  -g --grep=PATTERN          Show entries with MESSAGE matching PATTERN\n"
               "     --case-sensitive[=BOOL] Force case sensitive or insensitive matching\n"
               "  -k --dmesg                 Show kernel message log from the current boot\n"
               "\n%3$sOutput Control Options:%4$s\n"
               "  -o --output=STRING         Change journal output mode (short, short-precise,\n"
               "                               short-iso, short-iso-precise, short-full,\n"
               "                               short-monotonic, short-unix, verbose, export,\n"
               "                               json, json-pretty, json-sse, json-seq, cat,\n"
               "                               with-unit)\n"
               "     --output-fields=LIST    Select fields to print in verbose/export/json modes\n"
               "  -n --lines[=[+]INTEGER]    Number of journal entries to show\n"
               "  -r --reverse               Show the newest entries first\n"
               "     --show-cursor           Print the cursor after all the entries\n"
               "     --utc                   Express time in Coordinated Universal Time (UTC)\n"
               "  -x --catalog               Add message explanations where available\n"
               "  -W --no-hostname           Suppress output of hostname field\n"
               "     --no-full               Ellipsize fields\n"
               "  -a --all                   Show all fields, including long and unprintable\n"
               "  -f --follow                Follow the journal\n"
               "     --no-tail               Show all lines, even in follow mode\n"
               "     --truncate-newline      Truncate entries by first newline character\n"
               "  -q --quiet                 Do not show info messages and privilege warning\n"
               "     --synchronize-on-exit=BOOL\n"
               "                             Wait for Journal synchronization before exiting\n"
               "\n%3$sPager Control Options:%4$s\n"
               "     --no-pager              Do not pipe output into a pager\n"
               "  -e --pager-end             Immediately jump to the end in the pager\n"
               "\n%3$sForward Secure Sealing (FSS) Options:%4$s\n"
               "     --interval=TIME         Time interval for changing the FSS sealing key\n"
               "     --verify-key=KEY        Specify FSS verification key\n"
               "     --force                 Override of the FSS key pair with --setup-keys\n"
               "\n%3$sCommands:%4$s\n"
               "  -h --help                  Show this help text\n"
               "     --version               Show package version\n"
               "  -N --fields                List all field names currently used\n"
               "  -F --field=FIELD           List all values that a specified field takes\n"
               "     --list-boots            Show terse information about recorded boots\n"
               "     --list-invocations      Show invocation IDs of specified unit\n"
               "     --list-namespaces       Show list of journal namespaces\n"
               "     --disk-usage            Show total disk usage of all journal files\n"
               "     --vacuum-size=BYTES     Reduce disk usage below specified size\n"
               "     --vacuum-files=INT      Leave only the specified number of journal files\n"
               "     --vacuum-time=TIME      Remove journal files older than specified time\n"
               "     --verify                Verify journal file consistency\n"
               "     --sync                  Synchronize unwritten journal messages to disk\n"
               "     --relinquish-var        Stop logging to disk, log to temporary file system\n"
               "     --smart-relinquish-var  Similar, but NOP if log directory is on root mount\n"
               "     --flush                 Flush all journal data from /run into /var\n"
               "     --rotate                Request immediate rotation of the journal files\n"
               "     --header                Show journal header information\n"
               "     --list-catalog          Show all message IDs in the catalog\n"
               "     --dump-catalog          Show entries in the message catalog\n"
               "     --update-catalog        Update the message catalog database\n"
               "     --setup-keys            Generate a new FSS key pair\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

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

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_FULL,
                ARG_NO_TAIL,
                ARG_NEW_ID128,
                ARG_THIS_BOOT,
                ARG_LIST_BOOTS,
                ARG_LIST_INVOCATIONS,
                ARG_USER,
                ARG_SYSTEM,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_HEADER,
                ARG_FACILITY,
                ARG_SETUP_KEYS,
                ARG_INTERVAL,
                ARG_VERIFY,
                ARG_VERIFY_KEY,
                ARG_DISK_USAGE,
                ARG_AFTER_CURSOR,
                ARG_CURSOR_FILE,
                ARG_SHOW_CURSOR,
                ARG_USER_UNIT,
                ARG_INVOCATION,
                ARG_LIST_CATALOG,
                ARG_DUMP_CATALOG,
                ARG_UPDATE_CATALOG,
                ARG_FORCE,
                ARG_CASE_SENSITIVE,
                ARG_UTC,
                ARG_SYNC,
                ARG_FLUSH,
                ARG_RELINQUISH_VAR,
                ARG_SMART_RELINQUISH_VAR,
                ARG_ROTATE,
                ARG_TRUNCATE_NEWLINE,
                ARG_VACUUM_SIZE,
                ARG_VACUUM_FILES,
                ARG_VACUUM_TIME,
                ARG_OUTPUT_FIELDS,
                ARG_NAMESPACE,
                ARG_LIST_NAMESPACES,
                ARG_SYNCHRONIZE_ON_EXIT,
        };

        static const struct option options[] = {
                { "help",                 no_argument,       NULL, 'h'                      },
                { "version" ,             no_argument,       NULL, ARG_VERSION              },
                { "no-pager",             no_argument,       NULL, ARG_NO_PAGER             },
                { "pager-end",            no_argument,       NULL, 'e'                      },
                { "follow",               no_argument,       NULL, 'f'                      },
                { "force",                no_argument,       NULL, ARG_FORCE                },
                { "output",               required_argument, NULL, 'o'                      },
                { "all",                  no_argument,       NULL, 'a'                      },
                { "full",                 no_argument,       NULL, 'l'                      },
                { "no-full",              no_argument,       NULL, ARG_NO_FULL              },
                { "lines",                optional_argument, NULL, 'n'                      },
                { "truncate-newline",     no_argument,       NULL, ARG_TRUNCATE_NEWLINE     },
                { "no-tail",              no_argument,       NULL, ARG_NO_TAIL              },
                { "new-id128",            no_argument,       NULL, ARG_NEW_ID128            }, /* deprecated */
                { "quiet",                no_argument,       NULL, 'q'                      },
                { "merge",                no_argument,       NULL, 'm'                      },
                { "this-boot",            no_argument,       NULL, ARG_THIS_BOOT            }, /* deprecated */
                { "boot",                 optional_argument, NULL, 'b'                      },
                { "list-boots",           no_argument,       NULL, ARG_LIST_BOOTS           },
                { "list-invocations",     no_argument,       NULL, ARG_LIST_INVOCATIONS     },
                { "dmesg",                no_argument,       NULL, 'k'                      },
                { "system",               no_argument,       NULL, ARG_SYSTEM               },
                { "user",                 no_argument,       NULL, ARG_USER                 },
                { "directory",            required_argument, NULL, 'D'                      },
                { "file",                 required_argument, NULL, 'i'                      },
                { "root",                 required_argument, NULL, ARG_ROOT                 },
                { "image",                required_argument, NULL, ARG_IMAGE                },
                { "image-policy",         required_argument, NULL, ARG_IMAGE_POLICY         },
                { "header",               no_argument,       NULL, ARG_HEADER               },
                { "identifier",           required_argument, NULL, 't'                      },
                { "exclude-identifier",   required_argument, NULL, 'T'                      },
                { "priority",             required_argument, NULL, 'p'                      },
                { "facility",             required_argument, NULL, ARG_FACILITY             },
                { "grep",                 required_argument, NULL, 'g'                      },
                { "case-sensitive",       optional_argument, NULL, ARG_CASE_SENSITIVE       },
                { "setup-keys",           no_argument,       NULL, ARG_SETUP_KEYS           },
                { "interval",             required_argument, NULL, ARG_INTERVAL             },
                { "verify",               no_argument,       NULL, ARG_VERIFY               },
                { "verify-key",           required_argument, NULL, ARG_VERIFY_KEY           },
                { "disk-usage",           no_argument,       NULL, ARG_DISK_USAGE           },
                { "cursor",               required_argument, NULL, 'c'                      },
                { "cursor-file",          required_argument, NULL, ARG_CURSOR_FILE          },
                { "after-cursor",         required_argument, NULL, ARG_AFTER_CURSOR         },
                { "show-cursor",          no_argument,       NULL, ARG_SHOW_CURSOR          },
                { "since",                required_argument, NULL, 'S'                      },
                { "until",                required_argument, NULL, 'U'                      },
                { "unit",                 required_argument, NULL, 'u'                      },
                { "user-unit",            required_argument, NULL, ARG_USER_UNIT            },
                { "invocation",           required_argument, NULL, ARG_INVOCATION           },
                { "field",                required_argument, NULL, 'F'                      },
                { "fields",               no_argument,       NULL, 'N'                      },
                { "catalog",              no_argument,       NULL, 'x'                      },
                { "list-catalog",         no_argument,       NULL, ARG_LIST_CATALOG         },
                { "dump-catalog",         no_argument,       NULL, ARG_DUMP_CATALOG         },
                { "update-catalog",       no_argument,       NULL, ARG_UPDATE_CATALOG       },
                { "reverse",              no_argument,       NULL, 'r'                      },
                { "machine",              required_argument, NULL, 'M'                      },
                { "utc",                  no_argument,       NULL, ARG_UTC                  },
                { "flush",                no_argument,       NULL, ARG_FLUSH                },
                { "relinquish-var",       no_argument,       NULL, ARG_RELINQUISH_VAR       },
                { "smart-relinquish-var", no_argument,       NULL, ARG_SMART_RELINQUISH_VAR },
                { "sync",                 no_argument,       NULL, ARG_SYNC                 },
                { "rotate",               no_argument,       NULL, ARG_ROTATE               },
                { "vacuum-size",          required_argument, NULL, ARG_VACUUM_SIZE          },
                { "vacuum-files",         required_argument, NULL, ARG_VACUUM_FILES         },
                { "vacuum-time",          required_argument, NULL, ARG_VACUUM_TIME          },
                { "no-hostname",          no_argument,       NULL, 'W'                      },
                { "output-fields",        required_argument, NULL, ARG_OUTPUT_FIELDS        },
                { "namespace",            required_argument, NULL, ARG_NAMESPACE            },
                { "list-namespaces",      no_argument,       NULL, ARG_LIST_NAMESPACES      },
                { "synchronize-on-exit",  required_argument, NULL, ARG_SYNCHRONIZE_ON_EXIT  },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0) {
                arg_varlink = true;

                static const struct option varlink_options[] = {
                        { "system", no_argument, NULL, ARG_SYSTEM },
                        { "user",   no_argument, NULL, ARG_USER   },
                        {}
                };

                while ((c = getopt_long(argc, argv, "", varlink_options, NULL)) >= 0)

                        switch (c) {

                        case ARG_SYSTEM:
                                arg_varlink_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                                break;

                        case ARG_USER:
                                arg_varlink_runtime_scope = RUNTIME_SCOPE_USER;
                                break;

                        case '?':
                                return -EINVAL;

                        default:
                                assert_not_reached();
                        }

                if (arg_varlink_runtime_scope < 0)
                        return log_error_errno(arg_varlink_runtime_scope, "Cannot run in Varlink mode with no runtime scope specified.");

                return 1;
        }

        while ((c = getopt_long(argc, argv, "hefo:aln::qmb::kD:p:g:c:S:U:t:T:u:INF:xrM:i:W", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case 'e':
                        arg_pager_flags |= PAGER_JUMP_TO_END;
                        break;

                case 'f':
                        arg_follow = true;
                        break;

                case 'o':
                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);

                        arg_output = output_mode_from_string(optarg);
                        if (arg_output < 0)
                                return log_error_errno(arg_output, "Unknown output format '%s'.", optarg);

                        if (IN_SET(arg_output, OUTPUT_EXPORT, OUTPUT_JSON, OUTPUT_JSON_PRETTY, OUTPUT_JSON_SSE, OUTPUT_JSON_SEQ, OUTPUT_CAT))
                                arg_quiet = true;

                        if (OUTPUT_MODE_IS_JSON(arg_output))
                                arg_json_format_flags = output_mode_to_json_format_flags(arg_output) | SD_JSON_FORMAT_COLOR_AUTO;
                        else
                                arg_json_format_flags = SD_JSON_FORMAT_OFF;

                        break;

                case 'l':
                        arg_full = true;
                        break;

                case ARG_NO_FULL:
                        arg_full = false;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 'n':
                        r = parse_lines(optarg ?: argv[optind], !optarg);
                        if (r < 0)
                                return r;
                        if (r > 0 && !optarg)
                                optind++;

                        break;

                case ARG_NO_TAIL:
                        arg_no_tail = true;
                        break;

                case ARG_TRUNCATE_NEWLINE:
                        arg_truncate_newline = true;
                        break;

                case ARG_NEW_ID128:
                        arg_action = ACTION_NEW_ID128;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case 'm':
                        arg_merge = true;
                        break;

                case ARG_THIS_BOOT:
                        arg_boot = true;
                        arg_boot_id = SD_ID128_NULL;
                        arg_boot_offset = 0;
                        break;

                case 'b':
                        arg_boot = true;
                        arg_boot_id = SD_ID128_NULL;
                        arg_boot_offset = 0;

                        if (optarg) {
                                r = parse_id_descriptor(optarg, &arg_boot_id, &arg_boot_offset);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse boot descriptor '%s'", optarg);

                                arg_boot = r;

                        } else if (optind < argc) {
                                /* Hmm, no argument? Maybe the next word on the command line is supposed to be the
                                 * argument? Let's see if there is one and is parsable as a boot descriptor... */
                                r = parse_id_descriptor(argv[optind], &arg_boot_id, &arg_boot_offset);
                                if (r >= 0) {
                                        arg_boot = r;
                                        optind++;
                                }
                        }
                        break;

                case ARG_LIST_BOOTS:
                        arg_action = ACTION_LIST_BOOTS;
                        break;

                case ARG_LIST_INVOCATIONS:
                        arg_action = ACTION_LIST_INVOCATIONS;
                        break;

                case 'k':
                        arg_dmesg = true;
                        break;

                case ARG_SYSTEM:
                        arg_journal_type |= SD_JOURNAL_SYSTEM;
                        break;

                case ARG_USER:
                        arg_journal_type |= SD_JOURNAL_CURRENT_USER;
                        break;

                case 'M':
                        r = free_and_strdup_warn(&arg_machine, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_NAMESPACE:
                        if (streq(optarg, "*")) {
                                arg_namespace_flags = SD_JOURNAL_ALL_NAMESPACES;
                                arg_namespace = mfree(arg_namespace);
                        } else if (startswith(optarg, "+")) {
                                arg_namespace_flags = SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE;
                                r = free_and_strdup_warn(&arg_namespace, optarg + 1);
                                if (r < 0)
                                        return r;
                        } else if (isempty(optarg)) {
                                arg_namespace_flags = 0;
                                arg_namespace = mfree(arg_namespace);
                        } else {
                                arg_namespace_flags = 0;
                                r = free_and_strdup_warn(&arg_namespace, optarg);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case ARG_LIST_NAMESPACES:
                        arg_action = ACTION_LIST_NAMESPACES;
                        break;

                case 'D':
                        r = free_and_strdup_warn(&arg_directory, optarg);
                        if (r < 0)
                                return r;
                        break;

                case 'i':
                        if (streq(optarg, "-"))
                                /* An undocumented feature: we can read journal files from STDIN. We don't document
                                 * this though, since after all we only support this for mmap-able, seekable files, and
                                 * not for example pipes which are probably the primary use case for reading things from
                                 * STDIN. To avoid confusion we hence don't document this feature. */
                                arg_file_stdin = true;
                        else {
                                r = glob_extend(&arg_file, optarg, GLOB_NOCHECK);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add paths: %m");
                        }
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case 'c':
                        r = free_and_strdup_warn(&arg_cursor, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CURSOR_FILE:
                        r = free_and_strdup_warn(&arg_cursor_file, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_AFTER_CURSOR:
                        r = free_and_strdup_warn(&arg_after_cursor, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SHOW_CURSOR:
                        arg_show_cursor = true;
                        break;

                case ARG_HEADER:
                        arg_action = ACTION_PRINT_HEADER;
                        break;

                case ARG_VERIFY:
                        arg_action = ACTION_VERIFY;
                        break;

                case ARG_DISK_USAGE:
                        arg_action = ACTION_DISK_USAGE;
                        break;

                case ARG_VACUUM_SIZE:
                        r = parse_size(optarg, 1024, &arg_vacuum_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse vacuum size: %s", optarg);

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

                case ARG_VACUUM_FILES:
                        r = safe_atou64(optarg, &arg_vacuum_n_files);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse vacuum files: %s", optarg);

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

                case ARG_VACUUM_TIME:
                        r = parse_sec(optarg, &arg_vacuum_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse vacuum time: %s", optarg);

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

#if HAVE_GCRYPT
                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_SETUP_KEYS:
                        arg_action = ACTION_SETUP_KEYS;
                        break;

                case ARG_VERIFY_KEY:
                        erase_and_free(arg_verify_key);
                        arg_verify_key = strdup(optarg);
                        if (!arg_verify_key)
                                return log_oom();

                        /* Use memset not explicit_bzero() or similar so this doesn't look confusing
                         * in ps or htop output. */
                        memset(optarg, 'x', strlen(optarg));

                        arg_action = ACTION_VERIFY;
                        arg_merge = false;
                        break;

                case ARG_INTERVAL:
                        r = parse_sec(optarg, &arg_interval);
                        if (r < 0 || arg_interval <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse sealing key change interval: %s", optarg);
                        break;
#else
                case ARG_SETUP_KEYS:
                case ARG_VERIFY_KEY:
                case ARG_INTERVAL:
                case ARG_FORCE:
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Compiled without forward-secure sealing support.");
#endif

                case 'p': {
                        const char *dots;

                        dots = strstr(optarg, "..");
                        if (dots) {
                                _cleanup_free_ char *a = NULL;
                                int from, to, i;

                                /* a range */
                                a = strndup(optarg, dots - optarg);
                                if (!a)
                                        return log_oom();

                                from = log_level_from_string(a);
                                to = log_level_from_string(dots + 2);

                                if (from < 0 || to < 0)
                                        return log_error_errno(from < 0 ? from : to,
                                                               "Failed to parse log level range %s", optarg);

                                arg_priorities = 0;

                                if (from < to) {
                                        for (i = from; i <= to; i++)
                                                arg_priorities |= 1 << i;
                                } else {
                                        for (i = to; i <= from; i++)
                                                arg_priorities |= 1 << i;
                                }

                        } else {
                                int p, i;

                                p = log_level_from_string(optarg);
                                if (p < 0)
                                        return log_error_errno(p, "Unknown log level %s", optarg);

                                arg_priorities = 0;

                                for (i = 0; i <= p; i++)
                                        arg_priorities |= 1 << i;
                        }

                        break;
                }

                case ARG_FACILITY: {
                        const char *p;

                        for (p = optarg;;) {
                                _cleanup_free_ char *fac = NULL;
                                int num;

                                r = extract_first_word(&p, &fac, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse facilities: %s", optarg);
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
                }

                case 'g':
                        r = free_and_strdup_warn(&arg_pattern, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CASE_SENSITIVE:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Bad --case-sensitive= argument \"%s\": %m", optarg);
                                arg_case = r ? PATTERN_COMPILE_CASE_SENSITIVE : PATTERN_COMPILE_CASE_INSENSITIVE;
                        } else
                                arg_case = PATTERN_COMPILE_CASE_SENSITIVE;

                        break;

                case 'S':
                        r = parse_timestamp(optarg, &arg_since);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse timestamp: %s", optarg);
                        arg_since_set = true;
                        break;

                case 'U':
                        r = parse_timestamp(optarg, &arg_until);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse timestamp: %s", optarg);
                        arg_until_set = true;
                        break;

                case 't':
                        r = strv_extend(&arg_syslog_identifier, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case 'T':
                        r = strv_extend(&arg_exclude_identifier, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case 'u':
                        r = strv_extend(&arg_system_units, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_USER_UNIT:
                        r = strv_extend(&arg_user_units, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_INVOCATION:
                        r = parse_id_descriptor(optarg, &arg_invocation_id, &arg_invocation_offset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse invocation descriptor: %s", optarg);
                        arg_invocation = r;
                        break;

                case 'I':
                        /* Equivalent to --invocation=0 */
                        arg_invocation = true;
                        arg_invocation_id = SD_ID128_NULL;
                        arg_invocation_offset = 0;
                        break;

                case 'F':
                        arg_action = ACTION_LIST_FIELDS;
                        r = free_and_strdup_warn(&arg_field, optarg);
                        if (r < 0)
                                return r;
                        break;

                case 'N':
                        arg_action = ACTION_LIST_FIELD_NAMES;
                        break;

                case 'W':
                        arg_no_hostname = true;
                        break;

                case 'x':
                        arg_catalog = true;
                        break;

                case ARG_LIST_CATALOG:
                        arg_action = ACTION_LIST_CATALOG;
                        break;

                case ARG_DUMP_CATALOG:
                        arg_action = ACTION_DUMP_CATALOG;
                        break;

                case ARG_UPDATE_CATALOG:
                        arg_action = ACTION_UPDATE_CATALOG;
                        break;

                case 'r':
                        arg_reverse = true;
                        break;

                case ARG_UTC:
                        arg_utc = true;
                        break;

                case ARG_FLUSH:
                        arg_action = ACTION_FLUSH;
                        break;

                case ARG_SMART_RELINQUISH_VAR: {
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

                case ARG_RELINQUISH_VAR:
                        arg_action = ACTION_RELINQUISH_VAR;
                        break;

                case ARG_ROTATE:
                        arg_action = arg_action == ACTION_VACUUM ? ACTION_ROTATE_AND_VACUUM : ACTION_ROTATE;
                        break;

                case ARG_SYNC:
                        arg_action = ACTION_SYNC;
                        break;

                case ARG_OUTPUT_FIELDS: {
                        _cleanup_strv_free_ char **v = NULL;

                        v = strv_split(optarg, ",");
                        if (!v)
                                return log_oom();

                        r = set_put_strdupv(&arg_output_fields, v);
                        if (r < 0)
                                return log_oom();

                        break;
                }

                case ARG_SYNCHRONIZE_ON_EXIT:
                        r = parse_boolean_argument("--synchronize-on-exit", optarg, &arg_synchronize_on_exit);
                        if (r < 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

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

        if (!IN_SET(arg_action, ACTION_SHOW, ACTION_DUMP_CATALOG, ACTION_LIST_CATALOG) && optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous arguments starting with '%s'",
                                       argv[optind]);

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

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        _cleanup_strv_free_ char **args = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_varlink)
                return vl_server();

        r = strv_copy_unless_empty(strv_skip(argv, optind), &args);
        if (r < 0)
                return log_oom();

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
