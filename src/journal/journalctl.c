/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <linux/fs.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#if HAVE_PCRE2
#  define PCRE2_CODE_UNIT_WIDTH 8
#  include <pcre2.h>
#endif

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-journal.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "catalog.h"
#include "chattr-util.h"
#include "def.h"
#include "device-private.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fsprg.h"
#include "glob-util.h"
#include "hostname-util.h"
#include "id128-print.h"
#include "io-util.h"
#include "journal-def.h"
#include "journal-internal.h"
#include "journal-qrcode.h"
#include "journal-util.h"
#include "journal-vacuum.h"
#include "journal-verify.h"
#include "locale-util.h"
#include "log.h"
#include "logs-show.h"
#include "mkdir.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "rlimit-util.h"
#include "set.h"
#include "sigbus.h"
#include "string-table.h"
#include "strv.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "user-util.h"

#define DEFAULT_FSS_INTERVAL_USEC (15*USEC_PER_MINUTE)

#define PROCESS_INOTIFY_INTERVAL 1024   /* Every 1,024 messages processed */

#if HAVE_PCRE2
DEFINE_TRIVIAL_CLEANUP_FUNC(pcre2_match_data*, pcre2_match_data_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(pcre2_code*, pcre2_code_free);

static int pattern_compile(const char *pattern, unsigned flags, pcre2_code **out) {
        int errorcode, r;
        PCRE2_SIZE erroroffset;
        pcre2_code *p;

        p = pcre2_compile((PCRE2_SPTR8) pattern,
                          PCRE2_ZERO_TERMINATED, flags, &errorcode, &erroroffset, NULL);
        if (!p) {
                unsigned char buf[LINE_MAX];

                r = pcre2_get_error_message(errorcode, buf, sizeof buf);

                log_error("Bad pattern \"%s\": %s",
                          pattern,
                          r < 0 ? "unknown error" : (char*) buf);
                return -EINVAL;
        }

        *out = p;
        return 0;
}

#endif

enum {
        /* Special values for arg_lines */
        ARG_LINES_DEFAULT = -2,
        ARG_LINES_ALL = -1,
};

static OutputMode arg_output = OUTPUT_SHORT;
static bool arg_utc = false;
static bool arg_pager_end = false;
static bool arg_follow = false;
static bool arg_full = true;
static bool arg_all = false;
static bool arg_no_pager = false;
static int arg_lines = ARG_LINES_DEFAULT;
static bool arg_no_tail = false;
static bool arg_quiet = false;
static bool arg_merge = false;
static bool arg_boot = false;
static sd_id128_t arg_boot_id = {};
static int arg_boot_offset = 0;
static bool arg_dmesg = false;
static bool arg_no_hostname = false;
static const char *arg_cursor = NULL;
static const char *arg_after_cursor = NULL;
static bool arg_show_cursor = false;
static const char *arg_directory = NULL;
static char **arg_file = NULL;
static bool arg_file_stdin = false;
static int arg_priorities = 0xFF;
static char *arg_verify_key = NULL;
#if HAVE_GCRYPT
static usec_t arg_interval = DEFAULT_FSS_INTERVAL_USEC;
static bool arg_force = false;
#endif
static usec_t arg_since, arg_until;
static bool arg_since_set = false, arg_until_set = false;
static char **arg_syslog_identifier = NULL;
static char **arg_system_units = NULL;
static char **arg_user_units = NULL;
static const char *arg_field = NULL;
static bool arg_catalog = false;
static bool arg_reverse = false;
static int arg_journal_type = 0;
static char *arg_root = NULL;
static const char *arg_machine = NULL;
static uint64_t arg_vacuum_size = 0;
static uint64_t arg_vacuum_n_files = 0;
static usec_t arg_vacuum_time = 0;
static char **arg_output_fields = NULL;

#if HAVE_PCRE2
static const char *arg_pattern = NULL;
static pcre2_code *arg_compiled_pattern = NULL;
static int arg_case_sensitive = -1; /* -1 means be smart */
#endif

static enum {
        ACTION_SHOW,
        ACTION_NEW_ID128,
        ACTION_PRINT_HEADER,
        ACTION_SETUP_KEYS,
        ACTION_VERIFY,
        ACTION_DISK_USAGE,
        ACTION_LIST_CATALOG,
        ACTION_DUMP_CATALOG,
        ACTION_UPDATE_CATALOG,
        ACTION_LIST_BOOTS,
        ACTION_FLUSH,
        ACTION_SYNC,
        ACTION_ROTATE,
        ACTION_VACUUM,
        ACTION_ROTATE_AND_VACUUM,
        ACTION_LIST_FIELDS,
        ACTION_LIST_FIELD_NAMES,
} arg_action = ACTION_SHOW;

typedef struct BootId {
        sd_id128_t id;
        uint64_t first;
        uint64_t last;
        LIST_FIELDS(struct BootId, boot_list);
} BootId;

static int add_matches_for_device(sd_journal *j, const char *devpath) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        sd_device *d = NULL;
        struct stat st;
        int r;

        assert(j);
        assert(devpath);

        if (!path_startswith(devpath, "/dev/")) {
                log_error("Devpath does not start with /dev/");
                return -EINVAL;
        }

        if (stat(devpath, &st) < 0)
                return log_error_errno(errno, "Couldn't stat file: %m");

        r = device_new_from_stat_rdev(&device, &st);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from devnum %u:%u: %m", major(st.st_rdev), minor(st.st_rdev));

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

                        r = asprintf(&match1, "_KERNEL_DEVICE=%c%u:%u", S_ISBLK(st.st_mode) ? 'b' : 'c', major(st.st_rdev), minor(st.st_rdev));
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

static char *format_timestamp_maybe_utc(char *buf, size_t l, usec_t t) {

        if (arg_utc)
                return format_timestamp_utc(buf, l, t);

        return format_timestamp(buf, l, t);
}

static int parse_boot_descriptor(const char *x, sd_id128_t *boot_id, int *offset) {
        sd_id128_t id = SD_ID128_NULL;
        int off = 0, r;

        if (strlen(x) >= 32) {
                char *t;

                t = strndupa(x, 32);
                r = sd_id128_from_string(t, &id);
                if (r >= 0)
                        x += 32;

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

        if (boot_id)
                *boot_id = id;

        if (offset)
                *offset = off;

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        (void) pager_open(arg_no_pager, arg_pager_end);

        r = terminal_urlify_man("journalctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [MATCHES...]\n\n"
               "Query the journal.\n\n"
               "Options:\n"
               "     --system                Show the system journal\n"
               "     --user                  Show the user journal for the current user\n"
               "  -M --machine=CONTAINER     Operate on local container\n"
               "  -S --since=DATE            Show entries not older than the specified date\n"
               "  -U --until=DATE            Show entries not newer than the specified date\n"
               "  -c --cursor=CURSOR         Show entries starting at the specified cursor\n"
               "     --after-cursor=CURSOR   Show entries after the specified cursor\n"
               "     --show-cursor           Print the cursor after all the entries\n"
               "  -b --boot[=ID]             Show current boot or the specified boot\n"
               "     --list-boots            Show terse information about recorded boots\n"
               "  -k --dmesg                 Show kernel message log from the current boot\n"
               "  -u --unit=UNIT             Show logs from the specified unit\n"
               "     --user-unit=UNIT        Show logs from the specified user unit\n"
               "  -t --identifier=STRING     Show entries with the specified syslog identifier\n"
               "  -p --priority=RANGE        Show entries with the specified priority\n"
               "  -g --grep=PATTERN          Show entries with MESSAGE matching PATTERN\n"
               "     --case-sensitive[=BOOL] Force case sensitive or insenstive matching\n"
               "  -e --pager-end             Immediately jump to the end in the pager\n"
               "  -f --follow                Follow the journal\n"
               "  -n --lines[=INTEGER]       Number of journal entries to show\n"
               "     --no-tail               Show all lines, even in follow mode\n"
               "  -r --reverse               Show the newest entries first\n"
               "  -o --output=STRING         Change journal output mode (short, short-precise,\n"
               "                               short-iso, short-iso-precise, short-full,\n"
               "                               short-monotonic, short-unix, verbose, export,\n"
               "                               json, json-pretty, json-sse, json-seq, cat,\n"
               "                               with-unit)\n"
               "     --output-fields=LIST    Select fields to print in verbose/export/json modes\n"
               "     --utc                   Express time in Coordinated Universal Time (UTC)\n"
               "  -x --catalog               Add message explanations where available\n"
               "     --no-full               Ellipsize fields\n"
               "  -a --all                   Show all fields, including long and unprintable\n"
               "  -q --quiet                 Do not show info messages and privilege warning\n"
               "     --no-pager              Do not pipe output into a pager\n"
               "     --no-hostname           Suppress output of hostname field\n"
               "  -m --merge                 Show entries from all available journals\n"
               "  -D --directory=PATH        Show journal files from directory\n"
               "     --file=PATH             Show journal file\n"
               "     --root=ROOT             Operate on files below a root directory\n"
               "     --interval=TIME         Time interval for changing the FSS sealing key\n"
               "     --verify-key=KEY        Specify FSS verification key\n"
               "     --force                 Override of the FSS key pair with --setup-keys\n"
               "\nCommands:\n"
               "  -h --help                  Show this help text\n"
               "     --version               Show package version\n"
               "  -N --fields                List all field names currently used\n"
               "  -F --field=FIELD           List all values that a specified field takes\n"
               "     --disk-usage            Show total disk usage of all journal files\n"
               "     --vacuum-size=BYTES     Reduce disk usage below specified size\n"
               "     --vacuum-files=INT      Leave only the specified number of journal files\n"
               "     --vacuum-time=TIME      Remove journal files older than specified time\n"
               "     --verify                Verify journal file consistency\n"
               "     --sync                  Synchronize unwritten journal messages to disk\n"
               "     --flush                 Flush all journal data from /run into /var\n"
               "     --rotate                Request immediate rotation of the journal files\n"
               "     --header                Show journal header information\n"
               "     --list-catalog          Show all message IDs in the catalog\n"
               "     --dump-catalog          Show entries in the message catalog\n"
               "     --update-catalog        Update the message catalog database\n"
               "     --setup-keys            Generate a new FSS key pair\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

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
                ARG_USER,
                ARG_SYSTEM,
                ARG_ROOT,
                ARG_HEADER,
                ARG_SETUP_KEYS,
                ARG_FILE,
                ARG_INTERVAL,
                ARG_VERIFY,
                ARG_VERIFY_KEY,
                ARG_DISK_USAGE,
                ARG_AFTER_CURSOR,
                ARG_SHOW_CURSOR,
                ARG_USER_UNIT,
                ARG_LIST_CATALOG,
                ARG_DUMP_CATALOG,
                ARG_UPDATE_CATALOG,
                ARG_FORCE,
                ARG_CASE_SENSITIVE,
                ARG_UTC,
                ARG_SYNC,
                ARG_FLUSH,
                ARG_ROTATE,
                ARG_VACUUM_SIZE,
                ARG_VACUUM_FILES,
                ARG_VACUUM_TIME,
                ARG_NO_HOSTNAME,
                ARG_OUTPUT_FIELDS,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "version" ,       no_argument,       NULL, ARG_VERSION        },
                { "no-pager",       no_argument,       NULL, ARG_NO_PAGER       },
                { "pager-end",      no_argument,       NULL, 'e'                },
                { "follow",         no_argument,       NULL, 'f'                },
                { "force",          no_argument,       NULL, ARG_FORCE          },
                { "output",         required_argument, NULL, 'o'                },
                { "all",            no_argument,       NULL, 'a'                },
                { "full",           no_argument,       NULL, 'l'                },
                { "no-full",        no_argument,       NULL, ARG_NO_FULL        },
                { "lines",          optional_argument, NULL, 'n'                },
                { "no-tail",        no_argument,       NULL, ARG_NO_TAIL        },
                { "new-id128",      no_argument,       NULL, ARG_NEW_ID128      }, /* deprecated */
                { "quiet",          no_argument,       NULL, 'q'                },
                { "merge",          no_argument,       NULL, 'm'                },
                { "this-boot",      no_argument,       NULL, ARG_THIS_BOOT      }, /* deprecated */
                { "boot",           optional_argument, NULL, 'b'                },
                { "list-boots",     no_argument,       NULL, ARG_LIST_BOOTS     },
                { "dmesg",          no_argument,       NULL, 'k'                },
                { "system",         no_argument,       NULL, ARG_SYSTEM         },
                { "user",           no_argument,       NULL, ARG_USER           },
                { "directory",      required_argument, NULL, 'D'                },
                { "file",           required_argument, NULL, ARG_FILE           },
                { "root",           required_argument, NULL, ARG_ROOT           },
                { "header",         no_argument,       NULL, ARG_HEADER         },
                { "identifier",     required_argument, NULL, 't'                },
                { "priority",       required_argument, NULL, 'p'                },
                { "grep",           required_argument, NULL, 'g'                },
                { "case-sensitive", optional_argument, NULL, ARG_CASE_SENSITIVE },
                { "setup-keys",     no_argument,       NULL, ARG_SETUP_KEYS     },
                { "interval",       required_argument, NULL, ARG_INTERVAL       },
                { "verify",         no_argument,       NULL, ARG_VERIFY         },
                { "verify-key",     required_argument, NULL, ARG_VERIFY_KEY     },
                { "disk-usage",     no_argument,       NULL, ARG_DISK_USAGE     },
                { "cursor",         required_argument, NULL, 'c'                },
                { "after-cursor",   required_argument, NULL, ARG_AFTER_CURSOR   },
                { "show-cursor",    no_argument,       NULL, ARG_SHOW_CURSOR    },
                { "since",          required_argument, NULL, 'S'                },
                { "until",          required_argument, NULL, 'U'                },
                { "unit",           required_argument, NULL, 'u'                },
                { "user-unit",      required_argument, NULL, ARG_USER_UNIT      },
                { "field",          required_argument, NULL, 'F'                },
                { "fields",         no_argument,       NULL, 'N'                },
                { "catalog",        no_argument,       NULL, 'x'                },
                { "list-catalog",   no_argument,       NULL, ARG_LIST_CATALOG   },
                { "dump-catalog",   no_argument,       NULL, ARG_DUMP_CATALOG   },
                { "update-catalog", no_argument,       NULL, ARG_UPDATE_CATALOG },
                { "reverse",        no_argument,       NULL, 'r'                },
                { "machine",        required_argument, NULL, 'M'                },
                { "utc",            no_argument,       NULL, ARG_UTC            },
                { "flush",          no_argument,       NULL, ARG_FLUSH          },
                { "sync",           no_argument,       NULL, ARG_SYNC           },
                { "rotate",         no_argument,       NULL, ARG_ROTATE         },
                { "vacuum-size",    required_argument, NULL, ARG_VACUUM_SIZE    },
                { "vacuum-files",   required_argument, NULL, ARG_VACUUM_FILES   },
                { "vacuum-time",    required_argument, NULL, ARG_VACUUM_TIME    },
                { "no-hostname",    no_argument,       NULL, ARG_NO_HOSTNAME    },
                { "output-fields",  required_argument, NULL, ARG_OUTPUT_FIELDS  },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hefo:aln::qmb::kD:p:g:c:S:U:t:u:NF:xrM:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case 'e':
                        arg_pager_end = true;

                        if (arg_lines == ARG_LINES_DEFAULT)
                                arg_lines = 1000;

                        break;

                case 'f':
                        arg_follow = true;
                        break;

                case 'o':
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);
                                return 0;
                        }

                        arg_output = output_mode_from_string(optarg);
                        if (arg_output < 0) {
                                log_error("Unknown output format '%s'.", optarg);
                                return -EINVAL;
                        }

                        if (IN_SET(arg_output, OUTPUT_EXPORT, OUTPUT_JSON, OUTPUT_JSON_PRETTY, OUTPUT_JSON_SSE, OUTPUT_JSON_SEQ, OUTPUT_CAT))
                                arg_quiet = true;

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
                        if (optarg) {
                                if (streq(optarg, "all"))
                                        arg_lines = ARG_LINES_ALL;
                                else {
                                        r = safe_atoi(optarg, &arg_lines);
                                        if (r < 0 || arg_lines < 0) {
                                                log_error("Failed to parse lines '%s'", optarg);
                                                return -EINVAL;
                                        }
                                }
                        } else {
                                arg_lines = 10;

                                /* Hmm, no argument? Maybe the next
                                 * word on the command line is
                                 * supposed to be the argument? Let's
                                 * see if there is one, and is
                                 * parsable. */
                                if (optind < argc) {
                                        int n;
                                        if (streq(argv[optind], "all")) {
                                                arg_lines = ARG_LINES_ALL;
                                                optind++;
                                        } else if (safe_atoi(argv[optind], &n) >= 0 && n >= 0) {
                                                arg_lines = n;
                                                optind++;
                                        }
                                }
                        }

                        break;

                case ARG_NO_TAIL:
                        arg_no_tail = true;
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
                        break;

                case 'b':
                        arg_boot = true;

                        if (optarg) {
                                r = parse_boot_descriptor(optarg, &arg_boot_id, &arg_boot_offset);
                                if (r < 0) {
                                        log_error("Failed to parse boot descriptor '%s'", optarg);
                                        return -EINVAL;
                                }
                        } else {

                                /* Hmm, no argument? Maybe the next
                                 * word on the command line is
                                 * supposed to be the argument? Let's
                                 * see if there is one and is parsable
                                 * as a boot descriptor... */

                                if (optind < argc &&
                                    parse_boot_descriptor(argv[optind], &arg_boot_id, &arg_boot_offset) >= 0)
                                        optind++;
                        }

                        break;

                case ARG_LIST_BOOTS:
                        arg_action = ACTION_LIST_BOOTS;
                        break;

                case 'k':
                        arg_boot = arg_dmesg = true;
                        break;

                case ARG_SYSTEM:
                        arg_journal_type |= SD_JOURNAL_SYSTEM;
                        break;

                case ARG_USER:
                        arg_journal_type |= SD_JOURNAL_CURRENT_USER;
                        break;

                case 'M':
                        arg_machine = optarg;
                        break;

                case 'D':
                        arg_directory = optarg;
                        break;

                case ARG_FILE:
                        if (streq(optarg, "-"))
                                /* An undocumented feature: we can read journal files from STDIN. We don't document
                                 * this though, since after all we only support this for mmap-able, seekable files, and
                                 * not for example pipes which are probably the primary usecase for reading things from
                                 * STDIN. To avoid confusion we hence don't document this feature. */
                                arg_file_stdin = true;
                        else {
                                r = glob_extend(&arg_file, optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add paths: %m");
                        }
                        break;

                case ARG_ROOT:
                        r = parse_path_argument_and_warn(optarg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case 'c':
                        arg_cursor = optarg;
                        break;

                case ARG_AFTER_CURSOR:
                        arg_after_cursor = optarg;
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
                        if (r < 0) {
                                log_error("Failed to parse vacuum size: %s", optarg);
                                return r;
                        }

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

                case ARG_VACUUM_FILES:
                        r = safe_atou64(optarg, &arg_vacuum_n_files);
                        if (r < 0) {
                                log_error("Failed to parse vacuum files: %s", optarg);
                                return r;
                        }

                        arg_action = arg_action == ACTION_ROTATE ? ACTION_ROTATE_AND_VACUUM : ACTION_VACUUM;
                        break;

                case ARG_VACUUM_TIME:
                        r = parse_sec(optarg, &arg_vacuum_time);
                        if (r < 0) {
                                log_error("Failed to parse vacuum time: %s", optarg);
                                return r;
                        }

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
                        arg_action = ACTION_VERIFY;
                        r = free_and_strdup(&arg_verify_key, optarg);
                        if (r < 0)
                                return r;
                        /* Use memset not string_erase so this doesn't look confusing
                         * in ps or htop output. */
                        memset(optarg, 'x', strlen(optarg));

                        arg_merge = false;
                        break;

                case ARG_INTERVAL:
                        r = parse_sec(optarg, &arg_interval);
                        if (r < 0 || arg_interval <= 0) {
                                log_error("Failed to parse sealing key change interval: %s", optarg);
                                return -EINVAL;
                        }
                        break;
#else
                case ARG_SETUP_KEYS:
                case ARG_VERIFY_KEY:
                case ARG_INTERVAL:
                case ARG_FORCE:
                        log_error("Compiled without forward-secure sealing support.");
                        return -EOPNOTSUPP;
#endif

                case 'p': {
                        const char *dots;

                        dots = strstr(optarg, "..");
                        if (dots) {
                                char *a;
                                int from, to, i;

                                /* a range */
                                a = strndup(optarg, dots - optarg);
                                if (!a)
                                        return log_oom();

                                from = log_level_from_string(a);
                                to = log_level_from_string(dots + 2);
                                free(a);

                                if (from < 0 || to < 0) {
                                        log_error("Failed to parse log level range %s", optarg);
                                        return -EINVAL;
                                }

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
                                if (p < 0) {
                                        log_error("Unknown log level %s", optarg);
                                        return -EINVAL;
                                }

                                arg_priorities = 0;

                                for (i = 0; i <= p; i++)
                                        arg_priorities |= 1 << i;
                        }

                        break;
                }

#if HAVE_PCRE2
                case 'g':
                        arg_pattern = optarg;
                        break;

                case ARG_CASE_SENSITIVE:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Bad --case-sensitive= argument \"%s\": %m", optarg);
                                arg_case_sensitive = r;
                        } else
                                arg_case_sensitive = true;

                        break;
#else
                case 'g':
                case ARG_CASE_SENSITIVE:
                        return log_error("Compiled without pattern matching support");
#endif

                case 'S':
                        r = parse_timestamp(optarg, &arg_since);
                        if (r < 0) {
                                log_error("Failed to parse timestamp: %s", optarg);
                                return -EINVAL;
                        }
                        arg_since_set = true;
                        break;

                case 'U':
                        r = parse_timestamp(optarg, &arg_until);
                        if (r < 0) {
                                log_error("Failed to parse timestamp: %s", optarg);
                                return -EINVAL;
                        }
                        arg_until_set = true;
                        break;

                case 't':
                        r = strv_extend(&arg_syslog_identifier, optarg);
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

                case 'F':
                        arg_action = ACTION_LIST_FIELDS;
                        arg_field = optarg;
                        break;

                case 'N':
                        arg_action = ACTION_LIST_FIELD_NAMES;
                        break;

                case ARG_NO_HOSTNAME:
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

                        if (!arg_output_fields)
                                arg_output_fields = TAKE_PTR(v);
                        else {
                                r = strv_extend_strv(&arg_output_fields, v, true);
                                if (r < 0)
                                        return log_oom();
                        }
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_follow && !arg_no_tail && !arg_since && arg_lines == ARG_LINES_DEFAULT)
                arg_lines = 10;

        if (!!arg_directory + !!arg_file + !!arg_machine + !!arg_root > 1) {
                log_error("Please specify at most one of -D/--directory=, --file=, -M/--machine=, --root.");
                return -EINVAL;
        }

        if (arg_since_set && arg_until_set && arg_since > arg_until) {
                log_error("--since= must be before --until=.");
                return -EINVAL;
        }

        if (!!arg_cursor + !!arg_after_cursor + !!arg_since_set > 1) {
                log_error("Please specify only one of --since=, --cursor=, and --after-cursor.");
                return -EINVAL;
        }

        if (arg_follow && arg_reverse) {
                log_error("Please specify either --reverse= or --follow=, not both.");
                return -EINVAL;
        }

        if (!IN_SET(arg_action, ACTION_SHOW, ACTION_DUMP_CATALOG, ACTION_LIST_CATALOG) && optind < argc) {
                log_error("Extraneous arguments starting with '%s'", argv[optind]);
                return -EINVAL;
        }

        if ((arg_boot || arg_action == ACTION_LIST_BOOTS) && arg_merge) {
                log_error("Using --boot or --list-boots with --merge is not supported.");
                return -EINVAL;
        }

        if (!strv_isempty(arg_system_units) && arg_journal_type == SD_JOURNAL_CURRENT_USER) {
                /* Specifying --user and --unit= at the same time makes no sense (as the former excludes the user
                 * journal, but the latter excludes the system journal, thus resulting in empty output). Let's be nice
                 * to users, and automatically turn --unit= into --user-unit= if combined with --user. */
                r = strv_extend_strv(&arg_user_units, arg_system_units, true);
                if (r < 0)
                        return r;

                arg_system_units = strv_free(arg_system_units);
        }

#if HAVE_PCRE2
        if (arg_pattern) {
                unsigned flags;

                if (arg_case_sensitive >= 0)
                        flags = !arg_case_sensitive * PCRE2_CASELESS;
                else {
                        _cleanup_(pcre2_match_data_freep) pcre2_match_data *md = NULL;
                        bool has_case;
                        _cleanup_(pcre2_code_freep) pcre2_code *cs = NULL;

                        md = pcre2_match_data_create(1, NULL);
                        if (!md)
                                return log_oom();

                        r = pattern_compile("[[:upper:]]", 0, &cs);
                        if (r < 0)
                                return r;

                        r = pcre2_match(cs, (PCRE2_SPTR8) arg_pattern, PCRE2_ZERO_TERMINATED, 0, 0, md, NULL);
                        has_case = r >= 0;

                        flags = !has_case * PCRE2_CASELESS;
                }

                log_debug("Doing case %s matching based on %s",
                          flags & PCRE2_CASELESS ? "insensitive" : "sensitive",
                          arg_case_sensitive >= 0 ? "request" : "pattern casing");

                r = pattern_compile(arg_pattern, flags, &arg_compiled_pattern);
                if (r < 0)
                        return r;
        }
#endif

        return 1;
}

static int add_matches(sd_journal *j, char **args) {
        char **i;
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

                        r = chase_symlinks(*i, NULL, CHASE_TRAIL_SLASH, &p);
                        if (r < 0)
                                return log_error_errno(r, "Couldn't canonicalize path: %m");

                        if (lstat(p, &st) < 0)
                                return log_error_errno(errno, "Couldn't stat file: %m");

                        if (S_ISREG(st.st_mode) && (0111 & st.st_mode)) {
                                if (executable_is_script(p, &interpreter) > 0) {
                                        _cleanup_free_ char *comm;

                                        comm = strndup(basename(p), 15);
                                        if (!comm)
                                                return log_oom();

                                        t = strappend("_COMM=", comm);
                                        if (!t)
                                                return log_oom();

                                        /* Append _EXE only if the interpreter is not a link.
                                           Otherwise, it might be outdated often. */
                                        if (lstat(interpreter, &st) == 0 && !S_ISLNK(st.st_mode)) {
                                                t2 = strappend("_EXE=", interpreter);
                                                if (!t2)
                                                        return log_oom();
                                        }
                                } else {
                                        t = strappend("_EXE=", p);
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
                        } else {
                                log_error("File is neither a device node, nor regular file, nor executable: %s", *i);
                                return -EINVAL;
                        }

                        have_term = true;
                } else {
                        r = sd_journal_add_match(j, *i, 0);
                        have_term = true;
                }

                if (r < 0)
                        return log_error_errno(r, "Failed to add match '%s': %m", *i);
        }

        if (!strv_isempty(args) && !have_term) {
                log_error("\"+\" can only be used between terms");
                return -EINVAL;
        }

        return 0;
}

static void boot_id_free_all(BootId *l) {

        while (l) {
                BootId *i = l;
                LIST_REMOVE(boot_list, l, i);
                free(i);
        }
}

static int discover_next_boot(sd_journal *j,
                sd_id128_t previous_boot_id,
                bool advance_older,
                BootId **ret) {

        _cleanup_free_ BootId *next_boot = NULL;
        char match[9+32+1] = "_BOOT_ID=";
        sd_id128_t boot_id;
        int r;

        assert(j);
        assert(ret);

        /* We expect the journal to be on the last position of a boot
         * (in relation to the direction we are going), so that the next
         * invocation of sd_journal_next/previous will be from a different
         * boot. We then collect any information we desire and then jump
         * to the last location of the new boot by using a _BOOT_ID match
         * coming from the other journal direction. */

        /* Make sure we aren't restricted by any _BOOT_ID matches, so that
         * we can actually advance to a *different* boot. */
        sd_journal_flush_matches(j);

        do {
                if (advance_older)
                        r = sd_journal_previous(j);
                else
                        r = sd_journal_next(j);
                if (r < 0)
                        return r;
                else if (r == 0)
                        return 0; /* End of journal, yay. */

                r = sd_journal_get_monotonic_usec(j, NULL, &boot_id);
                if (r < 0)
                        return r;

                /* We iterate through this in a loop, until the boot ID differs from the previous one. Note that
                 * normally, this will only require a single iteration, as we seeked to the last entry of the previous
                 * boot entry already. However, it might happen that the per-journal-field entry arrays are less
                 * complete than the main entry array, and hence might reference an entry that's not actually the last
                 * one of the boot ID as last one. Let's hence use the per-field array is initial seek position to
                 * speed things up, but let's not trust that it is complete, and hence, manually advance as
                 * necessary. */

        } while (sd_id128_equal(boot_id, previous_boot_id));

        next_boot = new0(BootId, 1);
        if (!next_boot)
                return -ENOMEM;

        next_boot->id = boot_id;

        r = sd_journal_get_realtime_usec(j, &next_boot->first);
        if (r < 0)
                return r;

        /* Now seek to the last occurrence of this boot ID. */
        sd_id128_to_string(next_boot->id, match + 9);
        r = sd_journal_add_match(j, match, sizeof(match) - 1);
        if (r < 0)
                return r;

        if (advance_older)
                r = sd_journal_seek_head(j);
        else
                r = sd_journal_seek_tail(j);
        if (r < 0)
                return r;

        if (advance_older)
                r = sd_journal_next(j);
        else
                r = sd_journal_previous(j);
        if (r < 0)
                return r;
        else if (r == 0) {
                log_debug("Whoopsie! We found a boot ID but can't read its last entry.");
                return -ENODATA; /* This shouldn't happen. We just came from this very boot ID. */
        }

        r = sd_journal_get_realtime_usec(j, &next_boot->last);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(next_boot);

        return 0;
}

static int get_boots(
                sd_journal *j,
                BootId **boots,
                sd_id128_t *boot_id,
                int offset) {

        bool skip_once;
        int r, count = 0;
        BootId *head = NULL, *tail = NULL, *id;
        const bool advance_older = boot_id && offset <= 0;
        sd_id128_t previous_boot_id;

        assert(j);

        /* Adjust for the asymmetry that offset 0 is
         * the last (and current) boot, while 1 is considered the
         * (chronological) first boot in the journal. */
        skip_once = boot_id && sd_id128_is_null(*boot_id) && offset <= 0;

        /* Advance to the earliest/latest occurrence of our reference
         * boot ID (taking our lookup direction into account), so that
         * discover_next_boot() can do its job.
         * If no reference is given, the journal head/tail will do,
         * they're "virtual" boots after all. */
        if (boot_id && !sd_id128_is_null(*boot_id)) {
                char match[9+32+1] = "_BOOT_ID=";

                sd_journal_flush_matches(j);

                sd_id128_to_string(*boot_id, match + 9);
                r = sd_journal_add_match(j, match, sizeof(match) - 1);
                if (r < 0)
                        return r;

                if (advance_older)
                        r = sd_journal_seek_head(j); /* seek to oldest */
                else
                        r = sd_journal_seek_tail(j); /* seek to newest */
                if (r < 0)
                        return r;

                if (advance_older)
                        r = sd_journal_next(j);     /* read the oldest entry */
                else
                        r = sd_journal_previous(j); /* read the most recently added entry */
                if (r < 0)
                        return r;
                else if (r == 0)
                        goto finish;
                else if (offset == 0) {
                        count = 1;
                        goto finish;
                }

                /* At this point the read pointer is positioned at the oldest/newest occurence of the reference boot
                 * ID. After flushing the matches, one more invocation of _previous()/_next() will hence place us at
                 * the following entry, which must then have an older/newer boot ID */
        } else {

                if (advance_older)
                        r = sd_journal_seek_tail(j); /* seek to newest */
                else
                        r = sd_journal_seek_head(j); /* seek to oldest */
                if (r < 0)
                        return r;

                /* No sd_journal_next()/_previous() here.
                 *
                 * At this point the read pointer is positioned after the newest/before the oldest entry in the whole
                 * journal. The next invocation of _previous()/_next() will hence position us at the newest/oldest
                 * entry we have. */
        }

        previous_boot_id = SD_ID128_NULL;
        for (;;) {
                _cleanup_free_ BootId *current = NULL;

                r = discover_next_boot(j, previous_boot_id, advance_older, &current);
                if (r < 0) {
                        boot_id_free_all(head);
                        return r;
                }

                if (!current)
                        break;

                previous_boot_id = current->id;

                if (boot_id) {
                        if (!skip_once)
                                offset += advance_older ? 1 : -1;
                        skip_once = false;

                        if (offset == 0) {
                                count = 1;
                                *boot_id = current->id;
                                break;
                        }
                } else {
                        LIST_FOREACH(boot_list, id, head) {
                                if (sd_id128_equal(id->id, current->id)) {
                                        /* boot id already stored, something wrong with the journal files */
                                        /* exiting as otherwise this problem would cause forever loop */
                                        goto finish;
                                }
                        }
                        LIST_INSERT_AFTER(boot_list, head, tail, current);
                        tail = TAKE_PTR(current);
                        count++;
                }
        }

finish:
        if (boots)
                *boots = head;

        sd_journal_flush_matches(j);

        return count;
}

static int list_boots(sd_journal *j) {
        int w, i, count;
        BootId *id, *all_ids;

        assert(j);

        count = get_boots(j, &all_ids, NULL, 0);
        if (count < 0)
                return log_error_errno(count, "Failed to determine boots: %m");
        if (count == 0)
                return count;

        (void) pager_open(arg_no_pager, arg_pager_end);

        /* numbers are one less, but we need an extra char for the sign */
        w = DECIMAL_STR_WIDTH(count - 1) + 1;

        i = 0;
        LIST_FOREACH(boot_list, id, all_ids) {
                char a[FORMAT_TIMESTAMP_MAX], b[FORMAT_TIMESTAMP_MAX];

                printf("% *i " SD_ID128_FORMAT_STR " %s—%s\n",
                       w, i - count + 1,
                       SD_ID128_FORMAT_VAL(id->id),
                       format_timestamp_maybe_utc(a, sizeof(a), id->first),
                       format_timestamp_maybe_utc(b, sizeof(b), id->last));
                i++;
        }

        boot_id_free_all(all_ids);

        return 0;
}

static int add_boot(sd_journal *j) {
        char match[9+32+1] = "_BOOT_ID=";
        sd_id128_t boot_id;
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

        boot_id = arg_boot_id;
        r = get_boots(j, NULL, &boot_id, arg_boot_offset);
        assert(r <= 1);
        if (r <= 0) {
                const char *reason = (r == 0) ? "No such boot ID in journal" : strerror(-r);

                if (sd_id128_is_null(arg_boot_id))
                        log_error("Data from the specified boot (%+i) is not available: %s",
                                  arg_boot_offset, reason);
                else
                        log_error("Data from the specified boot ("SD_ID128_FORMAT_STR") is not available: %s",
                                  SD_ID128_FORMAT_VAL(arg_boot_id), reason);

                return r == 0 ? -ENODATA : r;
        }

        sd_id128_to_string(boot_id, match + 9);

        r = sd_journal_add_match(j, match, sizeof(match) - 1);
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

        _cleanup_set_free_free_ Set *found;
        const char *field;
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
                        char **pattern, *eq;
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
        "OBJECT_SYSTEMD_USER_UNIT\0"

static int add_units(sd_journal *j) {
        _cleanup_strv_free_ char **patterns = NULL;
        int r, count = 0;
        char **i;

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
                Iterator it;
                char *u;

                r = get_possible_units(j, SYSTEM_UNITS, patterns, &units);
                if (r < 0)
                        return r;

                SET_FOREACH(u, units, it) {
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
                Iterator it;
                char *u;

                r = get_possible_units(j, USER_UNITS, patterns, &units);
                if (r < 0)
                        return r;

                SET_FOREACH(u, units, it) {
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

static int add_syslog_identifier(sd_journal *j) {
        int r;
        char **i;

        assert(j);

        STRV_FOREACH(i, arg_syslog_identifier) {
                char *u;

                u = strjoina("SYSLOG_IDENTIFIER=", *i);
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

static int setup_keys(void) {
#if HAVE_GCRYPT
        size_t mpk_size, seed_size, state_size, i;
        uint8_t *mpk, *seed, *state;
        int fd = -1, r;
        sd_id128_t machine, boot;
        char *p = NULL, *k = NULL;
        struct FSSHeader h;
        uint64_t n;
        struct stat st;

        r = stat("/var/log/journal", &st);
        if (r < 0 && !IN_SET(errno, ENOENT, ENOTDIR))
                return log_error_errno(errno, "stat(\"%s\") failed: %m", "/var/log/journal");

        if (r < 0 || !S_ISDIR(st.st_mode)) {
                log_error("%s is not a directory, must be using persistent logging for FSS.",
                          "/var/log/journal");
                return r < 0 ? -errno : -ENOTDIR;
        }

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine ID: %m");

        r = sd_id128_get_boot(&boot);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID: %m");

        if (asprintf(&p, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return log_oom();

        if (arg_force) {
                r = unlink(p);
                if (r < 0 && errno != ENOENT) {
                        r = log_error_errno(errno, "unlink(\"%s\") failed: %m", p);
                        goto finish;
                }
        } else if (access(p, F_OK) >= 0) {
                log_error("Sealing key file %s exists already. Use --force to recreate.", p);
                r = -EEXIST;
                goto finish;
        }

        if (asprintf(&k, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss.tmp.XXXXXX",
                     SD_ID128_FORMAT_VAL(machine)) < 0) {
                r = log_oom();
                goto finish;
        }

        mpk_size = FSPRG_mskinbytes(FSPRG_RECOMMENDED_SECPAR);
        mpk = alloca(mpk_size);

        seed_size = FSPRG_RECOMMENDED_SEEDLEN;
        seed = alloca(seed_size);

        state_size = FSPRG_stateinbytes(FSPRG_RECOMMENDED_SECPAR);
        state = alloca(state_size);

        fd = open("/dev/random", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                r = log_error_errno(errno, "Failed to open /dev/random: %m");
                goto finish;
        }

        log_info("Generating seed...");
        r = loop_read_exact(fd, seed, seed_size, true);
        if (r < 0) {
                log_error_errno(r, "Failed to read random seed: %m");
                goto finish;
        }

        log_info("Generating key pair...");
        FSPRG_GenMK(NULL, mpk, seed, seed_size, FSPRG_RECOMMENDED_SECPAR);

        log_info("Generating sealing key...");
        FSPRG_GenState0(state, mpk, seed, seed_size);

        assert(arg_interval > 0);

        n = now(CLOCK_REALTIME);
        n /= arg_interval;

        safe_close(fd);
        fd = mkostemp_safe(k);
        if (fd < 0) {
                r = log_error_errno(fd, "Failed to open %s: %m", k);
                goto finish;
        }

        /* Enable secure remove, exclusion from dump, synchronous
         * writing and in-place updating */
        r = chattr_fd(fd, FS_SECRM_FL|FS_NODUMP_FL|FS_SYNC_FL|FS_NOCOW_FL, FS_SECRM_FL|FS_NODUMP_FL|FS_SYNC_FL|FS_NOCOW_FL, NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to set file attributes: %m");

        zero(h);
        memcpy(h.signature, "KSHHRHLP", 8);
        h.machine_id = machine;
        h.boot_id = boot;
        h.header_size = htole64(sizeof(h));
        h.start_usec = htole64(n * arg_interval);
        h.interval_usec = htole64(arg_interval);
        h.fsprg_secpar = htole16(FSPRG_RECOMMENDED_SECPAR);
        h.fsprg_state_size = htole64(state_size);

        r = loop_write(fd, &h, sizeof(h), false);
        if (r < 0) {
                log_error_errno(r, "Failed to write header: %m");
                goto finish;
        }

        r = loop_write(fd, state, state_size, false);
        if (r < 0) {
                log_error_errno(r, "Failed to write state: %m");
                goto finish;
        }

        if (link(k, p) < 0) {
                r = log_error_errno(errno, "Failed to link file: %m");
                goto finish;
        }

        if (on_tty()) {
                fprintf(stderr,
                        "\n"
                        "The new key pair has been generated. The %ssecret sealing key%s has been written to\n"
                        "the following local file. This key file is automatically updated when the\n"
                        "sealing key is advanced. It should not be used on multiple hosts.\n"
                        "\n"
                        "\t%s\n"
                        "\n"
                        "Please write down the following %ssecret verification key%s. It should be stored\n"
                        "at a safe location and should not be saved locally on disk.\n"
                        "\n\t%s",
                        ansi_highlight(), ansi_normal(),
                        p,
                        ansi_highlight(), ansi_normal(),
                        ansi_highlight_red());
                fflush(stderr);
        }
        for (i = 0; i < seed_size; i++) {
                if (i > 0 && i % 3 == 0)
                        putchar('-');
                printf("%02x", ((uint8_t*) seed)[i]);
        }

        printf("/%llx-%llx\n", (unsigned long long) n, (unsigned long long) arg_interval);

        if (on_tty()) {
                char tsb[FORMAT_TIMESPAN_MAX], *hn;

                fprintf(stderr,
                        "%s\n"
                        "The sealing key is automatically changed every %s.\n",
                        ansi_normal(),
                        format_timespan(tsb, sizeof(tsb), arg_interval, 0));

                hn = gethostname_malloc();

                if (hn) {
                        hostname_cleanup(hn);
                        fprintf(stderr, "\nThe keys have been generated for host %s/" SD_ID128_FORMAT_STR ".\n", hn, SD_ID128_FORMAT_VAL(machine));
                } else
                        fprintf(stderr, "\nThe keys have been generated for host " SD_ID128_FORMAT_STR ".\n", SD_ID128_FORMAT_VAL(machine));

#if HAVE_QRENCODE
                /* If this is not an UTF-8 system don't print any QR codes */
                if (is_locale_utf8()) {
                        fputs("\nTo transfer the verification key to your phone please scan the QR code below:\n\n", stderr);
                        print_qr_code(stderr, seed, seed_size, n, arg_interval, hn, machine);
                }
#endif
                free(hn);
        }

        r = 0;

finish:
        safe_close(fd);

        if (k) {
                unlink(k);
                free(k);
        }

        free(p);

        return r;
#else
        log_error("Forward-secure sealing not available.");
        return -EOPNOTSUPP;
#endif
}

static int verify(sd_journal *j) {
        int r = 0;
        Iterator i;
        JournalFile *f;

        assert(j);

        log_show_color(true);

        ORDERED_HASHMAP_FOREACH(f, j->files, i) {
                int k;
                usec_t first = 0, validated = 0, last = 0;

#if HAVE_GCRYPT
                if (!arg_verify_key && JOURNAL_HEADER_SEALED(f->header))
                        log_notice("Journal file %s has sealing enabled but verification key has not been passed using --verify-key=.", f->path);
#endif

                k = journal_file_verify(f, arg_verify_key, &first, &validated, &last, true);
                if (k == -EINVAL) {
                        /* If the key was invalid give up right-away. */
                        return k;
                } else if (k < 0) {
                        log_warning_errno(k, "FAIL: %s (%m)", f->path);
                        r = k;
                } else {
                        char a[FORMAT_TIMESTAMP_MAX], b[FORMAT_TIMESTAMP_MAX], c[FORMAT_TIMESPAN_MAX];
                        log_info("PASS: %s", f->path);

                        if (arg_verify_key && JOURNAL_HEADER_SEALED(f->header)) {
                                if (validated > 0) {
                                        log_info("=> Validated from %s to %s, final %s entries not sealed.",
                                                 format_timestamp_maybe_utc(a, sizeof(a), first),
                                                 format_timestamp_maybe_utc(b, sizeof(b), validated),
                                                 format_timespan(c, sizeof(c), last > validated ? last - validated : 0, 0));
                                } else if (last > 0)
                                        log_info("=> No sealing yet, %s of entries not sealed.",
                                                 format_timespan(c, sizeof(c), last - first, 0));
                                else
                                        log_info("=> No sealing yet, no entries in file.");
                        }
                }
        }

        return r;
}

static int flush_to_var(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int watch_fd = -1;
        int r;

        if (arg_machine) {
                log_error("--flush is not supported in conjunction with --machine=.");
                return -EOPNOTSUPP;
        }

        /* Quick exit */
        if (access("/run/systemd/journal/flushed", F_OK) >= 0)
                return 0;

        /* OK, let's actually do the full logic, send SIGUSR1 to the
         * daemon and set up inotify to wait for the flushed file to appear */
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get D-Bus connection: %m");

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "KillUnit",
                        &error,
                        NULL,
                        "ssi", "systemd-journald.service", "main", SIGUSR1);
        if (r < 0)
                return log_error_errno(r, "Failed to kill journal service: %s", bus_error_message(&error, r));

        mkdir_p("/run/systemd/journal", 0755);

        watch_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (watch_fd < 0)
                return log_error_errno(errno, "Failed to create inotify watch: %m");

        r = inotify_add_watch(watch_fd, "/run/systemd/journal", IN_CREATE|IN_DONT_FOLLOW|IN_ONLYDIR);
        if (r < 0)
                return log_error_errno(errno, "Failed to watch journal directory: %m");

        for (;;) {
                if (access("/run/systemd/journal/flushed", F_OK) >= 0)
                        break;

                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check for existence of /run/systemd/journal/flushed: %m");

                r = fd_wait_for_event(watch_fd, POLLIN, USEC_INFINITY);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for event: %m");

                r = flush_fd(watch_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to flush inotify events: %m");
        }

        return 0;
}

static int send_signal_and_wait(int sig, const char *watch_path) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int watch_fd = -1;
        usec_t start;
        int r;

        if (arg_machine) {
                log_error("--sync and --rotate are not supported in conjunction with --machine=.");
                return -EOPNOTSUPP;
        }

        start = now(CLOCK_MONOTONIC);

        /* This call sends the specified signal to journald, and waits
         * for acknowledgment by watching the mtime of the specified
         * flag file. This is used to trigger syncing or rotation and
         * then wait for the operation to complete. */

        for (;;) {
                usec_t tstamp;

                /* See if a sync happened by now. */
                r = read_timestamp_file(watch_path, &tstamp);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read %s: %m", watch_path);
                if (r >= 0 && tstamp >= start)
                        return 0;

                /* Let's ask for a sync, but only once. */
                if (!bus) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                        r = bus_connect_system_systemd(&bus);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get D-Bus connection: %m");

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.systemd1",
                                        "/org/freedesktop/systemd1",
                                        "org.freedesktop.systemd1.Manager",
                                        "KillUnit",
                                        &error,
                                        NULL,
                                        "ssi", "systemd-journald.service", "main", sig);
                        if (r < 0)
                                return log_error_errno(r, "Failed to kill journal service: %s", bus_error_message(&error, r));

                        continue;
                }

                /* Let's install the inotify watch, if we didn't do that yet. */
                if (watch_fd < 0) {

                        mkdir_p("/run/systemd/journal", 0755);

                        watch_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                        if (watch_fd < 0)
                                return log_error_errno(errno, "Failed to create inotify watch: %m");

                        r = inotify_add_watch(watch_fd, "/run/systemd/journal", IN_MOVED_TO|IN_DONT_FOLLOW|IN_ONLYDIR);
                        if (r < 0)
                                return log_error_errno(errno, "Failed to watch journal directory: %m");

                        /* Recheck the flag file immediately, so that we don't miss any event since the last check. */
                        continue;
                }

                /* OK, all preparatory steps done, let's wait until
                 * inotify reports an event. */

                r = fd_wait_for_event(watch_fd, POLLIN, USEC_INFINITY);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for event: %m");

                r = flush_fd(watch_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to flush inotify events: %m");
        }

        return 0;
}

static int rotate(void) {
        return send_signal_and_wait(SIGUSR2, "/run/systemd/journal/rotated");
}

static int sync_journal(void) {
        return send_signal_and_wait(SIGRTMIN+1, "/run/systemd/journal/synced");
}

static int wait_for_change(sd_journal *j, int poll_fd) {
        struct pollfd pollfds[] = {
                { .fd = poll_fd, .events = POLLIN },
                { .fd = STDOUT_FILENO },
        };

        struct timespec ts;
        usec_t timeout;
        int r;

        assert(j);
        assert(poll_fd >= 0);

        /* Much like sd_journal_wait() but also keeps an eye on STDOUT, and exits as soon as we see a POLLHUP on that,
         * i.e. when it is closed. */

        r = sd_journal_get_timeout(j, &timeout);
        if (r < 0)
                return log_error_errno(r, "Failed to determine journal waiting time: %m");

        if (ppoll(pollfds, ELEMENTSOF(pollfds), timeout == USEC_INFINITY ? NULL : timespec_store(&ts, timeout), NULL) < 0)
                return log_error_errno(errno, "Couldn't wait for journal event: %m");

        if (pollfds[1].revents & (POLLHUP|POLLERR)) { /* STDOUT has been closed? */
                log_debug("Standard output has been closed.");
                return -ECANCELED;
        }

        r = sd_journal_process(j);
        if (r < 0)
                return log_error_errno(r, "Failed to process journal events: %m");

        return 0;
}

int main(int argc, char *argv[]) {
        bool previous_boot_id_valid = false, first_line = true, ellipsized = false, need_seek = false;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        sd_id128_t previous_boot_id;
        int n_shown = 0, r, poll_fd = -1;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        /* Increase max number of open files if we can, we might needs this when browsing journal files, which might be
         * split up into many files. */
        (void) rlimit_nofile_bump(HIGH_RLIMIT_NOFILE);

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        signal(SIGWINCH, columns_lines_cache_reset);
        sigbus_install();

        switch (arg_action) {

        case ACTION_NEW_ID128:
                r = id128_print_new(true);
                goto finish;

        case ACTION_SETUP_KEYS:
                r = setup_keys();
                goto finish;

        case ACTION_LIST_CATALOG:
        case ACTION_DUMP_CATALOG:
        case ACTION_UPDATE_CATALOG: {
                _cleanup_free_ char *database;

                database = path_join(arg_root, CATALOG_DATABASE, NULL);
                if (!database) {
                        r = log_oom();
                        goto finish;
                }

                if (arg_action == ACTION_UPDATE_CATALOG) {
                        r = catalog_update(database, arg_root, catalog_file_dirs);
                        if (r < 0)
                                log_error_errno(r, "Failed to list catalog: %m");
                } else {
                        bool oneline = arg_action == ACTION_LIST_CATALOG;

                        (void) pager_open(arg_no_pager, arg_pager_end);

                        if (optind < argc)
                                r = catalog_list_items(stdout, database, oneline, argv + optind);
                        else
                                r = catalog_list(stdout, database, oneline);
                        if (r < 0)
                                log_error_errno(r, "Failed to list catalog: %m");
                }

                goto finish;
        }

        case ACTION_FLUSH:
                r = flush_to_var();
                goto finish;

        case ACTION_SYNC:
                r = sync_journal();
                goto finish;

        case ACTION_ROTATE:
                r = rotate();
                goto finish;

        case ACTION_SHOW:
        case ACTION_PRINT_HEADER:
        case ACTION_VERIFY:
        case ACTION_DISK_USAGE:
        case ACTION_LIST_BOOTS:
        case ACTION_VACUUM:
        case ACTION_ROTATE_AND_VACUUM:
        case ACTION_LIST_FIELDS:
        case ACTION_LIST_FIELD_NAMES:
                /* These ones require access to the journal files, continue below. */
                break;

        default:
                assert_not_reached("Unknown action");
        }

        if (arg_directory)
                r = sd_journal_open_directory(&j, arg_directory, arg_journal_type);
        else if (arg_root)
                r = sd_journal_open_directory(&j, arg_root, arg_journal_type | SD_JOURNAL_OS_ROOT);
        else if (arg_file_stdin) {
                int ifd = STDIN_FILENO;
                r = sd_journal_open_files_fd(&j, &ifd, 1, 0);
        } else if (arg_file)
                r = sd_journal_open_files(&j, (const char**) arg_file, 0);
        else if (arg_machine) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                int fd;

                if (geteuid() != 0) {
                        /* The file descriptor returned by OpenMachineRootDirectory() will be owned by users/groups of
                         * the container, thus we need root privileges to override them. */
                        log_error("Using the --machine= switch requires root privileges.");
                        r = -EPERM;
                        goto finish;
                }

                r = sd_bus_open_system(&bus);
                if (r < 0) {
                        log_error_errno(r, "Failed to open system bus: %m");
                        goto finish;
                }

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "OpenMachineRootDirectory",
                                &error,
                                &reply,
                                "s", arg_machine);
                if (r < 0) {
                        log_error_errno(r, "Failed to open root directory: %s", bus_error_message(&error, r));
                        goto finish;
                }

                r = sd_bus_message_read(reply, "h", &fd);
                if (r < 0) {
                        bus_log_parse_error(r);
                        goto finish;
                }

                fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (fd < 0) {
                        r = log_error_errno(errno, "Failed to duplicate file descriptor: %m");
                        goto finish;
                }

                r = sd_journal_open_directory_fd(&j, fd, SD_JOURNAL_OS_ROOT);
                if (r < 0)
                        safe_close(fd);
        } else
                r = sd_journal_open(&j, !arg_merge*SD_JOURNAL_LOCAL_ONLY + arg_journal_type);
        if (r < 0) {
                log_error_errno(r, "Failed to open %s: %m", arg_directory ?: arg_file ? "files" : "journal");
                goto finish;
        }

        r = journal_access_check_and_warn(j, arg_quiet,
                                          !(arg_journal_type == SD_JOURNAL_CURRENT_USER || arg_user_units));
        if (r < 0)
                goto finish;

        switch (arg_action) {

        case ACTION_NEW_ID128:
        case ACTION_SETUP_KEYS:
        case ACTION_LIST_CATALOG:
        case ACTION_DUMP_CATALOG:
        case ACTION_UPDATE_CATALOG:
        case ACTION_FLUSH:
        case ACTION_SYNC:
        case ACTION_ROTATE:
                assert_not_reached("Unexpected action.");

        case ACTION_PRINT_HEADER:
                journal_print_header(j);
                r = 0;
                goto finish;

        case ACTION_VERIFY:
                r = verify(j);
                goto finish;

        case ACTION_DISK_USAGE: {
                uint64_t bytes = 0;
                char sbytes[FORMAT_BYTES_MAX];

                r = sd_journal_get_usage(j, &bytes);
                if (r < 0)
                        goto finish;

                printf("Archived and active journals take up %s in the file system.\n",
                       format_bytes(sbytes, sizeof(sbytes), bytes));
                goto finish;
        }

        case ACTION_LIST_BOOTS:
                r = list_boots(j);
                goto finish;

        case ACTION_ROTATE_AND_VACUUM:

                r = rotate();
                if (r < 0)
                        goto finish;

                _fallthrough_;

        case ACTION_VACUUM: {
                Directory *d;
                Iterator i;

                HASHMAP_FOREACH(d, j->directories_by_path, i) {
                        int q;

                        if (d->is_root)
                                continue;

                        q = journal_directory_vacuum(d->path, arg_vacuum_size, arg_vacuum_n_files, arg_vacuum_time, NULL, !arg_quiet);
                        if (q < 0) {
                                log_error_errno(q, "Failed to vacuum %s: %m", d->path);
                                r = q;
                        }
                }

                goto finish;
        }

        case ACTION_LIST_FIELD_NAMES: {
                const char *field;

                SD_JOURNAL_FOREACH_FIELD(j, field) {
                        printf("%s\n", field);
                        n_shown++;
                }

                r = 0;
                goto finish;
        }

        case ACTION_SHOW:
        case ACTION_LIST_FIELDS:
                break;

        default:
                assert_not_reached("Unknown action");
        }

        if (arg_boot_offset != 0 &&
            sd_journal_has_runtime_files(j) > 0 &&
            sd_journal_has_persistent_files(j) == 0) {
                log_info("Specifying boot ID or boot offset has no effect, no persistent journal was found.");
                r = 0;
                goto finish;
        }
        /* add_boot() must be called first!
         * It may need to seek the journal to find parent boot IDs. */
        r = add_boot(j);
        if (r < 0)
                goto finish;

        r = add_dmesg(j);
        if (r < 0)
                goto finish;

        r = add_units(j);
        if (r < 0) {
                log_error_errno(r, "Failed to add filter for units: %m");
                goto finish;
        }

        r = add_syslog_identifier(j);
        if (r < 0) {
                log_error_errno(r, "Failed to add filter for syslog identifiers: %m");
                goto finish;
        }

        r = add_priorities(j);
        if (r < 0)
                goto finish;

        r = add_matches(j, argv + optind);
        if (r < 0)
                goto finish;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *filter;

                filter = journal_make_match_string(j);
                if (!filter)
                        return log_oom();

                log_debug("Journal filter: %s", filter);
        }

        if (arg_action == ACTION_LIST_FIELDS) {
                const void *data;
                size_t size;

                assert(arg_field);

                r = sd_journal_set_data_threshold(j, 0);
                if (r < 0) {
                        log_error_errno(r, "Failed to unset data size threshold: %m");
                        goto finish;
                }

                r = sd_journal_query_unique(j, arg_field);
                if (r < 0) {
                        log_error_errno(r, "Failed to query unique data objects: %m");
                        goto finish;
                }

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

                r = 0;
                goto finish;
        }

        /* Opening the fd now means the first sd_journal_wait() will actually wait */
        if (arg_follow) {
                poll_fd = sd_journal_get_fd(j);
                if (poll_fd == -EMFILE) {
                        log_warning_errno(poll_fd, "Insufficent watch descriptors available. Reverting to -n.");
                        arg_follow = false;
                } else if (poll_fd == -EMEDIUMTYPE) {
                        log_error_errno(poll_fd, "The --follow switch is not supported in conjunction with reading from STDIN.");
                        goto finish;
                } else if (poll_fd < 0) {
                        log_error_errno(poll_fd, "Failed to get journal fd: %m");
                        goto finish;
                }
        }

        if (arg_cursor || arg_after_cursor) {
                r = sd_journal_seek_cursor(j, arg_cursor ?: arg_after_cursor);
                if (r < 0) {
                        log_error_errno(r, "Failed to seek to cursor: %m");
                        goto finish;
                }

                if (!arg_reverse)
                        r = sd_journal_next_skip(j, 1 + !!arg_after_cursor);
                else
                        r = sd_journal_previous_skip(j, 1 + !!arg_after_cursor);

                if (arg_after_cursor && r < 2) {
                        /* We couldn't find the next entry after the cursor. */
                        if (arg_follow)
                                need_seek = true;
                        else
                                arg_lines = 0;
                }

        } else if (arg_since_set && !arg_reverse) {
                r = sd_journal_seek_realtime_usec(j, arg_since);
                if (r < 0) {
                        log_error_errno(r, "Failed to seek to date: %m");
                        goto finish;
                }
                r = sd_journal_next(j);

        } else if (arg_until_set && arg_reverse) {
                r = sd_journal_seek_realtime_usec(j, arg_until);
                if (r < 0) {
                        log_error_errno(r, "Failed to seek to date: %m");
                        goto finish;
                }
                r = sd_journal_previous(j);

        } else if (arg_lines >= 0) {
                r = sd_journal_seek_tail(j);
                if (r < 0) {
                        log_error_errno(r, "Failed to seek to tail: %m");
                        goto finish;
                }

                r = sd_journal_previous_skip(j, arg_lines);

        } else if (arg_reverse) {
                r = sd_journal_seek_tail(j);
                if (r < 0) {
                        log_error_errno(r, "Failed to seek to tail: %m");
                        goto finish;
                }

                r = sd_journal_previous(j);

        } else {
                r = sd_journal_seek_head(j);
                if (r < 0) {
                        log_error_errno(r, "Failed to seek to head: %m");
                        goto finish;
                }

                r = sd_journal_next(j);
        }

        if (r < 0) {
                log_error_errno(r, "Failed to iterate through journal: %m");
                goto finish;
        }
        if (r == 0)
                need_seek = true;

        if (!arg_follow)
                (void) pager_open(arg_no_pager, arg_pager_end);

        if (!arg_quiet && (arg_lines != 0 || arg_follow)) {
                usec_t start, end;
                char start_buf[FORMAT_TIMESTAMP_MAX], end_buf[FORMAT_TIMESTAMP_MAX];

                r = sd_journal_get_cutoff_realtime_usec(j, &start, &end);
                if (r < 0) {
                        log_error_errno(r, "Failed to get cutoff: %m");
                        goto finish;
                }

                if (r > 0) {
                        if (arg_follow)
                                printf("-- Logs begin at %s. --\n",
                                       format_timestamp_maybe_utc(start_buf, sizeof(start_buf), start));
                        else
                                printf("-- Logs begin at %s, end at %s. --\n",
                                       format_timestamp_maybe_utc(start_buf, sizeof(start_buf), start),
                                       format_timestamp_maybe_utc(end_buf, sizeof(end_buf), end));
                }
        }

        for (;;) {
                while (arg_lines < 0 || n_shown < arg_lines || (arg_follow && !first_line)) {
                        int flags;
                        size_t highlight[2] = {};

                        if (need_seek) {
                                if (!arg_reverse)
                                        r = sd_journal_next(j);
                                else
                                        r = sd_journal_previous(j);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to iterate through journal: %m");
                                        goto finish;
                                }
                                if (r == 0)
                                        break;
                        }

                        if (arg_until_set && !arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to determine timestamp: %m");
                                        goto finish;
                                }
                                if (usec > arg_until)
                                        goto finish;
                        }

                        if (arg_since_set && arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to determine timestamp: %m");
                                        goto finish;
                                }
                                if (usec < arg_since)
                                        goto finish;
                        }

                        if (!arg_merge && !arg_quiet) {
                                sd_id128_t boot_id;

                                r = sd_journal_get_monotonic_usec(j, NULL, &boot_id);
                                if (r >= 0) {
                                        if (previous_boot_id_valid &&
                                            !sd_id128_equal(boot_id, previous_boot_id))
                                                printf("%s-- Reboot --%s\n",
                                                       ansi_highlight(), ansi_normal());

                                        previous_boot_id = boot_id;
                                        previous_boot_id_valid = true;
                                }
                        }

#if HAVE_PCRE2
                        if (arg_compiled_pattern) {
                                _cleanup_(pcre2_match_data_freep) pcre2_match_data *md = NULL;
                                const void *message;
                                size_t len;
                                PCRE2_SIZE *ovec;

                                md = pcre2_match_data_create(1, NULL);
                                if (!md)
                                        return log_oom();

                                r = sd_journal_get_data(j, "MESSAGE", &message, &len);
                                if (r < 0) {
                                        if (r == -ENOENT) {
                                                need_seek = true;
                                                continue;
                                        }

                                        log_error_errno(r, "Failed to get MESSAGE field: %m");
                                        goto finish;
                                }

                                assert_se(message = startswith(message, "MESSAGE="));

                                r = pcre2_match(arg_compiled_pattern,
                                                message,
                                                len - strlen("MESSAGE="),
                                                0,      /* start at offset 0 in the subject */
                                                0,      /* default options */
                                                md,
                                                NULL);
                                if (r == PCRE2_ERROR_NOMATCH) {
                                        need_seek = true;
                                        continue;
                                }
                                if (r < 0) {
                                        unsigned char buf[LINE_MAX];
                                        int r2;

                                        r2 = pcre2_get_error_message(r, buf, sizeof buf);
                                        log_error("Pattern matching failed: %s",
                                                  r2 < 0 ? "unknown error" : (char*) buf);
                                        r = -EINVAL;
                                        goto finish;
                                }

                                ovec = pcre2_get_ovector_pointer(md);
                                highlight[0] = ovec[0];
                                highlight[1] = ovec[1];
                        }
#endif

                        flags =
                                arg_all * OUTPUT_SHOW_ALL |
                                arg_full * OUTPUT_FULL_WIDTH |
                                colors_enabled() * OUTPUT_COLOR |
                                arg_catalog * OUTPUT_CATALOG |
                                arg_utc * OUTPUT_UTC |
                                arg_no_hostname * OUTPUT_NO_HOSTNAME;

                        r = show_journal_entry(stdout, j, arg_output, 0, flags,
                                               arg_output_fields, highlight, &ellipsized);
                        need_seek = true;
                        if (r == -EADDRNOTAVAIL)
                                break;
                        else if (r < 0)
                                goto finish;

                        n_shown++;

                        /* If journalctl take a long time to process messages, and during that time journal file
                         * rotation occurs, a journalctl client will keep those rotated files open until it calls
                         * sd_journal_process(), which typically happens as a result of calling sd_journal_wait() below
                         * in the "following" case.  By periodically calling sd_journal_process() during the processing
                         * loop we shrink the window of time a client instance has open file descriptors for rotated
                         * (deleted) journal files. */
                        if ((n_shown % PROCESS_INOTIFY_INTERVAL) == 0) {
                                r = sd_journal_process(j);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to process inotify events: %m");
                                        goto finish;
                                }
                        }
                }

                if (!arg_follow) {
                        if (n_shown == 0 && !arg_quiet)
                                printf("-- No entries --\n");

                        if (arg_show_cursor) {
                                _cleanup_free_ char *cursor = NULL;

                                r = sd_journal_get_cursor(j, &cursor);
                                if (r < 0 && r != -EADDRNOTAVAIL)
                                        log_error_errno(r, "Failed to get cursor: %m");
                                else if (r >= 0)
                                        printf("-- cursor: %s\n", cursor);
                        }

                        break;
                }

                fflush(stdout);

                r = wait_for_change(j, poll_fd);
                if (r < 0)
                        goto finish;

                first_line = false;
        }

finish:
        fflush(stdout);
        pager_close();

        strv_free(arg_file);

        strv_free(arg_syslog_identifier);
        strv_free(arg_system_units);
        strv_free(arg_user_units);
        strv_free(arg_output_fields);

        free(arg_root);
        free(arg_verify_key);

#if HAVE_PCRE2
        if (arg_compiled_pattern)
                pcre2_code_free(arg_compiled_pattern);
#endif

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
