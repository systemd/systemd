/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <locale.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <linux/fs.h>

#include "sd-journal.h"
#include "sd-bus.h"
#include "log.h"
#include "logs-show.h"
#include "util.h"
#include "acl-util.h"
#include "path-util.h"
#include "fileio.h"
#include "build.h"
#include "pager.h"
#include "strv.h"
#include "set.h"
#include "sigbus.h"
#include "journal-internal.h"
#include "journal-def.h"
#include "journal-verify.h"
#include "journal-qrcode.h"
#include "journal-vacuum.h"
#include "fsprg.h"
#include "unit-name.h"
#include "catalog.h"
#include "mkdir.h"
#include "bus-util.h"
#include "bus-error.h"
#include "terminal-util.h"
#include "hostname-util.h"

#define DEFAULT_FSS_INTERVAL_USEC (15*USEC_PER_MINUTE)

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
static const char *arg_cursor = NULL;
static const char *arg_after_cursor = NULL;
static bool arg_show_cursor = false;
static const char *arg_directory = NULL;
static char **arg_file = NULL;
static int arg_priorities = 0xFF;
static const char *arg_verify_key = NULL;
#ifdef HAVE_GCRYPT
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
static const char *arg_root = NULL;
static const char *arg_machine = NULL;
static off_t arg_vacuum_size = (off_t) -1;
static usec_t arg_vacuum_time = USEC_INFINITY;

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
        ACTION_VACUUM,
} arg_action = ACTION_SHOW;

typedef struct BootId {
        sd_id128_t id;
        uint64_t first;
        uint64_t last;
        LIST_FIELDS(struct BootId, boot_list);
} BootId;

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(arg_pager_end);
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

                if (*x != '-' && *x != '+' && *x != 0)
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

static void help(void) {

        pager_open_if_enabled();

        printf("%s [OPTIONS...] [MATCHES...]\n\n"
               "Query the journal.\n\n"
               "Flags:\n"
               "     --system              Show the system journal\n"
               "     --user                Show the user journal for the current user\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "     --since=DATE          Show entries not older than the specified date\n"
               "     --until=DATE          Show entries not newer than the specified date\n"
               "  -c --cursor=CURSOR       Show entries starting at the specified cursor\n"
               "     --after-cursor=CURSOR Show entries after the specified cursor\n"
               "     --show-cursor         Print the cursor after all the entries\n"
               "  -b --boot[=ID]           Show current boot or the specified boot\n"
               "     --list-boots          Show terse information about recorded boots\n"
               "  -k --dmesg               Show kernel message log from the current boot\n"
               "  -u --unit=UNIT           Show logs from the specified unit\n"
               "     --user-unit=UNIT      Show logs from the specified user unit\n"
               "  -t --identifier=STRING   Show entries with the specified syslog identifier\n"
               "  -p --priority=RANGE      Show entries with the specified priority\n"
               "  -e --pager-end           Immediately jump to the end in the pager\n"
               "  -f --follow              Follow the journal\n"
               "  -n --lines[=INTEGER]     Number of journal entries to show\n"
               "     --no-tail             Show all lines, even in follow mode\n"
               "  -r --reverse             Show the newest entries first\n"
               "  -o --output=STRING       Change journal output mode (short, short-iso,\n"
               "                                   short-precise, short-monotonic, verbose,\n"
               "                                   export, json, json-pretty, json-sse, cat)\n"
               "     --utc                 Express time in Coordinated Universal Time (UTC)\n"
               "  -x --catalog             Add message explanations where available\n"
               "     --no-full             Ellipsize fields\n"
               "  -a --all                 Show all fields, including long and unprintable\n"
               "  -q --quiet               Do not show privilege warning\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "  -m --merge               Show entries from all available journals\n"
               "  -D --directory=PATH      Show journal files from directory\n"
               "     --file=PATH           Show journal file\n"
               "     --root=ROOT           Operate on catalog files underneath the root ROOT\n"
#ifdef HAVE_GCRYPT
               "     --interval=TIME       Time interval for changing the FSS sealing key\n"
               "     --verify-key=KEY      Specify FSS verification key\n"
               "     --force               Override of the FSS key pair with --setup-keys\n"
#endif
               "\nCommands:\n"
               "  -h --help                Show this help text\n"
               "     --version             Show package version\n"
               "  -F --field=FIELD         List all values that a specified field takes\n"
               "     --new-id128           Generate a new 128-bit ID\n"
               "     --disk-usage          Show total disk usage of all journal files\n"
               "     --vacuum-size=BYTES   Reduce disk usage below specified size\n"
               "     --vacuum-time=TIME    Remove journal files older than specified date\n"
               "     --flush               Flush all journal data from /run into /var\n"
               "     --header              Show journal header information\n"
               "     --list-catalog        Show all message IDs in the catalog\n"
               "     --dump-catalog        Show entries in the message catalog\n"
               "     --update-catalog      Update the message catalog database\n"
#ifdef HAVE_GCRYPT
               "     --setup-keys          Generate a new FSS key pair\n"
               "     --verify              Verify journal file consistency\n"
#endif
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_FULL,
                ARG_NO_TAIL,
                ARG_NEW_ID128,
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
                ARG_SINCE,
                ARG_UNTIL,
                ARG_AFTER_CURSOR,
                ARG_SHOW_CURSOR,
                ARG_USER_UNIT,
                ARG_LIST_CATALOG,
                ARG_DUMP_CATALOG,
                ARG_UPDATE_CATALOG,
                ARG_FORCE,
                ARG_UTC,
                ARG_FLUSH,
                ARG_VACUUM_SIZE,
                ARG_VACUUM_TIME,
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
                { "new-id128",      no_argument,       NULL, ARG_NEW_ID128      },
                { "quiet",          no_argument,       NULL, 'q'                },
                { "merge",          no_argument,       NULL, 'm'                },
                { "boot",           optional_argument, NULL, 'b'                },
                { "list-boots",     no_argument,       NULL, ARG_LIST_BOOTS     },
                { "this-boot",      optional_argument, NULL, 'b'                }, /* deprecated */
                { "dmesg",          no_argument,       NULL, 'k'                },
                { "system",         no_argument,       NULL, ARG_SYSTEM         },
                { "user",           no_argument,       NULL, ARG_USER           },
                { "directory",      required_argument, NULL, 'D'                },
                { "file",           required_argument, NULL, ARG_FILE           },
                { "root",           required_argument, NULL, ARG_ROOT           },
                { "header",         no_argument,       NULL, ARG_HEADER         },
                { "identifier",     required_argument, NULL, 't'                },
                { "priority",       required_argument, NULL, 'p'                },
                { "setup-keys",     no_argument,       NULL, ARG_SETUP_KEYS     },
                { "interval",       required_argument, NULL, ARG_INTERVAL       },
                { "verify",         no_argument,       NULL, ARG_VERIFY         },
                { "verify-key",     required_argument, NULL, ARG_VERIFY_KEY     },
                { "disk-usage",     no_argument,       NULL, ARG_DISK_USAGE     },
                { "cursor",         required_argument, NULL, 'c'                },
                { "after-cursor",   required_argument, NULL, ARG_AFTER_CURSOR   },
                { "show-cursor",    no_argument,       NULL, ARG_SHOW_CURSOR    },
                { "since",          required_argument, NULL, ARG_SINCE          },
                { "until",          required_argument, NULL, ARG_UNTIL          },
                { "unit",           required_argument, NULL, 'u'                },
                { "user-unit",      required_argument, NULL, ARG_USER_UNIT      },
                { "field",          required_argument, NULL, 'F'                },
                { "catalog",        no_argument,       NULL, 'x'                },
                { "list-catalog",   no_argument,       NULL, ARG_LIST_CATALOG   },
                { "dump-catalog",   no_argument,       NULL, ARG_DUMP_CATALOG   },
                { "update-catalog", no_argument,       NULL, ARG_UPDATE_CATALOG },
                { "reverse",        no_argument,       NULL, 'r'                },
                { "machine",        required_argument, NULL, 'M'                },
                { "utc",            no_argument,       NULL, ARG_UTC            },
                { "flush",          no_argument,       NULL, ARG_FLUSH          },
                { "vacuum-size",    required_argument, NULL, ARG_VACUUM_SIZE    },
                { "vacuum-time",    required_argument, NULL, ARG_VACUUM_TIME    },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hefo:aln::qmb::kD:p:c:t:u:F:xrM:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

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
                        arg_output = output_mode_from_string(optarg);
                        if (arg_output < 0) {
                                log_error("Unknown output format '%s'.", optarg);
                                return -EINVAL;
                        }

                        if (arg_output == OUTPUT_EXPORT ||
                            arg_output == OUTPUT_JSON ||
                            arg_output == OUTPUT_JSON_PRETTY ||
                            arg_output == OUTPUT_JSON_SSE ||
                            arg_output == OUTPUT_CAT)
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
                        r = glob_extend(&arg_file, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add paths: %m");
                        break;

                case ARG_ROOT:
                        arg_root = optarg;
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

                        arg_action = ACTION_VACUUM;
                        break;

                case ARG_VACUUM_TIME:
                        r = parse_sec(optarg, &arg_vacuum_time);
                        if (r < 0) {
                                log_error("Failed to parse vacuum time: %s", optarg);
                                return r;
                        }

                        arg_action = ACTION_VACUUM;
                        break;

#ifdef HAVE_GCRYPT
                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_SETUP_KEYS:
                        arg_action = ACTION_SETUP_KEYS;
                        break;


                case ARG_VERIFY_KEY:
                        arg_action = ACTION_VERIFY;
                        arg_verify_key = optarg;
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
                        log_error("Forward-secure sealing not available.");
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

                case ARG_SINCE:
                        r = parse_timestamp(optarg, &arg_since);
                        if (r < 0) {
                                log_error("Failed to parse timestamp: %s", optarg);
                                return -EINVAL;
                        }
                        arg_since_set = true;
                        break;

                case ARG_UNTIL:
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
                        arg_field = optarg;
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_follow && !arg_no_tail && !arg_since && arg_lines == ARG_LINES_DEFAULT)
                arg_lines = 10;

        if (!!arg_directory + !!arg_file + !!arg_machine > 1) {
                log_error("Please specify either -D/--directory= or --file= or -M/--machine=, not more than one.");
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

        if (arg_action != ACTION_SHOW && optind < argc) {
                log_error("Extraneous arguments starting with '%s'", argv[optind]);
                return -EINVAL;
        }

        if ((arg_boot || arg_action == ACTION_LIST_BOOTS) && (arg_file || arg_directory || arg_merge)) {
                log_error("Using --boot or --list-boots with --file, --directory or --merge is not supported.");
                return -EINVAL;
        }

        return 1;
}

static int generate_new_id128(void) {
        sd_id128_t id;
        int r;
        unsigned i;

        r = sd_id128_randomize(&id);
        if (r < 0)
                return log_error_errno(r, "Failed to generate ID: %m");

        printf("As string:\n"
               SD_ID128_FORMAT_STR "\n\n"
               "As UUID:\n"
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n\n"
               "As macro:\n"
               "#define MESSAGE_XYZ SD_ID128_MAKE(",
               SD_ID128_FORMAT_VAL(id),
               SD_ID128_FORMAT_VAL(id));
        for (i = 0; i < 16; i++)
                printf("%02x%s", id.bytes[i], i != 15 ? "," : "");
        fputs(")\n\n", stdout);

        printf("As Python constant:\n"
               ">>> import uuid\n"
               ">>> MESSAGE_XYZ = uuid.UUID('" SD_ID128_FORMAT_STR "')\n",
               SD_ID128_FORMAT_VAL(id));

        return 0;
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
                        _cleanup_free_ char *p, *t = NULL, *t2 = NULL;
                        const char *path;
                        _cleanup_free_ char *interpreter = NULL;
                        struct stat st;

                        p = canonicalize_file_name(*i);
                        path = p ? p : *i;

                        if (lstat(path, &st) < 0)
                                return log_error_errno(errno, "Couldn't stat file: %m");

                        if (S_ISREG(st.st_mode) && (0111 & st.st_mode)) {
                                if (executable_is_script(path, &interpreter) > 0) {
                                        _cleanup_free_ char *comm;

                                        comm = strndup(basename(path), 15);
                                        if (!comm)
                                                return log_oom();

                                        t = strappend("_COMM=", comm);

                                        /* Append _EXE only if the interpreter is not a link.
                                           Otherwise, it might be outdated often. */
                                        if (lstat(interpreter, &st) == 0 &&
                                            !S_ISLNK(st.st_mode)) {
                                                t2 = strappend("_EXE=", interpreter);
                                                if (!t2)
                                                        return log_oom();
                                        }
                                } else
                                        t = strappend("_EXE=", path);
                        } else if (S_ISCHR(st.st_mode))
                                (void) asprintf(&t, "_KERNEL_DEVICE=c%u:%u", major(st.st_rdev), minor(st.st_rdev));
                        else if (S_ISBLK(st.st_mode))
                                (void) asprintf(&t, "_KERNEL_DEVICE=b%u:%u", major(st.st_rdev), minor(st.st_rdev));
                        else {
                                log_error("File is neither a device node, nor regular file, nor executable: %s", *i);
                                return -EINVAL;
                        }

                        if (!t)
                                return log_oom();

                        r = sd_journal_add_match(j, t, 0);
                        if (t2)
                                r = sd_journal_add_match(j, t2, 0);
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

static int discover_next_boot(
                sd_journal *j,
                BootId **boot,
                bool advance_older,
                bool read_realtime) {

        int r;
        char match[9+32+1] = "_BOOT_ID=";
        _cleanup_free_ BootId *next_boot = NULL;

        assert(j);
        assert(boot);

        /* We expect the journal to be on the last position of a boot
         * (in relation to the direction we are going), so that the next
         * invocation of sd_journal_next/previous will be from a different
         * boot. We then collect any information we desire and then jump
         * to the last location of the new boot by using a _BOOT_ID match
         * coming from the other journal direction. */

        /* Make sure we aren't restricted by any _BOOT_ID matches, so that
         * we can actually advance to a *different* boot. */
        sd_journal_flush_matches(j);

        if (advance_older)
                r = sd_journal_previous(j);
        else
                r = sd_journal_next(j);
        if (r < 0)
                return r;
        else if (r == 0)
                return 0; /* End of journal, yay. */

        next_boot = new0(BootId, 1);
        if (!next_boot)
                return -ENOMEM;

        r = sd_journal_get_monotonic_usec(j, NULL, &next_boot->id);
        if (r < 0)
                return r;

        if (read_realtime) {
                r = sd_journal_get_realtime_usec(j, &next_boot->first);
                if (r < 0)
                        return r;
        }

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
        else if (r == 0)
                return -ENODATA; /* This shouldn't happen. We just came from this very boot ID. */

        if (read_realtime) {
                r = sd_journal_get_realtime_usec(j, &next_boot->last);
                if (r < 0)
                        return r;
        }

        *boot = next_boot;
        next_boot = NULL;

        return 0;
}

static int get_boots(
                sd_journal *j,
                BootId **boots,
                BootId *query_ref_boot,
                int ref_boot_offset) {

        bool skip_once;
        int r, count = 0;
        BootId *head = NULL, *tail = NULL;
        const bool advance_older = query_ref_boot && ref_boot_offset <= 0;

        assert(j);

        /* Adjust for the asymmetry that offset 0 is
         * the last (and current) boot, while 1 is considered the
         * (chronological) first boot in the journal. */
        skip_once = query_ref_boot && sd_id128_is_null(query_ref_boot->id) && ref_boot_offset < 0;

        /* Advance to the earliest/latest occurrence of our reference
         * boot ID (taking our lookup direction into account), so that
         * discover_next_boot() can do its job.
         * If no reference is given, the journal head/tail will do,
         * they're "virtual" boots after all. */
        if (query_ref_boot && !sd_id128_is_null(query_ref_boot->id)) {
                char match[9+32+1] = "_BOOT_ID=";

                sd_journal_flush_matches(j);

                sd_id128_to_string(query_ref_boot->id, match + 9);
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
                else if (r == 0)
                        goto finish;
                else if (ref_boot_offset == 0) {
                        count = 1;
                        goto finish;
                }
        } else {
                if (advance_older)
                        r = sd_journal_seek_tail(j);
                else
                        r = sd_journal_seek_head(j);
                if (r < 0)
                        return r;

                /* No sd_journal_next/previous here. */
        }

        for (;;) {
                _cleanup_free_ BootId *current = NULL;

                r = discover_next_boot(j, &current, advance_older, !query_ref_boot);
                if (r < 0) {
                        boot_id_free_all(head);
                        return r;
                }

                if (!current)
                        break;

                if (query_ref_boot) {
                        if (!skip_once)
                                ref_boot_offset += advance_older ? 1 : -1;
                        skip_once = false;

                        if (ref_boot_offset == 0) {
                                count = 1;
                                query_ref_boot->id = current->id;
                                break;
                        }
                } else {
                        LIST_INSERT_AFTER(boot_list, head, tail, current);
                        tail = current;
                        current = NULL;
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

        pager_open_if_enabled();

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
        int r;
        BootId ref_boot_id = {};

        assert(j);

        if (!arg_boot)
                return 0;

        if (arg_boot_offset == 0 && sd_id128_equal(arg_boot_id, SD_ID128_NULL))
                return add_match_this_boot(j, arg_machine);

        ref_boot_id.id = arg_boot_id;
        r = get_boots(j, NULL, &ref_boot_id, arg_boot_offset);
        assert(r <= 1);
        if (r <= 0) {
                const char *reason = (r == 0) ? "No such boot ID in journal" : strerror(-r);

                if (sd_id128_is_null(arg_boot_id))
                        log_error("Failed to look up boot %+i: %s", arg_boot_offset, reason);
                else
                        log_error("Failed to look up boot ID "SD_ID128_FORMAT_STR"%+i: %s",
                                  SD_ID128_FORMAT_VAL(arg_boot_id), arg_boot_offset, reason);

                return r == 0 ? -ENODATA : r;
        }

        sd_id128_to_string(ref_boot_id.id, match + 9);

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

        r = sd_journal_add_match(j, "_TRANSPORT=kernel", strlen("_TRANSPORT=kernel"));
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

        *units = found;
        found = NULL;
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

                r = unit_name_mangle(*i, UNIT_NAME_GLOB, &u);
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
                        count ++;
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
                        count ++;
                }
        }

        strv_free(patterns);
        patterns = NULL;

        STRV_FOREACH(i, arg_user_units) {
                _cleanup_free_ char *u = NULL;

                r = unit_name_mangle(*i, UNIT_NAME_GLOB, &u);
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
                        count ++;
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
                        count ++;
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
#ifdef HAVE_GCRYPT
        size_t mpk_size, seed_size, state_size, i;
        uint8_t *mpk, *seed, *state;
        int fd = -1, r;
        sd_id128_t machine, boot;
        char *p = NULL, *k = NULL;
        struct FSSHeader h;
        uint64_t n;
        struct stat st;

        r = stat("/var/log/journal", &st);
        if (r < 0 && errno != ENOENT && errno != ENOTDIR)
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
                log_error_errno(errno, "Failed to open /dev/random: %m");
                r = -errno;
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
        fd = mkostemp_safe(k, O_WRONLY|O_CLOEXEC);
        if (fd < 0) {
                log_error_errno(errno, "Failed to open %s: %m", k);
                r = -errno;
                goto finish;
        }

        /* Enable secure remove, exclusion from dump, synchronous
         * writing and in-place updating */
        r = chattr_fd(fd, FS_SECRM_FL|FS_NODUMP_FL|FS_SYNC_FL|FS_NOCOW_FL, FS_SECRM_FL|FS_NODUMP_FL|FS_SYNC_FL|FS_NOCOW_FL);
        if (r < 0)
                log_warning_errno(errno, "Failed to set file attributes: %m");

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
                log_error_errno(errno, "Failed to link file: %m");
                r = -errno;
                goto finish;
        }

        if (on_tty()) {
                fprintf(stderr,
                        "\n"
                        "The new key pair has been generated. The " ANSI_HIGHLIGHT_ON "secret sealing key" ANSI_HIGHLIGHT_OFF " has been written to\n"
                        "the following local file. This key file is automatically updated when the\n"
                        "sealing key is advanced. It should not be used on multiple hosts.\n"
                        "\n"
                        "\t%s\n"
                        "\n"
                        "Please write down the following " ANSI_HIGHLIGHT_ON "secret verification key" ANSI_HIGHLIGHT_OFF ". It should be stored\n"
                        "at a safe location and should not be saved locally on disk.\n"
                        "\n\t" ANSI_HIGHLIGHT_RED_ON, p);
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
                        ANSI_HIGHLIGHT_OFF "\n"
                        "The sealing key is automatically changed every %s.\n",
                        format_timespan(tsb, sizeof(tsb), arg_interval, 0));

                hn = gethostname_malloc();

                if (hn) {
                        hostname_cleanup(hn, false);
                        fprintf(stderr, "\nThe keys have been generated for host %s/" SD_ID128_FORMAT_STR ".\n", hn, SD_ID128_FORMAT_VAL(machine));
                } else
                        fprintf(stderr, "\nThe keys have been generated for host " SD_ID128_FORMAT_STR ".\n", SD_ID128_FORMAT_VAL(machine));

#ifdef HAVE_QRENCODE
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

#ifdef HAVE_GCRYPT
                if (!arg_verify_key && JOURNAL_HEADER_SEALED(f->header))
                        log_notice("Journal file %s has sealing enabled but verification key has not been passed using --verify-key=.", f->path);
#endif

                k = journal_file_verify(f, arg_verify_key, &first, &validated, &last, true);
                if (k == -EINVAL) {
                        /* If the key was invalid give up right-away. */
                        return k;
                } else if (k < 0) {
                        log_warning("FAIL: %s (%s)", f->path, strerror(-k));
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

static int access_check_var_log_journal(sd_journal *j) {
#ifdef HAVE_ACL
        _cleanup_strv_free_ char **g = NULL;
        const char* dir;
#endif
        int r;

        assert(j);

        if (arg_quiet)
                return 0;

        /* If we are root, we should have access, don't warn. */
        if (getuid() == 0)
                return 0;

        /* If we are in the 'systemd-journal' group, we should have
         * access too. */
        r = in_group("systemd-journal");
        if (r < 0)
                return log_error_errno(r, "Failed to check if we are in the 'systemd-journal' group: %m");
        if (r > 0)
                return 0;

#ifdef HAVE_ACL
        if (laccess("/run/log/journal", F_OK) >= 0)
                dir = "/run/log/journal";
        else
                dir = "/var/log/journal";

        /* If we are in any of the groups listed in the journal ACLs,
         * then all is good, too. Let's enumerate all groups from the
         * default ACL of the directory, which generally should allow
         * access to most journal files too. */
        r = acl_search_groups(dir, &g);
        if (r < 0)
                return log_error_errno(r, "Failed to search journal ACL: %m");
        if (r > 0)
                return 0;

        /* Print a pretty list, if there were ACLs set. */
        if (!strv_isempty(g)) {
                _cleanup_free_ char *s = NULL;

                /* Thre are groups in the ACL, let's list them */
                r = strv_extend(&g, "systemd-journal");
                if (r < 0)
                        return log_oom();

                strv_sort(g);
                strv_uniq(g);

                s = strv_join(g, "', '");
                if (!s)
                        return log_oom();

                log_notice("Hint: You are currently not seeing messages from other users and the system.\n"
                           "      Users in groups '%s' can see all messages.\n"
                           "      Pass -q to turn off this notice.", s);
                return 1;
        }
#endif

        /* If no ACLs were found, print a short version of the message. */
        log_notice("Hint: You are currently not seeing messages from other users and the system.\n"
                   "      Users in the 'systemd-journal' group can see all messages. Pass -q to\n"
                   "      turn off this notice.");

        return 1;
}

static int access_check(sd_journal *j) {
        Iterator it;
        void *code;
        int r = 0;

        assert(j);

        if (set_isempty(j->errors)) {
                if (ordered_hashmap_isempty(j->files))
                        log_notice("No journal files were found.");

                return 0;
        }

        if (set_contains(j->errors, INT_TO_PTR(-EACCES))) {
                (void) access_check_var_log_journal(j);

                if (ordered_hashmap_isempty(j->files))
                        r = log_error_errno(EACCES, "No journal files were opened due to insufficient permissions.");
        }

        SET_FOREACH(code, j->errors, it) {
                int err;

                err = -PTR_TO_INT(code);
                assert(err > 0);

                if (err == EACCES)
                        continue;

                log_warning_errno(err, "Error was encountered while opening journal files: %m");
                if (r == 0)
                        r = -err;
        }

        return r;
}

static int flush_to_var(void) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        _cleanup_close_ int watch_fd = -1;
        int r;

        /* Quick exit */
        if (access("/run/systemd/journal/flushed", F_OK) >= 0)
                return 0;

        /* OK, let's actually do the full logic, send SIGUSR1 to the
         * daemon and set up inotify to wait for the flushed file to appear */
        r = bus_open_system_systemd(&bus);
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
        if (r < 0) {
                log_error("Failed to kill journal service: %s", bus_error_message(&error, r));
                return r;
        }

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

int main(int argc, char *argv[]) {
        int r;
        _cleanup_journal_close_ sd_journal *j = NULL;
        bool need_seek = false;
        sd_id128_t previous_boot_id;
        bool previous_boot_id_valid = false, first_line = true;
        int n_shown = 0;
        bool ellipsized = false;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        signal(SIGWINCH, columns_lines_cache_reset);
        sigbus_install();

        /* Increase max number of open files to 16K if we can, we
         * might needs this when browsing journal files, which might
         * be split up into many files. */
        setrlimit_closest(RLIMIT_NOFILE, &RLIMIT_MAKE_CONST(16384));

        if (arg_action == ACTION_NEW_ID128) {
                r = generate_new_id128();
                goto finish;
        }

        if (arg_action == ACTION_FLUSH) {
                r = flush_to_var();
                goto finish;
        }

        if (arg_action == ACTION_SETUP_KEYS) {
                r = setup_keys();
                goto finish;
        }

        if (arg_action == ACTION_UPDATE_CATALOG ||
            arg_action == ACTION_LIST_CATALOG ||
            arg_action == ACTION_DUMP_CATALOG) {

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

                        if (optind < argc)
                                r = catalog_list_items(stdout, database,
                                                       oneline, argv + optind);
                        else
                                r = catalog_list(stdout, database, oneline);
                        if (r < 0)
                                log_error_errno(r, "Failed to list catalog: %m");
                }

                goto finish;
        }

        if (arg_directory)
                r = sd_journal_open_directory(&j, arg_directory, arg_journal_type);
        else if (arg_file)
                r = sd_journal_open_files(&j, (const char**) arg_file, 0);
        else if (arg_machine)
                r = sd_journal_open_container(&j, arg_machine, 0);
        else
                r = sd_journal_open(&j, !arg_merge*SD_JOURNAL_LOCAL_ONLY + arg_journal_type);
        if (r < 0) {
                log_error_errno(r, "Failed to open %s: %m",
                                arg_directory ? arg_directory : arg_file ? "files" : "journal");
                goto finish;
        }

        r = access_check(j);
        if (r < 0)
                goto finish;

        if (arg_action == ACTION_VERIFY) {
                r = verify(j);
                goto finish;
        }

        if (arg_action == ACTION_PRINT_HEADER) {
                journal_print_header(j);
                r = 0;
                goto finish;
        }

        if (arg_action == ACTION_DISK_USAGE) {
                uint64_t bytes = 0;
                char sbytes[FORMAT_BYTES_MAX];

                r = sd_journal_get_usage(j, &bytes);
                if (r < 0)
                        goto finish;

                printf("Archived and active journals take up %s on disk.\n",
                       format_bytes(sbytes, sizeof(sbytes), bytes));
                goto finish;
        }

        if (arg_action == ACTION_VACUUM) {
                Directory *d;
                Iterator i;

                HASHMAP_FOREACH(d, j->directories_by_path, i) {
                        int q;

                        if (d->is_root)
                                continue;

                        q = journal_directory_vacuum(d->path, arg_vacuum_size, arg_vacuum_time, NULL, true);
                        if (q < 0) {
                                log_error_errno(q, "Failed to vacuum: %m");
                                r = q;
                        }
                }

                goto finish;
        }

        if (arg_action == ACTION_LIST_BOOTS) {
                r = list_boots(j);
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

        if (_unlikely_(log_get_max_level() >= LOG_DEBUG)) {
                _cleanup_free_ char *filter;

                filter = journal_make_match_string(j);
                if (!filter)
                        return log_oom();

                log_debug("Journal filter: %s", filter);
        }

        if (arg_field) {
                const void *data;
                size_t size;

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

                        n_shown ++;
                }

                r = 0;
                goto finish;
        }

        /* Opening the fd now means the first sd_journal_wait() will actually wait */
        if (arg_follow) {
                r = sd_journal_get_fd(j);
                if (r < 0) {
                        log_error_errno(r, "Failed to get journal fd: %m");
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

        if (!arg_follow)
                pager_open_if_enabled();

        if (!arg_quiet) {
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
                                                       ansi_highlight(), ansi_highlight_off());

                                        previous_boot_id = boot_id;
                                        previous_boot_id_valid = true;
                                }
                        }

                        flags =
                                arg_all * OUTPUT_SHOW_ALL |
                                arg_full * OUTPUT_FULL_WIDTH |
                                on_tty() * OUTPUT_COLOR |
                                arg_catalog * OUTPUT_CATALOG |
                                arg_utc * OUTPUT_UTC;

                        r = output_journal(stdout, j, arg_output, 0, flags, &ellipsized);
                        need_seek = true;
                        if (r == -EADDRNOTAVAIL)
                                break;
                        else if (r < 0 || ferror(stdout))
                                goto finish;

                        n_shown++;
                }

                if (!arg_follow) {
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

                r = sd_journal_wait(j, (uint64_t) -1);
                if (r < 0) {
                        log_error_errno(r, "Couldn't wait for journal event: %m");
                        goto finish;
                }

                first_line = false;
        }

finish:
        pager_close();

        strv_free(arg_file);

        strv_free(arg_syslog_identifier);
        strv_free(arg_system_units);
        strv_free(arg_user_units);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
