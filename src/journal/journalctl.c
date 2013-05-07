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
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#ifdef HAVE_ACL
#include <sys/acl.h>
#include "acl-util.h"
#endif

#include <systemd/sd-journal.h>

#include "log.h"
#include "logs-show.h"
#include "util.h"
#include "path-util.h"
#include "build.h"
#include "pager.h"
#include "logs-show.h"
#include "strv.h"
#include "journal-internal.h"
#include "journal-def.h"
#include "journal-verify.h"
#include "journal-authenticate.h"
#include "journal-qrcode.h"
#include "fsprg.h"
#include "unit-name.h"
#include "catalog.h"

#define DEFAULT_FSS_INTERVAL_USEC (15*USEC_PER_MINUTE)

static OutputMode arg_output = OUTPUT_SHORT;
static bool arg_pager_end = false;
static bool arg_follow = false;
static bool arg_full = false;
static bool arg_all = false;
static bool arg_no_pager = false;
static int arg_lines = -1;
static bool arg_no_tail = false;
static bool arg_quiet = false;
static bool arg_merge = false;
static bool arg_this_boot = false;
static const char *arg_cursor = NULL;
static const char *arg_directory = NULL;
static int arg_priorities = 0xFF;
static const char *arg_verify_key = NULL;
#ifdef HAVE_GCRYPT
static usec_t arg_interval = DEFAULT_FSS_INTERVAL_USEC;
#endif
static usec_t arg_since, arg_until;
static bool arg_since_set = false, arg_until_set = false;
static char **arg_system_units = NULL;
static char **arg_user_units = NULL;
static const char *arg_field = NULL;
static bool arg_catalog = false;
static bool arg_reverse = false;
static const char *arg_root = NULL;

static enum {
        ACTION_SHOW,
        ACTION_NEW_ID128,
        ACTION_PRINT_HEADER,
        ACTION_SETUP_KEYS,
        ACTION_VERIFY,
        ACTION_DISK_USAGE,
        ACTION_LIST_CATALOG,
        ACTION_DUMP_CATALOG,
        ACTION_UPDATE_CATALOG
} arg_action = ACTION_SHOW;

static int help(void) {

        printf("%s [OPTIONS...] [MATCHES...]\n\n"
               "Query the journal.\n\n"
               "Flags:\n"
               "     --since=DATE        Start showing entries newer or of the specified date\n"
               "     --until=DATE        Stop showing entries older or of the specified date\n"
               "  -c --cursor=CURSOR     Start showing entries from specified cursor\n"
               "  -b --this-boot         Show data only from current boot\n"
               "  -u --unit=UNIT         Show data only from the specified unit\n"
               "     --user-unit=UNIT    Show data only from the specified user session unit\n"
               "  -p --priority=RANGE    Show only messages within the specified priority range\n"
               "  -e --pager-end         Immediately jump to end of the journal in the pager\n"
               "  -f --follow            Follow journal\n"
               "  -n --lines[=INTEGER]   Number of journal entries to show\n"
               "     --no-tail           Show all lines, even in follow mode\n"
               "  -r --reverse           Show the newest entries first\n"
               "  -o --output=STRING     Change journal output mode (short, short-monotonic,\n"
               "                         verbose, export, json, json-pretty, json-sse, cat)\n"
               "  -x --catalog           Add message explanations where available\n"
               "     --full              Do not ellipsize fields\n"
               "  -a --all               Show all fields, including long and unprintable\n"
               "  -q --quiet             Don't show privilege warning\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "  -m --merge             Show entries from all available journals\n"
               "  -D --directory=PATH    Show journal files from directory\n"
               "     --root=ROOT         Operate on catalog files underneath the root ROOT\n"
#ifdef HAVE_GCRYPT
               "     --interval=TIME     Time interval for changing the FSS sealing key\n"
               "     --verify-key=KEY    Specify FSS verification key\n"
#endif
               "\nCommands:\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --new-id128         Generate a new 128 Bit ID\n"
               "     --header            Show journal header information\n"
               "     --disk-usage        Show total disk usage\n"
               "  -F --field=FIELD       List all values a certain field takes\n"
               "     --list-catalog      Show message IDs of all entries in the message catalog\n"
               "     --dump-catalog      Show entries in the message catalog\n"
               "     --update-catalog    Update the message catalog database\n"
#ifdef HAVE_GCRYPT
               "     --setup-keys        Generate new FSS key pair\n"
               "     --verify            Verify journal file consistency\n"
#endif
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_TAIL,
                ARG_NEW_ID128,
                ARG_ROOT,
                ARG_HEADER,
                ARG_FULL,
                ARG_SETUP_KEYS,
                ARG_INTERVAL,
                ARG_VERIFY,
                ARG_VERIFY_KEY,
                ARG_DISK_USAGE,
                ARG_SINCE,
                ARG_UNTIL,
                ARG_USER_UNIT,
                ARG_LIST_CATALOG,
                ARG_DUMP_CATALOG,
                ARG_UPDATE_CATALOG
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version" ,     no_argument,       NULL, ARG_VERSION      },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                { "pager-end",    no_argument,       NULL, 'e'              },
                { "follow",       no_argument,       NULL, 'f'              },
                { "output",       required_argument, NULL, 'o'              },
                { "all",          no_argument,       NULL, 'a'              },
                { "full",         no_argument,       NULL, ARG_FULL         },
                { "lines",        optional_argument, NULL, 'n'              },
                { "no-tail",      no_argument,       NULL, ARG_NO_TAIL      },
                { "new-id128",    no_argument,       NULL, ARG_NEW_ID128    },
                { "quiet",        no_argument,       NULL, 'q'              },
                { "merge",        no_argument,       NULL, 'm'              },
                { "this-boot",    no_argument,       NULL, 'b'              },
                { "directory",    required_argument, NULL, 'D'              },
                { "root",         required_argument, NULL, ARG_ROOT         },
                { "header",       no_argument,       NULL, ARG_HEADER       },
                { "priority",     required_argument, NULL, 'p'              },
                { "setup-keys",   no_argument,       NULL, ARG_SETUP_KEYS   },
                { "interval",     required_argument, NULL, ARG_INTERVAL     },
                { "verify",       no_argument,       NULL, ARG_VERIFY       },
                { "verify-key",   required_argument, NULL, ARG_VERIFY_KEY   },
                { "disk-usage",   no_argument,       NULL, ARG_DISK_USAGE   },
                { "cursor",       required_argument, NULL, 'c'              },
                { "since",        required_argument, NULL, ARG_SINCE        },
                { "until",        required_argument, NULL, ARG_UNTIL        },
                { "unit",         required_argument, NULL, 'u'              },
                { "user-unit",    required_argument, NULL, ARG_USER_UNIT    },
                { "field",        required_argument, NULL, 'F'              },
                { "catalog",      no_argument,       NULL, 'x'              },
                { "list-catalog", no_argument,       NULL, ARG_LIST_CATALOG },
                { "dump-catalog", no_argument,       NULL, ARG_DUMP_CATALOG },
                { "update-catalog",no_argument,      NULL, ARG_UPDATE_CATALOG },
                { "reverse",      no_argument,       NULL, 'r'              },
                { NULL,           0,                 NULL, 0                }
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hefo:an::qmbD:p:c:u:F:xr", options, NULL)) >= 0) {

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

                        if (arg_lines < 0)
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

                case ARG_FULL:
                        arg_full = true;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 'n':
                        if (optarg) {
                                r = safe_atoi(optarg, &arg_lines);
                                if (r < 0 || arg_lines < 0) {
                                        log_error("Failed to parse lines '%s'", optarg);
                                        return -EINVAL;
                                }
                        } else {
                                int n;

                                /* Hmm, no argument? Maybe the next
                                 * word on the command line is
                                 * supposed to be the argument? Let's
                                 * see if there is one, and is
                                 * parsable as a positive
                                 * integer... */

                                if (optind < argc &&
                                    safe_atoi(argv[optind], &n) >= 0 &&
                                    n >= 0) {

                                        arg_lines = n;
                                        optind++;
                                } else
                                        arg_lines = 10;
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
                        arg_this_boot = true;
                        break;

                case 'D':
                        arg_directory = optarg;
                        break;

                case ARG_ROOT:
                        arg_root = optarg;
                        break;

                case 'c':
                        arg_cursor = optarg;
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

#ifdef HAVE_GCRYPT
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
                        log_error("Forward-secure sealing not available.");
                        return -ENOTSUP;
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

                case '?':
                        return -EINVAL;

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

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (arg_follow && !arg_no_tail && arg_lines < 0)
                arg_lines = 10;

        if (arg_since_set && arg_until_set && arg_since > arg_until) {
                log_error("--since= must be before --until=.");
                return -EINVAL;
        }

        if (arg_cursor && arg_since_set) {
                log_error("Please specify either --since= or --cursor=, not both.");
                return -EINVAL;
        }

        if (arg_follow && arg_reverse) {
                log_error("Please specify either --reverse= or --follow=, not both.");
                return -EINVAL;
        }

        return 1;
}

static int generate_new_id128(void) {
        sd_id128_t id;
        int r;
        unsigned i;

        r = sd_id128_randomize(&id);
        if (r < 0) {
                log_error("Failed to generate ID: %s", strerror(-r));
                return r;
        }

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

        assert(j);

        STRV_FOREACH(i, args) {
                int r;

                if (streq(*i, "+"))
                        r = sd_journal_add_disjunction(j);
                else if (path_is_absolute(*i)) {
                        _cleanup_free_ char *p, *t = NULL;
                        const char *path;
                        struct stat st;

                        p = canonicalize_file_name(*i);
                        path = p ? p : *i;

                        if (stat(path, &st) < 0)  {
                                log_error("Couldn't stat file: %m");
                                return -errno;
                        }

                        if (S_ISREG(st.st_mode) && (0111 & st.st_mode))
                                t = strappend("_EXE=", path);
                        else if (S_ISCHR(st.st_mode))
                                asprintf(&t, "_KERNEL_DEVICE=c%u:%u", major(st.st_rdev), minor(st.st_rdev));
                        else if (S_ISBLK(st.st_mode))
                                asprintf(&t, "_KERNEL_DEVICE=b%u:%u", major(st.st_rdev), minor(st.st_rdev));
                        else {
                                log_error("File is neither a device node, nor regular file, nor executable: %s", *i);
                                return -EINVAL;
                        }

                        if (!t)
                                return log_oom();

                        r = sd_journal_add_match(j, t, 0);
                } else
                        r = sd_journal_add_match(j, *i, 0);

                if (r < 0) {
                        log_error("Failed to add match '%s': %s", *i, strerror(-r));
                        return r;
                }
        }

        return 0;
}

static int add_this_boot(sd_journal *j) {
        char match[9+32+1] = "_BOOT_ID=";
        sd_id128_t boot_id;
        int r;

        assert(j);

        if (!arg_this_boot)
                return 0;

        r = sd_id128_get_boot(&boot_id);
        if (r < 0) {
                log_error("Failed to get boot id: %s", strerror(-r));
                return r;
        }

        sd_id128_to_string(boot_id, match + 9);
        r = sd_journal_add_match(j, match, strlen(match));
        if (r < 0) {
                log_error("Failed to add match: %s", strerror(-r));
                return r;
        }

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return r;

        return 0;
}

static int add_units(sd_journal *j) {
        _cleanup_free_ char *u = NULL;
        int r;
        char **i;

        assert(j);

        STRV_FOREACH(i, arg_system_units) {
                u = unit_name_mangle(*i);
                if (!u)
                        return log_oom();
                r = add_matches_for_unit(j, u);
                if (r < 0)
                        return r;
                r = sd_journal_add_disjunction(j);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, arg_user_units) {
                u = unit_name_mangle(*i);
                if (!u)
                        return log_oom();

                r = add_matches_for_user_unit(j, u, getuid());
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
                        if (r < 0) {
                                log_error("Failed to add match: %s", strerror(-r));
                                return r;
                        }
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
        ssize_t l;
        int fd = -1, r, attr = 0;
        sd_id128_t machine, boot;
        char *p = NULL, *k = NULL;
        struct FSSHeader h;
        uint64_t n;

        r = sd_id128_get_machine(&machine);
        if (r < 0) {
                log_error("Failed to get machine ID: %s", strerror(-r));
                return r;
        }

        r = sd_id128_get_boot(&boot);
        if (r < 0) {
                log_error("Failed to get boot ID: %s", strerror(-r));
                return r;
        }

        if (asprintf(&p, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss",
                     SD_ID128_FORMAT_VAL(machine)) < 0)
                return log_oom();

        if (access(p, F_OK) >= 0) {
                log_error("Sealing key file %s exists already.", p);
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
                log_error("Failed to open /dev/random: %m");
                r = -errno;
                goto finish;
        }

        log_info("Generating seed...");
        l = loop_read(fd, seed, seed_size, true);
        if (l < 0 || (size_t) l != seed_size) {
                log_error("Failed to read random seed: %s", strerror(EIO));
                r = -EIO;
                goto finish;
        }

        log_info("Generating key pair...");
        FSPRG_GenMK(NULL, mpk, seed, seed_size, FSPRG_RECOMMENDED_SECPAR);

        log_info("Generating sealing key...");
        FSPRG_GenState0(state, mpk, seed, seed_size);

        assert(arg_interval > 0);

        n = now(CLOCK_REALTIME);
        n /= arg_interval;

        close_nointr_nofail(fd);
        fd = mkostemp(k, O_WRONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                log_error("Failed to open %s: %m", k);
                r = -errno;
                goto finish;
        }

        /* Enable secure remove, exclusion from dump, synchronous
         * writing and in-place updating */
        if (ioctl(fd, FS_IOC_GETFLAGS, &attr) < 0)
                log_warning("FS_IOC_GETFLAGS failed: %m");

        attr |= FS_SECRM_FL|FS_NODUMP_FL|FS_SYNC_FL|FS_NOCOW_FL;

        if (ioctl(fd, FS_IOC_SETFLAGS, &attr) < 0)
                log_warning("FS_IOC_SETFLAGS failed: %m");

        zero(h);
        memcpy(h.signature, "KSHHRHLP", 8);
        h.machine_id = machine;
        h.boot_id = boot;
        h.header_size = htole64(sizeof(h));
        h.start_usec = htole64(n * arg_interval);
        h.interval_usec = htole64(arg_interval);
        h.fsprg_secpar = htole16(FSPRG_RECOMMENDED_SECPAR);
        h.fsprg_state_size = htole64(state_size);

        l = loop_write(fd, &h, sizeof(h), false);
        if (l < 0 || (size_t) l != sizeof(h)) {
                log_error("Failed to write header: %s", strerror(EIO));
                r = -EIO;
                goto finish;
        }

        l = loop_write(fd, state, state_size, false);
        if (l < 0 || (size_t) l != state_size) {
                log_error("Failed to write state: %s", strerror(EIO));
                r = -EIO;
                goto finish;
        }

        if (link(k, p) < 0) {
                log_error("Failed to link file: %m");
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
        if (fd >= 0)
                close_nointr_nofail(fd);

        if (k) {
                unlink(k);
                free(k);
        }

        free(p);

        return r;
#else
        log_error("Forward-secure sealing not available.");
        return -ENOTSUP;
#endif
}

static int verify(sd_journal *j) {
        int r = 0;
        Iterator i;
        JournalFile *f;

        assert(j);

        log_show_color(true);

        HASHMAP_FOREACH(f, j->files, i) {
                int k;
                usec_t first, validated, last;

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
                                                 format_timestamp(a, sizeof(a), first),
                                                 format_timestamp(b, sizeof(b), validated),
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

#ifdef HAVE_ACL
static int access_check_var_log_journal(sd_journal *j) {
        _cleanup_strv_free_ char **g = NULL;
        bool have_access;
        int r;

        assert(j);

        have_access = in_group("systemd-journal") > 0;

        if (!have_access) {
                /* Let's enumerate all groups from the default ACL of
                 * the directory, which generally should allow access
                 * to most journal files too */
                r = search_acl_groups(&g, "/var/log/journal/", &have_access);
                if (r < 0)
                        return r;
        }

        if (!have_access) {

                if (strv_isempty(g))
                        log_notice("Hint: You are currently not seeing messages from other users and the system.\n"
                                   "      Users in the 'systemd-journal' group can see all messages. Pass -q to\n"
                                   "      turn off this notice.");
                else {
                        _cleanup_free_ char *s = NULL;

                        r = strv_extend(&g, "systemd-journal");
                        if (r < 0)
                                return log_oom();

                        strv_sort(g);
                        strv_uniq(g);

                        s = strv_join(g, "', '");
                        if (!s)
                                return log_oom();

                        log_notice("Hint: You are currently not seeing messages from other users and the system.\n"
                                   "      Users in the groups '%s' can see all messages.\n"
                                   "      Pass -q to turn off this notice.", s);
                }
        }

        return 0;
}
#endif

static int access_check(sd_journal *j) {
        Iterator it;
        void *code;
        int r = 0;

        assert(j);

        if (set_isempty(j->errors)) {
                if (hashmap_isempty(j->files))
                        log_notice("No journal files were found.");
                return 0;
        }

        if (set_contains(j->errors, INT_TO_PTR(-EACCES))) {
#ifdef HAVE_ACL
                /* If /var/log/journal doesn't even exist,
                 * unprivileged users have no access at all */
                if (access("/var/log/journal", F_OK) < 0 &&
                    geteuid() != 0 &&
                    in_group("systemd-journal") <= 0) {
                        log_error("Unprivileged users cannot access messages, unless persistent log storage is\n"
                                  "enabled. Users in the 'systemd-journal' group may always access messages.");
                        return -EACCES;
                }

                /* If /var/log/journal exists, try to pring a nice
                   notice if the user lacks access to it */
                if (!arg_quiet && geteuid() != 0) {
                        r = access_check_var_log_journal(j);
                        if (r < 0)
                                return r;
                }
#else
                if (geteuid() != 0 && in_group("systemd-journal") <= 0) {
                        log_error("Unprivileged users cannot access messages. Users in the 'systemd-journal' group\n"
                                  "group may access messages.");
                        return -EACCES;
                }
#endif

                if (hashmap_isempty(j->files)) {
                        log_error("No journal files were opened due to insufficient permissions.");
                        r = -EACCES;
                }
        }

        SET_FOREACH(code, j->errors, it) {
                int err;

                err = -PTR_TO_INT(code);
                assert(err > 0);

                if (err != EACCES)
                        log_warning("Error was encountered while opening journal files: %s",
                                    strerror(err));
        }

        return r;
}

int main(int argc, char *argv[]) {
        int r;
        _cleanup_journal_close_ sd_journal*j = NULL;
        bool need_seek = false;
        sd_id128_t previous_boot_id;
        bool previous_boot_id_valid = false, first_line = true;
        int n_shown = 0;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        signal(SIGWINCH, columns_lines_cache_reset);

        if (arg_action == ACTION_NEW_ID128) {
                r = generate_new_id128();
                goto finish;
        }

        if (arg_action == ACTION_SETUP_KEYS) {
                r = setup_keys();
                goto finish;
        }

        if (arg_action == ACTION_UPDATE_CATALOG ||
            arg_action == ACTION_LIST_CATALOG ||
            arg_action == ACTION_DUMP_CATALOG) {

                const char* database = CATALOG_DATABASE;
                _cleanup_free_ char *copy = NULL;
                if (arg_root) {
                        copy = strjoin(arg_root, "/", CATALOG_DATABASE, NULL);
                        if (!copy) {
                                r = log_oom();
                                goto finish;
                        }
                        path_kill_slashes(copy);
                        database = copy;
                }

                if (arg_action == ACTION_UPDATE_CATALOG) {
                        r = catalog_update(database, arg_root, catalog_file_dirs);
                        if (r < 0)
                                log_error("Failed to list catalog: %s", strerror(-r));
                } else {
                        bool oneline = arg_action == ACTION_LIST_CATALOG;

                        if (optind < argc)
                                r = catalog_list_items(stdout, database,
                                                       oneline, argv + optind);
                        else
                                r = catalog_list(stdout, database, oneline);
                        if (r < 0)
                                log_error("Failed to list catalog: %s", strerror(-r));
                }

                goto finish;
        }

        if (arg_directory)
                r = sd_journal_open_directory(&j, arg_directory, 0);
        else
                r = sd_journal_open(&j, arg_merge ? 0 : SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        r = access_check(j);
        if (r < 0)
                return EXIT_FAILURE;

        if (arg_action == ACTION_VERIFY) {
                r = verify(j);
                goto finish;
        }

        if (arg_action == ACTION_PRINT_HEADER) {
                journal_print_header(j);
                return EXIT_SUCCESS;
        }

        if (arg_action == ACTION_DISK_USAGE) {
                uint64_t bytes;
                char sbytes[FORMAT_BYTES_MAX];

                r = sd_journal_get_usage(j, &bytes);
                if (r < 0)
                        return EXIT_FAILURE;

                printf("Journals take up %s on disk.\n",
                       format_bytes(sbytes, sizeof(sbytes), bytes));
                return EXIT_SUCCESS;
        }

        r = add_this_boot(j);
        if (r < 0)
                return EXIT_FAILURE;

        r = add_units(j);
        strv_free(arg_system_units);
        strv_free(arg_user_units);

        if (r < 0)
                return EXIT_FAILURE;

        r = add_priorities(j);
        if (r < 0)
                return EXIT_FAILURE;

        r = add_matches(j, argv + optind);
        if (r < 0)
                return EXIT_FAILURE;

        /* Opening the fd now means the first sd_journal_wait() will actually wait */
        r = sd_journal_get_fd(j);
        if (r < 0)
                return EXIT_FAILURE;

        if (arg_field) {
                const void *data;
                size_t size;

                r = sd_journal_set_data_threshold(j, 0);
                if (r < 0) {
                        log_error("Failed to unset data size threshold");
                        return EXIT_FAILURE;
                }

                r = sd_journal_query_unique(j, arg_field);
                if (r < 0) {
                        log_error("Failed to query unique data objects: %s", strerror(-r));
                        return EXIT_FAILURE;
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

                return EXIT_SUCCESS;
        }

        if (arg_cursor) {
                r = sd_journal_seek_cursor(j, arg_cursor);
                if (r < 0) {
                        log_error("Failed to seek to cursor: %s", strerror(-r));
                        return EXIT_FAILURE;
                }
                if (!arg_reverse)
                        r = sd_journal_next(j);
                else
                        r = sd_journal_previous(j);

        } else if (arg_since_set && !arg_reverse) {
                r = sd_journal_seek_realtime_usec(j, arg_since);
                if (r < 0) {
                        log_error("Failed to seek to date: %s", strerror(-r));
                        return EXIT_FAILURE;
                }
                r = sd_journal_next(j);

        } else if (arg_until_set && arg_reverse) {
                r = sd_journal_seek_realtime_usec(j, arg_until);
                if (r < 0) {
                        log_error("Failed to seek to date: %s", strerror(-r));
                        return EXIT_FAILURE;
                }
                r = sd_journal_previous(j);

        } else if (arg_lines >= 0) {
                r = sd_journal_seek_tail(j);
                if (r < 0) {
                        log_error("Failed to seek to tail: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

                r = sd_journal_previous_skip(j, arg_lines);

        } else if (arg_reverse) {
                r = sd_journal_seek_tail(j);
                if (r < 0) {
                        log_error("Failed to seek to tail: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

                r = sd_journal_previous(j);

        } else {
                r = sd_journal_seek_head(j);
                if (r < 0) {
                        log_error("Failed to seek to head: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

                r = sd_journal_next(j);
        }

        if (r < 0) {
                log_error("Failed to iterate through journal: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        if (!arg_no_pager && !arg_follow)
                pager_open(arg_pager_end);

        if (!arg_quiet) {
                usec_t start, end;
                char start_buf[FORMAT_TIMESTAMP_MAX], end_buf[FORMAT_TIMESTAMP_MAX];

                r = sd_journal_get_cutoff_realtime_usec(j, &start, &end);
                if (r < 0) {
                        log_error("Failed to get cutoff: %s", strerror(-r));
                        goto finish;
                }

                if (r > 0) {
                        if (arg_follow)
                                printf("-- Logs begin at %s. --\n",
                                       format_timestamp(start_buf, sizeof(start_buf), start));
                        else
                                printf("-- Logs begin at %s, end at %s. --\n",
                                       format_timestamp(start_buf, sizeof(start_buf), start),
                                       format_timestamp(end_buf, sizeof(end_buf), end));
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
                                        log_error("Failed to iterate through journal: %s", strerror(-r));
                                        goto finish;
                                }
                        }

                        if (r == 0)
                                break;

                        if (arg_until_set && !arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0) {
                                        log_error("Failed to determine timestamp: %s", strerror(-r));
                                        goto finish;
                                }
                                if (usec > arg_until)
                                        goto finish;
                        }

                        if (arg_since_set && arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0) {
                                        log_error("Failed to determine timestamp: %s", strerror(-r));
                                        goto finish;
                                }
                                if (usec < arg_since)
                                        goto finish;
                        }

                        if (!arg_merge) {
                                sd_id128_t boot_id;

                                r = sd_journal_get_monotonic_usec(j, NULL, &boot_id);
                                if (r >= 0) {
                                        if (previous_boot_id_valid &&
                                            !sd_id128_equal(boot_id, previous_boot_id))
                                                printf(ANSI_HIGHLIGHT_ON "-- Reboot --" ANSI_HIGHLIGHT_OFF "\n");

                                        previous_boot_id = boot_id;
                                        previous_boot_id_valid = true;
                                }
                        }

                        flags =
                                arg_all * OUTPUT_SHOW_ALL |
                                (arg_full || !on_tty() || pager_have()) * OUTPUT_FULL_WIDTH |
                                on_tty() * OUTPUT_COLOR |
                                arg_catalog * OUTPUT_CATALOG;

                        r = output_journal(stdout, j, arg_output, 0, flags);
                        if (r < 0 || ferror(stdout))
                                goto finish;

                        need_seek = true;
                        n_shown++;
                }

                if (!arg_follow)
                        break;

                r = sd_journal_wait(j, (uint64_t) -1);
                if (r < 0) {
                        log_error("Couldn't wait for journal event: %s", strerror(-r));
                        goto finish;
                }

                first_line = false;
        }

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
