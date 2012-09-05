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

#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include <systemd/sd-journal.h>

#include "log.h"
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

#define DEFAULT_FSS_INTERVAL_USEC (15*USEC_PER_MINUTE)

static OutputMode arg_output = OUTPUT_SHORT;
static bool arg_follow = false;
static bool arg_show_all = false;
static bool arg_no_pager = false;
static int arg_lines = -1;
static bool arg_no_tail = false;
static bool arg_quiet = false;
static bool arg_merge = false;
static bool arg_this_boot = false;
static const char *arg_directory = NULL;
static int arg_priorities = 0xFF;
static const char *arg_verify_key = NULL;
#ifdef HAVE_GCRYPT
static usec_t arg_interval = DEFAULT_FSS_INTERVAL_USEC;
#endif

static enum {
        ACTION_SHOW,
        ACTION_NEW_ID128,
        ACTION_PRINT_HEADER,
        ACTION_SETUP_KEYS,
        ACTION_VERIFY
} arg_action = ACTION_SHOW;

static int help(void) {

        printf("%s [OPTIONS...] [MATCH]\n\n"
               "Send control commands to or query the journal.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "  -a --all               Show all fields, including long and unprintable\n"
               "  -f --follow            Follow journal\n"
               "  -n --lines=INTEGER     Journal entries to show\n"
               "     --no-tail           Show all lines, even in follow mode\n"
               "  -o --output=STRING     Change journal output mode (short, short-monotonic,\n"
               "                         verbose, export, json, json-pretty, cat)\n"
               "  -q --quiet             Don't show privilege warning\n"
               "  -m --merge             Show entries from all available journals\n"
               "  -b --this-boot         Show data only from current boot\n"
               "  -D --directory=PATH    Show journal files from directory\n"
               "  -p --priority=RANGE    Show only messages within the specified priority range\n\n"
               "Commands:\n"
               "     --new-id128         Generate a new 128 Bit ID\n"
               "     --header            Show journal header information\n"
#ifdef HAVE_GCRYPT
               "     --setup-keys        Generate new FSS key pair\n"
               "       --interval=TIME   Time interval for changing the FSS sealing key\n"
               "     --verify            Verify journal file consistency\n"
               "       --verify-key=KEY  Specify FSS verification key\n"
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
                ARG_HEADER,
                ARG_SETUP_KEYS,
                ARG_INTERVAL,
                ARG_VERIFY,
                ARG_VERIFY_KEY
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version" ,     no_argument,       NULL, ARG_VERSION      },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                { "follow",       no_argument,       NULL, 'f'              },
                { "output",       required_argument, NULL, 'o'              },
                { "all",          no_argument,       NULL, 'a'              },
                { "lines",        required_argument, NULL, 'n'              },
                { "no-tail",      no_argument,       NULL, ARG_NO_TAIL      },
                { "new-id128",    no_argument,       NULL, ARG_NEW_ID128    },
                { "quiet",        no_argument,       NULL, 'q'              },
                { "merge",        no_argument,       NULL, 'm'              },
                { "this-boot",    no_argument,       NULL, 'b'              },
                { "directory",    required_argument, NULL, 'D'              },
                { "header",       no_argument,       NULL, ARG_HEADER       },
                { "priority",     no_argument,       NULL, 'p'              },
                { "setup-keys",   no_argument,       NULL, ARG_SETUP_KEYS   },
                { "interval",     required_argument, NULL, ARG_INTERVAL     },
                { "verify",       no_argument,       NULL, ARG_VERIFY       },
                { "verify-key",   required_argument, NULL, ARG_VERIFY_KEY   },
                { NULL,           0,                 NULL, 0                }
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hfo:an:qmbD:p:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(DISTRIBUTION);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case 'f':
                        arg_follow = true;
                        break;

                case 'o':
                        arg_output =  output_mode_from_string(optarg);
                        if (arg_output < 0) {
                                log_error("Unknown output '%s'.", optarg);
                                return -EINVAL;
                        }

                        break;

                case 'a':
                        arg_show_all = true;
                        break;

                case 'n':
                        r = safe_atoi(optarg, &arg_lines);
                        if (r < 0 || arg_lines < 0) {
                                log_error("Failed to parse lines '%s'", optarg);
                                return -EINVAL;
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

                case ARG_HEADER:
                        arg_action = ACTION_PRINT_HEADER;
                        break;

                case ARG_VERIFY:
                        arg_action = ACTION_VERIFY;
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
                        r = parse_usec(optarg, &arg_interval);
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

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (arg_follow && !arg_no_tail && arg_lines < 0)
                arg_lines = 10;

        return 1;
}

static bool on_tty(void) {
        static int t = -1;

        /* Note that this is invoked relatively early, before we start
         * the pager. That means the value we return reflects whether
         * we originally were started on a tty, not if we currently
         * are. But this is intended, since we want colour and so on
         * when run in our own pager. */

        if (_unlikely_(t < 0))
                t = isatty(STDOUT_FILENO) > 0;

        return t;
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

        fputs(")\n", stdout);

        return 0;
}

static int add_matches(sd_journal *j, char **args) {
        char **i;
        int r;

        assert(j);

        STRV_FOREACH(i, args) {

                if (streq(*i, "+"))
                        r = sd_journal_add_disjunction(j);
                else if (path_is_absolute(*i)) {
                        char *p, *t = NULL;
                        const char *path;
                        struct stat st;

                        p = canonicalize_file_name(*i);
                        path = p ? p : *i;

                        if (stat(path, &st) < 0)  {
                                free(p);
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
                                free(p);
                                log_error("File is not a device node, regular file or is not executable: %s", *i);
                                return -EINVAL;
                        }

                        free(p);

                        if (!t)
                                return log_oom();

                        r = sd_journal_add_match(j, t, 0);
                        free(t);
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

                        log_info("adding match %s", match);

                        r = sd_journal_add_match(j, match, strlen(match));
                        if (r < 0) {
                                log_error("Failed to add match: %s", strerror(-r));
                                return r;
                        }
                }

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

        if (isatty(STDOUT_FILENO)) {
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

        if (isatty(STDOUT_FILENO)) {
                char tsb[FORMAT_TIMESPAN_MAX], *hn;

                fprintf(stderr,
                        ANSI_HIGHLIGHT_OFF "\n"
                        "The sealing key is automatically changed every %s.\n",
                        format_timespan(tsb, sizeof(tsb), arg_interval));

                hn = gethostname_malloc();

                if (hn) {
                        hostname_cleanup(hn);
                        fprintf(stderr, "\nThe keys have been generated for host %s/" SD_ID128_FORMAT_STR ".\n", hn, SD_ID128_FORMAT_VAL(machine));
                } else
                        fprintf(stderr, "\nThe keys have been generated for host " SD_ID128_FORMAT_STR ".\n", SD_ID128_FORMAT_VAL(machine));

#ifdef HAVE_QRENCODE
                fprintf(stderr, "\nTo transfer the verification key to your phone please scan the QR code below:\n\n");
                print_qr_code(stderr, seed, seed_size, n, arg_interval, hn, machine);
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
                usec_t from, to, total;

#ifdef HAVE_GCRYPT
                if (!arg_verify_key && JOURNAL_HEADER_SEALED(f->header))
                        log_notice("Journal file %s has sealing enabled but verification key has not been passed using --verify-key=.", f->path);
#endif

                k = journal_file_verify(f, arg_verify_key, &from, &to, &total, true);
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
                                if (from > 0) {
                                        log_info("=> Validated from %s to %s, final %s entries not sealed.",
                                                 format_timestamp(a, sizeof(a), from),
                                                 format_timestamp(b, sizeof(b), to),
                                                 format_timespan(c, sizeof(c), total > to ? total - to : 0));
                                } else if (total > 0)
                                        log_info("=> No sealing yet, %s of entries not sealed.",
                                                 format_timespan(c, sizeof(c), total));
                                else
                                        log_info("=> No sealing yet, no entries in file.");
                        }
                }
        }

        return r;
}

int main(int argc, char *argv[]) {
        int r;
        sd_journal *j = NULL;
        unsigned line = 0;
        bool need_seek = false;
        sd_id128_t previous_boot_id;
        bool previous_boot_id_valid = false;
        bool have_pager;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_action == ACTION_NEW_ID128) {
                r = generate_new_id128();
                goto finish;
        }

        if (arg_action == ACTION_SETUP_KEYS) {
                r = setup_keys();
                goto finish;
        }

        if (arg_directory)
                r = sd_journal_open_directory(&j, arg_directory, 0);
        else
                r = sd_journal_open(&j, arg_merge ? 0 : SD_JOURNAL_LOCAL_ONLY);

        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                goto finish;
        }

        if (arg_action == ACTION_VERIFY) {
                r = verify(j);
                goto finish;
        }

        if (arg_action == ACTION_PRINT_HEADER) {
                journal_print_header(j);
                r = 0;
                goto finish;
        }

#ifdef HAVE_ACL
        if (access("/var/log/journal", F_OK) < 0 && geteuid() != 0 && in_group("adm") <= 0) {
                log_error("Unprivileged users can't see messages unless persistent log storage is enabled. Users in the group 'adm' can always see messages.");
                r = -EACCES;
                goto finish;
        }

        if (!arg_quiet && geteuid() != 0 && in_group("adm") <= 0)
                log_warning("Showing user generated messages only. Users in the group 'adm' can see all messages. Pass -q to turn this notice off.");
#else
        if (geteuid() != 0 && in_group("adm") <= 0) {
                log_error("No access to messages. Only users in the group 'adm' can see messages.");
                r = -EACCES;
                goto finish;
        }
#endif

        r = add_this_boot(j);
        if (r < 0)
                goto finish;

        r = add_matches(j, argv + optind);
        if (r < 0)
                goto finish;

        r = add_priorities(j);
        if (r < 0)
                goto finish;

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
                                printf("Logs begin at %s.\n", format_timestamp(start_buf, sizeof(start_buf), start));
                        else
                                printf("Logs begin at %s, end at %s.\n",
                                       format_timestamp(start_buf, sizeof(start_buf), start),
                                       format_timestamp(end_buf, sizeof(end_buf), end));
                }
        }

        if (arg_lines >= 0) {
                r = sd_journal_seek_tail(j);
                if (r < 0) {
                        log_error("Failed to seek to tail: %s", strerror(-r));
                        goto finish;
                }

                r = sd_journal_previous_skip(j, arg_lines);
        } else {
                r = sd_journal_seek_head(j);
                if (r < 0) {
                        log_error("Failed to seek to head: %s", strerror(-r));
                        goto finish;
                }

                r = sd_journal_next(j);
        }

        if (r < 0) {
                log_error("Failed to iterate through journal: %s", strerror(-r));
                goto finish;
        }

        on_tty();
        have_pager = !arg_no_pager && !arg_follow && pager_open();

        for (;;) {
                for (;;) {
                        int flags =
                                arg_show_all * OUTPUT_SHOW_ALL |
                                have_pager * OUTPUT_FULL_WIDTH |
                                on_tty() * OUTPUT_COLOR;

                        if (need_seek) {
                                r = sd_journal_next(j);
                                if (r < 0) {
                                        log_error("Failed to iterate through journal: %s", strerror(-r));
                                        goto finish;
                                }
                        }

                        if (r == 0)
                                break;

                        if (!arg_merge) {
                                sd_id128_t boot_id;

                                r = sd_journal_get_monotonic_usec(j, NULL, &boot_id);
                                if (r >= 0) {
                                        if (previous_boot_id_valid &&
                                            !sd_id128_equal(boot_id, previous_boot_id))
                                                printf(ANSI_HIGHLIGHT_ON "----- Reboot -----" ANSI_HIGHLIGHT_OFF "\n");

                                        previous_boot_id = boot_id;
                                        previous_boot_id_valid = true;
                                }
                        }

                        line ++;

                        r = output_journal(j, arg_output, line, 0, flags);
                        if (r < 0)
                                goto finish;

                        need_seek = true;
                }

                if (!arg_follow)
                        break;

                r = sd_journal_wait(j, (uint64_t) -1);
                if (r < 0) {
                        log_error("Couldn't wait for log event: %s", strerror(-r));
                        goto finish;
                }
        }

finish:
        if (j)
                sd_journal_close(j);

        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
