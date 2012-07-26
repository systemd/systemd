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

#include <systemd/sd-journal.h>

#include "log.h"
#include "util.h"
#include "path-util.h"
#include "build.h"
#include "pager.h"
#include "logs-show.h"
#include "strv.h"
#include "journal-internal.h"

static OutputMode arg_output = OUTPUT_SHORT;
static bool arg_follow = false;
static bool arg_show_all = false;
static bool arg_no_pager = false;
static int arg_lines = -1;
static bool arg_no_tail = false;
static bool arg_new_id128 = false;
static bool arg_print_header = false;
static bool arg_quiet = false;
static bool arg_local = false;
static bool arg_this_boot = false;
static const char *arg_directory = NULL;

static int help(void) {

        printf("%s [OPTIONS...] [MATCH]\n\n"
               "Send control commands to or query the journal.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "  -a --all            Show all fields, including long and unprintable\n"
               "  -f --follow         Follow journal\n"
               "  -n --lines=INTEGER  Journal entries to show\n"
               "     --no-tail        Show all lines, even in follow mode\n"
               "  -o --output=STRING  Change journal output mode (short, short-monotonic,\n"
               "                      verbose, export, json, cat)\n"
               "  -q --quiet          Don't show privilege warning\n"
               "  -l --local          Only local entries\n"
               "  -b --this-boot      Show data only from current boot\n"
               "  -D --directory=PATH Show journal files from directory\n"
               "     --header         Show journal header information\n"
               "     --new-id128      Generate a new 128 Bit id\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_TAIL,
                ARG_NEW_ID128,
                ARG_HEADER
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version" ,  no_argument,       NULL, ARG_VERSION   },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "follow",    no_argument,       NULL, 'f'           },
                { "output",    required_argument, NULL, 'o'           },
                { "all",       no_argument,       NULL, 'a'           },
                { "lines",     required_argument, NULL, 'n'           },
                { "no-tail",   no_argument,       NULL, ARG_NO_TAIL   },
                { "new-id128", no_argument,       NULL, ARG_NEW_ID128 },
                { "quiet",     no_argument,       NULL, 'q'           },
                { "local",     no_argument,       NULL, 'l'           },
                { "this-boot", no_argument,       NULL, 'b'           },
                { "directory", required_argument, NULL, 'D'           },
                { "header",    no_argument,       NULL, ARG_HEADER    },
                { NULL,        0,                 NULL, 0             }
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hfo:an:qlbD:", options, NULL)) >= 0) {

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
                        arg_new_id128 = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case 'l':
                        arg_local = true;
                        break;

                case 'b':
                        arg_this_boot = true;
                        break;

                case 'D':
                        arg_directory = optarg;
                        break;

                case ARG_HEADER:
                        arg_print_header = true;
                        break;

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
                        char *p;
                        const char *path;
                        struct stat st;

                        p = canonicalize_file_name(*i);
                        path = p ? p : *i;

                        if (stat(path, &st) < 0)  {
                                free(p);
                                log_error("Couldn't stat file: %m");
                                return -errno;
                        }

                        if (S_ISREG(st.st_mode) && (0111 & st.st_mode)) {
                                char *t;

                                t = strappend("_EXE=", path);
                                if (!t) {
                                        free(p);
                                        return log_oom();
                                }

                                r = sd_journal_add_match(j, t, 0);
                                free(t);
                        } else {
                                free(p);
                                log_error("File is not a regular file or is not executable: %s", *i);
                                return -EINVAL;
                        }

                        free(p);
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

        if (arg_new_id128) {
                r = generate_new_id128();
                goto finish;
        }

#ifdef HAVE_ACL
        if (!arg_quiet && geteuid() != 0 && in_group("adm") <= 0)
                log_warning("Showing user generated messages only. Users in the group 'adm' can see all messages. Pass -q to turn this message off.");
#endif

        if (arg_directory)
                r = sd_journal_open_directory(&j, arg_directory, 0);
        else
                r = sd_journal_open(&j, arg_local ? SD_JOURNAL_LOCAL_ONLY : 0);

        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                goto finish;
        }

        if (arg_print_header) {
                journal_print_header(j);
                r = 0;
                goto finish;
        }

        r = add_this_boot(j);
        if (r < 0)
                goto finish;

        r = add_matches(j, argv + optind);
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

        if (arg_output == OUTPUT_JSON) {
                fputc('[', stdout);
                fflush(stdout);
        }

        for (;;) {
                for (;;) {
                        sd_id128_t boot_id;
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

                        r = sd_journal_get_monotonic_usec(j, NULL, &boot_id);
                        if (r >= 0) {
                                if (previous_boot_id_valid &&
                                    !sd_id128_equal(boot_id, previous_boot_id))
                                        printf(ANSI_HIGHLIGHT_ON "----- Reboot -----" ANSI_HIGHLIGHT_OFF "\n");

                                previous_boot_id = boot_id;
                                previous_boot_id_valid = true;
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

        if (arg_output == OUTPUT_JSON)
                fputs("\n]\n", stdout);

finish:
        if (j)
                sd_journal_close(j);

        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
