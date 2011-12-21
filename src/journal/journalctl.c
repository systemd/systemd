/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
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

#include "sd-journal.h"
#include "log.h"
#include "util.h"
#include "build.h"
#include "pager.h"

#define PRINT_THRESHOLD 128

static enum {
        OUTPUT_SHORT,
        OUTPUT_VERBOSE,
        OUTPUT_EXPORT,
        OUTPUT_JSON,
        _OUTPUT_MAX
} arg_output = OUTPUT_SHORT;

static bool arg_follow = false;
static bool arg_show_all = false;
static bool arg_no_pager = false;

static bool contains_unprintable(const void *p, size_t l) {
        const char *j;

        for (j = p; j < (const char *) p + l; j++)
                if (*j < ' ' || *j >= 127)
                        return true;

        return false;
}

static int output_short(sd_journal *j, unsigned line) {
        int r;
        uint64_t realtime;
        time_t t;
        struct tm tm;
        char buf[64];
        const void *data;
        size_t length;
        size_t n = 0;

        assert(j);

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r < 0) {
                log_error("Failed to get realtime: %s", strerror(-r));
                return r;
        }

        t = (time_t) (realtime / USEC_PER_SEC);
        if (strftime(buf, sizeof(buf), "%b %d %H:%M:%S", localtime_r(&t, &tm)) <= 0) {
                log_error("Failed to format time.");
                return -EINVAL;
        }

        fputs(buf, stdout);
        n += strlen(buf);

        if (sd_journal_get_data(j, "_HOSTNAME", &data, &length) >= 0 &&
            (arg_show_all || (!contains_unprintable(data, length) &&
                              length < PRINT_THRESHOLD))) {
                printf(" %.*s", (int) length - 10, ((const char*) data) + 10);
                n += length - 10 + 1;
        }

        if (sd_journal_get_data(j, "MESSAGE", &data, &length) >= 0) {
                if (arg_show_all)
                        printf(" %.*s", (int) length - 8, ((const char*) data) + 8);
                else if (contains_unprintable(data, length))
                        fputs(" [blob data]", stdout);
                else if (length - 8 + n < columns())
                        printf(" %.*s", (int) length - 8, ((const char*) data) + 8);
                else if (n < columns()) {
                        char *e;

                        e = ellipsize_mem((const char *) data + 8, length - 8, columns() - n - 2, 90);

                        if (!e)
                                printf(" %.*s", (int) length - 8, ((const char*) data) + 8);
                        else
                                printf(" %s", e);

                        free(e);
                }
        }

        fputc('\n', stdout);

        return 0;
}

static int output_verbose(sd_journal *j, unsigned line) {
        const void *data;
        size_t length;
        char *cursor;
        uint64_t realtime;
        char ts[FORMAT_TIMESTAMP_MAX];
        int r;

        assert(j);

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r < 0) {
                log_error("Failed to get realtime timestamp: %s", strerror(-r));
                return r;
        }

        r = sd_journal_get_cursor(j, &cursor);
        if (r < 0) {
                log_error("Failed to get cursor: %s", strerror(-r));
                return r;
        }

        printf("%s [%s]\n",
               format_timestamp(ts, sizeof(ts), realtime),
               cursor);

        free(cursor);

        SD_JOURNAL_FOREACH_DATA(j, data, length) {
                if (!arg_show_all && (length > PRINT_THRESHOLD ||
                                      contains_unprintable(data, length))) {
                        const char *c;

                        c = memchr(data, '=', length);
                        if (!c) {
                                log_error("Invalid field.");
                                return -EINVAL;
                        }

                        printf("\t%.*s=[blob data]\n",
                               (int) (c - (const char*) data),
                               (const char*) data);
                } else
                        printf("\t%.*s\n", (int) length, (const char*) data);
        }

        return 0;
}

static int output_export(sd_journal *j, unsigned line) {
        sd_id128_t boot_id;
        char sid[33];
        int r;
        usec_t realtime, monotonic;
        char *cursor;
        const void *data;
        size_t length;

        assert(j);

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r < 0) {
                log_error("Failed to get realtime timestamp: %s", strerror(-r));
                return r;
        }

        r = sd_journal_get_monotonic_usec(j, &monotonic, &boot_id);
        if (r < 0) {
                log_error("Failed to get monotonic timestamp: %s", strerror(-r));
                return r;
        }

        r = sd_journal_get_cursor(j, &cursor);
        if (r < 0) {
                log_error("Failed to get cursor: %s", strerror(-r));
                return r;
        }

        printf(".cursor=%s\n"
               ".realtime=%llu\n"
               ".monotonic=%llu\n"
               ".boot_id=%s\n",
               cursor,
               (unsigned long long) realtime,
               (unsigned long long) monotonic,
               sd_id128_to_string(boot_id, sid));

        free(cursor);

        SD_JOURNAL_FOREACH_DATA(j, data, length) {

                if (contains_unprintable(data, length)) {
                        const char *c;
                        uint64_t le64;

                        c = memchr(data, '=', length);
                        if (!c) {
                                log_error("Invalid field.");
                                return -EINVAL;
                        }

                        fwrite(data, c - (const char*) data, 1, stdout);
                        fputc('\n', stdout);
                        le64 = htole64(length - (c - (const char*) data) - 1);
                        fwrite(&le64, sizeof(le64), 1, stdout);
                        fwrite(c + 1, length - (c - (const char*) data) - 1, 1, stdout);
                } else
                        fwrite(data, length, 1, stdout);

                fputc('\n', stdout);
        }

        fputc('\n', stdout);

        return 0;
}

static void json_escape(const char* p, size_t l) {

        if (contains_unprintable(p, l)) {
                bool not_first = false;

                fputs("[ ", stdout);

                while (l > 0) {
                        if (not_first)
                                printf(", %u", (uint8_t) *p);
                        else {
                                not_first = true;
                                printf("%u", (uint8_t) *p);
                        }

                        p++;
                        l--;
                }

                fputs(" ]", stdout);
        } else {
                fputc('\"', stdout);

                while (l > 0) {
                        if (*p == '"' || *p == '\\') {
                                fputc('\\', stdout);
                                fputc(*p, stdout);
                        } else
                                fputc(*p, stdout);

                        p++;
                        l--;
                }

                fputc('\"', stdout);
        }
}

static int output_json(sd_journal *j, unsigned line) {
        uint64_t realtime, monotonic;
        char *cursor;
        const void *data;
        size_t length;
        sd_id128_t boot_id;
        char sid[33];
        int r;

        assert(j);

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r < 0) {
                log_error("Failed to get realtime timestamp: %s", strerror(-r));
                return r;
        }

        r = sd_journal_get_monotonic_usec(j, &monotonic, &boot_id);
        if (r < 0) {
                log_error("Failed to get monotonic timestamp: %s", strerror(-r));
                return r;
        }

        r = sd_journal_get_cursor(j, &cursor);
        if (r < 0) {
                log_error("Failed to get cursor: %s", strerror(-r));
                return r;
        }

        if (line == 1)
                fputc('\n', stdout);
        else
                fputs(",\n", stdout);

        printf("{\n"
               "\t\".cursor\" : \"%s\",\n"
               "\t\".realtime\" : %llu,\n"
               "\t\".monotonic\" : %llu,\n"
               "\t\".boot_id\" : \"%s\"",
               cursor,
               (unsigned long long) realtime,
               (unsigned long long) monotonic,
               sd_id128_to_string(boot_id, sid));

        free(cursor);

        SD_JOURNAL_FOREACH_DATA(j, data, length) {
                const char *c;

                c = memchr(data, '=', length);
                if (!c) {
                        log_error("Invalid field.");
                        return -EINVAL;
                }

                fputs(",\n\t", stdout);
                json_escape(data, c - (const char*) data);
                fputs(" : ", stdout);
                json_escape(c + 1, length - (c - (const char*) data) - 1);
        }

        fputs("\n}", stdout);
        fflush(stdout);

        return 0;
}

static int (*output_funcs[_OUTPUT_MAX])(sd_journal*j, unsigned line) = {
        [OUTPUT_SHORT] = output_short,
        [OUTPUT_VERBOSE] = output_verbose,
        [OUTPUT_EXPORT] = output_export,
        [OUTPUT_JSON] = output_json
};

static int help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to or query the login manager.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "  -a --all            Show all properties, including long and unprintable\n"
               "  -f --follow         Follow journal\n"
               "  -o --output=STRING  Change output mode (short, verbose, export, json)\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version" ,  no_argument,       NULL, ARG_VERSION   },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "follow",    no_argument,       NULL, 'f'           },
                { "output",    required_argument, NULL, 'o'           },
                { "all",       no_argument,       NULL, 'a'           },
                { NULL,        0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hfo:a", options, NULL)) >= 0) {

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
                        if (streq(optarg, "short"))
                                arg_output = OUTPUT_SHORT;
                        else if (streq(optarg, "verbose"))
                                arg_output = OUTPUT_VERBOSE;
                        else if (streq(optarg, "export"))
                                arg_output = OUTPUT_EXPORT;
                        else if (streq(optarg, "json"))
                                arg_output = OUTPUT_JSON;
                        else {
                                log_error("Unknown output '%s'.", optarg);
                                return -EINVAL;
                        }
                        break;

                case 'a':
                        arg_show_all = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r, i, fd;
        sd_journal *j = NULL;
        unsigned line = 0;

        log_set_max_level(LOG_DEBUG);
        log_set_target(LOG_TARGET_CONSOLE);

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_journal_open(&j);
        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                goto finish;
        }

        for (i = optind; i < argc; i++) {
                r = sd_journal_add_match(j, argv[i], strlen(argv[i]));
                if (r < 0) {
                        log_error("Failed to add match: %s", strerror(-r));
                        goto finish;
                }
        }

        fd = sd_journal_get_fd(j);
        if (fd < 0) {
                log_error("Failed to get wakeup fd: %s", strerror(-fd));
                goto finish;
        }

        r = sd_journal_seek_head(j);
        if (r < 0) {
                log_error("Failed to seek to head: %s", strerror(-r));
                goto finish;
        }

        if (!arg_no_pager && !arg_follow) {
                columns();
                pager_open();
        }

        if (arg_output == OUTPUT_JSON) {
                fputc('[', stdout);
                fflush(stdout);
        }

        for (;;) {
                struct pollfd pollfd;

                for (;;) {
                        r = sd_journal_next(j);

                        if (r < 0) {
                                log_error("Failed to iterate through journal: %s", strerror(-r));
                                goto finish;
                        }

                        if (r == 0)
                                break;

                        line ++;

                        r = output_funcs[arg_output](j, line);
                        if (r < 0)
                                goto finish;
                }

                if (!arg_follow)
                        break;

                zero(pollfd);
                pollfd.fd = fd;
                pollfd.events = POLLIN;

                if (poll(&pollfd, 1, -1) < 0) {
                        if (errno == EINTR)
                                break;

                        log_error("poll(): %m");
                        r = -errno;
                        goto finish;
                }

                r = sd_journal_process(j);
                if (r < 0) {
                        log_error("Failed to process: %s", strerror(-r));
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
