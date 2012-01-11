/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/poll.h>
#include <string.h>

#include "logs-show.h"
#include "log.h"
#include "util.h"

#define PRINT_THRESHOLD 128

static bool contains_unprintable(const void *p, size_t l) {
        const char *j;

        for (j = p; j < (const char *) p + l; j++)
                if (*j < ' ' || *j >= 127)
                        return true;

        return false;
}

static int parse_field(const void *data, size_t length, const char *field, char **target, size_t *target_size) {
        size_t fl, nl;
        void *buf;

        assert(data);
        assert(field);
        assert(target);
        assert(target_size);

        fl = strlen(field);
        if (length < fl)
                return 0;

        if (memcmp(data, field, fl))
                return 0;

        nl = length - fl;
        buf = malloc(nl+1);
        memcpy(buf, (const char*) data + fl, nl);
        ((char*)buf)[nl] = 0;
        if (!buf) {
                log_error("Out of memory");
                return -ENOMEM;
        }

        free(*target);
        *target = buf;
        *target_size = nl;

        return 1;
}

static bool shall_print(bool show_all, char *p, size_t l) {
        if (show_all)
                return true;

        if (l > PRINT_THRESHOLD)
                return false;

        if (contains_unprintable(p, l))
                return false;

        return true;
}

static int output_short(sd_journal *j, unsigned line, bool show_all, bool monotonic_mode) {
        int r;
        const void *data;
        size_t length;
        size_t n = 0;
        char *hostname = NULL, *identifier = NULL, *comm = NULL, *pid = NULL, *fake_pid = NULL, *message = NULL, *realtime = NULL, *monotonic = NULL;
        size_t hostname_len = 0, identifier_len = 0, comm_len = 0, pid_len = 0, fake_pid_len = 0, message_len = 0, realtime_len = 0, monotonic_len = 0;

        assert(j);

        SD_JOURNAL_FOREACH_DATA(j, data, length) {

                r = parse_field(data, length, "_HOSTNAME=", &hostname, &hostname_len);
                if (r < 0)
                        goto finish;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "SYSLOG_IDENTIFIER=", &identifier, &identifier_len);
                if (r < 0)
                        goto finish;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_COMM=", &comm, &comm_len);
                if (r < 0)
                        goto finish;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_PID=", &pid, &pid_len);
                if (r < 0)
                        goto finish;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "SYSLOG_PID=", &fake_pid, &fake_pid_len);
                if (r < 0)
                        goto finish;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_SOURCE_REALTIME_TIMESTAMP=", &realtime, &realtime_len);
                if (r < 0)
                        goto finish;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_SOURCE_MONOTONIC_TIMESTAMP=", &monotonic, &monotonic_len);
                if (r < 0)
                        goto finish;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "MESSAGE=", &message, &message_len);
                if (r < 0)
                        goto finish;
        }

        if (!message) {
                r = 0;
                goto finish;
        }

        if (monotonic_mode) {
                uint64_t t;
                sd_id128_t boot_id;

                r = -ENOENT;

                if (monotonic)
                        r = safe_atou64(monotonic, &t);

                if (r < 0)
                        r = sd_journal_get_monotonic_usec(j, &t, &boot_id);

                if (r < 0) {
                        log_error("Failed to get monotonic: %s", strerror(-r));
                        goto finish;
                }

                printf("[%5llu.%06llu]",
                       (unsigned long long) (t / USEC_PER_SEC),
                       (unsigned long long) (t % USEC_PER_SEC));

                n += 1 + 5 + 1 + 6 + 1;

        } else {
                char buf[64];
                uint64_t x;
                time_t t;
                struct tm tm;

                r = -ENOENT;

                if (realtime)
                        r = safe_atou64(realtime, &x);

                if (r < 0)
                        r = sd_journal_get_realtime_usec(j, &x);

                if (r < 0) {
                        log_error("Failed to get realtime: %s", strerror(-r));
                        goto finish;
                }

                t = (time_t) (x / USEC_PER_SEC);
                if (strftime(buf, sizeof(buf), "%b %d %H:%M:%S", localtime_r(&t, &tm)) <= 0) {
                        log_error("Failed to format time.");
                        goto finish;
                }

                fputs(buf, stdout);
                n += strlen(buf);
        }

        if (hostname && shall_print(show_all, hostname, hostname_len)) {
                printf(" %.*s", (int) hostname_len, hostname);
                n += hostname_len + 1;
        }

        if (identifier && shall_print(show_all, identifier, identifier_len)) {
                printf(" %.*s", (int) identifier_len, identifier);
                n += identifier_len + 1;
        } else if (comm && shall_print(show_all, comm, comm_len)) {
                printf(" %.*s", (int) comm_len, comm);
                n += comm_len + 1;
        }

        if (pid && shall_print(show_all, pid, pid_len)) {
                printf("[%.*s]", (int) pid_len, pid);
                n += pid_len + 2;
        } else if (fake_pid && shall_print(show_all, fake_pid, fake_pid_len)) {
                printf("[%.*s]", (int) fake_pid_len, fake_pid);
                n += fake_pid_len + 2;
        }

        if (show_all)
                printf(": %.*s\n", (int) message_len, message);
        else if (contains_unprintable(message, message_len))
                fputs(": [blob data]\n", stdout);
        else if (message_len + n < columns())
                printf(": %.*s\n", (int) message_len, message);
        else if (n < columns()) {
                char *e;

                e = ellipsize_mem(message, message_len, columns() - n - 2, 90);

                if (!e)
                        printf(": %.*s\n", (int) message_len, message);
                else
                        printf(": %s", e);

                free(e);
        } else
                fputs("\n", stdout);

        r = 0;

finish:
        free(hostname);
        free(identifier);
        free(comm);
        free(pid);
        free(fake_pid);
        free(message);
        free(monotonic);
        free(realtime);

        return r;
}

static int output_short_realtime(sd_journal *j, unsigned line, bool show_all) {
        return output_short(j, line, show_all, false);
}

static int output_short_monotonic(sd_journal *j, unsigned line, bool show_all) {
        return output_short(j, line, show_all, true);
}

static int output_verbose(sd_journal *j, unsigned line, bool show_all) {
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
                if (!show_all && (length > PRINT_THRESHOLD ||
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

static int output_export(sd_journal *j, unsigned line, bool show_all) {
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

static int output_json(sd_journal *j, unsigned line, bool show_all) {
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

static int (*output_funcs[_OUTPUT_MODE_MAX])(sd_journal*j, unsigned line, bool show_all) = {
        [OUTPUT_SHORT] = output_short_realtime,
        [OUTPUT_SHORT_MONOTONIC] = output_short_monotonic,
        [OUTPUT_VERBOSE] = output_verbose,
        [OUTPUT_EXPORT] = output_export,
        [OUTPUT_JSON] = output_json
};

int output_journal(sd_journal *j, OutputMode mode, unsigned line, bool show_all) {
        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);

        return output_funcs[mode](j, line, show_all);
}

int show_journal_by_unit(
                const char *unit,
                OutputMode mode,
                const char *prefix,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                bool show_all,
                bool follow) {

        char *m = NULL;
        sd_journal *j;
        int r;
        int fd;
        unsigned line = 0;
        bool need_seek = false;

        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);
        assert(unit);

        if (!endswith(unit, ".service") &&
            !endswith(unit, ".socket") &&
            !endswith(unit, ".mount") &&
            !endswith(unit, ".swap"))
                return 0;

        if (how_many <= 0)
                return 0;

        if (n_columns <= 0)
                n_columns = columns();

        if (!prefix)
                prefix = "";

        if (asprintf(&m, "_SYSTEMD_UNIT=%s", unit) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY|SD_JOURNAL_SYSTEM_ONLY);
        if (r < 0)
                goto finish;

        fd = sd_journal_get_fd(j);
        if (fd < 0)
                goto finish;

        r = sd_journal_add_match(j, m, strlen(m));
        if (r < 0)
                goto finish;

        r = sd_journal_seek_tail(j);
        if (r < 0)
                goto finish;

        r = sd_journal_previous_skip(j, how_many);
        if (r < 0)
                goto finish;

        if (mode == OUTPUT_JSON) {
                fputc('[', stdout);
                fflush(stdout);
        }

        for (;;) {
                for (;;) {
                        usec_t usec;

                        if (need_seek) {
                                r = sd_journal_next(j);
                                if (r < 0)
                                        goto finish;
                        }

                        if (r == 0)
                                break;

                        need_seek = true;

                        if (not_before > 0) {
                                r = sd_journal_get_monotonic_usec(j, &usec, NULL);

                                /* -ESTALE is returned if the
                                   timestamp is not from this boot */
                                if (r == -ESTALE)
                                        continue;
                                else if (r < 0)
                                        goto finish;

                                if (usec < not_before)
                                        continue;
                        }

                        line ++;

                        r = output_journal(j, mode, line, show_all);
                        if (r < 0)
                                goto finish;
                }

                if (!follow)
                        break;

                r = fd_wait_for_event(fd, POLLIN);
                if (r < 0)
                        goto finish;

                r = sd_journal_process(j);
                if (r < 0)
                        goto finish;

        }

        if (mode == OUTPUT_JSON)
                fputs("\n]\n", stdout);

finish:
        if (m)
                free(m);

        if (j)
                sd_journal_close(j);

        return r;
}

static const char *const output_mode_table[_OUTPUT_MODE_MAX] = {
        [OUTPUT_SHORT] = "short",
        [OUTPUT_SHORT_MONOTONIC] = "short-monotonic",
        [OUTPUT_VERBOSE] = "verbose",
        [OUTPUT_EXPORT] = "export",
        [OUTPUT_JSON] = "json"
};

DEFINE_STRING_TABLE_LOOKUP(output_mode, OutputMode);
