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

static int output_short(sd_journal *j, unsigned line, bool show_all) {
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
            (show_all || (!contains_unprintable(data, length) &&
                          length < PRINT_THRESHOLD))) {
                printf(" %.*s", (int) length - 10, ((const char*) data) + 10);
                n += length - 10 + 1;
        }

        if (sd_journal_get_data(j, "MESSAGE", &data, &length) >= 0) {
                if (show_all)
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
        [OUTPUT_SHORT] = output_short,
        [OUTPUT_VERBOSE] = output_verbose,
        [OUTPUT_EXPORT] = output_export,
        [OUTPUT_JSON] = output_json
};

int output_journal(sd_journal *j, output_mode mode, unsigned line, bool show_all) {
        assert(mode < _OUTPUT_MODE_MAX);

        return output_funcs[mode](j, line, show_all);
}

int show_journal_by_service(
                const char *service,
                output_mode mode,
                const char *prefix,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                bool show_all) {

        char *m = NULL;
        sd_journal *j;
        int r;
        unsigned i;

        assert(service);

        if (!endswith(service, ".service") &&
            !endswith(service, ".socket") &&
            !endswith(service, ".mount") &&
            !endswith(service, ".swap"))
                return 0;

        if (n_columns <= 0)
                n_columns = columns();

        if (how_many <= 0)
                how_many = 10;

        if (!prefix)
                prefix = "";

        if (asprintf(&m, "_SYSTEMD_UNIT=%s", service) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY|SD_JOURNAL_SYSTEM_ONLY);
        if (r < 0)
                goto finish;

        r = sd_journal_add_match(j, m, strlen(m));
        if (r < 0)
                goto finish;

        r = sd_journal_seek_tail(j);
        if (r < 0)
                goto finish;

        for (i = 0; i < how_many; i++)
                sd_journal_previous(j);

        for (i = 0; i < how_many; i++) {

                r = sd_journal_next(j);
                if (r < 0)
                        goto finish;

                if (r == 0)
                        break;

                r = output_journal(j, mode, i+1, show_all);
                if (r < 0)
                        goto finish;
        }

finish:
        if (m)
                free(m);

        if (j)
                sd_journal_close(j);

        return r;
}
