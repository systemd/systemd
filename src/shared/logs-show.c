/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/poll.h>
#include <string.h>

#include "logs-show.h"
#include "log.h"
#include "util.h"
#include "utf8.h"
#include "hashmap.h"
#include "journal-internal.h"

#define PRINT_THRESHOLD 128
#define JSON_THRESHOLD 4096

static int print_catalog(FILE *f, sd_journal *j) {
        int r;
        _cleanup_free_ char *t = NULL, *z = NULL;


        r = sd_journal_get_catalog(j, &t);
        if (r < 0)
                return r;

        z = strreplace(strstrip(t), "\n", "\n-- ");
        if (!z)
                return log_oom();

        fputs("-- ", f);
        fputs(z, f);
        fputc('\n', f);

        return 0;
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
        if (!buf)
                return log_oom();

        memcpy(buf, (const char*) data + fl, nl);
        ((char*)buf)[nl] = 0;

        free(*target);
        *target = buf;
        *target_size = nl;

        return 1;
}

static bool shall_print(const char *p, size_t l, OutputFlags flags) {
        assert(p);

        if (flags & OUTPUT_SHOW_ALL)
                return true;

        if (l >= PRINT_THRESHOLD)
                return false;

        if (!utf8_is_printable_n(p, l))
                return false;

        return true;
}

static int output_short(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags) {

        int r;
        const void *data;
        size_t length;
        size_t n = 0;
        _cleanup_free_ char *hostname = NULL, *identifier = NULL, *comm = NULL, *pid = NULL, *fake_pid = NULL, *message = NULL, *realtime = NULL, *monotonic = NULL, *priority = NULL;
        size_t hostname_len = 0, identifier_len = 0, comm_len = 0, pid_len = 0, fake_pid_len = 0, message_len = 0, realtime_len = 0, monotonic_len = 0, priority_len = 0;
        int p = LOG_INFO;
        const char *color_on = "", *color_off = "";

        assert(f);
        assert(j);

        sd_journal_set_data_threshold(j, flags & OUTPUT_SHOW_ALL ? 0 : PRINT_THRESHOLD);

        SD_JOURNAL_FOREACH_DATA(j, data, length) {

                r = parse_field(data, length, "PRIORITY=", &priority, &priority_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_HOSTNAME=", &hostname, &hostname_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "SYSLOG_IDENTIFIER=", &identifier, &identifier_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_COMM=", &comm, &comm_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_PID=", &pid, &pid_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "SYSLOG_PID=", &fake_pid, &fake_pid_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_SOURCE_REALTIME_TIMESTAMP=", &realtime, &realtime_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "_SOURCE_MONOTONIC_TIMESTAMP=", &monotonic, &monotonic_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_field(data, length, "MESSAGE=", &message, &message_len);
                if (r < 0)
                        return r;
        }

        if (!message)
                return 0;

        if (!(flags & OUTPUT_SHOW_ALL))
                strip_tab_ansi(&message, &message_len);

        if (priority_len == 1 && *priority >= '0' && *priority <= '7')
                p = *priority - '0';

        if (mode == OUTPUT_SHORT_MONOTONIC) {
                uint64_t t;
                sd_id128_t boot_id;

                r = -ENOENT;

                if (monotonic)
                        r = safe_atou64(monotonic, &t);

                if (r < 0)
                        r = sd_journal_get_monotonic_usec(j, &t, &boot_id);

                if (r < 0) {
                        log_error("Failed to get monotonic: %s", strerror(-r));
                        return r;
                }

                fprintf(f, "[%5llu.%06llu]",
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
                        return r;
                }

                t = (time_t) (x / USEC_PER_SEC);
                if (strftime(buf, sizeof(buf), "%b %d %H:%M:%S", localtime_r(&t, &tm)) <= 0) {
                        log_error("Failed to format time.");
                        return r;
                }

                fputs(buf, f);
                n += strlen(buf);
        }

        if (hostname && shall_print(hostname, hostname_len, flags)) {
                fprintf(f, " %.*s", (int) hostname_len, hostname);
                n += hostname_len + 1;
        }

        if (identifier && shall_print(identifier, identifier_len, flags)) {
                fprintf(f, " %.*s", (int) identifier_len, identifier);
                n += identifier_len + 1;
        } else if (comm && shall_print(comm, comm_len, flags)) {
                fprintf(f, " %.*s", (int) comm_len, comm);
                n += comm_len + 1;
        } else
                fputc(' ', f);

        if (pid && shall_print(pid, pid_len, flags)) {
                fprintf(f, "[%.*s]", (int) pid_len, pid);
                n += pid_len + 2;
        } else if (fake_pid && shall_print(fake_pid, fake_pid_len, flags)) {
                fprintf(f, "[%.*s]", (int) fake_pid_len, fake_pid);
                n += fake_pid_len + 2;
        }

        if (flags & OUTPUT_COLOR) {
                if (p <= LOG_ERR) {
                        color_on = ANSI_HIGHLIGHT_RED_ON;
                        color_off = ANSI_HIGHLIGHT_OFF;
                } else if (p <= LOG_NOTICE) {
                        color_on = ANSI_HIGHLIGHT_ON;
                        color_off = ANSI_HIGHLIGHT_OFF;
                }
        }

        if (flags & OUTPUT_SHOW_ALL)
                fprintf(f, ": %s%.*s%s\n", color_on, (int) message_len, message, color_off);
        else if (!utf8_is_printable_n(message, message_len)) {
                char bytes[FORMAT_BYTES_MAX];
                fprintf(f, ": [%s blob data]\n", format_bytes(bytes, sizeof(bytes), message_len));
        } else if ((flags & OUTPUT_FULL_WIDTH) || (message_len + n + 1 < n_columns))
                fprintf(f, ": %s%.*s%s\n", color_on, (int) message_len, message, color_off);
        else if (n < n_columns && n_columns - n - 2 >= 3) {
                _cleanup_free_ char *e;

                e = ellipsize_mem(message, message_len, n_columns - n - 2, 90);

                if (!e)
                        fprintf(f, ": %s%.*s%s\n", color_on, (int) message_len, message, color_off);
                else
                        fprintf(f, ": %s%s%s\n", color_on, e, color_off);
        } else
                fputs("\n", f);

        if (flags & OUTPUT_CATALOG)
                print_catalog(f, j);

        return 0;
}

static int output_verbose(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags) {

        const void *data;
        size_t length;
        _cleanup_free_ char *cursor = NULL;
        uint64_t realtime;
        char ts[FORMAT_TIMESTAMP_MAX];
        int r;

        assert(f);
        assert(j);

        sd_journal_set_data_threshold(j, 0);

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

        fprintf(f, "%s [%s]\n",
                format_timestamp(ts, sizeof(ts), realtime),
                cursor);

        SD_JOURNAL_FOREACH_DATA(j, data, length) {
                if (!shall_print(data, length, flags)) {
                        const char *c;
                        char bytes[FORMAT_BYTES_MAX];

                        c = memchr(data, '=', length);
                        if (!c) {
                                log_error("Invalid field.");
                                return -EINVAL;
                        }

                        fprintf(f, "\t%.*s=[%s blob data]\n",
                               (int) (c - (const char*) data),
                               (const char*) data,
                               format_bytes(bytes, sizeof(bytes), length - (c - (const char *) data) - 1));
                } else
                        fprintf(f, "\t%.*s\n", (int) length, (const char*) data);
        }

        if (flags & OUTPUT_CATALOG)
                print_catalog(f, j);

        return 0;
}

static int output_export(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags) {

        sd_id128_t boot_id;
        char sid[33];
        int r;
        usec_t realtime, monotonic;
        _cleanup_free_ char *cursor = NULL;
        const void *data;
        size_t length;

        assert(j);

        sd_journal_set_data_threshold(j, 0);

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

        fprintf(f,
                "__CURSOR=%s\n"
                "__REALTIME_TIMESTAMP=%llu\n"
                "__MONOTONIC_TIMESTAMP=%llu\n"
                "_BOOT_ID=%s\n",
                cursor,
                (unsigned long long) realtime,
                (unsigned long long) monotonic,
                sd_id128_to_string(boot_id, sid));

        SD_JOURNAL_FOREACH_DATA(j, data, length) {

                /* We already printed the boot id, from the data in
                 * the header, hence let's suppress it here */
                if (length >= 9 &&
                    memcmp(data, "_BOOT_ID=", 9) == 0)
                        continue;

                if (!utf8_is_printable_n(data, length)) {
                        const char *c;
                        uint64_t le64;

                        c = memchr(data, '=', length);
                        if (!c) {
                                log_error("Invalid field.");
                                return -EINVAL;
                        }

                        fwrite(data, c - (const char*) data, 1, f);
                        fputc('\n', f);
                        le64 = htole64(length - (c - (const char*) data) - 1);
                        fwrite(&le64, sizeof(le64), 1, f);
                        fwrite(c + 1, length - (c - (const char*) data) - 1, 1, f);
                } else
                        fwrite(data, length, 1, f);

                fputc('\n', f);
        }

        fputc('\n', f);

        return 0;
}

void json_escape(
                FILE *f,
                const char* p,
                size_t l,
                OutputFlags flags) {

        assert(f);
        assert(p);

        if (!(flags & OUTPUT_SHOW_ALL) && l >= JSON_THRESHOLD)

                fputs("null", f);

        else if (!utf8_is_printable_n(p, l)) {
                bool not_first = false;

                fputs("[ ", f);

                while (l > 0) {
                        if (not_first)
                                fprintf(f, ", %u", (uint8_t) *p);
                        else {
                                not_first = true;
                                fprintf(f, "%u", (uint8_t) *p);
                        }

                        p++;
                        l--;
                }

                fputs(" ]", f);
        } else {
                fputc('\"', f);

                while (l > 0) {
                        if (*p == '"' || *p == '\\') {
                                fputc('\\', f);
                                fputc(*p, f);
                        } else if (*p < ' ')
                                fprintf(f, "\\u%04x", *p);
                        else
                                fputc(*p, f);

                        p++;
                        l--;
                }

                fputc('\"', f);
        }
}

static int output_json(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags) {

        uint64_t realtime, monotonic;
        _cleanup_free_ char *cursor = NULL;
        const void *data;
        size_t length;
        sd_id128_t boot_id;
        char sid[33], *k;
        int r;
        Hashmap *h = NULL;
        bool done, separator;

        assert(j);

        sd_journal_set_data_threshold(j, flags & OUTPUT_SHOW_ALL ? 0 : JSON_THRESHOLD);

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

        if (mode == OUTPUT_JSON_PRETTY)
                fprintf(f,
                        "{\n"
                        "\t\"__CURSOR\" : \"%s\",\n"
                        "\t\"__REALTIME_TIMESTAMP\" : \"%llu\",\n"
                        "\t\"__MONOTONIC_TIMESTAMP\" : \"%llu\",\n"
                        "\t\"_BOOT_ID\" : \"%s\"",
                        cursor,
                        (unsigned long long) realtime,
                        (unsigned long long) monotonic,
                        sd_id128_to_string(boot_id, sid));
        else {
                if (mode == OUTPUT_JSON_SSE)
                        fputs("data: ", f);

                fprintf(f,
                        "{ \"__CURSOR\" : \"%s\", "
                        "\"__REALTIME_TIMESTAMP\" : \"%llu\", "
                        "\"__MONOTONIC_TIMESTAMP\" : \"%llu\", "
                        "\"_BOOT_ID\" : \"%s\"",
                        cursor,
                        (unsigned long long) realtime,
                        (unsigned long long) monotonic,
                        sd_id128_to_string(boot_id, sid));
        }

        h = hashmap_new(string_hash_func, string_compare_func);
        if (!h)
                return -ENOMEM;

        /* First round, iterate through the entry and count how often each field appears */
        SD_JOURNAL_FOREACH_DATA(j, data, length) {
                const char *eq;
                char *n;
                unsigned u;

                if (length >= 9 &&
                    memcmp(data, "_BOOT_ID=", 9) == 0)
                        continue;

                eq = memchr(data, '=', length);
                if (!eq)
                        continue;

                n = strndup(data, eq - (const char*) data);
                if (!n) {
                        r = -ENOMEM;
                        goto finish;
                }

                u = PTR_TO_UINT(hashmap_get(h, n));
                if (u == 0) {
                        r = hashmap_put(h, n, UINT_TO_PTR(1));
                        if (r < 0) {
                                free(n);
                                goto finish;
                        }
                } else {
                        r = hashmap_update(h, n, UINT_TO_PTR(u + 1));
                        free(n);
                        if (r < 0)
                                goto finish;
                }
        }

        separator = true;
        do {
                done = true;

                SD_JOURNAL_FOREACH_DATA(j, data, length) {
                        const char *eq;
                        char *kk, *n;
                        size_t m;
                        unsigned u;

                        /* We already printed the boot id, from the data in
                         * the header, hence let's suppress it here */
                        if (length >= 9 &&
                            memcmp(data, "_BOOT_ID=", 9) == 0)
                                continue;

                        eq = memchr(data, '=', length);
                        if (!eq)
                                continue;

                        if (separator) {
                                if (mode == OUTPUT_JSON_PRETTY)
                                        fputs(",\n\t", f);
                                else
                                        fputs(", ", f);
                        }

                        m = eq - (const char*) data;

                        n = strndup(data, m);
                        if (!n) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        u = PTR_TO_UINT(hashmap_get2(h, n, (void**) &kk));
                        if (u == 0) {
                                /* We already printed this, let's jump to the next */
                                free(n);
                                separator = false;

                                continue;
                        } else if (u == 1) {
                                /* Field only appears once, output it directly */

                                json_escape(f, data, m, flags);
                                fputs(" : ", f);

                                json_escape(f, eq + 1, length - m - 1, flags);

                                hashmap_remove(h, n);
                                free(kk);
                                free(n);

                                separator = true;

                                continue;

                        } else {
                                /* Field appears multiple times, output it as array */
                                json_escape(f, data, m, flags);
                                fputs(" : [ ", f);
                                json_escape(f, eq + 1, length - m - 1, flags);

                                /* Iterate through the end of the list */

                                while (sd_journal_enumerate_data(j, &data, &length) > 0) {
                                        if (length < m + 1)
                                                continue;

                                        if (memcmp(data, n, m) != 0)
                                                continue;

                                        if (((const char*) data)[m] != '=')
                                                continue;

                                        fputs(", ", f);
                                        json_escape(f, (const char*) data + m + 1, length - m - 1, flags);
                                }

                                fputs(" ]", f);

                                hashmap_remove(h, n);
                                free(kk);
                                free(n);

                                /* Iterate data fields form the beginning */
                                done = false;
                                separator = true;

                                break;
                        }
                }

        } while (!done);

        if (mode == OUTPUT_JSON_PRETTY)
                fputs("\n}\n", f);
        else if (mode == OUTPUT_JSON_SSE)
                fputs("}\n\n", f);
        else
                fputs(" }\n", f);

        r = 0;

finish:
        while ((k = hashmap_steal_first_key(h)))
                free(k);

        hashmap_free(h);

        return r;
}

static int output_cat(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags) {

        const void *data;
        size_t l;
        int r;

        assert(j);
        assert(f);

        sd_journal_set_data_threshold(j, 0);

        r = sd_journal_get_data(j, "MESSAGE", &data, &l);
        if (r < 0) {
                /* An entry without MESSAGE=? */
                if (r == -ENOENT)
                        return 0;

                log_error("Failed to get data: %s", strerror(-r));
                return r;
        }

        assert(l >= 8);

        fwrite((const char*) data + 8, 1, l - 8, f);
        fputc('\n', f);

        return 0;
}

static int (*output_funcs[_OUTPUT_MODE_MAX])(
                FILE *f,
                sd_journal*j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags) = {

        [OUTPUT_SHORT] = output_short,
        [OUTPUT_SHORT_MONOTONIC] = output_short,
        [OUTPUT_VERBOSE] = output_verbose,
        [OUTPUT_EXPORT] = output_export,
        [OUTPUT_JSON] = output_json,
        [OUTPUT_JSON_PRETTY] = output_json,
        [OUTPUT_JSON_SSE] = output_json,
        [OUTPUT_CAT] = output_cat
};

int output_journal(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags) {

        int ret;
        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);

        if (n_columns <= 0)
                n_columns = columns();

        ret = output_funcs[mode](f, j, mode, n_columns, flags);
        fflush(stdout);
        return ret;
}

static int show_journal(FILE *f,
                        sd_journal *j,
                        OutputMode mode,
                        unsigned n_columns,
                        usec_t not_before,
                        unsigned how_many,
                        OutputFlags flags) {

        int r;
        unsigned line = 0;
        bool need_seek = false;
        int warn_cutoff = flags & OUTPUT_WARN_CUTOFF;

        assert(j);
        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);

        /* Seek to end */
        r = sd_journal_seek_tail(j);
        if (r < 0)
                goto finish;

        r = sd_journal_previous_skip(j, how_many);
        if (r < 0)
                goto finish;

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

                        r = output_journal(f, j, mode, n_columns, flags);
                        if (r < 0)
                                goto finish;
                }

                if (warn_cutoff && line < how_many && not_before > 0) {
                        sd_id128_t boot_id;
                        usec_t cutoff;

                        /* Check whether the cutoff line is too early */

                        r = sd_id128_get_boot(&boot_id);
                        if (r < 0)
                                goto finish;

                        r = sd_journal_get_cutoff_monotonic_usec(j, boot_id, &cutoff, NULL);
                        if (r < 0)
                                goto finish;

                        if (r > 0 && not_before < cutoff)
                                fprintf(f, "Warning: Journal has been rotated since unit was started. Log output is incomplete or unavailable.\n");

                        warn_cutoff = false;
                }

                if (!(flags & OUTPUT_FOLLOW))
                        break;

                r = sd_journal_wait(j, (usec_t) -1);
                if (r < 0)
                        goto finish;

        }

finish:
        return r;
}

int add_matches_for_unit(sd_journal *j, const char *unit) {
        int r;
        _cleanup_free_ char *m1 = NULL, *m2 = NULL, *m3 = NULL;

        assert(j);
        assert(unit);

        if (asprintf(&m1, "_SYSTEMD_UNIT=%s", unit) < 0 ||
            asprintf(&m2, "COREDUMP_UNIT=%s", unit) < 0 ||
            asprintf(&m3, "UNIT=%s", unit) < 0)
                return -ENOMEM;

        (void)(
            /* Look for messages from the service itself */
            (r = sd_journal_add_match(j, m1, 0)) ||

            /* Look for coredumps of the service */
            (r = sd_journal_add_disjunction(j)) ||
            (r = sd_journal_add_match(j,
                        "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1", 0)) ||
            (r = sd_journal_add_match(j, m2, 0)) ||

             /* Look for messages from PID 1 about this service */
            (r = sd_journal_add_disjunction(j)) ||
            (r = sd_journal_add_match(j, "_PID=1", 0)) ||
            (r = sd_journal_add_match(j, m3, 0))
        );
        return r;
}

int add_matches_for_user_unit(sd_journal *j, const char *unit, uid_t uid) {
        int r;
        _cleanup_free_ char *m1 = NULL, *m2 = NULL, *m3 = NULL, *m4 = NULL;

        assert(j);
        assert(unit);

        if (asprintf(&m1, "_SYSTEMD_USER_UNIT=%s", unit) < 0 ||
            asprintf(&m2, "USER_UNIT=%s", unit) < 0 ||
            asprintf(&m3, "COREDUMP_USER_UNIT=%s", unit) < 0 ||
            asprintf(&m4, "_UID=%d", uid) < 0)
                return -ENOMEM;

        (void) (
                /* Look for messages from the user service itself */
                (r = sd_journal_add_match(j, m1, 0)) ||
                (r = sd_journal_add_match(j, m4, 0)) ||

                /* Look for messages from systemd about this service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = sd_journal_add_match(j, m2, 0)) ||
                (r = sd_journal_add_match(j, m4, 0)) ||

                /* Look for coredumps of the service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = sd_journal_add_match(j, m3, 0)) ||
                (r = sd_journal_add_match(j, m4, 0))
        );
        return r;
}

int show_journal_by_unit(
                FILE *f,
                const char *unit,
                OutputMode mode,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                uid_t uid,
                OutputFlags flags,
                bool system) {

        _cleanup_journal_close_ sd_journal*j = NULL;
        int r;
        int jflags = SD_JOURNAL_LOCAL_ONLY | system * SD_JOURNAL_SYSTEM_ONLY;

        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);
        assert(unit);

        if (how_many <= 0)
                return 0;

        r = sd_journal_open(&j, jflags);
        if (r < 0)
                return r;

        if (system)
                r = add_matches_for_unit(j, unit);
        else
                r = add_matches_for_user_unit(j, unit, uid);
        if (r < 0)
                return r;

        r = show_journal(f, j, mode, n_columns, not_before, how_many, flags);
        if (r < 0)
                return r;

        return 0;
}

static const char *const output_mode_table[_OUTPUT_MODE_MAX] = {
        [OUTPUT_SHORT] = "short",
        [OUTPUT_SHORT_MONOTONIC] = "short-monotonic",
        [OUTPUT_VERBOSE] = "verbose",
        [OUTPUT_EXPORT] = "export",
        [OUTPUT_JSON] = "json",
        [OUTPUT_JSON_PRETTY] = "json-pretty",
        [OUTPUT_JSON_SSE] = "json-sse",
        [OUTPUT_CAT] = "cat"
};

DEFINE_STRING_TABLE_LOOKUP(output_mode, OutputMode);
