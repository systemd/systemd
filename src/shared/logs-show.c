/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "sd-id128.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "io-util.h"
#include "journal-internal.h"
#include "journal-util.h"
#include "json.h"
#include "locale-util.h"
#include "log.h"
#include "logs-show.h"
#include "macro.h"
#include "namespace-util.h"
#include "output-mode.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "sparse-endian.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "utf8.h"
#include "util.h"
#include "web-util.h"

/* up to three lines (each up to 100 characters) or 300 characters, whichever is less */
#define PRINT_LINE_THRESHOLD 3
#define PRINT_CHAR_THRESHOLD 300

#define JSON_THRESHOLD 4096U

static int print_catalog(FILE *f, sd_journal *j) {
        _cleanup_free_ char *t = NULL, *z = NULL;
        const char *newline, *prefix;
        int r;

        assert(j);

        r = sd_journal_get_catalog(j, &t);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to find catalog entry: %m");

        if (is_locale_utf8())
                prefix = strjoina(special_glyph(SPECIAL_GLYPH_LIGHT_SHADE), special_glyph(SPECIAL_GLYPH_LIGHT_SHADE));
        else
                prefix = "--";

        newline = strjoina(ansi_normal(), "\n", ansi_grey(), prefix, ansi_normal(), " ", ansi_green());

        z = strreplace(strstrip(t), "\n", newline);
        if (!z)
                return log_oom();

        fprintf(f, "%s%s %s%s", ansi_grey(), prefix, ansi_normal(), ansi_green());

        fputs(z, f);

        fprintf(f, "%s\n", ansi_normal());

        return 1;
}

static int url_from_catalog(sd_journal *j, char **ret) {
        _cleanup_free_ char *t = NULL, *url = NULL;
        const char *weblink;
        int r;

        assert(j);
        assert(ret);

        r = sd_journal_get_catalog(j, &t);
        if (r == -ENOENT)
                goto notfound;
        if (r < 0)
                return log_error_errno(r, "Failed to find catalog entry: %m");

        weblink = startswith(t, "Documentation:");
        if (!weblink) {
                weblink = strstr(t + 1, "\nDocumentation:");
                if (!weblink)
                        goto notfound;

                weblink += 15;
        }

        /* Skip whitespace to value */
        weblink += strspn(weblink, " \t");

        /* Cut out till next whitespace/newline */
        url = strndup(weblink, strcspn(weblink, WHITESPACE));
        if (!url)
                return log_oom();

        if (!documentation_url_is_valid(url))
                goto notfound;

        *ret = TAKE_PTR(url);
        return 1;

notfound:
        *ret = NULL;
        return 0;
}

static int parse_field(const void *data, size_t length, const char *field, size_t field_len, char **target, size_t *target_len) {
        size_t nl;
        char *buf;

        assert(data);
        assert(field);
        assert(target);

        if (length < field_len)
                return 0;

        if (memcmp(data, field, field_len))
                return 0;

        nl = length - field_len;

        buf = newdup_suffix0(char, (const char*) data + field_len, nl);
        if (!buf)
                return log_oom();

        free(*target);
        *target = buf;

        if (target_len)
                *target_len = nl;

        return 1;
}

typedef struct ParseFieldVec {
        const char *field;
        size_t field_len;
        char **target;
        size_t *target_len;
} ParseFieldVec;

#define PARSE_FIELD_VEC_ENTRY(_field, _target, _target_len) {           \
                .field = _field,                                        \
                .field_len = strlen(_field),                            \
                .target = _target,                                      \
                .target_len = _target_len                               \
        }

static int parse_fieldv(const void *data, size_t length, const ParseFieldVec *fields, unsigned n_fields) {
        unsigned i;

        for (i = 0; i < n_fields; i++) {
                const ParseFieldVec *f = &fields[i];
                int r;

                r = parse_field(data, length, f->field, f->field_len, f->target, f->target_len);
                if (r < 0)
                        return r;
                else if (r > 0)
                        break;
        }

        return 0;
}

static int field_set_test(const Set *fields, const char *name, size_t n) {
        char *s;

        if (!fields)
                return 1;

        s = strndupa_safe(name, n);
        return set_contains(fields, s);
}

static bool shall_print(const char *p, size_t l, OutputFlags flags) {
        assert(p);

        if (flags & OUTPUT_SHOW_ALL)
                return true;

        if (l >= PRINT_CHAR_THRESHOLD)
                return false;

        if (!utf8_is_printable(p, l))
                return false;

        return true;
}

static bool print_multiline(
                FILE *f,
                unsigned prefix,
                unsigned n_columns,
                OutputFlags flags,
                int priority,
                bool audit,
                const char* message,
                size_t message_len,
                size_t highlight[2]) {

        const char *color_on = "", *color_off = "", *highlight_on = "";
        const char *pos, *end;
        bool ellipsized = false;
        int line = 0;

        if (flags & OUTPUT_COLOR) {
                get_log_colors(priority, &color_on, &color_off, &highlight_on);

                if (audit && strempty(color_on)) {
                        color_on = ANSI_BLUE;
                        color_off = ANSI_NORMAL;
                }
        }

        /* A special case: make sure that we print a newline when
           the message is empty. */
        if (message_len == 0)
                fputs("\n", f);

        for (pos = message;
             pos < message + message_len;
             pos = end + 1, line++) {
                bool tail_line;
                int len, indent = (line > 0) * prefix;
                for (end = pos; end < message + message_len && *end != '\n'; end++)
                        ;
                len = end - pos;
                assert(len >= 0);

                /* We need to figure out when we are showing not-last line, *and*
                 * will skip subsequent lines. In that case, we will put the dots
                 * at the end of the line, instead of putting dots in the middle
                 * or not at all.
                 */
                tail_line =
                        line + 1 == PRINT_LINE_THRESHOLD ||
                        end + 1 >= message + PRINT_CHAR_THRESHOLD;

                if (flags & (OUTPUT_FULL_WIDTH | OUTPUT_SHOW_ALL) ||
                    (prefix + len + 1 < n_columns && !tail_line)) {
                        if (highlight &&
                            (size_t) (pos - message) <= highlight[0] &&
                            highlight[0] < (size_t) len) {

                                fprintf(f, "%*s%s%.*s",
                                        indent, "",
                                        color_on, (int) highlight[0], pos);
                                fprintf(f, "%s%.*s",
                                        highlight_on,
                                        (int) (MIN((size_t) len, highlight[1]) - highlight[0]),
                                        pos + highlight[0]);
                                if ((size_t) len > highlight[1])
                                        fprintf(f, "%s%.*s",
                                                color_on,
                                                (int) (len - highlight[1]),
                                                pos + highlight[1]);
                                fprintf(f, "%s\n", color_off);

                        } else
                                fprintf(f, "%*s%s%.*s%s\n",
                                        indent, "",
                                        color_on, len, pos, color_off);
                        continue;
                }

                /* Beyond this point, ellipsization will happen. */
                ellipsized = true;

                if (prefix < n_columns && n_columns - prefix >= 3) {
                        if (n_columns - prefix > (unsigned) len + 3)
                                fprintf(f, "%*s%s%.*s...%s\n",
                                        indent, "",
                                        color_on, len, pos, color_off);
                        else {
                                _cleanup_free_ char *e = NULL;

                                e = ellipsize_mem(pos, len, n_columns - prefix,
                                                  tail_line ? 100 : 90);
                                if (!e)
                                        fprintf(f, "%*s%s%.*s%s\n",
                                                indent, "",
                                                color_on, len, pos, color_off);
                                else
                                        fprintf(f, "%*s%s%s%s\n",
                                                indent, "",
                                                color_on, e, color_off);
                        }
                } else
                        fputs("...\n", f);

                if (tail_line)
                        break;
        }

        return ellipsized;
}

static int output_timestamp_monotonic(
                FILE *f, OutputMode mode,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_ts,
                const sd_id128_t *previous_boot_id) {

        int written_chars = 0;

        assert(f);
        assert(ts);
        assert(boot_id);
        assert(previous_ts);
        assert(previous_boot_id);

        if (!VALID_MONOTONIC(ts->monotonic))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No valid monotonic timestamp available");

        written_chars += fprintf(f, "[%5"PRI_USEC".%06"PRI_USEC, ts->monotonic / USEC_PER_SEC, ts->monotonic % USEC_PER_SEC);

        if (mode == OUTPUT_SHORT_DELTA) {
                uint64_t delta;
                bool reliable_ts = true;

                if (VALID_MONOTONIC(previous_ts->monotonic) && sd_id128_equal(*boot_id, *previous_boot_id))
                        delta = usec_sub_unsigned(ts->monotonic, previous_ts->monotonic);
                else if (VALID_REALTIME(ts->realtime) && VALID_REALTIME(previous_ts->realtime)) {
                        delta = usec_sub_unsigned(ts->realtime, previous_ts->realtime);
                        reliable_ts = false;
                } else {
                        written_chars += fprintf(f, "%16s", "");
                        goto finish;
                }

                written_chars += fprintf(f, " <%5"PRI_USEC".%06"PRI_USEC"%s>", delta / USEC_PER_SEC, delta % USEC_PER_SEC, reliable_ts ? " " : "*");
        }

finish:
        written_chars += fprintf(f, "%s", "]");

        return written_chars;
}

static int output_timestamp_realtime(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                OutputFlags flags,
                const dual_timestamp *ts) {

        char buf[CONST_MAX(FORMAT_TIMESTAMP_MAX, 64U)];
        int r;

        assert(f);
        assert(j);
        assert(ts);

        if (!VALID_REALTIME(ts->realtime))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No valid realtime timestamp available");

        if (IN_SET(mode, OUTPUT_SHORT_FULL, OUTPUT_WITH_UNIT)) {
                const char *k;

                if (flags & OUTPUT_UTC)
                        k = format_timestamp_style(buf, sizeof(buf), ts->realtime, TIMESTAMP_UTC);
                else
                        k = format_timestamp(buf, sizeof(buf), ts->realtime);
                if (!k)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Failed to format timestamp: %" PRIu64, ts->realtime);

        } else {
                struct tm tm;
                time_t t;

                t = (time_t) (ts->realtime / USEC_PER_SEC);

                switch (mode) {

                case OUTPUT_SHORT_UNIX:
                        xsprintf(buf, "%10"PRI_TIME".%06"PRIu64, t, ts->realtime % USEC_PER_SEC);
                        break;

                case OUTPUT_SHORT_ISO:
                        if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z",
                                     localtime_or_gmtime_r(&t, &tm, flags & OUTPUT_UTC)) <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to format ISO time");
                        break;

                case OUTPUT_SHORT_ISO_PRECISE: {
                        char usec[7];

                        /* No usec in strftime, so we leave space and copy over */
                        if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.xxxxxx%z",
                                     localtime_or_gmtime_r(&t, &tm, flags & OUTPUT_UTC)) <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to format ISO-precise time");
                        xsprintf(usec, "%06"PRI_USEC, ts->realtime % USEC_PER_SEC);
                        memcpy(buf + 20, usec, 6);
                        break;
                }
                case OUTPUT_SHORT:
                case OUTPUT_SHORT_PRECISE:

                        if (strftime(buf, sizeof(buf), "%b %d %H:%M:%S",
                                     localtime_or_gmtime_r(&t, &tm, flags & OUTPUT_UTC)) <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to format syslog time");

                        if (mode == OUTPUT_SHORT_PRECISE) {
                                size_t k;

                                assert(sizeof(buf) > strlen(buf));
                                k = sizeof(buf) - strlen(buf);

                                r = snprintf(buf + strlen(buf), k, ".%06"PRIu64, ts->realtime % USEC_PER_SEC);
                                if (r <= 0 || (size_t) r >= k) /* too long? */
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to format precise time");
                        }
                        break;

                default:
                        assert_not_reached();
                }
        }

        fputs(buf, f);
        return (int) strlen(buf);
}

static int output_short(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_ts,
                const sd_id128_t *previous_boot_id) {

        int r;
        const void *data;
        size_t length, n = 0;
        _cleanup_free_ char *hostname = NULL, *identifier = NULL, *comm = NULL, *pid = NULL, *fake_pid = NULL,
                *message = NULL, *priority = NULL, *transport = NULL,
                *config_file = NULL, *unit = NULL, *user_unit = NULL, *documentation_url = NULL;
        size_t hostname_len = 0, identifier_len = 0, comm_len = 0, pid_len = 0, fake_pid_len = 0, message_len = 0,
                priority_len = 0, transport_len = 0, config_file_len = 0,
                unit_len = 0, user_unit_len = 0, documentation_url_len = 0;
        int p = LOG_INFO;
        bool ellipsized = false, audit;
        const ParseFieldVec fields[] = {
                PARSE_FIELD_VEC_ENTRY("_PID=", &pid, &pid_len),
                PARSE_FIELD_VEC_ENTRY("_COMM=", &comm, &comm_len),
                PARSE_FIELD_VEC_ENTRY("MESSAGE=", &message, &message_len),
                PARSE_FIELD_VEC_ENTRY("PRIORITY=", &priority, &priority_len),
                PARSE_FIELD_VEC_ENTRY("_TRANSPORT=", &transport, &transport_len),
                PARSE_FIELD_VEC_ENTRY("_HOSTNAME=", &hostname, &hostname_len),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_PID=", &fake_pid, &fake_pid_len),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_IDENTIFIER=", &identifier, &identifier_len),
                PARSE_FIELD_VEC_ENTRY("CONFIG_FILE=", &config_file, &config_file_len),
                PARSE_FIELD_VEC_ENTRY("_SYSTEMD_UNIT=", &unit, &unit_len),
                PARSE_FIELD_VEC_ENTRY("_SYSTEMD_USER_UNIT=", &user_unit, &user_unit_len),
                PARSE_FIELD_VEC_ENTRY("DOCUMENTATION=", &documentation_url, &documentation_url_len),
        };
        size_t highlight_shifted[] = {highlight ? highlight[0] : 0, highlight ? highlight[1] : 0};

        assert(f);
        assert(j);
        assert(ts);
        assert(boot_id);
        assert(previous_ts);
        assert(previous_boot_id);

        /* Set the threshold to one bigger than the actual print
         * threshold, so that if the line is actually longer than what
         * we're willing to print, ellipsization will occur. This way
         * we won't output a misleading line without any indication of
         * truncation.
         */
        sd_journal_set_data_threshold(j, flags & (OUTPUT_SHOW_ALL|OUTPUT_FULL_WIDTH) ? 0 : PRINT_CHAR_THRESHOLD + 1);

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                r = parse_fieldv(data, length, fields, ELEMENTSOF(fields));
                if (r < 0)
                        return r;
        }
        if (r == -EBADMSG) {
                log_debug_errno(r, "Skipping message we can't read: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get journal fields: %m");

        if (!message) {
                log_debug("Skipping message without MESSAGE= field.");
                return 0;
        }

        if (!(flags & OUTPUT_SHOW_ALL))
                strip_tab_ansi(&message, &message_len, highlight_shifted);

        if (priority_len == 1 && *priority >= '0' && *priority <= '7')
                p = *priority - '0';

        audit = streq_ptr(transport, "audit");

        if (IN_SET(mode, OUTPUT_SHORT_MONOTONIC, OUTPUT_SHORT_DELTA))
                r = output_timestamp_monotonic(f, mode, ts, boot_id, previous_ts, previous_boot_id);
        else
                r = output_timestamp_realtime(f, j, mode, flags, ts);
        if (r < 0)
                return r;
        n += r;

        if (flags & OUTPUT_NO_HOSTNAME) {
                /* Suppress display of the hostname if this is requested. */
                hostname = mfree(hostname);
                hostname_len = 0;
        }

        if (hostname && shall_print(hostname, hostname_len, flags)) {
                fprintf(f, " %.*s", (int) hostname_len, hostname);
                n += hostname_len + 1;
        }

        if (mode == OUTPUT_WITH_UNIT && ((unit && shall_print(unit, unit_len, flags)) ||
                                         (user_unit && shall_print(user_unit, user_unit_len, flags)))) {
                if (unit) {
                        fprintf(f, " %.*s", (int) unit_len, unit);
                        n += unit_len + 1;
                }
                if (user_unit) {
                        if (unit)
                                fprintf(f, "/%.*s", (int) user_unit_len, user_unit);
                        else
                                fprintf(f, " %.*s", (int) user_unit_len, user_unit);
                        n += unit_len + 1;
                }
        } else if (identifier && shall_print(identifier, identifier_len, flags)) {
                fprintf(f, " %.*s", (int) identifier_len, identifier);
                n += identifier_len + 1;
        } else if (comm && shall_print(comm, comm_len, flags)) {
                fprintf(f, " %.*s", (int) comm_len, comm);
                n += comm_len + 1;
        } else
                fputs(" unknown", f);

        if (pid && shall_print(pid, pid_len, flags)) {
                fprintf(f, "[%.*s]", (int) pid_len, pid);
                n += pid_len + 2;
        } else if (fake_pid && shall_print(fake_pid, fake_pid_len, flags)) {
                fprintf(f, "[%.*s]", (int) fake_pid_len, fake_pid);
                n += fake_pid_len + 2;
        }

        fputs(": ", f);

        if (urlify_enabled()) {
                _cleanup_free_ char *c = NULL;

                /* Insert a hyperlink to a documentation URL before the message. Note that we don't make the
                 * whole message a hyperlink, since otherwise the whole screen might end up being just
                 * hyperlinks. Moreover, we want to be able to highlight parts of the message (such as the
                 * config file, see below) hence let's keep the documentation URL link separate. */

                if (documentation_url && shall_print(documentation_url, documentation_url_len, flags)) {
                        c = strndup(documentation_url, documentation_url_len);
                        if (!c)
                                return log_oom();

                        if (!documentation_url_is_valid(c)) /* Eat up invalid links */
                                c = mfree(c);
                }

                if (!c)
                        (void) url_from_catalog(j, &c); /* Acquire from catalog if not embedded in log message itself */

                if (c) {
                        _cleanup_free_ char *urlified = NULL;

                        if (terminal_urlify(c, special_glyph(SPECIAL_GLYPH_EXTERNAL_LINK), &urlified) >= 0) {
                                fputs(urlified, f);
                                fputc(' ', f);
                        }
                }
        }

        if (!(flags & OUTPUT_SHOW_ALL) && !utf8_is_printable(message, message_len))
                fprintf(f, "[%s blob data]\n", FORMAT_BYTES(message_len));
        else {

                /* URLify config_file string in message, if the message starts with it.
                 * Skip URLification if the highlighted pattern overlaps. */
                if (config_file &&
                    message_len >= config_file_len &&
                    memcmp(message, config_file, config_file_len) == 0 &&
                    (message_len == config_file_len || IN_SET(message[config_file_len], ':', ' ')) &&
                    (!highlight || highlight_shifted[0] == 0 || highlight_shifted[0] > config_file_len)) {

                        _cleanup_free_ char *t = NULL, *urlified = NULL;

                        t = strndup(config_file, config_file_len);
                        if (t && terminal_urlify_path(t, NULL, &urlified) >= 0) {
                                size_t urlified_len = strlen(urlified);
                                size_t shift = urlified_len - config_file_len;
                                char *joined;

                                joined = realloc(urlified, message_len + shift);
                                if (joined) {
                                        memcpy(joined + urlified_len, message + config_file_len, message_len - config_file_len);
                                        free_and_replace(message, joined);
                                        TAKE_PTR(urlified);
                                        message_len += shift;
                                        if (highlight) {
                                                highlight_shifted[0] += shift;
                                                highlight_shifted[1] += shift;
                                        }
                                }
                        }
                }

                ellipsized |=
                        print_multiline(f, n + 2, n_columns, flags, p, audit,
                                        message, message_len,
                                        highlight_shifted);
        }

        if (flags & OUTPUT_CATALOG)
                (void) print_catalog(f, j);

        return ellipsized;
}

static int output_verbose(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_ts,
                const sd_id128_t *previous_boot_id) {

        const void *data;
        size_t length;
        _cleanup_free_ char *cursor = NULL;
        char buf[FORMAT_TIMESTAMP_MAX + 7];
        const char *timestamp;
        int r;

        assert(f);
        assert(j);
        assert(ts);
        assert(boot_id);
        assert(previous_ts);
        assert(previous_boot_id);

        sd_journal_set_data_threshold(j, 0);

        if (!VALID_REALTIME(ts->realtime))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No valid realtime timestamp available");

        r = sd_journal_get_cursor(j, &cursor);
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        timestamp = format_timestamp_style(buf, sizeof buf, ts->realtime,
                                           flags & OUTPUT_UTC ? TIMESTAMP_US_UTC : TIMESTAMP_US);
        fprintf(f, "%s [%s]\n",
                timestamp ?: "(no timestamp)",
                cursor);

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                const char *c, *p;
                int fieldlen;
                const char *on = "", *off = "";
                _cleanup_free_ char *urlified = NULL;
                size_t valuelen;

                c = memchr(data, '=', length);
                if (!c)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid field.");

                fieldlen = c - (const char*) data;
                if (!journal_field_valid(data, fieldlen, true))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid field.");

                r = field_set_test(output_fields, data, fieldlen);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                valuelen = length - 1 - fieldlen;

                if ((flags & OUTPUT_COLOR) && (p = startswith(data, "MESSAGE="))) {
                        on = ANSI_HIGHLIGHT;
                        off = ANSI_NORMAL;
                } else if ((p = startswith(data, "CONFIG_FILE="))) {
                        if (terminal_urlify_path(p, NULL, &urlified) >= 0) {
                                p = urlified;
                                valuelen = strlen(urlified);
                        }
                } else
                        p = c + 1;

                if ((flags & OUTPUT_SHOW_ALL) ||
                    (((length < PRINT_CHAR_THRESHOLD) || flags & OUTPUT_FULL_WIDTH)
                     && utf8_is_printable(data, length))) {
                        fprintf(f, "    %s%.*s=", on, fieldlen, (const char*)data);
                        print_multiline(f, 4 + fieldlen + 1, 0, OUTPUT_FULL_WIDTH, 0, false,
                                        p, valuelen,
                                        NULL);
                        fputs(off, f);
                } else
                        fprintf(f, "    %s%.*s=[%s blob data]%s\n",
                                on,
                                (int) (c - (const char*) data),
                                (const char*) data,
                                FORMAT_BYTES(length - (c - (const char *) data) - 1),
                                off);
        }

        if (r < 0)
                return r;

        if (flags & OUTPUT_CATALOG)
                (void) print_catalog(f, j);

        return 0;
}

static int output_export(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_ts,
                const sd_id128_t *previous_boot_id) {

        _cleanup_free_ char *cursor = NULL;
        const void *data;
        size_t length;
        usec_t monotonic, realtime;
        sd_id128_t journal_boot_id;
        int r;

        assert(j);
        assert(ts);
        assert(boot_id);
        assert(previous_ts);
        assert(previous_boot_id);

        sd_journal_set_data_threshold(j, 0);

        r = sd_journal_get_cursor(j, &cursor);
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r < 0)
                return log_error_errno(r, "Failed to get realtime timestamp: %m");

        r = sd_journal_get_monotonic_usec(j, &monotonic, &journal_boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get monotonic timestamp: %m");

        fprintf(f,
                "__CURSOR=%s\n"
                "__REALTIME_TIMESTAMP="USEC_FMT"\n"
                "__MONOTONIC_TIMESTAMP="USEC_FMT"\n"
                "_BOOT_ID=%s\n",
                cursor,
                realtime,
                monotonic,
                SD_ID128_TO_STRING(journal_boot_id));

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                size_t fieldlen;
                const char *c;

                /* We already printed the boot id from the data in the header, hence let's suppress it here */
                if (memory_startswith(data, length, "_BOOT_ID="))
                        continue;

                c = memchr(data, '=', length);
                if (!c)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid field.");

                fieldlen = c - (const char*) data;
                if (!journal_field_valid(data, fieldlen, true))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid field.");

                r = field_set_test(output_fields, data, fieldlen);
                if (r < 0)
                        return r;
                if (!r)
                        continue;

                if (utf8_is_printable_newline(data, length, false))
                        fwrite(data, length, 1, f);
                else {
                        uint64_t le64;

                        fwrite(data, fieldlen, 1, f);
                        fputc('\n', f);
                        le64 = htole64(length - fieldlen - 1);
                        fwrite(&le64, sizeof(le64), 1, f);
                        fwrite(c + 1, length - fieldlen - 1, 1, f);
                }

                fputc('\n', f);
        }
        if (r == -EBADMSG) {
                log_debug_errno(r, "Skipping message we can't read: %m");
                return 0;
        }

        if (r < 0)
                return r;

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

        else if (!(flags & OUTPUT_SHOW_ALL) && !utf8_is_printable(p, l)) {
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
                fputc('"', f);

                while (l > 0) {
                        if (IN_SET(*p, '"', '\\')) {
                                fputc('\\', f);
                                fputc(*p, f);
                        } else if (*p == '\n')
                                fputs("\\n", f);
                        else if ((uint8_t) *p < ' ')
                                fprintf(f, "\\u%04x", (uint8_t) *p);
                        else
                                fputc(*p, f);

                        p++;
                        l--;
                }

                fputc('"', f);
        }
}

struct json_data {
        JsonVariant* name;
        size_t n_values;
        JsonVariant* values[];
};

static int update_json_data(
                Hashmap *h,
                OutputFlags flags,
                const char *name,
                const void *value,
                size_t size) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        struct json_data *d;
        int r;

        if (!(flags & OUTPUT_SHOW_ALL) && strlen(name) + 1 + size >= JSON_THRESHOLD)
                r = json_variant_new_null(&v);
        else if (utf8_is_printable(value, size))
                r = json_variant_new_stringn(&v, value, size);
        else
                r = json_variant_new_array_bytes(&v, value, size);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate JSON data: %m");

        d = hashmap_get(h, name);
        if (d) {
                struct json_data *w;

                w = realloc(d, offsetof(struct json_data, values) + sizeof(JsonVariant*) * (d->n_values + 1));
                if (!w)
                        return log_oom();

                d = w;
                assert_se(hashmap_update(h, json_variant_string(d->name), d) >= 0);
        } else {
                _cleanup_(json_variant_unrefp) JsonVariant *n = NULL;

                r = json_variant_new_string(&n, name);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate JSON name variant: %m");

                d = malloc0(offsetof(struct json_data, values) + sizeof(JsonVariant*));
                if (!d)
                        return log_oom();

                r = hashmap_put(h, json_variant_string(n), d);
                if (r < 0) {
                        free(d);
                        return log_error_errno(r, "Failed to insert JSON name into hashmap: %m");
                }

                d->name = TAKE_PTR(n);
        }

        d->values[d->n_values++] = TAKE_PTR(v);
        return 0;
}

static int update_json_data_split(
                Hashmap *h,
                OutputFlags flags,
                const Set *output_fields,
                const void *data,
                size_t size) {

        size_t fieldlen;
        const char *eq;
        char *name;

        assert(h);
        assert(data || size == 0);

        if (memory_startswith(data, size, "_BOOT_ID="))
                return 0;

        eq = memchr(data, '=', MIN(size, JSON_THRESHOLD));
        if (!eq)
                return 0;

        fieldlen = eq - (const char*) data;
        if (!journal_field_valid(data, fieldlen, true))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid field.");

        name = strndupa_safe(data, fieldlen);
        if (output_fields && !set_contains(output_fields, name))
                return 0;

        return update_json_data(h, flags, name, eq + 1, size - fieldlen - 1);
}

static int output_json(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_ts,
                const sd_id128_t *previous_boot_id) {

        char sid[SD_ID128_STRING_MAX], usecbuf[DECIMAL_STR_MAX(usec_t)];
        _cleanup_(json_variant_unrefp) JsonVariant *object = NULL;
        _cleanup_free_ char *cursor = NULL;
        JsonVariant **array = NULL;
        struct json_data *d;
        Hashmap *h = NULL;
        size_t n = 0;
        usec_t realtime, monotonic;
        sd_id128_t journal_boot_id;
        int r;

        assert(j);
        assert(ts);
        assert(boot_id);
        assert(previous_ts);
        assert(previous_boot_id);

        (void) sd_journal_set_data_threshold(j, flags & OUTPUT_SHOW_ALL ? 0 : JSON_THRESHOLD);

        r = sd_journal_get_cursor(j, &cursor);
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r < 0)
                return log_error_errno(r, "Failed to get realtime timestamp: %m");

        r = sd_journal_get_monotonic_usec(j, &monotonic, &journal_boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get monotonic timestamp: %m");

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return log_oom();

        r = update_json_data(h, flags, "__CURSOR", cursor, strlen(cursor));
        if (r < 0)
                goto finish;

        xsprintf(usecbuf, USEC_FMT, realtime);
        r = update_json_data(h, flags, "__REALTIME_TIMESTAMP", usecbuf, strlen(usecbuf));
        if (r < 0)
                goto finish;

        xsprintf(usecbuf, USEC_FMT, monotonic);
        r = update_json_data(h, flags, "__MONOTONIC_TIMESTAMP", usecbuf, strlen(usecbuf));
        if (r < 0)
                goto finish;

        sd_id128_to_string(journal_boot_id, sid);
        r = update_json_data(h, flags, "_BOOT_ID", sid, strlen(sid));
        if (r < 0)
                goto finish;

        for (;;) {
                const void *data;
                size_t size;

                r = sd_journal_enumerate_data(j, &data, &size);
                if (r == -EBADMSG) {
                        log_debug_errno(r, "Skipping message we can't read: %m");
                        r = 0;
                        goto finish;
                }
                if (r < 0) {
                        log_error_errno(r, "Failed to read journal: %m");
                        goto finish;
                }
                if (r == 0)
                        break;

                r = update_json_data_split(h, flags, output_fields, data, size);
                if (r < 0)
                        goto finish;
        }

        array = new(JsonVariant*, hashmap_size(h)*2);
        if (!array) {
                r = log_oom();
                goto finish;
        }

        HASHMAP_FOREACH(d, h) {
                assert(d->n_values > 0);

                array[n++] = json_variant_ref(d->name);

                if (d->n_values == 1)
                        array[n++] = json_variant_ref(d->values[0]);
                else {
                        _cleanup_(json_variant_unrefp) JsonVariant *q = NULL;

                        r = json_variant_new_array(&q, d->values, d->n_values);
                        if (r < 0) {
                                log_error_errno(r, "Failed to create JSON array: %m");
                                goto finish;
                        }

                        array[n++] = TAKE_PTR(q);
                }
        }

        r = json_variant_new_object(&object, array, n);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate JSON object: %m");
                goto finish;
        }

        json_variant_dump(object,
                          output_mode_to_json_format_flags(mode) |
                          (FLAGS_SET(flags, OUTPUT_COLOR) ? JSON_FORMAT_COLOR : 0),
                          f, NULL);

        r = 0;

finish:
        while ((d = hashmap_steal_first(h))) {
                size_t k;

                json_variant_unref(d->name);
                for (k = 0; k < d->n_values; k++)
                        json_variant_unref(d->values[k]);

                free(d);
        }

        hashmap_free(h);

        json_variant_unref_many(array, n);
        free(array);

        return r;
}

static int output_cat_field(
                FILE *f,
                sd_journal *j,
                OutputFlags flags,
                int prio,
                const char *field,
                const size_t highlight[2]) {

        const char *color_on = "", *color_off = "", *highlight_on = "";
        const void *data;
        size_t l, fl;
        int r;

        if (FLAGS_SET(flags, OUTPUT_COLOR))
                get_log_colors(prio, &color_on, &color_off, &highlight_on);

        r = sd_journal_get_data(j, field, &data, &l);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Skipping message we can't read: %m");
                return 0;
        }
        if (r == -ENOENT) /* An entry without the requested field */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get data: %m");

        fl = strlen(field);
        assert(l >= fl + 1);
        assert(((char*) data)[fl] == '=');

        data = (const uint8_t*) data + fl + 1;
        l -= fl + 1;

        if (FLAGS_SET(flags, OUTPUT_COLOR)) {
                if (highlight) {
                        assert(highlight[0] <= highlight[1]);
                        assert(highlight[1] <= l);

                        fputs(color_on, f);
                        fwrite((const char*) data, 1, highlight[0], f);
                        fputs(highlight_on, f);
                        fwrite((const char*) data + highlight[0], 1, highlight[1] - highlight[0], f);
                        fputs(color_on, f);
                        fwrite((const char*) data + highlight[1], 1, l - highlight[1], f);
                        fputs(color_off, f);
                } else {
                        fputs(color_on, f);
                        fwrite((const char*) data, 1, l, f);
                        fputs(color_off, f);
                }
        } else
                fwrite((const char*) data, 1, l, f);

        fputc('\n', f);
        return 0;
}

static int output_cat(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_ts,
                const sd_id128_t *previous_boot_id) {

        int r, prio = LOG_INFO;
        const char *field;

        assert(j);
        assert(f);
        assert(ts);
        assert(boot_id);
        assert(previous_ts);
        assert(previous_boot_id);

        (void) sd_journal_set_data_threshold(j, 0);

        if (FLAGS_SET(flags, OUTPUT_COLOR)) {
                const void *data;
                size_t l;

                /* Determine priority of this entry, so that we can color it nicely */

                r = sd_journal_get_data(j, "PRIORITY", &data, &l);
                if (r == -EBADMSG) {
                        log_debug_errno(r, "Skipping message we can't read: %m");
                        return 0;
                }
                if (r < 0) {
                        if (r != -ENOENT)
                                return log_error_errno(r, "Failed to get data: %m");

                        /* An entry without PRIORITY */
                } else if (l == 10 && memcmp(data, "PRIORITY=", 9) == 0) {
                        char c = ((char*) data)[9];

                        if (c >= '0' && c <= '7')
                                prio = c - '0';
                }
        }

        if (set_isempty(output_fields))
                return output_cat_field(f, j, flags, prio, "MESSAGE", highlight);

        SET_FOREACH(field, output_fields) {
                r = output_cat_field(f, j, flags, prio, field, streq(field, "MESSAGE") ? highlight : NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int get_dual_timestamp(sd_journal *j, dual_timestamp *ret_ts, sd_id128_t *ret_boot_id) {
        const void *data;
        _cleanup_free_ char *realtime = NULL, *monotonic = NULL;
        size_t length = 0, realtime_len = 0, monotonic_len = 0;
        const ParseFieldVec message_fields[] = {
                PARSE_FIELD_VEC_ENTRY("_SOURCE_REALTIME_TIMESTAMP=", &realtime, &realtime_len),
                PARSE_FIELD_VEC_ENTRY("_SOURCE_MONOTONIC_TIMESTAMP=", &monotonic, &monotonic_len),
        };
        int r;
        bool realtime_good = false, monotonic_good = false, boot_id_good = false;

        assert(j);
        assert(ret_ts);
        assert(ret_boot_id);

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                r = parse_fieldv(data, length, message_fields, ELEMENTSOF(message_fields));
                if (r < 0)
                        return r;

                if (realtime && monotonic)
                        break;
        }
        if (r < 0)
                return r;

        if (realtime)
                realtime_good = safe_atou64(realtime, &ret_ts->realtime) >= 0;
        if (!realtime_good || !VALID_REALTIME(ret_ts->realtime))
                realtime_good = sd_journal_get_realtime_usec(j, &ret_ts->realtime) >= 0;
        if (!realtime_good)
                ret_ts->realtime = USEC_INFINITY;

        if (monotonic)
                monotonic_good = safe_atou64(monotonic, &ret_ts->monotonic) >= 0;
        if (!monotonic_good || !VALID_MONOTONIC(ret_ts->monotonic))
                monotonic_good = boot_id_good = sd_journal_get_monotonic_usec(j, &ret_ts->monotonic, ret_boot_id) >= 0;
        if (!monotonic_good)
                ret_ts->monotonic = USEC_INFINITY;

        if (!boot_id_good)
                boot_id_good = sd_journal_get_monotonic_usec(j, NULL, ret_boot_id) >= 0;
        if (!boot_id_good)
                *ret_boot_id = SD_ID128_NULL;

        /* Restart all data before */
        sd_journal_restart_data(j);
        sd_journal_restart_unique(j);
        sd_journal_restart_fields(j);

        return 0;
}

static int (*output_funcs[_OUTPUT_MODE_MAX])(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_ts,
                const sd_id128_t *previous_boot_id) = {

        [OUTPUT_SHORT]             = output_short,
        [OUTPUT_SHORT_ISO]         = output_short,
        [OUTPUT_SHORT_ISO_PRECISE] = output_short,
        [OUTPUT_SHORT_PRECISE]     = output_short,
        [OUTPUT_SHORT_MONOTONIC]   = output_short,
        [OUTPUT_SHORT_DELTA]       = output_short,
        [OUTPUT_SHORT_UNIX]        = output_short,
        [OUTPUT_SHORT_FULL]        = output_short,
        [OUTPUT_VERBOSE]           = output_verbose,
        [OUTPUT_EXPORT]            = output_export,
        [OUTPUT_JSON]              = output_json,
        [OUTPUT_JSON_PRETTY]       = output_json,
        [OUTPUT_JSON_SSE]          = output_json,
        [OUTPUT_JSON_SEQ]          = output_json,
        [OUTPUT_CAT]               = output_cat,
        [OUTPUT_WITH_UNIT]         = output_short,
};

int show_journal_entry(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                char **output_fields,
                const size_t highlight[2],
                bool *ellipsized,
                dual_timestamp *previous_ts,
                sd_id128_t *previous_boot_id) {

        _cleanup_set_free_ Set *fields = NULL;
        dual_timestamp ts = DUAL_TIMESTAMP_NULL;
        sd_id128_t boot_id = SD_ID128_NULL;
        int r;

        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);
        assert(previous_ts);
        assert(previous_boot_id);

        if (n_columns <= 0)
                n_columns = columns();

        r = set_put_strdupv(&fields, output_fields);
        if (r < 0)
                return r;

        r = get_dual_timestamp(j, &ts, &boot_id);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Skipping message we can't read: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get journal fields: %m");

        r = output_funcs[mode](f, j, mode, n_columns, flags, fields, highlight, &ts, &boot_id, previous_ts, previous_boot_id);

        /* Store timestamp and boot ID for next iteration */
        *previous_ts = ts;
        *previous_boot_id = boot_id;

        if (ellipsized && r > 0)
                *ellipsized = true;

        return r;
}

static int maybe_print_begin_newline(FILE *f, OutputFlags *flags) {
        assert(f);
        assert(flags);

        if (!(*flags & OUTPUT_BEGIN_NEWLINE))
                return 0;

        /* Print a beginning new line if that's request, but only once
         * on the first line we print. */

        fputc('\n', f);
        *flags &= ~OUTPUT_BEGIN_NEWLINE;
        return 0;
}

int show_journal(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                OutputFlags flags,
                bool *ellipsized) {

        int r;
        unsigned line = 0;
        bool need_seek = false;
        int warn_cutoff = flags & OUTPUT_WARN_CUTOFF;
        dual_timestamp previous_ts = DUAL_TIMESTAMP_NULL;
        sd_id128_t previous_boot_id = SD_ID128_NULL;

        assert(j);
        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);

        if (how_many == UINT_MAX)
                need_seek = true;
        else {
                /* Seek to end */
                r = sd_journal_seek_tail(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to tail: %m");

                r = sd_journal_previous_skip(j, how_many);
                if (r < 0)
                        return log_error_errno(r, "Failed to skip previous: %m");
        }

        for (;;) {
                usec_t usec;

                if (need_seek) {
                        r = sd_journal_next(j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to iterate through journal: %m");
                }

                if (r == 0)
                        break;

                need_seek = true;

                if (not_before > 0) {
                        r = sd_journal_get_monotonic_usec(j, &usec, NULL);

                        /* -ESTALE is returned if the timestamp is not from this boot */
                        if (r == -ESTALE)
                                continue;
                        else if (r < 0)
                                return log_error_errno(r, "Failed to get journal time: %m");

                        if (usec < not_before)
                                continue;
                }

                line++;
                maybe_print_begin_newline(f, &flags);

                r = show_journal_entry(f, j, mode, n_columns, flags, NULL, NULL, ellipsized,
                                       &previous_ts, &previous_boot_id);
                if (r < 0)
                        return r;
        }

        if (warn_cutoff && line < how_many && not_before > 0) {
                sd_id128_t boot_id;
                usec_t cutoff = 0;

                /* Check whether the cutoff line is too early */

                r = sd_id128_get_boot(&boot_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to get boot id: %m");

                r = sd_journal_get_cutoff_monotonic_usec(j, boot_id, &cutoff, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to get journal cutoff time: %m");

                if (r > 0 && not_before < cutoff) {
                        maybe_print_begin_newline(f, &flags);

                        /* If we logged *something* and no permission error happened, than we can reliably
                         * emit the warning about rotation. If we didn't log anything and access errors
                         * happened, emit hint about permissions. Otherwise, give a generic message, since we
                         * can't diagnose the issue. */

                        bool noaccess = journal_access_blocked(j);

                        if (line == 0 && noaccess)
                                fprintf(f, "Warning: some journal files were not opened due to insufficient permissions.\n");
                        else if (!noaccess)
                                fprintf(f, "Notice: journal has been rotated since unit was started, output may be incomplete.\n");
                        else
                                fprintf(f, "Warning: journal has been rotated since unit was started and some journal "
                                        "files were not opened due to insufficient permissions, output may be incomplete.\n");
                }

                warn_cutoff = false;
        }

        return 0;
}

int add_matches_for_unit(sd_journal *j, const char *unit) {
        const char *m1, *m2, *m3, *m4;
        int r;

        assert(j);
        assert(unit);

        m1 = strjoina("_SYSTEMD_UNIT=", unit);
        m2 = strjoina("COREDUMP_UNIT=", unit);
        m3 = strjoina("UNIT=", unit);
        m4 = strjoina("OBJECT_SYSTEMD_UNIT=", unit);

        (void)(
            /* Look for messages from the service itself */
            (r = sd_journal_add_match(j, m1, 0)) ||

            /* Look for coredumps of the service */
            (r = sd_journal_add_disjunction(j)) ||
            (r = sd_journal_add_match(j, "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1", 0)) ||
            (r = sd_journal_add_match(j, "_UID=0", 0)) ||
            (r = sd_journal_add_match(j, m2, 0)) ||

             /* Look for messages from PID 1 about this service */
            (r = sd_journal_add_disjunction(j)) ||
            (r = sd_journal_add_match(j, "_PID=1", 0)) ||
            (r = sd_journal_add_match(j, m3, 0)) ||

            /* Look for messages from authorized daemons about this service */
            (r = sd_journal_add_disjunction(j)) ||
            (r = sd_journal_add_match(j, "_UID=0", 0)) ||
            (r = sd_journal_add_match(j, m4, 0))
        );

        if (r == 0 && endswith(unit, ".slice")) {
                const char *m5;

                m5 = strjoina("_SYSTEMD_SLICE=", unit);

                /* Show all messages belonging to a slice */
                (void)(
                        (r = sd_journal_add_disjunction(j)) ||
                        (r = sd_journal_add_match(j, m5, 0))
                        );
        }

        return r;
}

int add_matches_for_user_unit(sd_journal *j, const char *unit, uid_t uid) {
        int r;
        char *m1, *m2, *m3, *m4;
        char muid[sizeof("_UID=") + DECIMAL_STR_MAX(uid_t)];

        assert(j);
        assert(unit);

        m1 = strjoina("_SYSTEMD_USER_UNIT=", unit);
        m2 = strjoina("USER_UNIT=", unit);
        m3 = strjoina("COREDUMP_USER_UNIT=", unit);
        m4 = strjoina("OBJECT_SYSTEMD_USER_UNIT=", unit);
        sprintf(muid, "_UID="UID_FMT, uid);

        (void) (
                /* Look for messages from the user service itself */
                (r = sd_journal_add_match(j, m1, 0)) ||
                (r = sd_journal_add_match(j, muid, 0)) ||

                /* Look for messages from systemd about this service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = sd_journal_add_match(j, m2, 0)) ||
                (r = sd_journal_add_match(j, muid, 0)) ||

                /* Look for coredumps of the service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = sd_journal_add_match(j, m3, 0)) ||
                (r = sd_journal_add_match(j, muid, 0)) ||
                (r = sd_journal_add_match(j, "_UID=0", 0)) ||

                /* Look for messages from authorized daemons about this service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = sd_journal_add_match(j, m4, 0)) ||
                (r = sd_journal_add_match(j, muid, 0)) ||
                (r = sd_journal_add_match(j, "_UID=0", 0))
        );

        if (r == 0 && endswith(unit, ".slice")) {
                const char *m5;

                m5 = strjoina("_SYSTEMD_USER_SLICE=", unit);

                /* Show all messages belonging to a slice */
                (void)(
                        (r = sd_journal_add_disjunction(j)) ||
                        (r = sd_journal_add_match(j, m5, 0)) ||
                        (r = sd_journal_add_match(j, muid, 0))
                        );
        }

        return r;
}

static int get_boot_id_for_machine(const char *machine, sd_id128_t *boot_id) {
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_close_ int pidnsfd = -1, mntnsfd = -1, rootfd = -1;
        char buf[SD_ID128_UUID_STRING_MAX];
        pid_t pid, child;
        ssize_t k;
        int r;

        assert(machine);
        assert(boot_id);

        r = container_get_leader(machine, &pid);
        if (r < 0)
                return r;

        r = namespace_open(pid, &pidnsfd, &mntnsfd, NULL, NULL, &rootfd);
        if (r < 0)
                return r;

        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0)
                return -errno;

        r = namespace_fork("(sd-bootidns)", "(sd-bootid)", NULL, 0, FORK_RESET_SIGNALS|FORK_DEATHSIG,
                           pidnsfd, mntnsfd, -1, -1, rootfd, &child);
        if (r < 0)
                return r;
        if (r == 0) {
                int fd;

                pair[0] = safe_close(pair[0]);

                fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        _exit(EXIT_FAILURE);

                r = loop_read_exact(fd, buf, 36, false);
                safe_close(fd);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                k = send(pair[1], buf, 36, MSG_NOSIGNAL);
                if (k != 36)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        r = wait_for_terminate_and_check("(sd-bootidns)", child, 0);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS)
                return -EIO;

        k = recv(pair[0], buf, 36, 0);
        if (k != 36)
                return -EIO;

        buf[36] = 0;
        r = sd_id128_from_string(buf, boot_id);
        if (r < 0)
                return r;

        return 0;
}

int add_match_this_boot(sd_journal *j, const char *machine) {
        char match[9+32+1] = "_BOOT_ID=";
        sd_id128_t boot_id;
        int r;

        assert(j);

        if (machine) {
                r = get_boot_id_for_machine(machine, &boot_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to get boot id of container %s: %m", machine);
        } else {
                r = sd_id128_get_boot(&boot_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to get boot id: %m");
        }

        sd_id128_to_string(boot_id, match + 9);
        r = sd_journal_add_match(j, match, strlen(match));
        if (r < 0)
                return log_error_errno(r, "Failed to add match: %m");

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add conjunction: %m");

        return 0;
}

int show_journal_by_unit(
                FILE *f,
                const char *unit,
                const char *log_namespace,
                OutputMode mode,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                uid_t uid,
                OutputFlags flags,
                int journal_open_flags,
                bool system_unit,
                bool *ellipsized) {

        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);
        assert(unit);

        if (how_many <= 0)
                return 0;

        r = sd_journal_open_namespace(&j, log_namespace, journal_open_flags | SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        if (system_unit)
                r = add_matches_for_unit(j, unit);
        else
                r = add_matches_for_user_unit(j, unit, uid);
        if (r < 0)
                return log_error_errno(r, "Failed to add unit matches: %m");

        r = sd_journal_add_conjunction(j);
        if (r < 0)
                return log_error_errno(r, "Failed to add conjunction: %m");

        r = add_match_this_boot(j, NULL);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *filter = NULL;

                filter = journal_make_match_string(j);
                if (!filter)
                        return log_oom();

                log_debug("Journal filter: %s", filter);
        }

        return show_journal(f, j, mode, n_columns, not_before, how_many, flags, ellipsized);
}
