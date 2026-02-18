/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#include "sd-id128.h"
#include "sd-journal.h"
#include "sd-json.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "format-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "id128-util.h"
#include "journal-internal.h"
#include "journal-util.h"
#include "locale-util.h"
#include "log.h"
#include "logs-show.h"
#include "output-mode.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "rlimit-util.h"
#include "set.h"
#include "sigbus.h"
#include "sparse-endian.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "user-util.h"
#include "utf8.h"
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
                prefix = strjoina(glyph(GLYPH_LIGHT_SHADE), glyph(GLYPH_LIGHT_SHADE));
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

        weblink = find_line_startswith(t, "Documentation:");
        if (!weblink)
                goto notfound;

        /* Skip whitespace to value */
        weblink += strspn(weblink, " \t");

        /* Cut out till next whitespace/newline */
        url = strdupcspn(weblink, WHITESPACE);
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

static int parse_field(
                const void *data,
                size_t length,
                const char *field,
                size_t field_len,
                char **target,
                size_t *target_len) {

        size_t nl;
        char *buf;

        assert(data);
        assert(field);
        assert(target);

        if (length < field_len)
                return 0;

        if (memcmp(data, field, field_len) != 0)
                return 0;

        nl = length - field_len;

        buf = newdup_suffix0(char, (const char*) data + field_len, nl);
        if (!buf)
                return log_oom();

        free_and_replace(*target, buf);

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

static int parse_fieldv(
                const void *data,
                size_t length,
                const ParseFieldVec *fields,
                size_t n_fields) {

        int r;

        for (size_t i = 0; i < n_fields; i++) {
                const ParseFieldVec *f = &fields[i];

                r = parse_field(data, length, f->field, f->field_len, f->target, f->target_len);
                if (r < 0)
                        return r;
                if (r > 0)
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
                        color_on = ansi_blue();
                        color_off = ansi_normal();
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
                FILE *f,
                OutputMode mode,
                const dual_timestamp *display_ts,
                const sd_id128_t *boot_id,
                const dual_timestamp *previous_display_ts,
                const sd_id128_t *previous_boot_id) {

        int written_chars = 0;

        assert(f);
        assert(display_ts);
        assert(boot_id);
        assert(previous_display_ts);
        assert(previous_boot_id);

        if (!VALID_MONOTONIC(display_ts->monotonic))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "No valid monotonic timestamp available, skipping showing journal entry.");

        written_chars += fprintf(f, "[%5"PRI_USEC".%06"PRI_USEC, display_ts->monotonic / USEC_PER_SEC, display_ts->monotonic % USEC_PER_SEC);

        if (mode == OUTPUT_SHORT_DELTA) {
                uint64_t delta;
                bool reliable_ts = true;

                if (VALID_MONOTONIC(previous_display_ts->monotonic) && sd_id128_equal(*boot_id, *previous_boot_id))
                        delta = usec_sub_unsigned(display_ts->monotonic, previous_display_ts->monotonic);
                else if (VALID_REALTIME(display_ts->realtime) && VALID_REALTIME(previous_display_ts->realtime)) {
                        delta = usec_sub_unsigned(display_ts->realtime, previous_display_ts->realtime);
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
                OutputMode mode,
                OutputFlags flags,
                usec_t usec) {

        char buf[CONST_MAX(FORMAT_TIMESTAMP_MAX, 64U)];
        int r;

        assert(f);

        if (!VALID_REALTIME(usec))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "No valid realtime timestamp available, skipping showing journal entry.");

        switch (mode) {

        case OUTPUT_SHORT_FULL:
        case OUTPUT_WITH_UNIT: {
                if (!format_timestamp_style(buf, sizeof(buf), usec, flags & OUTPUT_UTC ? TIMESTAMP_UTC : TIMESTAMP_PRETTY))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to format timestamp (%"PRIu64"), skipping showing journal entry.", usec);
                break;
        }

        case OUTPUT_SHORT_UNIX:
                xsprintf(buf, "%10" PRI_USEC ".%06" PRI_USEC, usec / USEC_PER_SEC, usec % USEC_PER_SEC);
                break;

        case OUTPUT_SHORT:
        case OUTPUT_SHORT_PRECISE:
        case OUTPUT_SHORT_ISO:
        case OUTPUT_SHORT_ISO_PRECISE: {
                struct tm tm;
                size_t tail = 0;

                r = localtime_or_gmtime_usec(usec, flags & OUTPUT_UTC, &tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to convert timestamp to calendar time, generating fallback timestamp: %m");
                else {
                        tail = strftime(
                                        buf, sizeof(buf),
                                        IN_SET(mode, OUTPUT_SHORT_ISO, OUTPUT_SHORT_ISO_PRECISE) ? "%Y-%m-%dT%H:%M:%S" : "%b %d %H:%M:%S",
                                        &tm);
                        if (tail <= 0)
                                log_debug("Failed to format calendar time, generating fallback timestamp.");
                }

                if (tail <= 0) {
                        /* Generate fallback timestamp if regular formatting didn't work. (This might happen on systems where time_t is 32bit) */

                        static const char *const xxx[_OUTPUT_MODE_MAX] = {
                                [OUTPUT_SHORT]             = "XXX XX XX:XX:XX",
                                [OUTPUT_SHORT_PRECISE]     = "XXX XX XX:XX:XX.XXXXXX",
                                [OUTPUT_SHORT_ISO]         = "XXXX-XX-XXTXX:XX:XX+XX:XX",
                                [OUTPUT_SHORT_ISO_PRECISE] = "XXXX-XX-XXTXX:XX:XX.XXXXXX+XX:XX",
                        };

                        fputs(xxx[mode], f);
                        return strlen(xxx[mode]);
                }

                assert(tail <= sizeof(buf));

                /* No usec in strftime, need to append */
                if (IN_SET(mode, OUTPUT_SHORT_ISO_PRECISE, OUTPUT_SHORT_PRECISE)) {
                        assert_se(snprintf_ok(buf + tail, sizeof(buf) - tail, ".%06" PRI_USEC, usec % USEC_PER_SEC));

                        tail += 7;

                        assert(tail <= sizeof(buf));
                }

                if (IN_SET(mode, OUTPUT_SHORT_ISO, OUTPUT_SHORT_ISO_PRECISE)) {
                        int h = tm.tm_gmtoff / 60 / 60,
                                m = ABS((int) ((tm.tm_gmtoff / 60) % 60));

                        assert_se(snprintf_ok(buf + tail, sizeof(buf) - tail, "%+03d:%02d", h, m));
                }

                break;
        }

        default:
                assert_not_reached();
        }

        fputs(buf, f);
        return (int) strlen(buf);
}

static void parse_display_realtime(
                sd_journal *j,
                const char *source_realtime,
                const char *source_monotonic,
                usec_t *ret) {

        usec_t t;

        assert(j);
        assert(ret);

        /* First, try _SOURCE_REALTIME_TIMESTAMP. */
        if (source_realtime && safe_atou64(source_realtime, &t) >= 0 && VALID_REALTIME(t)) {
                *ret = t;
                return;
        }

        /* Read realtime timestamp in the entry header. */
        if (sd_journal_get_realtime_usec(j, &t) < 0) {
                *ret = USEC_INFINITY;
                return;
        }

        /* If _SOURCE_MONOTONIC_TIMESTAMP is provided, adjust the header timestamp. */
        // FIXME: _SOURCE_MONOTONIC_TIMESTAMP is in CLOCK_BOOTTIME, hence we cannot use it for adjusting realtime.
        /*
        usec_t s, u;
        if (source_monotonic && safe_atou64(source_monotonic, &s) >= 0 && VALID_MONOTONIC(s) &&
            sd_journal_get_monotonic_usec(j, &u, &(sd_id128_t) {}) >= 0) {
                *ret = map_clock_usec_raw(t, u, s);
                return;
        }
        */

        /* Otherwise, use the header timestamp as is. */
        *ret = t;
}

static void parse_display_timestamp(
                sd_journal *j,
                const char *source_realtime,
                const char *source_monotonic,
                dual_timestamp *ret_display_ts,
                sd_id128_t *ret_boot_id) {

        dual_timestamp header_ts = DUAL_TIMESTAMP_INFINITY, source_ts = DUAL_TIMESTAMP_INFINITY;
        sd_id128_t boot_id = SD_ID128_NULL;
        usec_t t;

        assert(j);
        assert(ret_display_ts);
        assert(ret_boot_id);

        if (source_realtime && safe_atou64(source_realtime, &t) >= 0 && VALID_REALTIME(t))
                source_ts.realtime = t;

        // FIXME: _SOURCE_MONOTONIC_TIMESTAMP is in CLOCK_BOOTTIME, hence we cannot use it for adjusting realtime.
        /*
        if (source_monotonic && safe_atou64(source_monotonic, &t) >= 0 && VALID_MONOTONIC(t))
                source_ts.monotonic = t;
        */

        (void) sd_journal_get_realtime_usec(j, &header_ts.realtime);
        (void) sd_journal_get_monotonic_usec(j, &header_ts.monotonic, &boot_id);

        /* Adjust timestamp if possible. */
        if (header_ts.realtime != USEC_INFINITY && header_ts.monotonic != USEC_INFINITY) {
                if (source_ts.realtime == USEC_INFINITY && source_ts.monotonic != USEC_INFINITY)
                        source_ts.realtime = map_clock_usec_raw(header_ts.realtime, header_ts.monotonic, source_ts.monotonic);
                else if (source_ts.realtime != USEC_INFINITY && source_ts.monotonic == USEC_INFINITY)
                        source_ts.monotonic = map_clock_usec_raw(header_ts.monotonic, header_ts.realtime, source_ts.realtime);
        }

        ret_display_ts->realtime = source_ts.realtime != USEC_INFINITY ? source_ts.realtime : header_ts.realtime;
        ret_display_ts->monotonic = source_ts.monotonic != USEC_INFINITY ? source_ts.monotonic : header_ts.monotonic;
        *ret_boot_id = boot_id;
}

static int output_short(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                dual_timestamp *previous_display_ts, /* in and out, used only when mode is OUTPUT_SHORT_MONOTONIC, OUTPUT_SHORT_DELTA. */
                sd_id128_t *previous_boot_id) {      /* in and out, used only when mode is OUTPUT_SHORT_MONOTONIC, OUTPUT_SHORT_DELTA. */

        int r;
        const void *data;
        size_t length, n = 0;
        _cleanup_free_ char *hostname = NULL, *identifier = NULL, *comm = NULL, *pid = NULL, *fake_pid = NULL,
                *message = NULL, *priority = NULL, *transport = NULL,
                *config_file = NULL, *unit = NULL, *user_unit = NULL, *documentation_url = NULL,
                *realtime = NULL, *monotonic = NULL;
        size_t hostname_len = 0, identifier_len = 0, comm_len = 0, pid_len = 0, fake_pid_len = 0, message_len = 0,
                priority_len = 0, transport_len = 0, config_file_len = 0,
                unit_len = 0, user_unit_len = 0, documentation_url_len = 0;
        dual_timestamp display_ts;
        sd_id128_t boot_id;
        int p = LOG_INFO;
        bool ellipsized = false, audit;
        const ParseFieldVec fields[] = {
                PARSE_FIELD_VEC_ENTRY("_PID=",                        &pid,               &pid_len              ),
                PARSE_FIELD_VEC_ENTRY("_COMM=",                       &comm,              &comm_len             ),
                PARSE_FIELD_VEC_ENTRY("MESSAGE=",                     &message,           &message_len          ),
                PARSE_FIELD_VEC_ENTRY("PRIORITY=",                    &priority,          &priority_len         ),
                PARSE_FIELD_VEC_ENTRY("_TRANSPORT=",                  &transport,         &transport_len        ),
                PARSE_FIELD_VEC_ENTRY("_HOSTNAME=",                   &hostname,          &hostname_len         ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_PID=",                  &fake_pid,          &fake_pid_len         ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_IDENTIFIER=",           &identifier,        &identifier_len       ),
                PARSE_FIELD_VEC_ENTRY("CONFIG_FILE=",                 &config_file,       &config_file_len      ),
                PARSE_FIELD_VEC_ENTRY("_SYSTEMD_UNIT=",               &unit,              &unit_len             ),
                PARSE_FIELD_VEC_ENTRY("_SYSTEMD_USER_UNIT=",          &user_unit,         &user_unit_len        ),
                PARSE_FIELD_VEC_ENTRY("DOCUMENTATION=",               &documentation_url, &documentation_url_len),
                PARSE_FIELD_VEC_ENTRY("_SOURCE_REALTIME_TIMESTAMP=",  &realtime,          NULL                  ),
                PARSE_FIELD_VEC_ENTRY("_SOURCE_MONOTONIC_TIMESTAMP=", &monotonic,         NULL                  ),
        };
        size_t highlight_shifted[] = {highlight ? highlight[0] : 0, highlight ? highlight[1] : 0};

        assert(f);
        assert(j);
        assert(previous_display_ts);
        assert(previous_boot_id);

        /* Set the threshold to one bigger than the actual print threshold, so that if the line is actually
         * longer than what we're willing to print, ellipsization will occur. This way we won't output a
         * misleading line without any indication of truncation.
         */
        (void) sd_journal_set_data_threshold(j, flags & (OUTPUT_SHOW_ALL|OUTPUT_FULL_WIDTH) ? 0 : PRINT_CHAR_THRESHOLD + 1);

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                r = parse_fieldv(data, length, fields, ELEMENTSOF(fields));
                if (r < 0)
                        return r;
        }
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_debug_errno(r, "Skipping message we can't read: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get journal fields: %m");

        if (!message) {
                log_debug("Skipping message without MESSAGE= field.");
                return 0;
        }

        if (identifier && set_contains(j->exclude_syslog_identifiers, identifier))
                return 0;

        if (!(flags & OUTPUT_SHOW_ALL))
                strip_tab_ansi(&message, &message_len, highlight_shifted);

        if (flags & OUTPUT_TRUNCATE_NEWLINE)
                truncate_nl_full(message, &message_len);

        if (priority_len == 1 && *priority >= '0' && *priority <= '7')
                p = *priority - '0';

        audit = streq_ptr(transport, "audit");

        if (IN_SET(mode, OUTPUT_SHORT_MONOTONIC, OUTPUT_SHORT_DELTA)) {
                parse_display_timestamp(j, realtime, monotonic, &display_ts, &boot_id);
                r = output_timestamp_monotonic(f, mode, &display_ts, &boot_id, previous_display_ts, previous_boot_id);
        } else {
                usec_t usec;
                parse_display_realtime(j, realtime, monotonic, &usec);
                r = output_timestamp_realtime(f, mode, flags, usec);
        }
        if (r == -EINVAL)
                return 0;
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

                        if (terminal_urlify(c, glyph(GLYPH_EXTERNAL_LINK), &urlified) >= 0) {
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

        if (IN_SET(mode, OUTPUT_SHORT_MONOTONIC, OUTPUT_SHORT_DELTA)) {
                *previous_display_ts = display_ts;
                *previous_boot_id = boot_id;
        }

        return ellipsized;
}

static int get_display_realtime(sd_journal *j, usec_t *ret) {
        const void *data;
        _cleanup_free_ char *realtime = NULL, *monotonic = NULL;
        size_t length;
        const ParseFieldVec message_fields[] = {
                PARSE_FIELD_VEC_ENTRY("_SOURCE_REALTIME_TIMESTAMP=",  &realtime,  NULL),
                PARSE_FIELD_VEC_ENTRY("_SOURCE_MONOTONIC_TIMESTAMP=", &monotonic, NULL),
        };
        int r;

        assert(j);
        assert(ret);

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                r = parse_fieldv(data, length, message_fields, ELEMENTSOF(message_fields));
                if (r < 0)
                        return r;

                if (realtime && monotonic)
                        break;
        }
        if (r < 0)
                return r;

        parse_display_realtime(j, realtime, monotonic, ret);

        /* Restart all data before */
        sd_journal_restart_data(j);
        sd_journal_restart_unique(j);
        sd_journal_restart_fields(j);

        return 0;
}

static int output_verbose(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                dual_timestamp *previous_display_ts, /* unused */
                sd_id128_t *previous_boot_id) {      /* unused */

        const void *data;
        size_t length;
        _cleanup_free_ char *cursor = NULL;
        char buf[FORMAT_TIMESTAMP_MAX + 7];
        const char *timestamp;
        usec_t usec;
        int r;

        assert(f);
        assert(j);

        (void) sd_journal_set_data_threshold(j, 0);

        r = get_display_realtime(j, &usec);
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_debug_errno(r, "Unable to read realtime timestamp from entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get journal fields: %m");

        if (!VALID_REALTIME(usec))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No valid realtime timestamp available");

        r = sd_journal_get_cursor(j, &cursor);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Unable to determine cursor for entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        timestamp = format_timestamp_style(buf, sizeof buf, usec,
                                           flags & OUTPUT_UTC ? TIMESTAMP_US_UTC : TIMESTAMP_US);
        fprintf(f, "%s%s%s %s[%s]%s\n",
                timestamp && (flags & OUTPUT_COLOR) ? ansi_underline() : "",
                timestamp ?: "(no timestamp)",
                timestamp && (flags & OUTPUT_COLOR) ? ansi_normal() : "",
                (flags & OUTPUT_COLOR) ? ansi_grey() : "",
                cursor,
                (flags & OUTPUT_COLOR) ? ansi_grey() : "");

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                _cleanup_free_ char *urlified = NULL;
                const char *on = "", *off = "";
                const char *c, *p = NULL;
                size_t fieldlen, valuelen;

                c = memchr(data, '=', length);
                if (!c) {
                        log_debug("Encountered field without '=', assuming bad or partially written entry, leaving.");
                        break;
                }

                fieldlen = c - (const char*) data;
                if (!journal_field_valid(data, fieldlen, /* allow_protected= */ true)) {
                        log_debug("Encountered invalid field, assuming bad or partially written entry, leaving.");
                        break;
                }

                r = field_set_test(output_fields, data, fieldlen);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                valuelen = length - 1 - fieldlen;
                p = c + 1;

                if (flags & OUTPUT_COLOR) {
                        if (memory_startswith(data, length, "MESSAGE=")) {
                                on = ansi_highlight();
                                off = ansi_normal();
                        } else if (memory_startswith(data, length, "CONFIG_FILE=")) {
                                _cleanup_free_ char *u = NULL;

                                u = memdup_suffix0(p, valuelen);
                                if (!u)
                                        return log_oom();

                                if (terminal_urlify_path(u, NULL, &urlified) >= 0) {
                                        p = urlified;
                                        valuelen = strlen(urlified);
                                }

                        } else if (memory_startswith(data, length, "_")) {
                                /* Highlight trusted data as such */
                                on = ansi_green();
                                off = ansi_normal();
                        }
                }

                if ((flags & OUTPUT_SHOW_ALL) ||
                    (((length < PRINT_CHAR_THRESHOLD) || flags & OUTPUT_FULL_WIDTH)
                     && utf8_is_printable(data, length))) {
                        fprintf(f, "    %s%.*s=", on, (int) fieldlen, (const char*)data);
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
                dual_timestamp *previous_display_ts, /* unused */
                sd_id128_t *previous_boot_id) {      /* unused */

        sd_id128_t journal_boot_id, seqnum_id;
        _cleanup_free_ char *cursor = NULL;
        usec_t monotonic, realtime;
        const void *data;
        uint64_t seqnum;
        size_t length;
        int r;

        assert(j);

        (void) sd_journal_set_data_threshold(j, 0);

        r = sd_journal_get_cursor(j, &cursor);
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_debug_errno(r, "Unable to determine cursor of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Unable to read realtime timestamp of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get realtime timestamp: %m");

        r = sd_journal_get_monotonic_usec(j, &monotonic, &journal_boot_id);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Unable to read monotonic timestamp of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get monotonic timestamp: %m");

        r = sd_journal_get_seqnum(j, &seqnum, &seqnum_id);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Unable to read sequence number of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get seqnum: %m");

        fprintf(f,
                "__CURSOR=%s\n"
                "__REALTIME_TIMESTAMP=" USEC_FMT "\n"
                "__MONOTONIC_TIMESTAMP=" USEC_FMT "\n"
                "__SEQNUM=%" PRIu64 "\n"
                "__SEQNUM_ID=%s\n"
                "_BOOT_ID=%s\n",
                cursor,
                realtime,
                monotonic,
                seqnum,
                SD_ID128_TO_STRING(seqnum_id),
                SD_ID128_TO_STRING(journal_boot_id));

        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {
                size_t fieldlen;
                const char *c;

                /* We already printed the boot id from the data in the header, hence let's suppress it here */
                if (memory_startswith(data, length, "_BOOT_ID="))
                        continue;

                c = memchr(data, '=', length);
                if (!c) {
                        log_debug("Encountered data field without '=', assuming bad or partially written entry, leaving.");
                        break;
                }

                fieldlen = c - (const char*) data;
                if (!journal_field_valid(data, fieldlen, /* allow_protected= */ true)) {
                        log_debug("Encountered invalid field, assuming bad or partially written entry, leaving.");
                        break;
                }

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
        if (IN_SET(r, -EADDRNOTAVAIL, -EBADMSG)) {
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

typedef struct JsonData {
        sd_json_variant* name;
        sd_json_variant* values;
} JsonData;

static JsonData* json_data_free(JsonData *d) {
        if (!d)
                return NULL;

        sd_json_variant_unref(d->name);
        sd_json_variant_unref(d->values);

        return mfree(d);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonData*, json_data_free);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(json_data_hash_ops_free,
                                      char, string_hash_func, string_compare_func,
                                      JsonData, json_data_free);

static int update_json_data(
                Hashmap *h,
                OutputFlags flags,
                const char *name,
                const void *value,
                size_t size) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        JsonData *d;
        int r;

        assert(name);
        assert(value);

        if (size == SIZE_MAX)
                size = strlen(value);

        if (!(flags & OUTPUT_SHOW_ALL) && strlen(name) + 1 + size >= JSON_THRESHOLD)
                r = sd_json_variant_new_null(&v);
        else if (utf8_is_printable(value, size))
                r = sd_json_variant_new_stringn(&v, value, size);
        else
                r = sd_json_variant_new_array_bytes(&v, value, size);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate JSON data: %m");

        d = hashmap_get(h, name);
        if (d) {
                r = sd_json_variant_append_array(&d->values, v);
                if (r < 0)
                        return log_error_errno(r, "Failed to append JSON value into array: %m");
        } else {
                _cleanup_(json_data_freep) JsonData *e = NULL;

                e = new0(JsonData, 1);
                if (!e)
                        return log_oom();

                r = sd_json_variant_new_string(&e->name, name);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate JSON name variant: %m");

                r = sd_json_variant_append_array(&e->values, v);
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON value array: %m");

                r = hashmap_put(h, sd_json_variant_string(e->name), e);
                if (r < 0)
                        return log_error_errno(r, "Failed to insert JSON data into hashmap: %m");

                TAKE_PTR(e);
        }

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
        if (!journal_field_valid(data, fieldlen, /* allow_protected= */ true)) {
                log_debug("Encountered invalid field, assuming bad or incompletely written field, leaving.");
                return 0;
        }

        name = strndupa_safe(data, fieldlen);
        if (output_fields && !set_contains(output_fields, name))
                return 0;

        return update_json_data(h, flags, name, eq + 1, size - fieldlen - 1);
}

int journal_entry_to_json(sd_journal *j, OutputFlags flags, const Set *output_fields, sd_json_variant **ret) {

        char usecbuf[CONST_MAX(DECIMAL_STR_MAX(usec_t), DECIMAL_STR_MAX(uint64_t))];
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *object = NULL;
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        sd_id128_t journal_boot_id, seqnum_id;
        _cleanup_free_ char *cursor = NULL;
        usec_t realtime, monotonic;
        sd_json_variant **array = NULL;
        JsonData *d;
        uint64_t seqnum;
        size_t n = 0;
        int r;

        assert(j);
        assert(ret);

        (void) sd_journal_set_data_threshold(j, flags & OUTPUT_SHOW_ALL ? 0 : JSON_THRESHOLD);

        r = sd_journal_get_cursor(j, &cursor);
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_debug_errno(r, "Unable to determine cursor of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        r = sd_journal_get_realtime_usec(j, &realtime);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Unable to read realtime timestamp of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get realtime timestamp: %m");

        r = sd_journal_get_monotonic_usec(j, &monotonic, &journal_boot_id);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Unable to read monotonic timestamp of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get monotonic timestamp: %m");

        r = sd_journal_get_seqnum(j, &seqnum, &seqnum_id);
        if (r == -EBADMSG) {
                log_debug_errno(r, "Unable to read sequence number of entry, assuming bad or partially written entry: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get seqnum: %m");

        h = hashmap_new(&json_data_hash_ops_free);
        if (!h)
                return log_oom();

        r = update_json_data(h, flags, "__CURSOR", cursor, SIZE_MAX);
        if (r < 0)
                return r;

        xsprintf(usecbuf, USEC_FMT, realtime);
        r = update_json_data(h, flags, "__REALTIME_TIMESTAMP", usecbuf, SIZE_MAX);
        if (r < 0)
                return r;

        xsprintf(usecbuf, USEC_FMT, monotonic);
        r = update_json_data(h, flags, "__MONOTONIC_TIMESTAMP", usecbuf, SIZE_MAX);
        if (r < 0)
                return r;

        r = update_json_data(h, flags, "_BOOT_ID", SD_ID128_TO_STRING(journal_boot_id), SIZE_MAX);
        if (r < 0)
                return r;

        xsprintf(usecbuf, USEC_FMT, seqnum);
        r = update_json_data(h, flags, "__SEQNUM", usecbuf, SIZE_MAX);
        if (r < 0)
                return r;

        r = update_json_data(h, flags, "__SEQNUM_ID", SD_ID128_TO_STRING(seqnum_id), SIZE_MAX);
        if (r < 0)
                return r;

        for (;;) {
                const void *data;
                size_t size;

                r = sd_journal_enumerate_data(j, &data, &size);
                if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                        log_debug_errno(r, "Skipping message we can't read: %m");
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to read journal: %m");
                if (r == 0)
                        break;

                r = update_json_data_split(h, flags, output_fields, data, size);
                if (r < 0)
                        return r;
        }

        array = new(sd_json_variant*, hashmap_size(h)*2);
        if (!array)
                return log_oom();

        CLEANUP_ARRAY(array, n, sd_json_variant_unref_many);

        HASHMAP_FOREACH(d, h) {
                assert(sd_json_variant_elements(d->values) > 0);

                array[n++] = sd_json_variant_ref(d->name);

                if (sd_json_variant_elements(d->values) == 1)
                        array[n++] = sd_json_variant_ref(sd_json_variant_by_index(d->values, 0));
                else
                        array[n++] = sd_json_variant_ref(d->values);
        }

        r = sd_json_variant_new_object(&object, array, n);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate JSON object: %m");

        *ret = TAKE_PTR(object);
        return 1;
}

static int output_json(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                dual_timestamp *previous_display_ts, /* unused */
                sd_id128_t *previous_boot_id) {      /* unused */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *object = NULL;
        int r;

        r = journal_entry_to_json(j, flags, output_fields, &object);
        if (r <= 0)
                return r;

        return sd_json_variant_dump(object,
                                 output_mode_to_json_format_flags(mode) |
                                 (FLAGS_SET(flags, OUTPUT_COLOR) ? SD_JSON_FORMAT_COLOR : 0),
                                 f, NULL);
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
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
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
                dual_timestamp *previous_display_ts, /* unused */
                sd_id128_t *previous_boot_id) {      /* unused */

        int r, prio = LOG_INFO;
        const char *field;

        assert(j);
        assert(f);

        (void) sd_journal_set_data_threshold(j, 0);

        if (FLAGS_SET(flags, OUTPUT_COLOR)) {
                const void *data;
                size_t l;

                /* Determine priority of this entry, so that we can color it nicely */

                r = sd_journal_get_data(j, "PRIORITY", &data, &l);
                if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
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

typedef int (*output_func_t)(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                const Set *output_fields,
                const size_t highlight[2],
                dual_timestamp *previous_display_ts,
                sd_id128_t *previous_boot_id);

static output_func_t output_funcs[_OUTPUT_MODE_MAX] = {
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
                Set *output_fields,
                const size_t highlight[2],
                bool *ellipsized,
                dual_timestamp *previous_display_ts,
                sd_id128_t *previous_boot_id) {

        int r;

        assert(mode >= 0);
        assert(mode < _OUTPUT_MODE_MAX);
        assert(previous_display_ts);
        assert(previous_boot_id);

        if (n_columns <= 0)
                n_columns = columns();

        r = output_funcs[mode](
                        f,
                        j,
                        mode,
                        n_columns,
                        flags,
                        output_fields,
                        highlight,
                        previous_display_ts,
                        previous_boot_id);

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
        dual_timestamp previous_display_ts = DUAL_TIMESTAMP_NULL;
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
                        if (r == -EBADMSG) {
                                log_debug_errno(r, "Bad or partially written entry, leaving.");
                                break;
                        }
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
                        if (r < 0)
                                return log_error_errno(r, "Failed to get journal time: %m");

                        if (usec < not_before)
                                continue;
                }

                line++;
                maybe_print_begin_newline(f, &flags);

                r = show_journal_entry(
                                f,
                                j,
                                mode,
                                n_columns,
                                flags,
                                /* output_fields= */ NULL,
                                /* highlight= */ NULL,
                                ellipsized,
                                &previous_display_ts,
                                &previous_boot_id);
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

int add_matches_for_invocation_id(sd_journal *j, sd_id128_t id) {
        int r;

        assert(j);
        assert(!sd_id128_is_null(id));

        (void) (
                /* Look for messages from the service itself. */
                (r = journal_add_match_pair(j, "_SYSTEMD_INVOCATION_ID", SD_ID128_TO_STRING(id))) ||

                /* Look for messages from authorized daemons about this service. */
                (r = sd_journal_add_disjunction(j)) ||
                (r = journal_add_match_pair(j, "OBJECT_SYSTEMD_INVOCATION_ID", SD_ID128_TO_STRING(id))) ||

                /* Look for messages from system service manager (PID 1) about this service. */
                (r = sd_journal_add_disjunction(j)) ||
                (r = journal_add_match_pair(j, "INVOCATION_ID", SD_ID128_TO_STRING(id))) ||

                /* Look for messages from user-session service manager about this service. */
                (r = sd_journal_add_disjunction(j)) ||
                (r = journal_add_match_pair(j, "USER_INVOCATION_ID", SD_ID128_TO_STRING(id)))
        );

        return r;
}

static int add_matches_for_coredump_uid(sd_journal *j, MatchUnitFlag flags, const char *unit) {
        static uid_t cached_uid = 0;
        int r;

        assert(j);
        assert(unit);

        if (!FLAGS_SET(flags, MATCH_UNIT_COREDUMP_UID))
                return 0;

        if (cached_uid == 0) {
                const char *user = "systemd-coredump";

                r = get_user_creds(&user, &cached_uid, NULL, NULL, NULL, 0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to resolve systemd-coredump user, ignoring: %m");
                        cached_uid = UID_INVALID;
                } else if (cached_uid == 0) /* Huh? Let's handle that gracefully. */
                        cached_uid = UID_INVALID;
        }

        if (!uid_is_valid(cached_uid))
                return 0;

        r = journal_add_matchf(j, "_UID="UID_FMT, cached_uid);
        if (r < 0)
                return r;

        /* for systemd-coredump older than 888e378da2dbf4520e68a9d7e59712a3cd5a830f */
        return sd_journal_add_match(j, "_UID=0", SIZE_MAX);
}

int add_matches_for_unit_full(sd_journal *j, MatchUnitFlag flags, const char *unit) {
        int r;

        assert(j);
        assert(unit);

        (void) (
                /* Look for messages from the service itself */
                (r = journal_add_match_pair(j, "_SYSTEMD_UNIT", unit)) ||

                /* Look for messages from PID 1 about this service. Note that the actual match is placed
                 * on init.scope rather than _PID=1, as we want to match messages from helper processes
                 * forked off by init too. */
                (r = sd_journal_add_disjunction(j)) ||
                (r = sd_journal_add_match(j, "_SYSTEMD_CGROUP=/init.scope", SIZE_MAX)) ||
                (r = journal_add_match_pair(j, "UNIT", unit)) ||

                /* Look for messages from authorized daemons about this service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = sd_journal_add_match(j, "_UID=0", SIZE_MAX)) ||
                (r = journal_add_match_pair(j, "OBJECT_SYSTEMD_UNIT", unit))
        );

        if (r == 0 && FLAGS_SET(flags, MATCH_UNIT_COREDUMP))
                (void) (
                        /* Look for coredumps of the service */
                        (r = sd_journal_add_disjunction(j)) ||
                        (r = sd_journal_add_match(j, "MESSAGE_ID=" SD_MESSAGE_COREDUMP_STR, SIZE_MAX)) ||
                        (r = add_matches_for_coredump_uid(j, flags, unit)) ||
                        (r = journal_add_match_pair(j, "COREDUMP_UNIT", unit))
                );

        if (r == 0 && FLAGS_SET(flags, MATCH_UNIT_SLICE) && endswith(unit, ".slice"))
                /* Show all messages belonging to a slice */
                (void) (
                        (r = sd_journal_add_disjunction(j)) ||
                        (r = journal_add_match_pair(j, "_SYSTEMD_SLICE", unit))
                );

        return r;
}

int add_matches_for_user_unit_full(sd_journal *j, MatchUnitFlag flags, const char *unit) {
        uid_t uid = getuid();
        int r;

        assert(j);
        assert(unit);

        (void) (
                /* Look for messages from the user service itself */
                (r = journal_add_match_pair(j, "_SYSTEMD_USER_UNIT", unit)) ||
                (r = journal_add_matchf(j, "_UID="UID_FMT, uid)) ||

                /* Look for messages from systemd about this service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = journal_add_match_pair(j, "USER_UNIT", unit)) ||
                (r = journal_add_matchf(j, "_UID="UID_FMT, uid)) ||

                /* Look for messages from authorized daemons about this service */
                (r = sd_journal_add_disjunction(j)) ||
                (r = journal_add_match_pair(j, "OBJECT_SYSTEMD_USER_UNIT", unit)) ||
                (r = journal_add_matchf(j, "_UID="UID_FMT, uid)) ||
                (r = sd_journal_add_match(j, "_UID=0", SIZE_MAX))
        );

        if (r == 0 && FLAGS_SET(flags, MATCH_UNIT_COREDUMP))
                (void) (
                        /* Look for coredumps of the service */
                        (r = sd_journal_add_disjunction(j)) ||
                        (r = journal_add_match_pair(j, "COREDUMP_USER_UNIT", unit)) ||
                        (r = journal_add_matchf(j, "_UID="UID_FMT, uid)) ||
                        (r = sd_journal_add_match(j, "_UID=0", SIZE_MAX))
                );

        if (r == 0 && FLAGS_SET(flags, MATCH_UNIT_SLICE) && endswith(unit, ".slice"))
                /* Show all messages belonging to a slice */
                (void) (
                        (r = sd_journal_add_disjunction(j)) ||
                        (r = journal_add_match_pair(j, "_SYSTEMD_USER_SLICE", unit)) ||
                        (r = journal_add_matchf(j, "_UID="UID_FMT, uid))
                );

        return r;
}

int add_match_boot_id(sd_journal *j, sd_id128_t id) {
        int r;

        assert(j);

        if (sd_id128_is_null(id)) {
                r = sd_id128_get_boot(&id);
                if (r < 0)
                        return log_error_errno(r, "Failed to get boot ID: %m");
        }

        r = journal_add_match_pair(j, "_BOOT_ID", SD_ID128_TO_STRING(id));
        if (r < 0)
                return log_error_errno(r, "Failed to add match: %m");

        return 0;
}

int add_match_this_boot(sd_journal *j, const char *machine) {
        sd_id128_t boot_id;
        int r;

        assert(j);

        r = id128_get_boot_for_machine(machine, &boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID%s%s: %m",
                                       isempty(machine) ? "" : " of container ", strempty(machine));

        r = add_match_boot_id(j, boot_id);
        if (r < 0)
                return r;

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

        r = sd_journal_open_namespace(&j, log_namespace,
                                      journal_open_flags |
                                      SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE |
                                      SD_JOURNAL_ASSUME_IMMUTABLE);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        if (system_unit)
                r = add_matches_for_unit(j, unit);
        else
                r = add_matches_for_user_unit(j, unit);
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

static int journal_get_id128(sd_journal *j, const char *field, sd_id128_t *ret) {
        const char *data, *str;
        size_t len, fl;
        sd_id128_t v;
        int r;

        assert(j);
        assert(field);

        /* This returns 1 when non-null ID is found, 0 when null ID is found, -ENOENT when the field not
         * found, -EINVAL when the field found but not a valid ID, -EBADMSG or -EADDRNOTAVAIL when journal
         * corruption detected. On a critical issue, other negative errno may be returned. */

        r = sd_journal_get_data(j, field, (const void**) &data, &len);
        if (r < 0)
                return r;

        fl = strlen(field);
        assert(len > fl);
        assert(data[fl] == '=');

        if (len > fl + 1 + SD_ID128_UUID_STRING_MAX)
                return -EINVAL;

        str = memdupa_suffix0(data + fl + 1, len - fl - 1);

        r = sd_id128_from_string(str, ret ?: &v);
        if (r < 0)
                return r;

        return !sd_id128_is_null(ret ? *ret : v);
}

static int journal_get_invocation_id(sd_journal *j, sd_id128_t *ret) {
        int r;

        assert(j);

        FOREACH_STRING(s,
                       "_SYSTEMD_INVOCATION_ID",       /* By the systemd unit. */
                       "OBJECT_SYSTEMD_INVOCATION_ID", /* Added by journald. */
                       "INVOCATION_ID",                /* By the system service manager (PID 1). */
                       "USER_INVOCATION_ID") {         /* By the user session service manager. */

                r = journal_get_id128(j, s, ret);
                if (!IN_SET(r, 0, -ENOENT, -EINVAL, -EBADMSG, -EADDRNOTAVAIL))
                        return r;
        }

        /* No invocation ID found in the entry. */
        if (ret)
                *ret = SD_ID128_NULL;
        return 0;
}

static const char* const log_id_type_table[_LOG_ID_TYPE_MAX] = {
        [LOG_BOOT_ID]                   = "boot ID",
        [LOG_SYSTEM_UNIT_INVOCATION_ID] = "system unit invocation ID",
        [LOG_USER_UNIT_INVOCATION_ID]   = "user unit invocation ID",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(log_id_type, LogIdType);

static int set_matches_for_discover_id(
                sd_journal *j,
                LogIdType type,
                sd_id128_t boot_id,
                const char *unit,
                sd_id128_t id) {

        int r;

        assert(j);
        assert(type >= 0 && type < _LOG_ID_TYPE_MAX);

        sd_journal_flush_matches(j);

        if (type == LOG_BOOT_ID) {
                if (sd_id128_is_null(id))
                        return 0;

                return add_match_boot_id(j, id);
        }

        if (!sd_id128_is_null(boot_id)) {
                r = add_match_boot_id(j, boot_id);
                if (r < 0)
                        return r;

                r = sd_journal_add_conjunction(j);
                if (r < 0)
                        return r;
        }

        if (!sd_id128_is_null(id))
                return add_matches_for_invocation_id(j, id);

        if (type == LOG_SYSTEM_UNIT_INVOCATION_ID)
                return add_matches_for_unit_full(j, /* flags= */ 0, unit);

        if (type == LOG_USER_UNIT_INVOCATION_ID)
                return add_matches_for_user_unit_full(j, /* flags= */ 0, unit);

        return -EINVAL;
}

int discover_next_id(
                sd_journal *j,
                LogIdType type,
                sd_id128_t boot_id,  /* optional, used when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID */
                const char *unit,    /* mandatory when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID */
                sd_id128_t previous_id,
                bool advance_older,
                LogId *ret) {

        _cleanup_set_free_ Set *broken_ids = NULL;
        int r;

        assert(j);
        assert(type >= 0 && type < _LOG_ID_TYPE_MAX);
        assert(type == LOG_BOOT_ID || unit);
        assert(ret);

        /* We expect the journal to be on the last position of a boot
         * (in relation to the direction we are going), so that the next
         * invocation of sd_journal_next/previous will be from a different
         * boot. We then collect any information we desire and then jump
         * to the last location of the new boot by using a _BOOT_ID match
         * coming from the other journal direction. */

        /* Make sure we aren't restricted by any _BOOT_ID matches, so that
         * we can actually advance to a *different* boot. */
        r = set_matches_for_discover_id(j, type, boot_id, unit, SD_ID128_NULL);
        if (r < 0)
                return r;

        for (;;) {
                sd_id128_t *id_dup;
                LogId id;

                r = sd_journal_step_one(j, !advance_older);
                if (r < 0)
                        return r;
                if (r == 0) {
                        sd_journal_flush_matches(j);
                        *ret = (LogId) {};
                        return 0; /* End of journal, yay. */
                }

                if (type == LOG_BOOT_ID)
                        r = sd_journal_get_monotonic_usec(j, NULL, &id.id);
                else
                        r = journal_get_invocation_id(j, &id.id);
                if (r < 0)
                        return r;

                if (sd_id128_is_null(id.id))
                        continue;

                /* We iterate through this in a loop, until the boot or invocation ID differs from the
                 * previous one. Note that normally, this will only require a single iteration, as we moved
                 * to the last entry of the previous boot or invocation entry already. However, it might
                 * happen that the per-journal-field entry arrays are less complete than the main entry
                 * array, and hence might reference an entry that's not actually the last one of the boot or
                 * invocation ID as last one. Let's hence use the per-field array is initial seek position to
                 * speed things up, but let's not trust that it is complete, and hence, manually advance as
                 * necessary. */

                if (!sd_id128_is_null(previous_id) && sd_id128_equal(id.id, previous_id))
                        continue;

                if (set_contains(broken_ids, &id.id))
                        continue;

                /* Yay, we found a new boot or invocation ID from the entry object. Let's check there exist
                 * corresponding entries matching with the _BOOT_ID=, INVOCATION_ID= or friends data. */

                r = set_matches_for_discover_id(j, type, boot_id, unit, id.id);
                if (r < 0)
                        return r;

                /* First, seek to the first (or the last when we are going upwards) occurrence of this boot
                 * or invocation ID. You may think this is redundant. Yes, that's redundant unless the
                 * journal is corrupted. But when the journal is corrupted, especially, badly 'truncated',
                 * then the below may fail.
                 * See https://github.com/systemd/systemd/pull/29334#issuecomment-1736567951. */
                if (advance_older)
                        r = sd_journal_seek_tail(j);
                else
                        r = sd_journal_seek_head(j);
                if (r < 0)
                        return r;

                r = sd_journal_step_one(j, 0);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Whoopsie! We found a %s %s but can't read its first entry. "
                                  "The journal seems to be corrupted. Ignoring the %s.",
                                  log_id_type_to_string(type),
                                  SD_ID128_TO_STRING(id.id),
                                  log_id_type_to_string(type));
                        goto try_again;
                }

                r = sd_journal_get_realtime_usec(j, advance_older ? &id.last_usec : &id.first_usec);
                if (r < 0)
                        return r;

                /* Next, seek to the last occurrence of this boot or invocation ID. */
                if (advance_older)
                        r = sd_journal_seek_head(j);
                else
                        r = sd_journal_seek_tail(j);
                if (r < 0)
                        return r;

                r = sd_journal_step_one(j, 0);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Whoopsie! We found a %s %s but can't read its last entry. "
                                  "The journal seems to be corrupted. Ignoring the %s.",
                                  log_id_type_to_string(type),
                                  SD_ID128_TO_STRING(id.id),
                                  log_id_type_to_string(type));
                        goto try_again;
                }

                r = sd_journal_get_realtime_usec(j, advance_older ? &id.first_usec : &id.last_usec);
                if (r < 0)
                        return r;

                sd_journal_flush_matches(j);
                *ret = id;
                return 1;

        try_again:
                /* Save the bad boot or invocation ID. */
                id_dup = newdup(sd_id128_t, &id.id, 1);
                if (!id_dup)
                        return -ENOMEM;

                r = set_ensure_consume(&broken_ids, &id128_hash_ops_free, id_dup);
                if (r < 0)
                        return r;

                /* Move to the previous position again. */
                r = set_matches_for_discover_id(j, type, boot_id, unit, previous_id);
                if (r < 0)
                        return r;

                if (advance_older)
                        r = sd_journal_seek_head(j);
                else
                        r = sd_journal_seek_tail(j);
                if (r < 0)
                        return r;

                r = sd_journal_step_one(j, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                               "Whoopsie! Cannot seek to the last entry of %s %s.",
                                               log_id_type_to_string(type),
                                               SD_ID128_TO_STRING(previous_id));

                sd_journal_flush_matches(j);
        }
}

int journal_find_log_id(
                sd_journal *j,
                LogIdType type,
                sd_id128_t boot_id,  /* optional, used when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID */
                const char *unit,    /* mandatory when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID
                                      * unless an invocation ID is explicitly specified without an offset. */
                sd_id128_t previous_id,
                int offset,
                sd_id128_t *ret) {

        bool advance_older;
        int r, offset_start;

        assert(j);
        assert(type >= 0 && type < _LOG_ID_TYPE_MAX);
        assert(type == LOG_BOOT_ID || (!sd_id128_is_null(previous_id) && offset == 0) || unit);
        assert(ret);

        /* Adjust for the asymmetry that offset 0 is the last (and current) boot or invocation, while 1 is
         * considered the (chronological) first boot or invocation in the journal. */
        advance_older = offset <= 0;

        r = set_matches_for_discover_id(j, type, boot_id, unit, previous_id);
        if (r < 0)
                return r;

        if (!sd_id128_is_null(previous_id)) {
                if (advance_older)
                        r = sd_journal_seek_head(j); /* seek to oldest */
                else
                        r = sd_journal_seek_tail(j); /* seek to newest */
                if (r < 0)
                        return r;

                r = sd_journal_step_one(j, advance_older);
                if (r < 0)
                        return r;
                if (r == 0) {
                        sd_journal_flush_matches(j);
                        *ret = SD_ID128_NULL;
                        return false;
                }
                if (offset == 0) {
                        /* If a non-null ID is specified without an offset, then let's short cut the loop below. */
                        sd_journal_flush_matches(j);
                        *ret = previous_id;
                        return true;
                }

                offset_start = advance_older ? -1 : 1;
        } else {
                if (advance_older)
                        r = sd_journal_seek_tail(j); /* seek to newest */
                else
                        r = sd_journal_seek_head(j); /* seek to oldest */
                if (r < 0)
                        return r;

                offset_start = advance_older ? 0 : 1;
        }

        /* At this point the cursor is positioned at the newest/oldest entry of the reference boot or
         * invocation ID if specified, or whole journal otherwise. The next invocation of _previous()/_next()
         * will hence position us at the newest/oldest entry we have. */

        for (int off = offset_start; ; off += advance_older ? -1 : 1) {
                LogId id;

                r = discover_next_id(j, type, boot_id, unit, previous_id, advance_older, &id);
                if (r < 0)
                        return r;
                if (r == 0) {
                        *ret = SD_ID128_NULL;
                        return false;
                }

                previous_id = id.id;
                log_debug("Found %s %s by offset %i.",
                          log_id_type_to_string(type), SD_ID128_TO_STRING(previous_id), off);

                if (off == offset) {
                        *ret = previous_id;
                        return true;
                }
        }
}

int journal_get_log_ids(
                sd_journal *j,
                LogIdType type,
                sd_id128_t boot_id,  /* optional, used when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID */
                const char *unit,    /* mandatory when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID */
                bool advance_older,
                size_t max_ids,
                LogId **ret_ids,
                size_t *ret_n_ids) {

        _cleanup_free_ LogId *ids = NULL;
        size_t n_ids = 0;
        int r;

        assert(j);
        assert(type >= 0 && type < _LOG_ID_TYPE_MAX);
        assert(type == LOG_BOOT_ID || unit);
        assert(ret_ids);
        assert(ret_n_ids);

        sd_journal_flush_matches(j);

        if (advance_older)
                r = sd_journal_seek_tail(j); /* seek to newest */
        else
                r = sd_journal_seek_head(j); /* seek to oldest */
        if (r < 0)
                return r;

        /* No sd_journal_next()/_previous() here.
         *
         * At this point the read pointer is positioned before the oldest entry in the whole journal. The
         * next invocation of _next() will hence position us at the oldest entry we have. */

        sd_id128_t previous_id = SD_ID128_NULL;
        for (;;) {
                LogId id;

                if (n_ids >= max_ids)
                        break;

                r = discover_next_id(j, type, boot_id, unit, previous_id, advance_older, &id);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                previous_id = id.id;

                FOREACH_ARRAY(i, ids, n_ids)
                        if (sd_id128_equal(i->id, id.id))
                                /* The boot or invocation ID is already stored, something wrong with the
                                 * journal files. Exiting as otherwise this problem would cause an infinite
                                 * loop. */
                                goto finish;

                if (!GREEDY_REALLOC_APPEND(ids, n_ids, &id, 1))
                        return -ENOMEM;
        }

 finish:
        *ret_ids = TAKE_PTR(ids);
        *ret_n_ids = n_ids;
        return n_ids > 0;
}

void journal_browse_prepare(void) {
        /* Increase max number of open files if we can, we might needs this when browsing journal files,
         * which might be split up into many files. */
        (void) rlimit_nofile_bump(HIGH_RLIMIT_NOFILE);

        sigbus_install();
}
