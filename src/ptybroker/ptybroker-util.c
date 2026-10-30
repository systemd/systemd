/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>

#include "json-util.h"
#include "ptybroker-util.h"
#include "string-util.h"
#include "terminal-util.h"

bool pseudo_tty_name_valid(const char *s) {
        if (!string_is_safe(s, STRING_ASCII|STRING_DISALLOW_WHITESPACE))
                return false;

        return strlen(s) < 64;
}

bool pseudo_tty_description_valid(const char *s) {
        if (!string_is_safe(s, STRING_ALLOW_QUOTES|STRING_ALLOW_BACKSLASHES|STRING_ALLOW_GLOBS))
                return false;

        return strlen(s) < 256;
}

bool pseudo_tty_tag_valid(const char *s) {
        if (!string_is_safe(s, STRING_ASCII|STRING_DISALLOW_WHITESPACE))
                return false;

        return strlen(s) < 64;
}

EndOfLine end_of_line_from_char(char c) {
        if (c == '\n')
                return EOL_NEWLINE;
        if (c == '\r')
                return EOL_CARRIAGE_RETURN;
        if (c == '\f')
                return EOL_FORM_FEED;
        if (c == 0)
                return EOL_NUL;

        return EOL_NONE;
}

void terminal_settings_done(TerminalSettings *ts) {
        assert(ts);

        ts->env_term = mfree(ts->env_term);
        ts->env_colorterm = mfree(ts->env_colorterm);
}

int terminal_settings_from_json(sd_json_variant *v, TerminalSettings *ret) {
        int r;

        assert(ret);

        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        if (v) {
                static const sd_json_dispatch_field terminal_dispatch_table[] = {
                        { "lines",           _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,     offsetof(TerminalSettings, lines),            0 },
                        { "columns",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,     offsetof(TerminalSettings, columns),          0 },
                        { "envTERM",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(TerminalSettings, env_term),         0 },
                        { "envCOLORTERM",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(TerminalSettings, env_colorterm),    0 },
                        { "envNO_COLOR",     SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, offsetof(TerminalSettings, env_no_color),     0 },
                        {}
                };

                r = sd_json_dispatch(v, terminal_dispatch_table, /* flags= */ 0, &ts);
                if (r < 0)
                        return r;

                /* $COLORTERM values (e.g. "truecolor", "24bit") follow the same rules as $TERM values */
                if ((ts.lines != UINT_MAX && (ts.lines <= 0 || ts.lines > USHRT_MAX)) ||
                    (ts.columns != UINT_MAX && (ts.columns <= 0 || ts.columns > USHRT_MAX)) ||
                    (ts.env_term && !term_env_valid(ts.env_term)) ||
                    (ts.env_colorterm && !term_env_valid(ts.env_colorterm)))
                        return -EINVAL;
        }

        *ret = TAKE_TERMINAL_SETTINGS(ts);
        return 0;
}

int terminal_settings_to_json(const TerminalSettings *ts, sd_json_variant **ret) {
        assert(ts);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_CONDITION(ts->lines != UINT_MAX, "lines", SD_JSON_BUILD_UNSIGNED(ts->lines)),
                        SD_JSON_BUILD_PAIR_CONDITION(ts->columns != UINT_MAX, "columns", SD_JSON_BUILD_UNSIGNED(ts->columns)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("envTERM", ts->env_term),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("envCOLORTERM", ts->env_colorterm),
                        SD_JSON_BUILD_PAIR_CONDITION(ts->env_no_color >= 0, "envNO_COLOR", SD_JSON_BUILD_BOOLEAN(ts->env_no_color)));
}

int terminal_settings_settle(TerminalSettings *ts) {
        assert(ts);

        if (ts->lines == UINT_MAX)
                ts->lines = 25;
        if (ts->columns == UINT_MAX)
                ts->columns = 80;

        if (ts->env_no_color < 0)
                ts->env_no_color = streq_ptr(ts->env_term, "dumb");

        if (!ts->env_term) {
                ts->env_term = strdup(FALLBACK_TERM);
                if (!ts->env_term)
                        return -ENOMEM;

                /* NB: We only default to "truecolor" for $COLORTERM if $TERM is not set either. We assume
                 * that if people set $TERM explicitly they will also set $COLORTERM on their own */
                if (!ts->env_colorterm && ts->env_no_color <= 0)  {
                        ts->env_colorterm = strdup("truecolor");
                        if (!ts->env_colorterm)
                                return -ENOMEM;
                }
        }

        return 0;
}

int terminal_settings_copy(const TerminalSettings *ts, TerminalSettings *ret) {
        int r;

        assert(ts);
        assert(ret);

        _cleanup_free_ char *t = NULL, *ct = NULL;
        r = strdup_to(&t, ts->env_term);
        if (r < 0)
                return r;

        r = strdup_to(&ct, ts->env_colorterm);
        if (r < 0)
                return r;

        *ret = (TerminalSettings) {
                .lines = ts->lines,
                .columns = ts->columns,
                .env_term = TAKE_PTR(t),
                .env_colorterm = TAKE_PTR(ct),
                .env_no_color = ts->env_no_color,
        };

        return 0;
}

int terminal_settings_merge(TerminalSettings *ts, const TerminalSettings *override) {
        assert(ts);

        if (!override)
                return 0;

        /* Copies all values from 'override' into 'ts' – if they are set. */

        _cleanup_free_ char *t = NULL;
        bool force_colorterm = false;
        if (override->env_term) {
                if (!streq_ptr(ts->env_term, override->env_term)) {
                        t = strdup(override->env_term);
                        if (!t)
                                return -ENOMEM;
                }

                force_colorterm = true;
        }

        _cleanup_free_ char *ct = NULL;
        if (override->env_colorterm && (force_colorterm || !streq_ptr(ts->env_colorterm, override->env_colorterm))) {
                ct = strdup(override->env_colorterm);
                if (!ct)
                        return -ENOMEM;
        }

        if (t)
                free_and_replace(ts->env_term, t);
        if (force_colorterm || ct)
                free_and_replace(ts->env_colorterm, ct);
        if (override->lines != UINT_MAX)
                ts->lines = override->lines;
        if (override->columns != UINT_MAX)
                ts->columns = override->columns;
        if (override->env_no_color >= 0)
                ts->env_no_color = override->env_no_color;

        return 0;
}

int terminal_settings_sync_size_fd(TerminalSettings *ts, int fd, const char *path) {
        int r;

        assert(ts);
        assert(fd >= 0);

        /* First set the desired size, but don't fail if this doesn't work */
        r = terminal_set_size_fd(fd, path, ts->lines, ts->columns);

        /* Read what is actually in effect. This is fatal if it fails */
        struct winsize ws = {};
        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        ts->lines = ws.ws_row;
        ts->columns = ws.ws_col;

        /* Return the original error */
        return r;
}
