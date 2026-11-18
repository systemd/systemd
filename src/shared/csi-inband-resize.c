/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "csi-inband-resize.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

static bool params_valid(const char *s, size_t n, bool allow_colon) {
        assert(s || n == 0);

        /* Only accepts parameter bytes, i.e. refuses private markers and intermediate bytes */
        FOREACH_ARRAY(c, s, n)
                if (!ascii_isdigit(*c) && *c != ';' && !(allow_colon && *c == ':'))
                        return false;

        return true;
}

static bool param_is_mode(const char *s, size_t n) {
        unsigned u;

        assert(s || n == 0);

        if (n == 0 || n > DECIMAL_STR_MAX(unsigned))
                return false;

        char *t = strndupa_safe(s, n);
        return safe_atou_full(t, 10, &u) >= 0 && u == INBAND_RESIZE_MODE;
}

int inband_resize_parse_request(const char *csi, InbandResizeRequest *ret, char **ret_remaining) {
        assert(csi);
        assert(ret);
        assert(ret_remaining);

        /* All requests use the DEC private marker */
        const char *p = startswith(csi, "?");
        if (!p)
                return 0;

        size_t n = strlen(p);
        if (n == 0)
                return 0;

        /* DECRQM can only query a single mode at a time */
        if (endswith(p, "$p")) {
                if (!params_valid(p, n - 2, /* allow_colon= */ false) || !param_is_mode(p, n - 2))
                        return 0;

                *ret = INBAND_RESIZE_QUERY;
                *ret_remaining = NULL;
                return 1;
        }

        char final = p[n - 1];
        if (!IN_SET(final, 'h', 'l'))
                return 0;
        n--;

        if (!params_valid(p, n, /* allow_colon= */ false))
                return 0;

        /* DECSET/DECRST may cover multiple modes at once: pick out ours, and keep the rest in order */
        _cleanup_strv_free_ char **others = NULL;
        bool found = false;
        for (const char *q = p, *e = p + n;; q++) {
                size_t k = strcspn(q, ";");
                k = MIN(k, (size_t) (e - q));

                if (param_is_mode(q, k))
                        found = true;
                else if (strv_consume(&others, strndup(q, k)) < 0)
                        return -ENOMEM;

                q += k;
                if (q >= e)
                        break;
        }

        if (!found)
                return 0;

        _cleanup_free_ char *remaining = NULL;
        if (!strv_isempty(others)) {
                _cleanup_free_ char *j = strv_join(others, ";");
                if (!j)
                        return -ENOMEM;

                remaining = strjoin("?", j, CHAR_TO_STR(final));
                if (!remaining)
                        return -ENOMEM;
        }

        *ret = final == 'h' ? INBAND_RESIZE_ENABLE : INBAND_RESIZE_DISABLE;
        *ret_remaining = TAKE_PTR(remaining);
        return 1;
}

static unsigned parse_field(const char *s, size_t n) {
        uint16_t u;

        assert(s || n == 0);

        /* As per spec, sub-parameters (separated by colons) are to be ignored. A field value that cannot be
         * parsed is treated as 0, i.e. as unknown. */
        n = MIN(n, strcspn(s, ":"));
        if (n == 0 || n > DECIMAL_STR_MAX(uint16_t))
                return 0;

        char *t = strndupa_safe(s, n);
        if (safe_atou16_full(t, 10, &u) < 0)
                return 0;

        return u;
}

int inband_resize_parse_report(const char *csi, InbandResizeReport *ret) {
        assert(csi);
        assert(ret);

        size_t n = strlen(csi);
        if (n == 0 || csi[n - 1] != 't')
                return 0;
        n--;

        if (!params_valid(csi, n, /* allow_colon= */ true))
                return 0;

        unsigned fields[5] = {};
        size_t i = 0;
        for (const char *q = csi, *e = csi + n;; q++) {
                size_t k = strcspn(q, ";");
                k = MIN(k, (size_t) (e - q));

                if (i == 0) {
                        /* The first parameter identifies the report (ignoring any sub-parameters) */
                        if (MIN(k, strcspn(q, ":")) != 2 || !strneq(q, "48", 2))
                                return 0;
                } else if (i < ELEMENTSOF(fields))
                        fields[i] = parse_field(q, k);
                /* else: as per spec, ignore extra fields */

                i++;

                q += k;
                if (q >= e)
                        break;
        }

        *ret = (InbandResizeReport) {
                .lines = fields[1],
                .columns = fields[2],
                .height_pixels = fields[3],
                .width_pixels = fields[4],
        };
        return 1;
}

int inband_resize_format_report(const InbandResizeReport *report, char **ret) {
        assert(report);
        assert(report->lines <= UINT16_MAX);
        assert(report->columns <= UINT16_MAX);
        assert(report->height_pixels <= UINT16_MAX);
        assert(report->width_pixels <= UINT16_MAX);
        assert(ret);

        if (asprintf(ret, "\x1B[48;%u;%u;%u;%ut",
                     report->lines, report->columns,
                     report->height_pixels, report->width_pixels) < 0)
                return -ENOMEM;

        return 0;
}

int inband_resize_format_mode_report(bool enabled, char **ret) {
        assert(ret);

        return strdup_to(ret, enabled ? "\x1B[?2048;1$y" : "\x1B[?2048;2$y");
}
