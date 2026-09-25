/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "osc-winsize.h"
#include "parse-util.h"
#include "string-util.h"
#include "terminal-util.h"

static unsigned parse_dimension(const char *s) {
        uint16_t u;

        assert(s);

        /* As per spec: a field value that cannot be parsed is treated as 0 */

        if (safe_atou16_full(s, 10, &u) < 0)
                return 0;

        return u;
}

int osc_winsize_parse(const char *seq, OscWinsize *ret) {
        assert(seq);
        assert(ret);

        const char *p = startswith(seq, "2811");
        if (!p || !IN_SET(*p, ';', 0)) /* refuse other sequence numbers that merely share the prefix */
                return 0;

        OscWinsize ws = {
                .type = _OSC_WINSIZE_TYPE_INVALID,
        };

        bool request = false;
        if (p[0] == ';' && p[1] == '?' && IN_SET(p[2], ';', 0)) {
                /* The request marker, which must be the first field */
                request = true;
                p += 2;
        }

        bool any_fields = false;
        while (*p == ';') {
                p++;

                size_t n = strcspn(p, ";");
                _cleanup_free_ char *field = strndup(p, n);
                if (!field)
                        return -ENOMEM;
                p += n;

                any_fields = true;

                const char *v = startswith(field, "columns=");
                if (v) {
                        ws.columns = parse_dimension(v);
                        continue;
                }

                v = startswith(field, "lines=");
                if (v) {
                        ws.lines = parse_dimension(v);
                        continue;
                }

                /* As per spec: ignore unknown fields */
        }

        if (request)
                ws.type = any_fields ? OSC_WINSIZE_SUBSCRIBE : OSC_WINSIZE_CANCEL;
        else
                ws.type = OSC_WINSIZE_REPORT;

        *ret = ws;
        return 1;
}

int osc_winsize_format(OscWinsizeType type, unsigned columns, unsigned lines, char **ret) {
        assert(type >= 0 && type < _OSC_WINSIZE_TYPE_MAX);
        assert(columns <= UINT16_MAX);
        assert(lines <= UINT16_MAX);
        assert(ret);

        if (type == OSC_WINSIZE_CANCEL)
                return strdup_to(ret, ANSI_OSC "2811;?" ANSI_ST);

        if (asprintf(ret, ANSI_OSC "2811%s;columns=%u;lines=%u" ANSI_ST,
                     type == OSC_WINSIZE_SUBSCRIBE ? ";?" : "", columns, lines) < 0)
                return -ENOMEM;

        return 0;
}
