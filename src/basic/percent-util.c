/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-util.h"
#include "percent-util.h"
#include "string-util.h"

static int parse_parts_integer(const char *n) {
        unsigned v;
        int r;

        /* Refuse signs, leading zeros and non-decimal forms: percentages are plain non-negative decimal
         * integers, so hex or octal spellings must not be accepted either. */
        r = safe_atou_full(n, 10 | SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO, &v);
        if (r < 0)
                return r;
        if (v > INT_MAX)
                return -ERANGE;

        return (int) v;
}

static int parse_parts_value_whole(const char *p, const char *symbol) {
        const char *pc, *n;

        pc = endswith(p, symbol);
        if (!pc)
                return -EINVAL;

        n = strndupa_safe(p, pc - p);
        return parse_parts_integer(n);
}

static int parse_parts_value_with_tenths_place(const char *p, const char *symbol) {
        const char *pc, *dot, *n;
        int q, v;

        pc = endswith(p, symbol);
        if (!pc)
                return -EINVAL;

        dot = memchr(p, '.', pc - p);
        if (dot) {
                if (dot + 2 != pc)
                        return -EINVAL;
                if (dot[1] < '0' || dot[1] > '9')
                        return -EINVAL;
                q = dot[1] - '0';
                n = strndupa_safe(p, dot - p);
        } else {
                q = 0;
                n = strndupa_safe(p, pc - p);
        }
        v = parse_parts_integer(n);
        if (v < 0)
                return v;
        if (v > (INT_MAX - q) / 10)
                return -ERANGE;

        v = v * 10 + q;
        return v;
}

static int parse_parts_value_with_hundredths_place(const char *p, const char *symbol) {
        const char *pc, *dot, *n;
        int q, v;

        pc = endswith(p, symbol);
        if (!pc)
                return -EINVAL;

        dot = memchr(p, '.', pc - p);
        if (dot) {
                if (dot + 3 == pc) {
                        /* Support two places after the dot */

                        if (dot[1] < '0' || dot[1] > '9' || dot[2] < '0' || dot[2] > '9')
                                return -EINVAL;
                        q = (dot[1] - '0') * 10 + (dot[2] - '0');

                } else if (dot + 2 == pc) {
                        /* Support one place after the dot */

                        if (dot[1] < '0' || dot[1] > '9')
                                return -EINVAL;
                        q = (dot[1] - '0') * 10;
                } else
                        /* We do not support zero or more than two places */
                        return -EINVAL;

                n = strndupa_safe(p, dot - p);
        } else {
                q = 0;
                n = strndupa_safe(p, pc - p);
        }
        v = parse_parts_integer(n);
        if (v < 0)
                return v;
        if (v > (INT_MAX - q) / 100)
                return -ERANGE;

        v = v * 100 + q;
        return v;
}

int parse_percent_unbounded(const char *p) {
        return parse_parts_value_whole(p, "%");
}

int parse_percent(const char *p) {
        int v;

        v = parse_percent_unbounded(p);
        if (v > 100)
                return -ERANGE;

        return v;
}

int parse_permille_unbounded(const char *p) {
        const char *pm;

        pm = endswith(p, "‰");
        if (pm)
                return parse_parts_value_whole(p, "‰");

        return parse_parts_value_with_tenths_place(p, "%");
}

int parse_permille(const char *p) {
        int v;

        v = parse_permille_unbounded(p);
        if (v > 1000)
                return -ERANGE;

        return v;
}

int parse_permyriad_unbounded(const char *p) {
        const char *pm;

        pm = endswith(p, "‱");
        if (pm)
                return parse_parts_value_whole(p, "‱");

        pm = endswith(p, "‰");
        if (pm)
                return parse_parts_value_with_tenths_place(p, "‰");

        return parse_parts_value_with_hundredths_place(p, "%");
}

int parse_permyriad(const char *p) {
        int v;

        v = parse_permyriad_unbounded(p);
        if (v > 10000)
                return -ERANGE;

        return v;
}
