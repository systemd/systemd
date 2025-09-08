/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <string.h>
#include <time.h>

/* The header time.h overrides strptime with strerror_fallback, hence we need to undef it here. */
#undef strptime

char* strptime_fallback(const char *s, const char *format, struct tm *tm) {
        /* First try native strptime() as is, and if it succeeds, return the resuit as is. */
        char *k = strptime(s, format, tm);
        if (k)
                return k;

        /* Check inputs for safety. */
        if (!s || !format || !tm)
                return NULL;

        /* We only fallback if the format is exactly "%z". */
        if (strcmp(format, "%z") != 0)
                return NULL;

        /* In the below, we parse timezone specifiction compatible with RFC-822/ISO 8601 and its extensions
         * (e.g. +06, +0900, or -03:00). */

        bool positive;
        switch (*s) {
        case '+':
                positive = true;
                break;
        case '-':
                positive = false;
                break;
        default:
                return NULL;
        }

        s++;

        if (*s < '0' || *s > '9')
                return NULL;
        long t = (*s - '0') * 10 * 60 * 60;

        s++;

        if (*s < '0' || *s > '9')
                return NULL;
        t += (*s - '0') * 60 * 60;

        s++;

        if (*s == '\0') /* 2 digits case */
                goto finalize;

        if (*s == ':') /* skip colon */
                s++;

        if (*s < '0' || *s >= '6') /* refuse minutes equal to or larger than 60 */
                return NULL;
        t += (*s - '0') * 10 * 60;

        s++;

        if (*s < '0' || *s > '9')
                return NULL;
        t += (*s - '0') * 60;

        s++;

        if (*s != '\0')
                return NULL;

finalize:
        if (t > 24 * 60 * 60) /* refuse larger than 24 hours */
                return NULL;

        if (!positive)
                t = -t;

        *tm = (struct tm) {
                .tm_gmtoff = t,
        };

        return (char*) s;
}
