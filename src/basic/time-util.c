/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

static clockid_t map_clock_id(clockid_t c) {

        /* Some more exotic archs (s390, ppc, …) lack the "ALARM" flavour of the clocks. Thus, clock_gettime() will
         * fail for them. Since they are essentially the same as their non-ALARM pendants (their only difference is
         * when timers are set on them), let's just map them accordingly. This way, we can get the correct time even on
         * those archs. */

        switch (c) {

        case CLOCK_BOOTTIME_ALARM:
                return CLOCK_BOOTTIME;

        case CLOCK_REALTIME_ALARM:
                return CLOCK_REALTIME;

        default:
                return c;
        }
}

usec_t now(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(map_clock_id(clock_id), &ts) == 0);

        return timespec_load(&ts);
}

nsec_t now_nsec(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(map_clock_id(clock_id), &ts) == 0);

        return timespec_load_nsec(&ts);
}

dual_timestamp* dual_timestamp_get(dual_timestamp *ts) {
        assert(ts);

        ts->realtime = now(CLOCK_REALTIME);
        ts->monotonic = now(CLOCK_MONOTONIC);

        return ts;
}

triple_timestamp* triple_timestamp_get(triple_timestamp *ts) {
        assert(ts);

        ts->realtime = now(CLOCK_REALTIME);
        ts->monotonic = now(CLOCK_MONOTONIC);
        ts->boottime = clock_boottime_supported() ? now(CLOCK_BOOTTIME) : USEC_INFINITY;

        return ts;
}

dual_timestamp* dual_timestamp_from_realtime(dual_timestamp *ts, usec_t u) {
        int64_t delta;
        assert(ts);

        if (u == USEC_INFINITY || u <= 0) {
                ts->realtime = ts->monotonic = u;
                return ts;
        }

        ts->realtime = u;

        delta = (int64_t) now(CLOCK_REALTIME) - (int64_t) u;
        ts->monotonic = usec_sub_signed(now(CLOCK_MONOTONIC), delta);

        return ts;
}

triple_timestamp* triple_timestamp_from_realtime(triple_timestamp *ts, usec_t u) {
        int64_t delta;

        assert(ts);

        if (u == USEC_INFINITY || u <= 0) {
                ts->realtime = ts->monotonic = ts->boottime = u;
                return ts;
        }

        ts->realtime = u;
        delta = (int64_t) now(CLOCK_REALTIME) - (int64_t) u;
        ts->monotonic = usec_sub_signed(now(CLOCK_MONOTONIC), delta);
        ts->boottime = clock_boottime_supported() ? usec_sub_signed(now(CLOCK_BOOTTIME), delta) : USEC_INFINITY;

        return ts;
}

dual_timestamp* dual_timestamp_from_monotonic(dual_timestamp *ts, usec_t u) {
        int64_t delta;
        assert(ts);

        if (u == USEC_INFINITY) {
                ts->realtime = ts->monotonic = USEC_INFINITY;
                return ts;
        }

        ts->monotonic = u;
        delta = (int64_t) now(CLOCK_MONOTONIC) - (int64_t) u;
        ts->realtime = usec_sub_signed(now(CLOCK_REALTIME), delta);

        return ts;
}

dual_timestamp* dual_timestamp_from_boottime_or_monotonic(dual_timestamp *ts, usec_t u) {
        int64_t delta;

        if (u == USEC_INFINITY) {
                ts->realtime = ts->monotonic = USEC_INFINITY;
                return ts;
        }

        dual_timestamp_get(ts);
        delta = (int64_t) now(clock_boottime_or_monotonic()) - (int64_t) u;
        ts->realtime = usec_sub_signed(ts->realtime, delta);
        ts->monotonic = usec_sub_signed(ts->monotonic, delta);

        return ts;
}

usec_t triple_timestamp_by_clock(triple_timestamp *ts, clockid_t clock) {

        switch (clock) {

        case CLOCK_REALTIME:
        case CLOCK_REALTIME_ALARM:
                return ts->realtime;

        case CLOCK_MONOTONIC:
                return ts->monotonic;

        case CLOCK_BOOTTIME:
        case CLOCK_BOOTTIME_ALARM:
                return ts->boottime;

        default:
                return USEC_INFINITY;
        }
}

usec_t timespec_load(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec < 0 || ts->tv_nsec < 0)
                return USEC_INFINITY;

        if ((usec_t) ts->tv_sec > (UINT64_MAX - (ts->tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
                return USEC_INFINITY;

        return
                (usec_t) ts->tv_sec * USEC_PER_SEC +
                (usec_t) ts->tv_nsec / NSEC_PER_USEC;
}

nsec_t timespec_load_nsec(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec < 0 || ts->tv_nsec < 0)
                return NSEC_INFINITY;

        if ((nsec_t) ts->tv_sec >= (UINT64_MAX - ts->tv_nsec) / NSEC_PER_SEC)
                return NSEC_INFINITY;

        return (nsec_t) ts->tv_sec * NSEC_PER_SEC + (nsec_t) ts->tv_nsec;
}

struct timespec *timespec_store(struct timespec *ts, usec_t u)  {
        assert(ts);

        if (u == USEC_INFINITY ||
            u / USEC_PER_SEC >= TIME_T_MAX) {
                ts->tv_sec = (time_t) -1;
                ts->tv_nsec = (long) -1;
                return ts;
        }

        ts->tv_sec = (time_t) (u / USEC_PER_SEC);
        ts->tv_nsec = (long int) ((u % USEC_PER_SEC) * NSEC_PER_USEC);

        return ts;
}

usec_t timeval_load(const struct timeval *tv) {
        assert(tv);

        if (tv->tv_sec < 0 || tv->tv_usec < 0)
                return USEC_INFINITY;

        if ((usec_t) tv->tv_sec > (UINT64_MAX - tv->tv_usec) / USEC_PER_SEC)
                return USEC_INFINITY;

        return
                (usec_t) tv->tv_sec * USEC_PER_SEC +
                (usec_t) tv->tv_usec;
}

struct timeval *timeval_store(struct timeval *tv, usec_t u) {
        assert(tv);

        if (u == USEC_INFINITY ||
            u / USEC_PER_SEC > TIME_T_MAX) {
                tv->tv_sec = (time_t) -1;
                tv->tv_usec = (suseconds_t) -1;
        } else {
                tv->tv_sec = (time_t) (u / USEC_PER_SEC);
                tv->tv_usec = (suseconds_t) (u % USEC_PER_SEC);
        }

        return tv;
}

static char *format_timestamp_internal(
                char *buf,
                size_t l,
                usec_t t,
                bool utc,
                bool us) {

        /* The weekdays in non-localized (English) form. We use this instead of the localized form, so that our
         * generated timestamps may be parsed with parse_timestamp(), and always read the same. */
        static const char * const weekdays[] = {
                [0] = "Sun",
                [1] = "Mon",
                [2] = "Tue",
                [3] = "Wed",
                [4] = "Thu",
                [5] = "Fri",
                [6] = "Sat",
        };

        struct tm tm;
        time_t sec;
        size_t n;

        assert(buf);

        if (l <
            3 +                  /* week day */
            1 + 10 +             /* space and date */
            1 + 8 +              /* space and time */
            (us ? 1 + 6 : 0) +   /* "." and microsecond part */
            1 + 1 +              /* space and shortest possible zone */
            1)
                return NULL; /* Not enough space even for the shortest form. */
        if (t <= 0 || t == USEC_INFINITY)
                return NULL; /* Timestamp is unset */

        /* Let's not format times with years > 9999 */
        if (t > USEC_TIMESTAMP_FORMATTABLE_MAX)
                return NULL;

        sec = (time_t) (t / USEC_PER_SEC); /* Round down */

        if (!localtime_or_gmtime_r(&sec, &tm, utc))
                return NULL;

        /* Start with the week day */
        assert((size_t) tm.tm_wday < ELEMENTSOF(weekdays));
        memcpy(buf, weekdays[tm.tm_wday], 4);

        /* Add the main components */
        if (strftime(buf + 3, l - 3, " %Y-%m-%d %H:%M:%S", &tm) <= 0)
                return NULL; /* Doesn't fit */

        /* Append the microseconds part, if that's requested */
        if (us) {
                n = strlen(buf);
                if (n + 8 > l)
                        return NULL; /* Microseconds part doesn't fit. */

                sprintf(buf + n, ".%06"PRI_USEC, t % USEC_PER_SEC);
        }

        /* Append the timezone */
        n = strlen(buf);
        if (utc) {
                /* If this is UTC then let's explicitly use the "UTC" string here, because gmtime_r() normally uses the
                 * obsolete "GMT" instead. */
                if (n + 5 > l)
                        return NULL; /* "UTC" doesn't fit. */

                strcpy(buf + n, " UTC");

        } else if (!isempty(tm.tm_zone)) {
                size_t tn;

                /* An explicit timezone is specified, let's use it, if it fits */
                tn = strlen(tm.tm_zone);
                if (n + 1 + tn + 1 > l) {
                        /* The full time zone does not fit in. Yuck. */

                        if (n + 1 + _POSIX_TZNAME_MAX + 1 > l)
                                return NULL; /* Not even enough space for the POSIX minimum (of 6)? In that case, complain that it doesn't fit */

                        /* So the time zone doesn't fit in fully, but the caller passed enough space for the POSIX
                         * minimum time zone length. In this case suppress the timezone entirely, in order not to dump
                         * an overly long, hard to read string on the user. This should be safe, because the user will
                         * assume the local timezone anyway if none is shown. And so does parse_timestamp(). */
                } else {
                        buf[n++] = ' ';
                        strcpy(buf + n, tm.tm_zone);
                }
        }

        return buf;
}

char *format_timestamp(char *buf, size_t l, usec_t t) {
        return format_timestamp_internal(buf, l, t, false, false);
}

char *format_timestamp_utc(char *buf, size_t l, usec_t t) {
        return format_timestamp_internal(buf, l, t, true, false);
}

char *format_timestamp_us(char *buf, size_t l, usec_t t) {
        return format_timestamp_internal(buf, l, t, false, true);
}

char *format_timestamp_us_utc(char *buf, size_t l, usec_t t) {
        return format_timestamp_internal(buf, l, t, true, true);
}

char *format_timestamp_relative(char *buf, size_t l, usec_t t) {
        const char *s;
        usec_t n, d;

        if (t <= 0 || t == USEC_INFINITY)
                return NULL;

        n = now(CLOCK_REALTIME);
        if (n > t) {
                d = n - t;
                s = "ago";
        } else {
                d = t - n;
                s = "left";
        }

        if (d >= USEC_PER_YEAR)
                snprintf(buf, l, USEC_FMT " years " USEC_FMT " months %s",
                         d / USEC_PER_YEAR,
                         (d % USEC_PER_YEAR) / USEC_PER_MONTH, s);
        else if (d >= USEC_PER_MONTH)
                snprintf(buf, l, USEC_FMT " months " USEC_FMT " days %s",
                         d / USEC_PER_MONTH,
                         (d % USEC_PER_MONTH) / USEC_PER_DAY, s);
        else if (d >= USEC_PER_WEEK)
                snprintf(buf, l, USEC_FMT " weeks " USEC_FMT " days %s",
                         d / USEC_PER_WEEK,
                         (d % USEC_PER_WEEK) / USEC_PER_DAY, s);
        else if (d >= 2*USEC_PER_DAY)
                snprintf(buf, l, USEC_FMT " days %s", d / USEC_PER_DAY, s);
        else if (d >= 25*USEC_PER_HOUR)
                snprintf(buf, l, "1 day " USEC_FMT "h %s",
                         (d - USEC_PER_DAY) / USEC_PER_HOUR, s);
        else if (d >= 6*USEC_PER_HOUR)
                snprintf(buf, l, USEC_FMT "h %s",
                         d / USEC_PER_HOUR, s);
        else if (d >= USEC_PER_HOUR)
                snprintf(buf, l, USEC_FMT "h " USEC_FMT "min %s",
                         d / USEC_PER_HOUR,
                         (d % USEC_PER_HOUR) / USEC_PER_MINUTE, s);
        else if (d >= 5*USEC_PER_MINUTE)
                snprintf(buf, l, USEC_FMT "min %s",
                         d / USEC_PER_MINUTE, s);
        else if (d >= USEC_PER_MINUTE)
                snprintf(buf, l, USEC_FMT "min " USEC_FMT "s %s",
                         d / USEC_PER_MINUTE,
                         (d % USEC_PER_MINUTE) / USEC_PER_SEC, s);
        else if (d >= USEC_PER_SEC)
                snprintf(buf, l, USEC_FMT "s %s",
                         d / USEC_PER_SEC, s);
        else if (d >= USEC_PER_MSEC)
                snprintf(buf, l, USEC_FMT "ms %s",
                         d / USEC_PER_MSEC, s);
        else if (d > 0)
                snprintf(buf, l, USEC_FMT"us %s",
                         d, s);
        else
                snprintf(buf, l, "now");

        buf[l-1] = 0;
        return buf;
}

char *format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy) {
        static const struct {
                const char *suffix;
                usec_t usec;
        } table[] = {
                { "y",     USEC_PER_YEAR   },
                { "month", USEC_PER_MONTH  },
                { "w",     USEC_PER_WEEK   },
                { "d",     USEC_PER_DAY    },
                { "h",     USEC_PER_HOUR   },
                { "min",   USEC_PER_MINUTE },
                { "s",     USEC_PER_SEC    },
                { "ms",    USEC_PER_MSEC   },
                { "us",    1               },
        };

        unsigned i;
        char *p = buf;
        bool something = false;

        assert(buf);
        assert(l > 0);

        if (t == USEC_INFINITY) {
                strncpy(p, "infinity", l-1);
                p[l-1] = 0;
                return p;
        }

        if (t <= 0) {
                strncpy(p, "0", l-1);
                p[l-1] = 0;
                return p;
        }

        /* The result of this function can be parsed with parse_sec */

        for (i = 0; i < ELEMENTSOF(table); i++) {
                int k = 0;
                size_t n;
                bool done = false;
                usec_t a, b;

                if (t <= 0)
                        break;

                if (t < accuracy && something)
                        break;

                if (t < table[i].usec)
                        continue;

                if (l <= 1)
                        break;

                a = t / table[i].usec;
                b = t % table[i].usec;

                /* Let's see if we should shows this in dot notation */
                if (t < USEC_PER_MINUTE && b > 0) {
                        usec_t cc;
                        int j;

                        j = 0;
                        for (cc = table[i].usec; cc > 1; cc /= 10)
                                j++;

                        for (cc = accuracy; cc > 1; cc /= 10) {
                                b /= 10;
                                j--;
                        }

                        if (j > 0) {
                                k = snprintf(p, l,
                                             "%s"USEC_FMT".%0*"PRI_USEC"%s",
                                             p > buf ? " " : "",
                                             a,
                                             j,
                                             b,
                                             table[i].suffix);

                                t = 0;
                                done = true;
                        }
                }

                /* No? Then let's show it normally */
                if (!done) {
                        k = snprintf(p, l,
                                     "%s"USEC_FMT"%s",
                                     p > buf ? " " : "",
                                     a,
                                     table[i].suffix);

                        t = b;
                }

                n = MIN((size_t) k, l);

                l -= n;
                p += n;

                something = true;
        }

        *p = 0;

        return buf;
}

void dual_timestamp_serialize(FILE *f, const char *name, dual_timestamp *t) {

        assert(f);
        assert(name);
        assert(t);

        if (!dual_timestamp_is_set(t))
                return;

        fprintf(f, "%s="USEC_FMT" "USEC_FMT"\n",
                name,
                t->realtime,
                t->monotonic);
}

int dual_timestamp_deserialize(const char *value, dual_timestamp *t) {
        uint64_t a, b;
        int r, pos;

        assert(value);
        assert(t);

        pos = strspn(value, WHITESPACE);
        if (value[pos] == '-')
                return -EINVAL;
        pos += strspn(value + pos, DIGITS);
        pos += strspn(value + pos, WHITESPACE);
        if (value[pos] == '-')
                return -EINVAL;

        r = sscanf(value, "%" PRIu64 "%" PRIu64 "%n", &a, &b, &pos);
        if (r != 2) {
                log_debug("Failed to parse dual timestamp value \"%s\".", value);
                return -EINVAL;
        }

        if (value[pos] != '\0')
                /* trailing garbage */
                return -EINVAL;

        t->realtime = a;
        t->monotonic = b;

        return 0;
}

int timestamp_deserialize(const char *value, usec_t *timestamp) {
        int r;

        assert(value);

        r = safe_atou64(value, timestamp);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse timestamp value \"%s\": %m", value);

        return r;
}

int parse_timestamp(const char *t, usec_t *usec) {
        static const struct {
                const char *name;
                const int nr;
        } day_nr[] = {
                { "Sunday",    0 },
                { "Sun",       0 },
                { "Monday",    1 },
                { "Mon",       1 },
                { "Tuesday",   2 },
                { "Tue",       2 },
                { "Wednesday", 3 },
                { "Wed",       3 },
                { "Thursday",  4 },
                { "Thu",       4 },
                { "Friday",    5 },
                { "Fri",       5 },
                { "Saturday",  6 },
                { "Sat",       6 },
        };

        const char *k, *utc, *tzn = NULL;
        struct tm tm, copy;
        time_t x;
        usec_t x_usec, plus = 0, minus = 0, ret;
        int r, weekday = -1, dst = -1;
        unsigned i;

        /*
         * Allowed syntaxes:
         *
         *   2012-09-22 16:34:22
         *   2012-09-22 16:34     (seconds will be set to 0)
         *   2012-09-22           (time will be set to 00:00:00)
         *   16:34:22             (date will be set to today)
         *   16:34                (date will be set to today, seconds to 0)
         *   now
         *   yesterday            (time is set to 00:00:00)
         *   today                (time is set to 00:00:00)
         *   tomorrow             (time is set to 00:00:00)
         *   +5min
         *   -5days
         *   @2147483647          (seconds since epoch)
         *
         */

        assert(t);
        assert(usec);

        if (t[0] == '@')
                return parse_sec(t + 1, usec);

        ret = now(CLOCK_REALTIME);

        if (streq(t, "now"))
                goto finish;

        else if (t[0] == '+') {
                r = parse_sec(t+1, &plus);
                if (r < 0)
                        return r;

                goto finish;

        } else if (t[0] == '-') {
                r = parse_sec(t+1, &minus);
                if (r < 0)
                        return r;

                goto finish;

        } else if ((k = endswith(t, " ago"))) {
                t = strndupa(t, k - t);

                r = parse_sec(t, &minus);
                if (r < 0)
                        return r;

                goto finish;

        } else if ((k = endswith(t, " left"))) {
                t = strndupa(t, k - t);

                r = parse_sec(t, &plus);
                if (r < 0)
                        return r;

                goto finish;
        }

        /* See if the timestamp is suffixed with UTC */
        utc = endswith_no_case(t, " UTC");
        if (utc)
                t = strndupa(t, utc - t);
        else {
                const char *e = NULL;
                int j;

                tzset();

                /* See if the timestamp is suffixed by either the DST or non-DST local timezone. Note that we only
                 * support the local timezones here, nothing else. Not because we wouldn't want to, but simply because
                 * there are no nice APIs available to cover this. By accepting the local time zone strings, we make
                 * sure that all timestamps written by format_timestamp() can be parsed correctly, even though we don't
                 * support arbitrary timezone specifications.  */

                for (j = 0; j <= 1; j++) {

                        if (isempty(tzname[j]))
                                continue;

                        e = endswith_no_case(t, tzname[j]);
                        if (!e)
                                continue;
                        if (e == t)
                                continue;
                        if (e[-1] != ' ')
                                continue;

                        break;
                }

                if (IN_SET(j, 0, 1)) {
                        /* Found one of the two timezones specified. */
                        t = strndupa(t, e - t - 1);
                        dst = j;
                        tzn = tzname[j];
                }
        }

        x = (time_t) (ret / USEC_PER_SEC);
        x_usec = 0;

        if (!localtime_or_gmtime_r(&x, &tm, utc))
                return -EINVAL;

        tm.tm_isdst = dst;
        if (tzn)
                tm.tm_zone = tzn;

        if (streq(t, "today")) {
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto from_tm;

        } else if (streq(t, "yesterday")) {
                tm.tm_mday--;
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto from_tm;

        } else if (streq(t, "tomorrow")) {
                tm.tm_mday++;
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto from_tm;
        }

        for (i = 0; i < ELEMENTSOF(day_nr); i++) {
                size_t skip;

                if (!startswith_no_case(t, day_nr[i].name))
                        continue;

                skip = strlen(day_nr[i].name);
                if (t[skip] != ' ')
                        continue;

                weekday = day_nr[i].nr;
                t += skip + 1;
                break;
        }

        copy = tm;
        k = strptime(t, "%y-%m-%d %H:%M:%S", &tm);
        if (k) {
                if (*k == '.')
                        goto parse_usec;
                else if (*k == 0)
                        goto from_tm;
        }

        tm = copy;
        k = strptime(t, "%Y-%m-%d %H:%M:%S", &tm);
        if (k) {
                if (*k == '.')
                        goto parse_usec;
                else if (*k == 0)
                        goto from_tm;
        }

        tm = copy;
        k = strptime(t, "%y-%m-%d %H:%M", &tm);
        if (k && *k == 0) {
                tm.tm_sec = 0;
                goto from_tm;
        }

        tm = copy;
        k = strptime(t, "%Y-%m-%d %H:%M", &tm);
        if (k && *k == 0) {
                tm.tm_sec = 0;
                goto from_tm;
        }

        tm = copy;
        k = strptime(t, "%y-%m-%d", &tm);
        if (k && *k == 0) {
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto from_tm;
        }

        tm = copy;
        k = strptime(t, "%Y-%m-%d", &tm);
        if (k && *k == 0) {
                tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
                goto from_tm;
        }

        tm = copy;
        k = strptime(t, "%H:%M:%S", &tm);
        if (k) {
                if (*k == '.')
                        goto parse_usec;
                else if (*k == 0)
                        goto from_tm;
        }

        tm = copy;
        k = strptime(t, "%H:%M", &tm);
        if (k && *k == 0) {
                tm.tm_sec = 0;
                goto from_tm;
        }

        return -EINVAL;

parse_usec:
        {
                unsigned add;

                k++;
                r = parse_fractional_part_u(&k, 6, &add);
                if (r < 0)
                        return -EINVAL;

                if (*k)
                        return -EINVAL;

                x_usec = add;
        }

from_tm:
        x = mktime_or_timegm(&tm, utc);
        if (x < 0)
                return -EINVAL;

        if (weekday >= 0 && tm.tm_wday != weekday)
                return -EINVAL;

        ret = (usec_t) x * USEC_PER_SEC + x_usec;
        if (ret > USEC_TIMESTAMP_FORMATTABLE_MAX)
                return -EINVAL;

finish:
        if (ret + plus < ret) /* overflow? */
                return -EINVAL;
        ret += plus;
        if (ret > USEC_TIMESTAMP_FORMATTABLE_MAX)
                return -EINVAL;

        if (ret >= minus)
                ret -= minus;
        else
                return -EINVAL;

        *usec = ret;

        return 0;
}

static char* extract_multiplier(char *p, usec_t *multiplier) {
        static const struct {
                const char *suffix;
                usec_t usec;
        } table[] = {
                { "seconds", USEC_PER_SEC    },
                { "second",  USEC_PER_SEC    },
                { "sec",     USEC_PER_SEC    },
                { "s",       USEC_PER_SEC    },
                { "minutes", USEC_PER_MINUTE },
                { "minute",  USEC_PER_MINUTE },
                { "min",     USEC_PER_MINUTE },
                { "months",  USEC_PER_MONTH  },
                { "month",   USEC_PER_MONTH  },
                { "M",       USEC_PER_MONTH  },
                { "msec",    USEC_PER_MSEC   },
                { "ms",      USEC_PER_MSEC   },
                { "m",       USEC_PER_MINUTE },
                { "hours",   USEC_PER_HOUR   },
                { "hour",    USEC_PER_HOUR   },
                { "hr",      USEC_PER_HOUR   },
                { "h",       USEC_PER_HOUR   },
                { "days",    USEC_PER_DAY    },
                { "day",     USEC_PER_DAY    },
                { "d",       USEC_PER_DAY    },
                { "weeks",   USEC_PER_WEEK   },
                { "week",    USEC_PER_WEEK   },
                { "w",       USEC_PER_WEEK   },
                { "years",   USEC_PER_YEAR   },
                { "year",    USEC_PER_YEAR   },
                { "y",       USEC_PER_YEAR   },
                { "usec",    1ULL            },
                { "us",      1ULL            },
                { "µs",      1ULL            },
        };
        unsigned i;

        for (i = 0; i < ELEMENTSOF(table); i++) {
                char *e;

                e = startswith(p, table[i].suffix);
                if (e) {
                        *multiplier = table[i].usec;
                        return e;
                }
        }

        return p;
}

int parse_time(const char *t, usec_t *usec, usec_t default_unit) {
        const char *p, *s;
        usec_t r = 0;
        bool something = false;

        assert(t);
        assert(usec);
        assert(default_unit > 0);

        p = t;

        p += strspn(p, WHITESPACE);
        s = startswith(p, "infinity");
        if (s) {
                s += strspn(s, WHITESPACE);
                if (*s != 0)
                        return -EINVAL;

                *usec = USEC_INFINITY;
                return 0;
        }

        for (;;) {
                long long l, z = 0;
                char *e;
                unsigned n = 0;
                usec_t multiplier = default_unit, k;

                p += strspn(p, WHITESPACE);

                if (*p == 0) {
                        if (!something)
                                return -EINVAL;

                        break;
                }

                errno = 0;
                l = strtoll(p, &e, 10);
                if (errno > 0)
                        return -errno;
                if (l < 0)
                        return -ERANGE;

                if (*e == '.') {
                        char *b = e + 1;

                        errno = 0;
                        z = strtoll(b, &e, 10);
                        if (errno > 0)
                                return -errno;

                        if (z < 0)
                                return -ERANGE;

                        if (e == b)
                                return -EINVAL;

                        n = e - b;

                } else if (e == p)
                        return -EINVAL;

                e += strspn(e, WHITESPACE);
                p = extract_multiplier(e, &multiplier);

                something = true;

                k = (usec_t) z * multiplier;

                for (; n > 0; n--)
                        k /= 10;

                r += (usec_t) l * multiplier + k;
        }

        *usec = r;

        return 0;
}

int parse_sec(const char *t, usec_t *usec) {
        return parse_time(t, usec, USEC_PER_SEC);
}

int parse_sec_fix_0(const char *t, usec_t *usec) {
        t += strspn(t, WHITESPACE);
        if (streq(t, "0")) {
                *usec = USEC_INFINITY;
                return 0;
        }

        return parse_sec(t, usec);
}

int parse_nsec(const char *t, nsec_t *nsec) {
        static const struct {
                const char *suffix;
                nsec_t nsec;
        } table[] = {
                { "seconds", NSEC_PER_SEC },
                { "second", NSEC_PER_SEC },
                { "sec", NSEC_PER_SEC },
                { "s", NSEC_PER_SEC },
                { "minutes", NSEC_PER_MINUTE },
                { "minute", NSEC_PER_MINUTE },
                { "min", NSEC_PER_MINUTE },
                { "months", NSEC_PER_MONTH },
                { "month", NSEC_PER_MONTH },
                { "msec", NSEC_PER_MSEC },
                { "ms", NSEC_PER_MSEC },
                { "m", NSEC_PER_MINUTE },
                { "hours", NSEC_PER_HOUR },
                { "hour", NSEC_PER_HOUR },
                { "hr", NSEC_PER_HOUR },
                { "h", NSEC_PER_HOUR },
                { "days", NSEC_PER_DAY },
                { "day", NSEC_PER_DAY },
                { "d", NSEC_PER_DAY },
                { "weeks", NSEC_PER_WEEK },
                { "week", NSEC_PER_WEEK },
                { "w", NSEC_PER_WEEK },
                { "years", NSEC_PER_YEAR },
                { "year", NSEC_PER_YEAR },
                { "y", NSEC_PER_YEAR },
                { "usec", NSEC_PER_USEC },
                { "us", NSEC_PER_USEC },
                { "µs", NSEC_PER_USEC },
                { "nsec", 1ULL },
                { "ns", 1ULL },
                { "", 1ULL }, /* default is nsec */
        };

        const char *p, *s;
        nsec_t r = 0;
        bool something = false;

        assert(t);
        assert(nsec);

        p = t;

        p += strspn(p, WHITESPACE);
        s = startswith(p, "infinity");
        if (s) {
                s += strspn(s, WHITESPACE);
                if (*s != 0)
                        return -EINVAL;

                *nsec = NSEC_INFINITY;
                return 0;
        }

        for (;;) {
                long long l, z = 0;
                char *e;
                unsigned i, n = 0;

                p += strspn(p, WHITESPACE);

                if (*p == 0) {
                        if (!something)
                                return -EINVAL;

                        break;
                }

                errno = 0;
                l = strtoll(p, &e, 10);

                if (errno > 0)
                        return -errno;

                if (l < 0)
                        return -ERANGE;

                if (*e == '.') {
                        char *b = e + 1;

                        errno = 0;
                        z = strtoll(b, &e, 10);
                        if (errno > 0)
                                return -errno;

                        if (z < 0)
                                return -ERANGE;

                        if (e == b)
                                return -EINVAL;

                        n = e - b;

                } else if (e == p)
                        return -EINVAL;

                e += strspn(e, WHITESPACE);

                for (i = 0; i < ELEMENTSOF(table); i++)
                        if (startswith(e, table[i].suffix)) {
                                nsec_t k = (nsec_t) z * table[i].nsec;

                                for (; n > 0; n--)
                                        k /= 10;

                                r += (nsec_t) l * table[i].nsec + k;
                                p = e + strlen(table[i].suffix);

                                something = true;
                                break;
                        }

                if (i >= ELEMENTSOF(table))
                        return -EINVAL;

        }

        *nsec = r;

        return 0;
}

bool ntp_synced(void) {
        struct timex txc = {};

        if (adjtimex(&txc) < 0)
                return false;

        if (txc.status & STA_UNSYNC)
                return false;

        return true;
}

int get_timezones(char ***ret) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **zones = NULL;
        size_t n_zones = 0, n_allocated = 0;

        assert(ret);

        zones = strv_new("UTC", NULL);
        if (!zones)
                return -ENOMEM;

        n_allocated = 2;
        n_zones = 1;

        f = fopen("/usr/share/zoneinfo/zone.tab", "re");
        if (f) {
                char l[LINE_MAX];

                FOREACH_LINE(l, f, return -errno) {
                        char *p, *w;
                        size_t k;

                        p = strstrip(l);

                        if (isempty(p) || *p == '#')
                                continue;

                        /* Skip over country code */
                        p += strcspn(p, WHITESPACE);
                        p += strspn(p, WHITESPACE);

                        /* Skip over coordinates */
                        p += strcspn(p, WHITESPACE);
                        p += strspn(p, WHITESPACE);

                        /* Found timezone name */
                        k = strcspn(p, WHITESPACE);
                        if (k <= 0)
                                continue;

                        w = strndup(p, k);
                        if (!w)
                                return -ENOMEM;

                        if (!GREEDY_REALLOC(zones, n_allocated, n_zones + 2)) {
                                free(w);
                                return -ENOMEM;
                        }

                        zones[n_zones++] = w;
                        zones[n_zones] = NULL;
                }

                strv_sort(zones);

        } else if (errno != ENOENT)
                return -errno;

        *ret = zones;
        zones = NULL;

        return 0;
}

bool timezone_is_valid(const char *name) {
        bool slash = false;
        const char *p, *t;
        struct stat st;

        if (isempty(name))
                return false;

        if (name[0] == '/')
                return false;

        for (p = name; *p; p++) {
                if (!(*p >= '0' && *p <= '9') &&
                    !(*p >= 'a' && *p <= 'z') &&
                    !(*p >= 'A' && *p <= 'Z') &&
                    !(*p == '-' || *p == '_' || *p == '+' || *p == '/'))
                        return false;

                if (*p == '/') {

                        if (slash)
                                return false;

                        slash = true;
                } else
                        slash = false;
        }

        if (slash)
                return false;

        t = strjoina("/usr/share/zoneinfo/", name);
        if (stat(t, &st) < 0)
                return false;

        if (!S_ISREG(st.st_mode))
                return false;

        return true;
}

bool clock_boottime_supported(void) {
        static int supported = -1;

        /* Note that this checks whether CLOCK_BOOTTIME is available in general as well as available for timerfds()! */

        if (supported < 0) {
                int fd;

                fd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK|TFD_CLOEXEC);
                if (fd < 0)
                        supported = false;
                else {
                        safe_close(fd);
                        supported = true;
                }
        }

        return supported;
}

clockid_t clock_boottime_or_monotonic(void) {
        if (clock_boottime_supported())
                return CLOCK_BOOTTIME;
        else
                return CLOCK_MONOTONIC;
}

bool clock_supported(clockid_t clock) {
        struct timespec ts;

        switch (clock) {

        case CLOCK_MONOTONIC:
        case CLOCK_REALTIME:
                return true;

        case CLOCK_BOOTTIME:
                return clock_boottime_supported();

        case CLOCK_BOOTTIME_ALARM:
                if (!clock_boottime_supported())
                        return false;

                /* fall through */

        default:
                /* For everything else, check properly */
                return clock_gettime(clock, &ts) >= 0;
        }
}

int get_timezone(char **tz) {
        _cleanup_free_ char *t = NULL;
        const char *e;
        char *z;
        int r;

        r = readlink_malloc("/etc/localtime", &t);
        if (r < 0)
                return r; /* returns EINVAL if not a symlink */

        e = path_startswith(t, "/usr/share/zoneinfo/");
        if (!e)
                e = path_startswith(t, "../usr/share/zoneinfo/");
        if (!e)
                return -EINVAL;

        if (!timezone_is_valid(e))
                return -EINVAL;

        z = strdup(e);
        if (!z)
                return -ENOMEM;

        *tz = z;
        return 0;
}

time_t mktime_or_timegm(struct tm *tm, bool utc) {
        return utc ? timegm(tm) : mktime(tm);
}

struct tm *localtime_or_gmtime_r(const time_t *t, struct tm *tm, bool utc) {
        return utc ? gmtime_r(t, tm) : localtime_r(t, tm);
}

unsigned long usec_to_jiffies(usec_t u) {
        static thread_local unsigned long hz = 0;
        long r;

        if (hz == 0) {
                r = sysconf(_SC_CLK_TCK);

                assert(r > 0);
                hz = r;
        }

        return DIV_ROUND_UP(u , USEC_PER_SEC / hz);
}

usec_t usec_shift_clock(usec_t x, clockid_t from, clockid_t to) {
        usec_t a, b;

        if (x == USEC_INFINITY)
                return USEC_INFINITY;
        if (map_clock_id(from) == map_clock_id(to))
                return x;

        a = now(from);
        b = now(to);

        if (x > a)
                /* x lies in the future */
                return usec_add(b, usec_sub_unsigned(x, a));
        else
                /* x lies in the past */
                return usec_sub_unsigned(b, usec_sub_unsigned(a, x));
}
