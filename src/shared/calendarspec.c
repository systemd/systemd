/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "alloc-util.h"
#include "calendarspec.h"
#include "errno-util.h"
#include "fileio.h"
#include "macro.h"
#include "parse-util.h"
#include "process-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

#define BITS_WEEKDAYS 127
#define MIN_YEAR 1970
#define MAX_YEAR 2199

/* An arbitrary limit on the length of the chains of components. We don't want to
 * build a very long linked list, which would be slow to iterate over and might cause
 * our stack to overflow. It's unlikely that legitimate uses require more than a few
 * linked components anyway. */
#define CALENDARSPEC_COMPONENTS_MAX 240

/* Let's make sure that the microsecond component is safe to be stored in an 'int' */
assert_cc(INT_MAX >= USEC_PER_SEC);

static CalendarComponent* chain_free(CalendarComponent *c) {
        while (c) {
                CalendarComponent *n = c->next;
                free(c);
                c = n;
        }
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(CalendarComponent*, chain_free);

CalendarSpec* calendar_spec_free(CalendarSpec *c) {

        if (!c)
                return NULL;

        chain_free(c->year);
        chain_free(c->month);
        chain_free(c->day);
        chain_free(c->hour);
        chain_free(c->minute);
        chain_free(c->microsecond);
        free(c->timezone);

        return mfree(c);
}

static int component_compare(CalendarComponent * const *a, CalendarComponent * const *b) {
        int r;

        r = CMP((*a)->start, (*b)->start);
        if (r != 0)
                return r;

        r = CMP((*a)->stop, (*b)->stop);
        if (r != 0)
                return r;

        return CMP((*a)->repeat, (*b)->repeat);
}

static void normalize_chain(CalendarComponent **c) {
        CalendarComponent **b, *i, **j, *next;
        size_t n = 0, k;

        assert(c);

        for (i = *c; i; i = i->next) {
                n++;

                /*
                 * While we're counting the chain, also normalize `stop`
                 * so the length of the range is a multiple of `repeat`
                 */
                if (i->stop > i->start && i->repeat > 0)
                        i->stop -= (i->stop - i->start) % i->repeat;

                /* If a repeat value is specified, but it cannot even be triggered once, let's suppress
                 * it.
                 *
                 * Similar, if the stop value is the same as the start value, then let's just make this a
                 * non-repeating chain element */
                if ((i->stop > i->start && i->repeat > 0 && i->start + i->repeat > i->stop) ||
                    i->start == i->stop) {
                        i->repeat = 0;
                        i->stop = -1;
                }
        }

        if (n <= 1)
                return;

        j = b = newa(CalendarComponent*, n);
        for (i = *c; i; i = i->next)
                *(j++) = i;

        typesafe_qsort(b, n, component_compare);

        b[n-1]->next = NULL;
        next = b[n-1];

        /* Drop non-unique entries */
        for (k = n-1; k > 0; k--) {
                if (component_compare(&b[k-1], &next) == 0) {
                        free(b[k-1]);
                        continue;
                }

                b[k-1]->next = next;
                next = b[k-1];
        }

        *c = next;
}

static void fix_year(CalendarComponent *c) {
        /* Turns 12 → 2012, 89 → 1989 */

        while (c) {
                if (c->start >= 0 && c->start < 70)
                        c->start += 2000;

                if (c->stop >= 0 && c->stop < 70)
                        c->stop += 2000;

                if (c->start >= 70 && c->start < 100)
                        c->start += 1900;

                if (c->stop >= 70 && c->stop < 100)
                        c->stop += 1900;

                c = c->next;
        }
}

int calendar_spec_normalize(CalendarSpec *c) {
        assert(c);

        if (streq_ptr(c->timezone, "UTC")) {
                c->utc = true;
                c->timezone = mfree(c->timezone);
        }

        if (c->weekdays_bits <= 0 || c->weekdays_bits >= BITS_WEEKDAYS)
                c->weekdays_bits = -1;

        if (c->end_of_month && !c->day)
                c->end_of_month = false;

        fix_year(c->year);

        normalize_chain(&c->year);
        normalize_chain(&c->month);
        normalize_chain(&c->day);
        normalize_chain(&c->hour);
        normalize_chain(&c->minute);
        normalize_chain(&c->microsecond);

        return 0;
}

static bool chain_valid(CalendarComponent *c, int from, int to, bool end_of_month) {
        assert(to >= from);

        if (!c)
                return true;

        /* Forbid dates more than 28 days from the end of the month */
        if (end_of_month)
                to -= 3;

        if (c->start < from || c->start > to)
                return false;

        /* Avoid overly large values that could cause overflow */
        if (c->repeat > to - from)
                return false;

        /*
         * c->repeat must be short enough so at least one repetition may
         * occur before the end of the interval.  For dates scheduled
         * relative to the end of the month, c->start and c->stop
         * correspond to the Nth last day of the month.
         */
        if (c->stop >= 0) {
                if (c->stop < from || c ->stop > to)
                        return false;

                if (c->start + c->repeat > c->stop)
                        return false;
        } else {
                if (end_of_month && c->start - c->repeat < from)
                        return false;

                if (!end_of_month && c->start + c->repeat > to)
                        return false;
        }

        if (c->next)
                return chain_valid(c->next, from, to, end_of_month);

        return true;
}

_pure_ bool calendar_spec_valid(CalendarSpec *c) {
        assert(c);

        if (c->weekdays_bits > BITS_WEEKDAYS)
                return false;

        if (!chain_valid(c->year, MIN_YEAR, MAX_YEAR, false))
                return false;

        if (!chain_valid(c->month, 1, 12, false))
                return false;

        if (!chain_valid(c->day, 1, 31, c->end_of_month))
                return false;

        if (!chain_valid(c->hour, 0, 23, false))
                return false;

        if (!chain_valid(c->minute, 0, 59, false))
                return false;

        if (!chain_valid(c->microsecond, 0, 60*USEC_PER_SEC-1, false))
                return false;

        return true;
}

static void format_weekdays(FILE *f, const CalendarSpec *c) {
        static const char *const days[] = {
                "Mon",
                "Tue",
                "Wed",
                "Thu",
                "Fri",
                "Sat",
                "Sun"
        };

        int l, x;
        bool need_comma = false;

        assert(f);
        assert(c);
        assert(c->weekdays_bits > 0 && c->weekdays_bits <= BITS_WEEKDAYS);

        for (x = 0, l = -1; x < (int) ELEMENTSOF(days); x++) {

                if (c->weekdays_bits & (1 << x)) {

                        if (l < 0) {
                                if (need_comma)
                                        fputc(',', f);
                                else
                                        need_comma = true;

                                fputs(days[x], f);
                                l = x;
                        }

                } else if (l >= 0) {

                        if (x > l + 1) {
                                fputs(x > l + 2 ? ".." : ",", f);
                                fputs(days[x-1], f);
                        }

                        l = -1;
                }
        }

        if (l >= 0 && x > l + 1) {
                fputs(x > l + 2 ? ".." : ",", f);
                fputs(days[x-1], f);
        }
}

static void format_chain(FILE *f, int space, const CalendarComponent *c, bool usec) {
        int d = usec ? (int) USEC_PER_SEC : 1;

        assert(f);

        if (!c) {
                fputc('*', f);
                return;
        }

        if (usec && c->start == 0 && c->repeat == USEC_PER_SEC && !c->next) {
                fputc('*', f);
                return;
        }

        assert(c->start >= 0);

        fprintf(f, "%0*i", space, c->start / d);
        if (c->start % d > 0)
                fprintf(f, ".%06i", c->start % d);

        if (c->stop > 0)
                fprintf(f, "..%0*i", space, c->stop / d);
        if (c->stop % d > 0)
                fprintf(f, ".%06i", c->stop % d);

        if (c->repeat > 0 && !(c->stop > 0 && c->repeat == d))
                fprintf(f, "/%i", c->repeat / d);
        if (c->repeat % d > 0)
                fprintf(f, ".%06i", c->repeat % d);

        if (c->next) {
                fputc(',', f);
                format_chain(f, space, c->next, usec);
        }
}

int calendar_spec_to_string(const CalendarSpec *c, char **p) {
        char *buf = NULL;
        size_t sz = 0;
        FILE *f;
        int r;

        assert(c);
        assert(p);

        f = open_memstream_unlocked(&buf, &sz);
        if (!f)
                return -ENOMEM;

        if (c->weekdays_bits > 0 && c->weekdays_bits <= BITS_WEEKDAYS) {
                format_weekdays(f, c);
                fputc(' ', f);
        }

        format_chain(f, 4, c->year, false);
        fputc('-', f);
        format_chain(f, 2, c->month, false);
        fputc(c->end_of_month ? '~' : '-', f);
        format_chain(f, 2, c->day, false);
        fputc(' ', f);
        format_chain(f, 2, c->hour, false);
        fputc(':', f);
        format_chain(f, 2, c->minute, false);
        fputc(':', f);
        format_chain(f, 2, c->microsecond, true);

        if (c->utc)
                fputs(" UTC", f);
        else if (c->timezone) {
                fputc(' ', f);
                fputs(c->timezone, f);
        } else if (IN_SET(c->dst, 0, 1)) {

                /* If daylight saving is explicitly on or off, let's show the used timezone. */

                tzset();

                if (!isempty(tzname[c->dst])) {
                        fputc(' ', f);
                        fputs(tzname[c->dst], f);
                }
        }

        r = fflush_and_check(f);
        fclose(f);

        if (r < 0) {
                free(buf);
                return r;
        }

        *p = buf;
        return 0;
}

static int parse_weekdays(const char **p, CalendarSpec *c) {
        static const struct {
                const char *name;
                const int nr;
        } day_nr[] = {
                { "Monday",    0 },
                { "Mon",       0 },
                { "Tuesday",   1 },
                { "Tue",       1 },
                { "Wednesday", 2 },
                { "Wed",       2 },
                { "Thursday",  3 },
                { "Thu",       3 },
                { "Friday",    4 },
                { "Fri",       4 },
                { "Saturday",  5 },
                { "Sat",       5 },
                { "Sunday",    6 },
                { "Sun",       6 }
        };

        int l = -1;
        bool first = true;

        assert(p);
        assert(*p);
        assert(c);

        for (;;) {
                size_t i;

                for (i = 0; i < ELEMENTSOF(day_nr); i++) {
                        size_t skip;

                        if (!startswith_no_case(*p, day_nr[i].name))
                                continue;

                        skip = strlen(day_nr[i].name);

                        if (!IN_SET((*p)[skip], 0, '-', '.', ',', ' '))
                                return -EINVAL;

                        c->weekdays_bits |= 1 << day_nr[i].nr;

                        if (l >= 0) {
                                int j;

                                if (l > day_nr[i].nr)
                                        return -EINVAL;

                                for (j = l + 1; j < day_nr[i].nr; j++)
                                        c->weekdays_bits |= 1 << j;
                        }

                        *p += skip;
                        break;
                }

                /* Couldn't find this prefix, so let's assume the
                   weekday was not specified and let's continue with
                   the date */
                if (i >= ELEMENTSOF(day_nr))
                        return first ? 0 : -EINVAL;

                /* We reached the end of the string */
                if (**p == 0)
                        return 0;

                /* We reached the end of the weekday spec part */
                if (**p == ' ') {
                        *p += strspn(*p, " ");
                        return 0;
                }

                if (**p == '.') {
                        if (l >= 0)
                                return -EINVAL;

                        if ((*p)[1] != '.')
                                return -EINVAL;

                        l = day_nr[i].nr;
                        *p += 2;

                /* Support ranges with "-" for backwards compatibility */
                } else if (**p == '-') {
                        if (l >= 0)
                                return -EINVAL;

                        l = day_nr[i].nr;
                        *p += 1;

                } else if (**p == ',') {
                        l = -1;
                        *p += 1;
                }

                /* Allow a trailing comma but not an open range */
                if (IN_SET(**p, 0, ' ')) {
                        *p += strspn(*p, " ");
                        return l < 0 ? 0 : -EINVAL;
                }

                first = false;
        }
}

static int parse_one_number(const char *p, const char **e, unsigned long *ret) {
        char *ee = NULL;
        unsigned long value;

        errno = 0;
        value = strtoul(p, &ee, 10);
        if (errno > 0)
                return -errno;
        if (ee == p)
                return -EINVAL;

        *ret = value;
        *e = ee;
        return 0;
}

static int parse_component_decimal(const char **p, bool usec, int *res) {
        unsigned long value;
        const char *e = NULL;
        int r;

        if (!isdigit(**p))
                return -EINVAL;

        r = parse_one_number(*p, &e, &value);
        if (r < 0)
                return r;

        if (usec) {
                if (value * USEC_PER_SEC / USEC_PER_SEC != value)
                        return -ERANGE;

                value *= USEC_PER_SEC;

                /* One "." is a decimal point, but ".." is a range separator */
                if (e[0] == '.' && e[1] != '.') {
                        unsigned add;

                        e++;
                        r = parse_fractional_part_u(&e, 6, &add);
                        if (r < 0)
                                return r;

                        if (add + value < value)
                                return -ERANGE;
                        value += add;
                }
        }

        if (value > INT_MAX)
                return -ERANGE;

        *p = e;
        *res = value;

        return 0;
}

static int const_chain(int value, CalendarComponent **c) {
        CalendarComponent *cc = NULL;

        assert(c);

        cc = new(CalendarComponent, 1);
        if (!cc)
                return -ENOMEM;

        *cc = (CalendarComponent) {
                .start = value,
                .stop = -1,
                .repeat = 0,
                .next = *c,
        };

        *c = cc;

        return 0;
}

static int calendarspec_from_time_t(CalendarSpec *c, time_t time) {
        _cleanup_(chain_freep) CalendarComponent
                *year = NULL, *month = NULL, *day = NULL,
                *hour = NULL, *minute = NULL, *us = NULL;
        struct tm tm;
        int r;

        if (!gmtime_r(&time, &tm))
                return -ERANGE;

        if (tm.tm_year > INT_MAX - 1900)
                return -ERANGE;

        r = const_chain(tm.tm_year + 1900, &year);
        if (r < 0)
                return r;

        r = const_chain(tm.tm_mon + 1, &month);
        if (r < 0)
                return r;

        r = const_chain(tm.tm_mday, &day);
        if (r < 0)
                return r;

        r = const_chain(tm.tm_hour, &hour);
        if (r < 0)
                return r;

        r = const_chain(tm.tm_min, &minute);
        if (r < 0)
                return r;

        r = const_chain(tm.tm_sec * USEC_PER_SEC, &us);
        if (r < 0)
                return r;

        c->utc = true;
        c->year = TAKE_PTR(year);
        c->month = TAKE_PTR(month);
        c->day = TAKE_PTR(day);
        c->hour = TAKE_PTR(hour);
        c->minute = TAKE_PTR(minute);
        c->microsecond = TAKE_PTR(us);
        return 0;
}

static int prepend_component(const char **p, bool usec, unsigned nesting, CalendarComponent **c) {
        int r, start, stop = -1, repeat = 0;
        CalendarComponent *cc;
        const char *e = *p;

        assert(p);
        assert(c);

        if (nesting > CALENDARSPEC_COMPONENTS_MAX)
                return -ENOBUFS;

        r = parse_component_decimal(&e, usec, &start);
        if (r < 0)
                return r;

        if (e[0] == '.' && e[1] == '.') {
                e += 2;
                r = parse_component_decimal(&e, usec, &stop);
                if (r < 0)
                        return r;

                repeat = usec ? USEC_PER_SEC : 1;
        }

        if (*e == '/') {
                e++;
                r = parse_component_decimal(&e, usec, &repeat);
                if (r < 0)
                        return r;

                if (repeat == 0)
                        return -ERANGE;
        } else {
                /* If no repeat value is specified for the µs component, then let's explicitly refuse ranges
                 * below 1s because our default repeat granularity is beyond that. */

                /* Overflow check */
                if (start > INT_MAX - repeat)
                        return -ERANGE;

                if (usec && stop >= 0 && start + repeat > stop)
                        return -EINVAL;
        }

        if (!IN_SET(*e, 0, ' ', ',', '-', '~', ':'))
                return -EINVAL;

        cc = new(CalendarComponent, 1);
        if (!cc)
                return -ENOMEM;

        *cc = (CalendarComponent) {
                .start = start,
                .stop = stop,
                .repeat = repeat,
                .next = *c,
        };

        *p = e;
        *c = cc;

        if (*e ==',') {
                *p += 1;
                return prepend_component(p, usec, nesting + 1, c);
        }

        return 0;
}

static int parse_chain(const char **p, bool usec, CalendarComponent **c) {
        _cleanup_(chain_freep) CalendarComponent *cc = NULL;
        const char *t;
        int r;

        assert(p);
        assert(c);

        t = *p;

        if (t[0] == '*') {
                if (usec) {
                        r = const_chain(0, c);
                        if (r < 0)
                                return r;
                        (*c)->repeat = USEC_PER_SEC;
                } else
                        *c = NULL;

                *p = t + 1;
                return 0;
        }

        r = prepend_component(&t, usec, 0, &cc);
        if (r < 0)
                return r;

        *p = t;
        *c = TAKE_PTR(cc);
        return 0;
}

static int parse_date(const char **p, CalendarSpec *c) {
        _cleanup_(chain_freep) CalendarComponent *first = NULL, *second = NULL, *third = NULL;
        const char *t;
        int r;

        assert(p);
        assert(*p);
        assert(c);

        t = *p;

        if (*t == 0)
                return 0;

        /* @TIMESTAMP — UNIX time in seconds since the epoch */
        if (*t == '@') {
                unsigned long value;
                time_t time;

                r = parse_one_number(t + 1, &t, &value);
                if (r < 0)
                        return r;

                time = value;
                if ((unsigned long) time != value)
                        return -ERANGE;

                r = calendarspec_from_time_t(c, time);
                if (r < 0)
                        return r;

                *p = t;
                return 1; /* finito, don't parse H:M:S after that */
        }

        r = parse_chain(&t, false, &first);
        if (r < 0)
                return r;

        /* Already the end? A ':' as separator? In that case this was a time, not a date */
        if (IN_SET(*t, 0, ':'))
                return 0;

        if (*t == '~')
                c->end_of_month = true;
        else if (*t != '-')
                return -EINVAL;

        t++;
        r = parse_chain(&t, false, &second);
        if (r < 0)
                return r;

        /* Got two parts, hence it's month and day */
        if (IN_SET(*t, 0, ' ')) {
                *p = t + strspn(t, " ");
                c->month = TAKE_PTR(first);
                c->day = TAKE_PTR(second);
                return 0;
        } else if (c->end_of_month)
                return -EINVAL;

        if (*t == '~')
                c->end_of_month = true;
        else if (*t != '-')
                return -EINVAL;

        t++;
        r = parse_chain(&t, false, &third);
        if (r < 0)
                return r;

        if (!IN_SET(*t, 0, ' '))
                return -EINVAL;

        /* Got three parts, hence it is year, month and day */
        *p = t + strspn(t, " ");
        c->year = TAKE_PTR(first);
        c->month = TAKE_PTR(second);
        c->day = TAKE_PTR(third);
        return 0;
}

static int parse_calendar_time(const char **p, CalendarSpec *c) {
        _cleanup_(chain_freep) CalendarComponent *h = NULL, *m = NULL, *s = NULL;
        const char *t;
        int r;

        assert(p);
        assert(*p);
        assert(c);

        t = *p;

        /* If no time is specified at all, then this means 00:00:00 */
        if (*t == 0)
                goto null_hour;

        r = parse_chain(&t, false, &h);
        if (r < 0)
                return r;

        if (*t != ':')
                return -EINVAL;

        t++;
        r = parse_chain(&t, false, &m);
        if (r < 0)
                return r;

        /* Already at the end? Then it's hours and minutes, and seconds are 0 */
        if (*t == 0)
                goto null_second;

        if (*t != ':')
                return -EINVAL;

        t++;
        r = parse_chain(&t, true, &s);
        if (r < 0)
                return r;

        /* At the end? Then it's hours, minutes and seconds */
        if (*t == 0)
                goto finish;

        return -EINVAL;

null_hour:
        r = const_chain(0, &h);
        if (r < 0)
                return r;

        r = const_chain(0, &m);
        if (r < 0)
                return r;

null_second:
        r = const_chain(0, &s);
        if (r < 0)
                return r;

finish:
        *p = t;
        c->hour = TAKE_PTR(h);
        c->minute = TAKE_PTR(m);
        c->microsecond = TAKE_PTR(s);

        return 0;
}

int calendar_spec_from_string(const char *p, CalendarSpec **spec) {
        const char *utc;
        _cleanup_(calendar_spec_freep) CalendarSpec *c = NULL;
        _cleanup_free_ char *p_tmp = NULL;
        int r;

        assert(p);

        c = new(CalendarSpec, 1);
        if (!c)
                return -ENOMEM;

        *c = (CalendarSpec) {
                .dst = -1,
                .timezone = NULL,
        };

        utc = endswith_no_case(p, " UTC");
        if (utc) {
                c->utc = true;
                p = p_tmp = strndup(p, utc - p);
                if (!p)
                        return -ENOMEM;
        } else {
                const char *e = NULL;
                int j;

                tzset();

                /* Check if the local timezone was specified? */
                for (j = 0; j <= 1; j++) {
                        if (isempty(tzname[j]))
                                continue;

                        e = endswith_no_case(p, tzname[j]);
                        if (!e)
                                continue;
                        if (e == p)
                                continue;
                        if (e[-1] != ' ')
                                continue;

                        break;
                }

                /* Found one of the two timezones specified? */
                if (IN_SET(j, 0, 1)) {
                        p = p_tmp = strndup(p, e - p - 1);
                        if (!p)
                                return -ENOMEM;

                        c->dst = j;
                } else {
                        const char *last_space;

                        last_space = strrchr(p, ' ');
                        if (last_space != NULL && timezone_is_valid(last_space + 1, LOG_DEBUG)) {
                                c->timezone = strdup(last_space + 1);
                                if (!c->timezone)
                                        return -ENOMEM;

                                p = p_tmp = strndup(p, last_space - p);
                                if (!p)
                                        return -ENOMEM;
                        }
                }
        }

        if (isempty(p))
                return -EINVAL;

        if (strcaseeq(p, "minutely")) {
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else if (strcaseeq(p, "hourly")) {
                r = const_chain(0, &c->minute);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else if (strcaseeq(p, "daily")) {
                r = const_chain(0, &c->hour);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->minute);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else if (strcaseeq(p, "monthly")) {
                r = const_chain(1, &c->day);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->hour);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->minute);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else if (STRCASE_IN_SET(p,
                                  "annually",
                                  "yearly",
                                  "anually") /* backwards compatibility */ ) {

                r = const_chain(1, &c->month);
                if (r < 0)
                        return r;
                r = const_chain(1, &c->day);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->hour);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->minute);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else if (strcaseeq(p, "weekly")) {

                c->weekdays_bits = 1;

                r = const_chain(0, &c->hour);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->minute);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else if (strcaseeq(p, "quarterly")) {

                r = const_chain(1, &c->month);
                if (r < 0)
                        return r;
                r = const_chain(4, &c->month);
                if (r < 0)
                        return r;
                r = const_chain(7, &c->month);
                if (r < 0)
                        return r;
                r = const_chain(10, &c->month);
                if (r < 0)
                        return r;
                r = const_chain(1, &c->day);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->hour);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->minute);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else if (STRCASE_IN_SET(p,
                                  "biannually",
                                  "bi-annually",
                                  "semiannually",
                                  "semi-annually")) {

                r = const_chain(1, &c->month);
                if (r < 0)
                        return r;
                r = const_chain(7, &c->month);
                if (r < 0)
                        return r;
                r = const_chain(1, &c->day);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->hour);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->minute);
                if (r < 0)
                        return r;
                r = const_chain(0, &c->microsecond);
                if (r < 0)
                        return r;

        } else {
                r = parse_weekdays(&p, c);
                if (r < 0)
                        return r;

                r = parse_date(&p, c);
                if (r < 0)
                        return r;

                if (r == 0) {
                        r = parse_calendar_time(&p, c);
                        if (r < 0)
                                return r;
                }

                if (*p != 0)
                        return -EINVAL;
        }

        r = calendar_spec_normalize(c);
        if (r < 0)
                return r;

        if (!calendar_spec_valid(c))
                return -EINVAL;

        if (spec)
                *spec = TAKE_PTR(c);
        return 0;
}

static int find_end_of_month(const struct tm *tm, bool utc, int day) {
        struct tm t = *tm;

        t.tm_mon++;
        t.tm_mday = 1 - day;

        if (mktime_or_timegm(&t, utc) < 0 ||
            t.tm_mon != tm->tm_mon)
                return -1;

        return t.tm_mday;
}

static int find_matching_component(
                const CalendarSpec *spec,
                const CalendarComponent *c,
                const struct tm *tm,           /* tm is only used for end-of-month calculations */
                int *val) {

        int d = -1, r;
        bool d_set = false;

        assert(val);

        /* Finds the *earliest* matching time specified by one of the CalendarCompoment items in chain c.
         * If no matches can be found, returns -ENOENT.
         * Otherwise, updates *val to the matching time. 1 is returned if *val was changed, 0 otherwise.
         */

        if (!c)
                return 0;

        bool end_of_month = spec->end_of_month && c == spec->day;

        while (c) {
                int start, stop;

                if (end_of_month) {
                        start = find_end_of_month(tm, spec->utc, c->start);
                        stop = find_end_of_month(tm, spec->utc, c->stop);

                        if (stop > 0)
                                SWAP_TWO(start, stop);
                } else {
                        start = c->start;
                        stop = c->stop;
                }

                if (start >= *val) {

                        if (!d_set || start < d) {
                                d = start;
                                d_set = true;
                        }

                } else if (c->repeat > 0) {
                        int k;

                        k = start + c->repeat * DIV_ROUND_UP(*val - start, c->repeat);

                        if ((!d_set || k < d) && (stop < 0 || k <= stop)) {
                                d = k;
                                d_set = true;
                        }
                }

                c = c->next;
        }

        if (!d_set)
                return -ENOENT;

        r = *val != d;
        *val = d;
        return r;
}

static int tm_within_bounds(struct tm *tm, bool utc) {
        struct tm t;
        int cmp;
        assert(tm);

        /*
         * Set an upper bound on the year so impossible dates like "*-02-31"
         * don't cause find_next() to loop forever. tm_year contains years
         * since 1900, so adjust it accordingly.
         */
        if (tm->tm_year + 1900 > MAX_YEAR)
                return -ERANGE;

        t = *tm;
        if (mktime_or_timegm(&t, utc) < 0)
                return negative_errno();

        /*
         * Did any normalization take place? If so, it was out of bounds before.
         * Normalization could skip next elapse, e.g. result of normalizing 3-33
         * is 4-2. This skips 4-1. So reset the sub time unit if upper unit was
         * out of bounds. Normalization has occurred implies find_matching_component() > 0,
         * other sub time units are already reset in find_next().
         */
        if ((cmp = CMP(t.tm_year, tm->tm_year)) != 0)
                t.tm_mon = 0;
        else if ((cmp = CMP(t.tm_mon, tm->tm_mon)) != 0)
                t.tm_mday = 1;
        else if ((cmp = CMP(t.tm_mday, tm->tm_mday)) != 0)
                t.tm_hour = 0;
        else if ((cmp = CMP(t.tm_hour, tm->tm_hour)) != 0)
                t.tm_min = 0;
        else if ((cmp = CMP(t.tm_min, tm->tm_min)) != 0)
                t.tm_sec = 0;
        else
                cmp = CMP(t.tm_sec, tm->tm_sec);

        if (cmp < 0)
                return -EDEADLK; /* Refuse to go backward */
        if (cmp > 0)
                *tm = t;
        return cmp == 0;
}

static bool matches_weekday(int weekdays_bits, const struct tm *tm, bool utc) {
        struct tm t;
        int k;

        if (weekdays_bits < 0 || weekdays_bits >= BITS_WEEKDAYS)
                return true;

        t = *tm;
        if (mktime_or_timegm(&t, utc) < 0)
                return false;

        k = t.tm_wday == 0 ? 6 : t.tm_wday - 1;
        return (weekdays_bits & (1 << k));
}

/* A safety valve: if we get stuck in the calculation, return an error.
 * C.f. https://bugzilla.redhat.com/show_bug.cgi?id=1941335. */
#define MAX_CALENDAR_ITERATIONS 1000

static int find_next(const CalendarSpec *spec, struct tm *tm, usec_t *usec) {
        struct tm c;
        int tm_usec;
        int r;

        /* Returns -ENOENT if the expression is not going to elapse anymore */

        assert(spec);
        assert(tm);

        c = *tm;
        tm_usec = *usec;

        for (unsigned iteration = 0; iteration < MAX_CALENDAR_ITERATIONS; iteration++) {
                /* Normalize the current date */
                (void) mktime_or_timegm(&c, spec->utc);
                c.tm_isdst = spec->dst;

                c.tm_year += 1900;
                r = find_matching_component(spec, spec->year, &c, &c.tm_year);
                c.tm_year -= 1900;

                if (r > 0) {
                        c.tm_mon = 0;
                        c.tm_mday = 1;
                        c.tm_hour = c.tm_min = c.tm_sec = tm_usec = 0;
                }
                if (r < 0)
                        return r;
                if (tm_within_bounds(&c, spec->utc) <= 0)
                        return -ENOENT;

                c.tm_mon += 1;
                r = find_matching_component(spec, spec->month, &c, &c.tm_mon);
                c.tm_mon -= 1;

                if (r > 0) {
                        c.tm_mday = 1;
                        c.tm_hour = c.tm_min = c.tm_sec = tm_usec = 0;
                }
                if (r < 0 || (r = tm_within_bounds(&c, spec->utc)) < 0) {
                        c.tm_year++;
                        c.tm_mon = 0;
                        c.tm_mday = 1;
                        c.tm_hour = c.tm_min = c.tm_sec = tm_usec = 0;
                        continue;
                }
                if (r == 0)
                        continue;

                r = find_matching_component(spec, spec->day, &c, &c.tm_mday);
                if (r > 0)
                        c.tm_hour = c.tm_min = c.tm_sec = tm_usec = 0;
                if (r < 0 || (r = tm_within_bounds(&c, spec->utc)) < 0) {
                        c.tm_mon++;
                        c.tm_mday = 1;
                        c.tm_hour = c.tm_min = c.tm_sec = tm_usec = 0;
                        continue;
                }
                if (r == 0)
                        continue;

                if (!matches_weekday(spec->weekdays_bits, &c, spec->utc)) {
                        c.tm_mday++;
                        c.tm_hour = c.tm_min = c.tm_sec = tm_usec = 0;
                        continue;
                }

                r = find_matching_component(spec, spec->hour, &c, &c.tm_hour);
                if (r > 0)
                        c.tm_min = c.tm_sec = tm_usec = 0;
                if (r < 0 || (r = tm_within_bounds(&c, spec->utc)) < 0) {
                        c.tm_mday++;
                        c.tm_hour = c.tm_min = c.tm_sec = tm_usec = 0;
                        continue;
                }
                if (r == 0)
                        /* The next hour we set might be missing if there
                         * are time zone changes. Let's try again starting at
                         * normalized time. */
                        continue;

                r = find_matching_component(spec, spec->minute, &c, &c.tm_min);
                if (r > 0)
                        c.tm_sec = tm_usec = 0;
                if (r < 0 || (r = tm_within_bounds(&c, spec->utc)) < 0) {
                        c.tm_hour++;
                        c.tm_min = c.tm_sec = tm_usec = 0;
                        continue;
                }
                if (r == 0)
                        continue;

                c.tm_sec = c.tm_sec * USEC_PER_SEC + tm_usec;
                r = find_matching_component(spec, spec->microsecond, &c, &c.tm_sec);
                tm_usec = c.tm_sec % USEC_PER_SEC;
                c.tm_sec /= USEC_PER_SEC;

                if (r < 0 || (r = tm_within_bounds(&c, spec->utc)) < 0) {
                        c.tm_min++;
                        c.tm_sec = tm_usec = 0;
                        continue;
                }
                if (r == 0)
                        continue;

                *tm = c;
                *usec = tm_usec;
                return 0;
        }

        /* It seems we entered an infinite loop. Let's gracefully return an error instead of hanging or
         * aborting. This code is also exercised when timers.target is brought up during early boot, so
         * aborting here is problematic and hard to diagnose for users. */
        _cleanup_free_ char *s = NULL;
        (void) calendar_spec_to_string(spec, &s);
        return log_warning_errno(SYNTHETIC_ERRNO(EDEADLK),
                                 "Infinite loop in calendar calculation: %s", strna(s));
}

static int calendar_spec_next_usec_impl(const CalendarSpec *spec, usec_t usec, usec_t *ret_next) {
        struct tm tm;
        time_t t;
        int r;
        usec_t tm_usec;

        assert(spec);

        if (usec > USEC_TIMESTAMP_FORMATTABLE_MAX)
                return -EINVAL;

        usec++;
        t = (time_t) (usec / USEC_PER_SEC);
        assert_se(localtime_or_gmtime_r(&t, &tm, spec->utc));
        tm_usec = usec % USEC_PER_SEC;

        r = find_next(spec, &tm, &tm_usec);
        if (r < 0)
                return r;

        t = mktime_or_timegm(&tm, spec->utc);
        if (t < 0)
                return -EINVAL;

        if (ret_next)
                *ret_next = (usec_t) t * USEC_PER_SEC + tm_usec;

        return 0;
}

typedef struct SpecNextResult {
        usec_t next;
        int return_value;
} SpecNextResult;

int calendar_spec_next_usec(const CalendarSpec *spec, usec_t usec, usec_t *ret_next) {
        SpecNextResult *shared, tmp;
        int r;

        assert(spec);

        if (isempty(spec->timezone))
                return calendar_spec_next_usec_impl(spec, usec, ret_next);

        shared = mmap(NULL, sizeof *shared, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        if (shared == MAP_FAILED)
                return negative_errno();

        r = safe_fork("(sd-calendar)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_WAIT, NULL);
        if (r < 0) {
                (void) munmap(shared, sizeof *shared);
                return r;
        }
        if (r == 0) {
                char *colon_tz;

                /* tzset(3) says $TZ should be prefixed with ":" if we reference timezone files */
                colon_tz = strjoina(":", spec->timezone);

                if (setenv("TZ", colon_tz, 1) != 0) {
                        shared->return_value = negative_errno();
                        _exit(EXIT_FAILURE);
                }

                tzset();

                shared->return_value = calendar_spec_next_usec_impl(spec, usec, &shared->next);

                _exit(EXIT_SUCCESS);
        }

        tmp = *shared;
        if (munmap(shared, sizeof *shared) < 0)
                return negative_errno();

        if (tmp.return_value == 0 && ret_next)
                *ret_next = tmp.next;

        return tmp.return_value;
}
