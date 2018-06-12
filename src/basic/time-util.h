/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

#define PRI_NSEC PRIu64
#define PRI_USEC PRIu64
#define NSEC_FMT "%" PRI_NSEC
#define USEC_FMT "%" PRI_USEC

#include "macro.h"

typedef struct dual_timestamp {
        usec_t realtime;
        usec_t monotonic;
} dual_timestamp;

typedef struct triple_timestamp {
        usec_t realtime;
        usec_t monotonic;
        usec_t boottime;
} triple_timestamp;

#define USEC_INFINITY ((usec_t) -1)
#define NSEC_INFINITY ((nsec_t) -1)

#define MSEC_PER_SEC  1000ULL
#define USEC_PER_SEC  ((usec_t) 1000000ULL)
#define USEC_PER_MSEC ((usec_t) 1000ULL)
#define NSEC_PER_SEC  ((nsec_t) 1000000000ULL)
#define NSEC_PER_MSEC ((nsec_t) 1000000ULL)
#define NSEC_PER_USEC ((nsec_t) 1000ULL)

#define USEC_PER_MINUTE ((usec_t) (60ULL*USEC_PER_SEC))
#define NSEC_PER_MINUTE ((nsec_t) (60ULL*NSEC_PER_SEC))
#define USEC_PER_HOUR ((usec_t) (60ULL*USEC_PER_MINUTE))
#define NSEC_PER_HOUR ((nsec_t) (60ULL*NSEC_PER_MINUTE))
#define USEC_PER_DAY ((usec_t) (24ULL*USEC_PER_HOUR))
#define NSEC_PER_DAY ((nsec_t) (24ULL*NSEC_PER_HOUR))
#define USEC_PER_WEEK ((usec_t) (7ULL*USEC_PER_DAY))
#define NSEC_PER_WEEK ((nsec_t) (7ULL*NSEC_PER_DAY))
#define USEC_PER_MONTH ((usec_t) (2629800ULL*USEC_PER_SEC))
#define NSEC_PER_MONTH ((nsec_t) (2629800ULL*NSEC_PER_SEC))
#define USEC_PER_YEAR ((usec_t) (31557600ULL*USEC_PER_SEC))
#define NSEC_PER_YEAR ((nsec_t) (31557600ULL*NSEC_PER_SEC))

/* We assume a maximum timezone length of 6. TZNAME_MAX is not defined on Linux, but glibc internally initializes this
 * to 6. Let's rely on that. */
#define FORMAT_TIMESTAMP_MAX (3+1+10+1+8+1+6+1+6+1)
#define FORMAT_TIMESTAMP_WIDTH 28 /* when outputting, assume this width */
#define FORMAT_TIMESTAMP_RELATIVE_MAX 256
#define FORMAT_TIMESPAN_MAX 64

#define TIME_T_MAX (time_t)((UINTMAX_C(1) << ((sizeof(time_t) << 3) - 1)) - 1)

#define DUAL_TIMESTAMP_NULL ((struct dual_timestamp) {})
#define TRIPLE_TIMESTAMP_NULL ((struct triple_timestamp) {})

usec_t now(clockid_t clock);
nsec_t now_nsec(clockid_t clock);

dual_timestamp* dual_timestamp_get(dual_timestamp *ts);
dual_timestamp* dual_timestamp_from_realtime(dual_timestamp *ts, usec_t u);
dual_timestamp* dual_timestamp_from_monotonic(dual_timestamp *ts, usec_t u);
dual_timestamp* dual_timestamp_from_boottime_or_monotonic(dual_timestamp *ts, usec_t u);

triple_timestamp* triple_timestamp_get(triple_timestamp *ts);
triple_timestamp* triple_timestamp_from_realtime(triple_timestamp *ts, usec_t u);

#define DUAL_TIMESTAMP_HAS_CLOCK(clock)                               \
        IN_SET(clock, CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC)

#define TRIPLE_TIMESTAMP_HAS_CLOCK(clock)                               \
        IN_SET(clock, CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM)

static inline bool dual_timestamp_is_set(const dual_timestamp *ts) {
        return ((ts->realtime > 0 && ts->realtime != USEC_INFINITY) ||
                (ts->monotonic > 0 && ts->monotonic != USEC_INFINITY));
}

static inline bool triple_timestamp_is_set(const triple_timestamp *ts) {
        return ((ts->realtime > 0 && ts->realtime != USEC_INFINITY) ||
                (ts->monotonic > 0 && ts->monotonic != USEC_INFINITY) ||
                (ts->boottime > 0 && ts->boottime != USEC_INFINITY));
}

usec_t triple_timestamp_by_clock(triple_timestamp *ts, clockid_t clock);

usec_t timespec_load(const struct timespec *ts) _pure_;
nsec_t timespec_load_nsec(const struct timespec *ts) _pure_;
struct timespec *timespec_store(struct timespec *ts, usec_t u);

usec_t timeval_load(const struct timeval *tv) _pure_;
struct timeval *timeval_store(struct timeval *tv, usec_t u);

char *format_timestamp(char *buf, size_t l, usec_t t);
char *format_timestamp_utc(char *buf, size_t l, usec_t t);
char *format_timestamp_us(char *buf, size_t l, usec_t t);
char *format_timestamp_us_utc(char *buf, size_t l, usec_t t);
char *format_timestamp_relative(char *buf, size_t l, usec_t t);
char *format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy);

void dual_timestamp_serialize(FILE *f, const char *name, dual_timestamp *t);
int dual_timestamp_deserialize(const char *value, dual_timestamp *t);
int timestamp_deserialize(const char *value, usec_t *timestamp);

int parse_timestamp(const char *t, usec_t *usec);

int parse_sec(const char *t, usec_t *usec);
int parse_sec_fix_0(const char *t, usec_t *usec);
int parse_time(const char *t, usec_t *usec, usec_t default_unit);
int parse_nsec(const char *t, nsec_t *nsec);

bool ntp_synced(void);

int get_timezones(char ***l);
bool timezone_is_valid(const char *name, int log_level);

bool clock_boottime_supported(void);
bool clock_supported(clockid_t clock);
clockid_t clock_boottime_or_monotonic(void);

usec_t usec_shift_clock(usec_t, clockid_t from, clockid_t to);

int get_timezone(char **timezone);

time_t mktime_or_timegm(struct tm *tm, bool utc);
struct tm *localtime_or_gmtime_r(const time_t *t, struct tm *tm, bool utc);

unsigned long usec_to_jiffies(usec_t usec);

bool in_utc_timezone(void);

static inline usec_t usec_add(usec_t a, usec_t b) {
        usec_t c;

        /* Adds two time values, and makes sure USEC_INFINITY as input results as USEC_INFINITY in output, and doesn't
         * overflow. */

        c = a + b;
        if (c < a || c < b) /* overflow check */
                return USEC_INFINITY;

        return c;
}

static inline usec_t usec_sub_unsigned(usec_t timestamp, usec_t delta) {

        if (timestamp == USEC_INFINITY) /* Make sure infinity doesn't degrade */
                return USEC_INFINITY;
        if (timestamp < delta)
                return 0;

        return timestamp - delta;
}

static inline usec_t usec_sub_signed(usec_t timestamp, int64_t delta) {
        if (delta < 0)
                return usec_add(timestamp, (usec_t) (-delta));
        else
                return usec_sub_unsigned(timestamp, (usec_t) delta);
}

#if SIZEOF_TIME_T == 8
/* The last second we can format is 31. Dec 9999, 1s before midnight, because otherwise we'd enter 5 digit year
 * territory. However, since we want to stay away from this in all timezones we take one day off. */
#define USEC_TIMESTAMP_FORMATTABLE_MAX ((usec_t) 253402214399000000)
#elif SIZEOF_TIME_T == 4
/* With a 32bit time_t we can't go beyond 2038... */
#define USEC_TIMESTAMP_FORMATTABLE_MAX ((usec_t) 2147483647000000)
#else
#error "Yuck, time_t is neither 4 nor 8 bytes wide?"
#endif

int time_change_fd(void);
