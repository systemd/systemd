/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

typedef enum TimestampStyle {
        TIMESTAMP_PRETTY,
        TIMESTAMP_US,
        TIMESTAMP_UTC,
        TIMESTAMP_US_UTC,
        TIMESTAMP_UNIX,
        TIMESTAMP_DATE,
        _TIMESTAMP_STYLE_MAX,
        _TIMESTAMP_STYLE_INVALID = -EINVAL,
} TimestampStyle;

#define USEC_INFINITY ((usec_t) UINT64_MAX)
#define NSEC_INFINITY ((nsec_t) UINT64_MAX)

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
#define FORMAT_TIMESTAMP_MAX (3U+1U+10U+1U+8U+1U+6U+1U+6U+1U)
#define FORMAT_TIMESTAMP_RELATIVE_MAX 256U
#define FORMAT_TIMESPAN_MAX 64U

#define TIME_T_MAX (time_t)((UINTMAX_C(1) << ((sizeof(time_t) << 3) - 1)) - 1)

#define DUAL_TIMESTAMP_NULL ((struct dual_timestamp) {})
#define TRIPLE_TIMESTAMP_NULL ((struct triple_timestamp) {})

usec_t now(clockid_t clock);
nsec_t now_nsec(clockid_t clock);

usec_t map_clock_usec(usec_t from, clockid_t from_clock, clockid_t to_clock);

dual_timestamp* dual_timestamp_now(dual_timestamp *ts);
dual_timestamp* dual_timestamp_from_realtime(dual_timestamp *ts, usec_t u);
dual_timestamp* dual_timestamp_from_monotonic(dual_timestamp *ts, usec_t u);
dual_timestamp* dual_timestamp_from_boottime(dual_timestamp *ts, usec_t u);

triple_timestamp* triple_timestamp_now(triple_timestamp *ts);
triple_timestamp* triple_timestamp_from_realtime(triple_timestamp *ts, usec_t u);
triple_timestamp* triple_timestamp_from_boottime(triple_timestamp *ts, usec_t u);

#define DUAL_TIMESTAMP_HAS_CLOCK(clock)                               \
        IN_SET(clock, CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC)

#define TRIPLE_TIMESTAMP_HAS_CLOCK(clock)                               \
        IN_SET(clock, CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM)

static inline bool timestamp_is_set(usec_t timestamp) {
        return timestamp > 0 && timestamp != USEC_INFINITY;
}

static inline bool dual_timestamp_is_set(const dual_timestamp *ts) {
        return timestamp_is_set(ts->realtime) ||
               timestamp_is_set(ts->monotonic);
}

static inline bool triple_timestamp_is_set(const triple_timestamp *ts) {
        return timestamp_is_set(ts->realtime) ||
               timestamp_is_set(ts->monotonic) ||
               timestamp_is_set(ts->boottime);
}

usec_t triple_timestamp_by_clock(triple_timestamp *ts, clockid_t clock);

usec_t timespec_load(const struct timespec *ts) _pure_;
nsec_t timespec_load_nsec(const struct timespec *ts) _pure_;
struct timespec* timespec_store(struct timespec *ts, usec_t u);
struct timespec* timespec_store_nsec(struct timespec *ts, nsec_t n);
#define TIMESPEC_STORE(u) timespec_store(&(struct timespec) {}, (u))

usec_t timeval_load(const struct timeval *tv) _pure_;
struct timeval* timeval_store(struct timeval *tv, usec_t u);

#define TIMEVAL_STORE(u) timeval_store(&(struct timeval) {}, (u))

char* format_timestamp_style(char *buf, size_t l, usec_t t, TimestampStyle style) _warn_unused_result_;
char* format_timestamp_relative_full(char *buf, size_t l, usec_t t, clockid_t clock, bool implicit_left) _warn_unused_result_;
char* format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy) _warn_unused_result_;

_warn_unused_result_
static inline char* format_timestamp_relative(char *buf, size_t l, usec_t t) {
        return format_timestamp_relative_full(buf, l, t, CLOCK_REALTIME, /* implicit_left = */ false);
}
_warn_unused_result_
static inline char* format_timestamp_relative_monotonic(char *buf, size_t l, usec_t t) {
        return format_timestamp_relative_full(buf, l, t, CLOCK_MONOTONIC, /* implicit_left = */ false);
}

_warn_unused_result_
static inline char* format_timestamp(char *buf, size_t l, usec_t t) {
        return format_timestamp_style(buf, l, t, TIMESTAMP_PRETTY);
}

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_TIMESTAMP(t) format_timestamp((char[FORMAT_TIMESTAMP_MAX]){}, FORMAT_TIMESTAMP_MAX, t)
#define FORMAT_TIMESTAMP_RELATIVE(t)                                    \
        format_timestamp_relative((char[FORMAT_TIMESTAMP_RELATIVE_MAX]){}, FORMAT_TIMESTAMP_RELATIVE_MAX, t)
#define FORMAT_TIMESTAMP_RELATIVE_MONOTONIC(t)                          \
        format_timestamp_relative_monotonic((char[FORMAT_TIMESTAMP_RELATIVE_MAX]){}, FORMAT_TIMESTAMP_RELATIVE_MAX, t)
#define FORMAT_TIMESPAN(t, accuracy) format_timespan((char[FORMAT_TIMESPAN_MAX]){}, FORMAT_TIMESPAN_MAX, t, accuracy)
#define FORMAT_TIMESTAMP_STYLE(t, style) \
        format_timestamp_style((char[FORMAT_TIMESTAMP_MAX]){}, FORMAT_TIMESTAMP_MAX, t, style)

int parse_timestamp(const char *t, usec_t *ret);

int parse_sec(const char *t, usec_t *ret);
int parse_sec_fix_0(const char *t, usec_t *ret);
int parse_sec_def_infinity(const char *t, usec_t *ret);
int parse_time(const char *t, usec_t *ret, usec_t default_unit);
int parse_nsec(const char *t, nsec_t *ret);

int get_timezones(char ***ret);
int verify_timezone(const char *name, int log_level);
static inline bool timezone_is_valid(const char *name, int log_level) {
        return verify_timezone(name, log_level) >= 0;
}

bool clock_supported(clockid_t clock);

usec_t usec_shift_clock(usec_t, clockid_t from, clockid_t to);

int get_timezone(char **ret);

time_t mktime_or_timegm(struct tm *tm, bool utc);
struct tm *localtime_or_gmtime_r(const time_t *t, struct tm *tm, bool utc);

uint32_t usec_to_jiffies(usec_t usec);
usec_t jiffies_to_usec(uint32_t jiffies);

bool in_utc_timezone(void);

static inline usec_t usec_add(usec_t a, usec_t b) {
        /* Adds two time values, and makes sure USEC_INFINITY as input results as USEC_INFINITY in output,
         * and doesn't overflow. */

        if (a > USEC_INFINITY - b) /* overflow check */
                return USEC_INFINITY;

        return a + b;
}

static inline usec_t usec_sub_unsigned(usec_t timestamp, usec_t delta) {
        if (timestamp == USEC_INFINITY) /* Make sure infinity doesn't degrade */
                return USEC_INFINITY;
        if (timestamp < delta)
                return 0;

        return timestamp - delta;
}

static inline usec_t usec_sub_signed(usec_t timestamp, int64_t delta) {
        if (delta == INT64_MIN) { /* prevent overflow */
                assert_cc(-(INT64_MIN + 1) == INT64_MAX);
                assert_cc(USEC_INFINITY > INT64_MAX);
                return usec_add(timestamp, (usec_t) INT64_MAX + 1);
        }
        if (delta < 0)
                return usec_add(timestamp, (usec_t) (-delta));

        return usec_sub_unsigned(timestamp, (usec_t) delta);
}

static inline int usleep_safe(usec_t usec) {
        /* usleep() takes useconds_t that is (typically?) uint32_t. Also, usleep() may only support the
         * range [0, 1000000]. See usleep(3). Let's override usleep() with clock_nanosleep().
         *
         * ⚠️ Note we are not using plain nanosleep() here, since that operates on CLOCK_REALTIME, not
         *    CLOCK_MONOTONIC! */

        if (usec == 0)
                return 0;

        // FIXME: use RET_NERRNO() macro here. Currently, this header cannot include errno-util.h.
        return clock_nanosleep(CLOCK_MONOTONIC, 0, TIMESPEC_STORE(usec), NULL) < 0 ? -errno : 0;
}

/* The last second we can format is 31. Dec 9999, 1s before midnight, because otherwise we'd enter 5 digit
 * year territory. However, since we want to stay away from this in all timezones we take one day off. */
#define USEC_TIMESTAMP_FORMATTABLE_MAX_64BIT ((usec_t) 253402214399000000) /* Thu 9999-12-30 23:59:59 UTC */
/* With a 32-bit time_t we can't go beyond 2038...
 * We parse timestamp with RFC-822/ISO 8601 (e.g. +06, or -03:00) as UTC, hence the upper bound must be off
 * by USEC_PER_DAY. See parse_timestamp() for more details. */
#define USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT (((usec_t) INT32_MAX) * USEC_PER_SEC - USEC_PER_DAY)
#if SIZEOF_TIME_T == 8
#  define USEC_TIMESTAMP_FORMATTABLE_MAX USEC_TIMESTAMP_FORMATTABLE_MAX_64BIT
#elif SIZEOF_TIME_T == 4
#  define USEC_TIMESTAMP_FORMATTABLE_MAX USEC_TIMESTAMP_FORMATTABLE_MAX_32BIT
#else
#  error "Yuck, time_t is neither 4 nor 8 bytes wide?"
#endif

int time_change_fd(void);

const char* timestamp_style_to_string(TimestampStyle t) _const_;
TimestampStyle timestamp_style_from_string(const char *s) _pure_;
