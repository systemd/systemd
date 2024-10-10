/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Timer Timer;
typedef struct ActivationDetailsTimer ActivationDetailsTimer;

#include "calendarspec.h"
#include "unit.h"

typedef enum TimerBase {
        TIMER_ACTIVE,
        TIMER_BOOT,
        TIMER_STARTUP,
        TIMER_UNIT_ACTIVE,
        TIMER_UNIT_INACTIVE,
        TIMER_CALENDAR,
        _TIMER_BASE_MAX,
        _TIMER_BASE_INVALID = -EINVAL,
} TimerBase;

typedef struct TimerValue {
        TimerBase base;
        bool disabled;

        usec_t value; /* only for monotonic events */
        CalendarSpec *calendar_spec; /* only for calendar events */
        usec_t next_elapse;

        LIST_FIELDS(struct TimerValue, value);
} TimerValue;

typedef enum TimerResult {
        TIMER_SUCCESS,
        TIMER_FAILURE_RESOURCES,
        TIMER_FAILURE_START_LIMIT_HIT,
        _TIMER_RESULT_MAX,
        _TIMER_RESULT_INVALID = -EINVAL,
} TimerResult;

struct Timer {
        Unit meta;

        usec_t accuracy_usec;
        usec_t random_usec;

        LIST_HEAD(TimerValue, values);
        usec_t next_elapse_realtime;
        usec_t next_elapse_monotonic_or_boottime;
        dual_timestamp last_trigger;

        TimerState state, deserialized_state;

        sd_event_source *monotonic_event_source;
        sd_event_source *realtime_event_source;

        TimerResult result;

        bool persistent;
        bool wake_system;
        bool remain_after_elapse;
        bool on_clock_change;
        bool on_timezone_change;
        bool fixed_random_delay;
        bool defer_reactivation;

        char *stamp_path;
};

struct ActivationDetailsTimer {
        ActivationDetails meta;
        dual_timestamp last_trigger;
};

#define TIMER_MONOTONIC_CLOCK(t) ((t)->wake_system ? CLOCK_BOOTTIME_ALARM : CLOCK_MONOTONIC)

uint64_t timer_next_elapse_monotonic(const Timer *t);

void timer_free_values(Timer *t);

extern const UnitVTable timer_vtable;
extern const ActivationDetailsVTable activation_details_timer_vtable;

const char* timer_base_to_string(TimerBase i) _const_;
TimerBase timer_base_from_string(const char *s) _pure_;

char* timer_base_to_usec_string(TimerBase i);

const char* timer_result_to_string(TimerResult i) _const_;
TimerResult timer_result_from_string(const char *s) _pure_;

DEFINE_CAST(TIMER, Timer);
DEFINE_ACTIVATION_DETAILS_CAST(ACTIVATION_DETAILS_TIMER, ActivationDetailsTimer, TIMER);
