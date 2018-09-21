/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* A structure for specifying (possibly repetitive) points in calendar
 * time, a la cron */

#include <stdbool.h>

#include "time-util.h"
#include "util.h"

typedef struct CalendarComponent {
        int start;
        int stop;
        int repeat;

        struct CalendarComponent *next;
} CalendarComponent;

typedef struct CalendarSpec {
        int weekdays_bits;
        bool end_of_month;
        bool utc;
        int dst;
        char *timezone;

        CalendarComponent *year;
        CalendarComponent *month;
        CalendarComponent *day;

        CalendarComponent *hour;
        CalendarComponent *minute;
        CalendarComponent *microsecond;
} CalendarSpec;

CalendarSpec* calendar_spec_free(CalendarSpec *c);

int calendar_spec_normalize(CalendarSpec *spec);
bool calendar_spec_valid(CalendarSpec *spec);

int calendar_spec_to_string(const CalendarSpec *spec, char **p);
int calendar_spec_from_string(const char *p, CalendarSpec **spec);

int calendar_spec_next_usec(const CalendarSpec *spec, usec_t usec, usec_t *next);

DEFINE_TRIVIAL_CLEANUP_FUNC(CalendarSpec*, calendar_spec_free);
