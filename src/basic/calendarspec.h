/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

/* A structure for specifying (possibly repetitive) points in calendar
 * time, a la cron */

#include <stdbool.h>
#include "util.h"

typedef struct CalendarComponent {
        int value;
        int repeat;

        struct CalendarComponent *next;
} CalendarComponent;

typedef struct CalendarSpec {
        int weekdays_bits;

        CalendarComponent *year;
        CalendarComponent *month;
        CalendarComponent *day;

        CalendarComponent *hour;
        CalendarComponent *minute;
        CalendarComponent *second;
} CalendarSpec;

void calendar_spec_free(CalendarSpec *c);

int calendar_spec_normalize(CalendarSpec *spec);
bool calendar_spec_valid(CalendarSpec *spec);

int calendar_spec_to_string(const CalendarSpec *spec, char **p);
int calendar_spec_from_string(const char *p, CalendarSpec **spec);

int calendar_spec_next_usec(const CalendarSpec *spec, usec_t usec, usec_t *next);
