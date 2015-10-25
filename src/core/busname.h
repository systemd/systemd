/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

typedef struct BusName BusName;
typedef struct BusNamePolicy BusNamePolicy;

#include "unit.h"

typedef enum BusNameResult {
        BUSNAME_SUCCESS,
        BUSNAME_FAILURE_RESOURCES,
        BUSNAME_FAILURE_TIMEOUT,
        BUSNAME_FAILURE_EXIT_CODE,
        BUSNAME_FAILURE_SIGNAL,
        BUSNAME_FAILURE_CORE_DUMP,
        BUSNAME_FAILURE_SERVICE_FAILED_PERMANENT,
        _BUSNAME_RESULT_MAX,
        _BUSNAME_RESULT_INVALID = -1
} BusNameResult;

struct BusName {
        Unit meta;

        char *name;
        int starter_fd;

        bool activating;
        bool accept_fd;

        UnitRef service;

        BusNameState state, deserialized_state;
        BusNameResult result;

        usec_t timeout_usec;

        sd_event_source *starter_event_source;
        sd_event_source *timer_event_source;

        pid_t control_pid;

        LIST_HEAD(BusNamePolicy, policy);
        BusPolicyAccess policy_world;
};

extern const UnitVTable busname_vtable;

const char* busname_result_to_string(BusNameResult i) _const_;
BusNameResult busname_result_from_string(const char *s) _pure_;
