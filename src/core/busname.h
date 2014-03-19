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

typedef enum BusNameState {
        BUSNAME_DEAD,
        BUSNAME_REGISTERED,
        BUSNAME_LISTENING,
        BUSNAME_RUNNING,
        BUSNAME_FAILED,
        _BUSNAME_STATE_MAX,
        _BUSNAME_STATE_INVALID = -1
} BusNameState;

typedef enum BusNameResult {
        BUSNAME_SUCCESS,
        BUSNAME_FAILURE_RESOURCES,
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

        sd_event_source *event_source;

        LIST_HEAD(BusNamePolicy, policy);
};

typedef enum BusNamePolicyType {
        BUSNAME_POLICY_TYPE_USER,
        BUSNAME_POLICY_TYPE_GROUP,
        BUSNAME_POLICY_TYPE_WORLD,
        _BUSNAME_POLICY_TYPE_MAX,
        _BUSNAME_POLICY_TYPE_INVALID = -1
} BusNamePolicyType;

typedef enum BusNamePolicyAccess {
        BUSNAME_POLICY_ACCESS_SEE,
        BUSNAME_POLICY_ACCESS_TALK,
        BUSNAME_POLICY_ACCESS_OWN,
        _BUSNAME_POLICY_ACCESS_MAX,
        _BUSNAME_POLICY_ACCESS_INVALID = -1
} BusNamePolicyAccess;

struct BusNamePolicy {
        BusNamePolicyType type;
        BusNamePolicyAccess access;

        union {
                uid_t uid;
                gid_t gid;
        };

        LIST_FIELDS(BusNamePolicy, policy);
};

extern const UnitVTable busname_vtable;

const char* busname_state_to_string(BusNameState i) _const_;
BusNameState busname_state_from_string(const char *s) _pure_;

const char* busname_result_to_string(BusNameResult i) _const_;
BusNameResult busname_result_from_string(const char *s) _pure_;

const char* busname_policy_access_to_string(BusNamePolicyAccess i) _const_;
BusNamePolicyAccess busname_policy_access_from_string(const char *s) _pure_;
