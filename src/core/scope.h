/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Scope Scope;

#include "cgroup.h"
#include "kill.h"
#include "unit.h"

typedef enum ScopeResult {
        SCOPE_SUCCESS,
        SCOPE_FAILURE_RESOURCES,
        SCOPE_FAILURE_TIMEOUT,
        SCOPE_FAILURE_OOM_KILL,
        _SCOPE_RESULT_MAX,
        _SCOPE_RESULT_INVALID = -EINVAL,
} ScopeResult;

struct Scope {
        Unit meta;

        CGroupContext cgroup_context;
        KillContext kill_context;

        ScopeState state, deserialized_state;
        ScopeResult result;

        usec_t runtime_max_usec;
        usec_t runtime_rand_extra_usec;
        usec_t timeout_stop_usec;

        char *controller;
        sd_bus_track *controller_track;

        bool was_abandoned;

        sd_event_source *timer_event_source;

        char *user;
        char *group;

        OOMPolicy oom_policy;
};

extern const UnitVTable scope_vtable;

int scope_abandon(Scope *s);

const char* scope_result_to_string(ScopeResult i) _const_;
ScopeResult scope_result_from_string(const char *s) _pure_;

DEFINE_CAST(SCOPE, Scope);
