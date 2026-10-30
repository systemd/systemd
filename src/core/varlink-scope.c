/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "json-util.h"
#include "pidref.h"
#include "scope.h"
#include "unit.h"
#include "varlink-common.h"
#include "varlink-scope.h"
#include "varlink-util.h"

/* Read side of the Scope context and runtime for List. */

int scope_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Scope *s = ASSERT_PTR(SCOPE(userdata));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_ENUM("OOMPolicy", oom_policy_to_string(s->oom_policy)),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RuntimeMaxUSec", s->runtime_max_usec),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RuntimeRandomizedExtraUSec", s->runtime_rand_extra_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutStopUSec", s->timeout_stop_usec));
}

int scope_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Scope *s = ASSERT_PTR(SCOPE(userdata));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_ENUM("Result", scope_result_to_string(s->result)));
}

/* Write side of the Scope context for StartTransient. */

struct TransientScopeParameters {
        OOMPolicy oom_policy;
        usec_t runtime_max_usec;
        bool runtime_max_usec_set;
        usec_t runtime_rand_extra_usec;
        bool runtime_rand_extra_usec_set;
        usec_t timeout_stop_usec;
        bool timeout_stop_usec_set;
        sd_json_variant *pids;

        char *bad_field; /* Field path for error propagation. */
};

static JSON_DISPATCH_ENUM_DEFINE(dispatch_oom_policy, OOMPolicy, oom_policy_from_string);
static DEFINE_VARLINK_APPLY_ENUM(oom_policy, OOMPolicy, oom_policy_to_string);

TransientScopeParameters* transient_scope_parameters_free(TransientScopeParameters *p) {
        if (!p)
                return NULL;

        p->pids = sd_json_variant_unref(p->pids);
        free(p->bad_field);
        return mfree(p);
}

static DEFINE_VARLINK_DISPATCH_SETTABLE(runtime_max_usec,        TransientScopeParameters, sd_json_dispatch_uint64);
static DEFINE_VARLINK_DISPATCH_SETTABLE(runtime_rand_extra_usec, TransientScopeParameters, sd_json_dispatch_uint64);
static DEFINE_VARLINK_DISPATCH_SETTABLE(timeout_stop_usec,       TransientScopeParameters, sd_json_dispatch_uint64);

DEFINE_TRIVIAL_CLEANUP_FUNC(TransientScopeParameters*, transient_scope_parameters_free);

int transient_scope_dispatch(
                sd_json_variant *variant,
                TransientScopeParameters **ret,
                char **reterr_bad_field) {

        static const sd_json_dispatch_field scope_dispatch[] = {
                { "OOMPolicy",                  SD_JSON_VARIANT_STRING,        dispatch_oom_policy,                               offsetof(TransientScopeParameters, oom_policy), 0                },
                { "RuntimeMaxUSec",             _SD_JSON_VARIANT_TYPE_INVALID, varlink_dispatch_settable_runtime_max_usec,        0,                                              SD_JSON_NULLABLE },
                { "RuntimeRandomizedExtraUSec", _SD_JSON_VARIANT_TYPE_INVALID, varlink_dispatch_settable_runtime_rand_extra_usec, 0,                                              SD_JSON_NULLABLE },
                { "TimeoutStopUSec",            _SD_JSON_VARIANT_TYPE_INVALID, varlink_dispatch_settable_timeout_stop_usec,       0,                                              SD_JSON_NULLABLE },
                { "PIDs",                       SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant,                          offsetof(TransientScopeParameters, pids),       0                },
                {}
        };

        const char *bad_field = NULL;
        int r;

        assert(ret);

        _cleanup_(transient_scope_parameters_freep) TransientScopeParameters *p = NULL;
        p = new(TransientScopeParameters, 1);
        if (!p)
                return -ENOMEM;

        *p = (TransientScopeParameters) {
                .oom_policy = _OOM_POLICY_INVALID,
        };

        r = sd_json_dispatch_full(variant, scope_dispatch, /* bad= */ NULL, /* flags= */ 0, p, &bad_field);
        if (r < 0) {
                if (bad_field)
                        varlink_propagate_bad_field(bad_field, p->bad_field, reterr_bad_field);
                return r;
        }

        *ret = TAKE_PTR(p);
        return r;
}

static int transient_scope_apply_pid(Scope *s, sd_json_variant *json, sd_varlink *link, sd_bus_error *reterr_bus_error) {
        Unit *u = UNIT(ASSERT_PTR(s));
        int r;

        _cleanup_(pidref_done) PidRef json_pidref = PIDREF_NULL;
        r = json_dispatch_pidref("Scope.PIDs", json, SD_JSON_STRICT|SD_JSON_RELAX, &json_pidref);
        if (r < 0)
                return sd_bus_error_set_errno(reterr_bus_error, r);

        _cleanup_(pidref_done) PidRef peer_pidref = PIDREF_NULL;
        PidRef *pidref;
        if (pidref_is_automatic(&json_pidref)) {
                r = varlink_get_peer_pidref(link, &peer_pidref);
                if (r < 0)
                        return r;

                pidref = &peer_pidref;
        } else
                pidref = &json_pidref;

        r = unit_pid_attachable(u, pidref, reterr_bus_error);
        if (r < 0)
                return r;

        r = unit_watch_pidref(u, pidref, /* exclusive= */ false);
        if (r < 0)
                return r;

        return 0;
}

int transient_scope_apply_properties(
                Scope *s,
                TransientScopeParameters *sp,
                sd_varlink *link,
                char **reterr_bad_field,
                sd_bus_error *reterr_bus_error) {

        Unit *u = UNIT(ASSERT_PTR(s));
        int r = -EINVAL; /* Scope.PIDs is required! */

        if (sp) {
                varlink_apply_enum_oom_policy(u, "OOMPolicy", &s->oom_policy, sp->oom_policy,
                                              /* refuse= */ NULL, UNIT_RUNTIME|UNIT_PRIVATE);
                if (sp->runtime_max_usec_set)
                        varlink_apply_usec_per_msec(u, "RuntimeMaxSec", &s->runtime_max_usec, sp->runtime_max_usec, UNIT_RUNTIME|UNIT_PRIVATE);
                if (sp->runtime_rand_extra_usec_set)
                        varlink_apply_usec_per_msec(u, "RuntimeRandomizedExtraSec", &s->runtime_rand_extra_usec, sp->runtime_rand_extra_usec, UNIT_RUNTIME|UNIT_PRIVATE);
                if (sp->timeout_stop_usec_set)
                        varlink_apply_usec_per_msec(u, "TimeoutStopSec", &s->timeout_stop_usec, sp->timeout_stop_usec, UNIT_RUNTIME|UNIT_PRIVATE);

                sd_json_variant *json_pid = NULL;
                JSON_VARIANT_ARRAY_FOREACH(json_pid, sp->pids) {
                        r = transient_scope_apply_pid(s, json_pid, link, reterr_bus_error);
                        if (r < 0)
                                break;
                }
        }

        if (r < 0)
                return varlink_propagate_bad_field_errno(r, "PIDs", /* child_bad_field= */ NULL, reterr_bad_field);

        return 0;
}
