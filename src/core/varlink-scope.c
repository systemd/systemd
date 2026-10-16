/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "json-util.h"
#include "pidref.h"
#include "scope.h"
#include "string-util.h"
#include "time-util.h"
#include "unit.h"
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

typedef struct TransientUSec {
        usec_t value;
        bool present;
} TransientUSec;

struct TransientScopeParameters {
        OOMPolicy oom_policy;
        TransientUSec runtime_max_usec;
        TransientUSec runtime_rand_extra_usec;
        TransientUSec timeout_stop_usec;
        sd_json_variant *pids;
};

static JSON_DISPATCH_ENUM_DEFINE(dispatch_oom_policy, OOMPolicy, oom_policy_from_string);

TransientScopeParameters* transient_scope_parameters_free(TransientScopeParameters *p) {
        if (!p)
                return NULL;

        p->pids = sd_json_variant_unref(p->pids);
        return mfree(p);
}

static int dispatch_transient_usec(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        TransientUSec *t = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_is_null(variant)) {
                t->present = false;
                return 0;
        }

        r = sd_json_dispatch_uint64(name, variant, flags, &t->value);
        if (r < 0)
                return r;

        t->present = true;
        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(TransientScopeParameters*, transient_scope_parameters_free);

int transient_scope_dispatch(
                sd_json_variant *variant,
                TransientScopeParameters **ret,
                const char **reterr_field) {

        static const sd_json_dispatch_field scope_dispatch[] = {
                { "OOMPolicy",                  SD_JSON_VARIANT_STRING,        dispatch_oom_policy,      offsetof(TransientScopeParameters, oom_policy),              0 },
                { "RuntimeMaxUSec",             _SD_JSON_VARIANT_TYPE_INVALID, dispatch_transient_usec,  offsetof(TransientScopeParameters, runtime_max_usec),        0 },
                { "RuntimeRandomizedExtraUSec", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_transient_usec,  offsetof(TransientScopeParameters, runtime_rand_extra_usec), 0 },
                { "TimeoutStopUSec",            _SD_JSON_VARIANT_TYPE_INVALID, dispatch_transient_usec,  offsetof(TransientScopeParameters, timeout_stop_usec),       0 },
                { "PIDs",                       SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant, offsetof(TransientScopeParameters, pids),                    0 },
                {}
        };

        int r;

        assert(ret);

        _cleanup_(transient_scope_parameters_freep) TransientScopeParameters *p = NULL;
        p = new(TransientScopeParameters, 1);
        if (!p)
                return -ENOMEM;

        *p = (TransientScopeParameters) {
                .oom_policy = _OOM_POLICY_INVALID,
        };

        r = sd_json_dispatch_full(variant, scope_dispatch, /* bad= */ NULL, /* flags= */ 0, p, reterr_field);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(p);
        return r;
}

static void transient_unit_apply_usec(Unit *u, const char *name, usec_t *p, UnitWriteFlags flags, TransientUSec *v) {
        assert(u);
        assert(name);
        assert(p);
        assert(v);

        if (!v->present)
                return;

        *p = v->value;

        const char *e = ASSERT_PTR(endswith(name, "USec"));
        char *n = strndupa_safe(name, e - name);
        const char *f = FORMAT_TIMESPAN(v->value, USEC_PER_MSEC);
        unit_write_settingf(u, UNIT_RUNTIME|flags, name, "%sSec=%s", n, f);
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
                const char **reterr_field,
                sd_bus_error *reterr_bus_error) {

        Unit *u = UNIT(ASSERT_PTR(s));
        int r = -EINVAL; /* Scope.PIDs is required! */

        if (sp) {
                if (sp->oom_policy != _OOM_POLICY_INVALID) {
                        s->oom_policy = sp->oom_policy;
                        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "OOMPolicy", "OOMPolicy=%s", oom_policy_to_string(sp->oom_policy));
                }

                transient_unit_apply_usec(u, "RuntimeMaxUSec", &s->runtime_max_usec, UNIT_PRIVATE, &sp->runtime_max_usec);
                transient_unit_apply_usec(u, "RuntimeRandomizedExtraUSec", &s->runtime_rand_extra_usec, UNIT_PRIVATE, &sp->runtime_rand_extra_usec);
                transient_unit_apply_usec(u, "TimeoutStopUSec", &s->timeout_stop_usec, UNIT_PRIVATE, &sp->timeout_stop_usec);

                sd_json_variant *json_pid = NULL;
                JSON_VARIANT_ARRAY_FOREACH(json_pid, sp->pids) {
                        r = transient_scope_apply_pid(s, json_pid, link, reterr_bus_error);
                        if (r < 0)
                                break;
                }
        }

        if (r < 0) {
                if (reterr_field)
                        *reterr_field = "Scope.PIDs";
                return r;
        }

        return 0;
}
