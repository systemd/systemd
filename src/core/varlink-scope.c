/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "json-util.h"
#include "scope.h"
#include "varlink-scope.h"

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
