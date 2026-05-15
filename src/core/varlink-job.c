/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "job.h"
#include "json-util.h"
#include "strv.h"
#include "unit.h"
#include "varlink-job.h"

static int activation_details_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_strv_free_ char **pairs = NULL;
        Job *j = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = activation_details_append_pair(j->activation_details, &pairs);
        if (r < 0)
                return log_debug_errno(r, "Failed to get activation details: %m");
        if (r == 0) {
                *ret = NULL;
                return 0;
        }

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = sd_json_variant_set_field_string(&v, *key, *value);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int job_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Job *j = ASSERT_PTR(userdata);

        /* "Unit" is omitted in StartTransient streaming notifications where the caller already knows the unit. */
        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_INTEGER("Id", j->id),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Unit", j->unit ? j->unit->id : NULL),
                        JSON_BUILD_PAIR_ENUM("JobType", job_type_to_string(j->type)),
                        JSON_BUILD_PAIR_ENUM("State", job_state_to_string(j->state)),
                        JSON_BUILD_PAIR_ENUM_NON_EMPTY("Result", job_result_to_string(j->result)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ActivationDetails", activation_details_build_json, j));
}
