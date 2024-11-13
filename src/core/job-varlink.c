/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "job.h"
#include "job-varlink.h"
#include "json-util.h"
#include "manager.h"
#include "strv.h"
#include "varlink-io.systemd.Job.h"

static int activation_details_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_strv_free_ char **pairs = NULL;
        ActivationDetails *activation_details = userdata;
        int r;

        assert(ret);

        r = activation_details_append_pair(activation_details, &pairs);
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = sd_json_variant_set_field_string(&v, *key, *value);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int list_job_one(sd_varlink *link, Job *job, bool more) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(job);

        r = sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", job->id),
                        SD_JSON_BUILD_PAIR_STRING("unit", job->unit->id),
                        SD_JSON_BUILD_PAIR_STRING("jobType", job_type_to_string(job->type)),
                        SD_JSON_BUILD_PAIR_STRING("state", job_state_to_string(job->state)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("activationDetails", activation_details_build_json, job->activation_details));

        if (r < 0)
                return r;

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

int vl_method_list_jobs(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "id", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32, 0, 0 },
                {},
        };

        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        uint32_t id = 0;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &id);
        if (r != 0)
                return r;

        if (id > 0) {
                j = hashmap_get(m->jobs, UINT_TO_PTR(id));
                if (!j)
                        return sd_varlink_error(link, "io.systemd.Manager.NoSuchJob", NULL);

                return list_job_one(link, j, /* more = */ false);
        }

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        Job *previous = NULL;
        HASHMAP_FOREACH(j, m->jobs) {
                if (previous) {
                        r = list_job_one(link, previous, /* more = */ true);
                        if (r < 0)
                                return r;
                }

                previous = j;
        }

        if (previous)
                return list_job_one(link, previous, /* more = */ false);

        return sd_varlink_error(link, "io.systemd.Manager.NoSuchJob", NULL);
}
