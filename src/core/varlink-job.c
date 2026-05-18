/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "bus-polkit.h"
#include "job.h"
#include "json-util.h"
#include "locale-util.h"
#include "manager.h"
#include "selinux-access.h"
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

static int varlink_error_no_such_job(sd_varlink *link, const char *name) {
        return sd_varlink_errorbo(
                        ASSERT_PTR(link),
                        VARLINK_ERROR_JOB_NO_SUCH_JOB,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("parameter", name));
}

static int list_job_one(sd_varlink *link, Job *job) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(job);

        r = job_build_json(&v, /* name= */ NULL, job);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int list_job_one_with_selinux_access_check(sd_varlink *link, Job *job) {
        int r;

        assert(link);
        assert(job);
        assert(job->unit);

        r = mac_selinux_unit_access_check_varlink(job->unit, link, "status");
        if (r < 0)
                /* If mac_selinux_unit_access_check_varlink() returned an error,
                 * it means that SELinux enforce is on. It also does all the logging(). */
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        return list_job_one(link, job);
}

typedef struct JobLookupParameters {
        uint32_t id;
        const char *unit;
} JobLookupParameters;

static int lookup_job_by_parameters(
                sd_varlink *link,
                Manager *manager,
                JobLookupParameters *p,
                Job **ret) {

        /* The function can return ret=NULL if no lookup parameters provided */
        Job *job = NULL;

        assert(link);
        assert(manager);
        assert(p);
        assert(ret);

        if (p->id > 0) {
                job = manager_get_job(manager, p->id);
                if (!job)
                        return varlink_error_no_such_job(link, "id");
        }

        if (p->unit) {
                Unit *u = manager_get_unit(manager, p->unit);
                if (!u || !u->job)
                        return varlink_error_no_such_job(link, "unit");
                if (job && u->job != job) {
                        log_debug("Job lookup by parameters id=%u unit='%s' resulted in different jobs.", p->id, p->unit);
                        return varlink_error_no_such_job(link, /* name= */ NULL);
                }

                job = u->job;
        }

        *ret = job;
        return !!job;
}

int vl_method_list_jobs(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",   _SD_JSON_VARIANT_TYPE_INVALID,  json_dispatch_job_id,          offsetof(JobLookupParameters, id),   0 },
                { "unit", SD_JSON_VARIANT_STRING,         json_dispatch_const_unit_name, offsetof(JobLookupParameters, unit), 0 },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        JobLookupParameters p = {};
        Job *job;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = lookup_job_by_parameters(link, manager, &p, &job);
        if (r < 0)
                return r;
        if (r > 0)
                return list_job_one_with_selinux_access_check(link, job);

        /* List all jobs */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = sd_varlink_set_sentinel(link, VARLINK_ERROR_JOB_NO_SUCH_JOB);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(job, manager->jobs) {
                r = mac_selinux_unit_access_check_varlink(job->unit, link, "status");
                if (r < 0)
                        continue;

                r = list_job_one(link, job);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vl_method_cancel_job(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "id", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_job_id, 0, SD_JSON_MANDATORY },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        uint32_t id = 0;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &id);
        if (r != 0)
                return r;

        Job *j = manager_get_job(manager, id);
        if (!j)
                return varlink_error_no_such_job(link, "id");

        r = mac_selinux_unit_access_check_varlink(j->unit, link, "stop");
        if (r < 0)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.manage-units",
                        (const char**) STRV_MAKE(
                                        "unit", j->unit ? j->unit->id : NULL,
                                        "verb", "cancel",
                                        "polkit.message", N_("Authentication is required to cancel job for unit '$(unit)'."),
                                        "polkit.gettext_domain", GETTEXT_PACKAGE),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        job_finish_and_invalidate(j, JOB_CANCELED, /* recursive= */ true, /* already= */ false);

        return sd_varlink_reply(link, NULL);
}

int vl_method_clear_all_jobs(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = mac_selinux_access_check_varlink(link, "reload");
        if (r < 0)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.manage-units",
                        (const char**) STRV_MAKE(
                                        "verb", "clear-jobs",
                                        "polkit.message", N_("Authentication is required to clear all pending jobs."),
                                        "polkit.gettext_domain", GETTEXT_PACKAGE),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        manager_clear_jobs(manager);

        return sd_varlink_reply(link, NULL);
}
