/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "glob-util.h"
#include "hashmap.h"
#include "job.h"
#include "json-util.h"
#include "locale-util.h"
#include "manager.h"
#include "selinux-access.h"
#include "strv.h"
#include "unit.h"
#include "unit-name.h"
#include "varlink-common.h"
#include "varlink-job.h"

DEFINE_PRIVATE_HASH_OPS_FULL(
                job_subscriber_hash_ops,
                void, trivial_hash_func, trivial_compare_func, sd_varlink_unref,
                char*, strv_free);

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

        /* A job removed without ever completing (e.g. because its unit is unloaded) has no result. Report
         * it as canceled, so that a finished job always carries one. */
        JobResult result = j->result;
        if (j->state == JOB_FINISHED && result < 0)
                result = JOB_CANCELED;

        /* "Unit" is omitted in StartTransient streaming notifications where the caller already knows the unit. */
        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_INTEGER("Id", j->id),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Unit", j->unit ? j->unit->id : NULL),
                        JSON_BUILD_PAIR_ENUM("JobType", job_type_to_string(j->type)),
                        JSON_BUILD_PAIR_ENUM("State", job_state_to_string(j->state)),
                        JSON_BUILD_PAIR_ENUM_NON_EMPTY("Result", job_result_to_string(result)),
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
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

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
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, /* parameters= */ NULL);

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
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        const UnitPolkitDetails details = {
                .unit = j->unit,
                .verb = "cancel",
                .message = N_("Authentication is required to cancel job for unit '$(unit)'."),
        };
        r = varlink_verify_manage_units_async(link, manager, &details);
        if (r <= 0)
                return r;

        job_finish_and_invalidate(j, JOB_CANCELED, /* recursive= */ true, /* already= */ false);

        return sd_varlink_reply(link, /* parameters= */ NULL);
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
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        const UnitPolkitDetails details = {
                .verb = "clear-jobs",
                .message = N_("Authentication is required to clear all pending jobs."),
        };
        r = varlink_verify_manage_units_async(link, manager, &details);
        if (r <= 0)
                return r;

        manager_clear_jobs(manager);

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

bool varlink_job_unsubscribe(Manager *m, sd_varlink *link) {
        char **units;

        assert(m);
        assert(link);

        units = hashmap_remove(m->varlink_job_subscribers, link);
        if (!units)
                return false;

        strv_free(units);
        sd_varlink_unref(link);
        return true;
}

static bool job_subscriber_wants(sd_varlink *link, char **units, Job *j) {
        assert(link);
        assert(j);
        assert(j->unit);

        if (!strv_fnmatch_or_empty(units, j->unit->id, FNM_NOESCAPE))
                return false;

        /* Silently skip the jobs the subscriber may not see, as List does */
        return mac_selinux_unit_access_check_varlink(j->unit, link, "status") >= 0;
}

void varlink_job_notify_subscribers(Job *j) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Manager *m;
        sd_varlink *link;
        char **units;
        int r;

        assert(j);
        m = ASSERT_PTR(j->manager);

        HASHMAP_FOREACH_KEY(units, link, m->varlink_job_subscribers) {
                if (!job_subscriber_wants(link, units, j))
                        continue;

                /* Build the notification only once, all subscribers share it */
                if (!v) {
                        r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_CALLBACK("job", job_build_json, j));
                        if (r < 0) {
                                log_debug_errno(r, "Failed to build job notification, ignoring: %m");
                                return;
                        }
                }

                r = sd_varlink_notify(link, v);
                if (r < 0) {
                        /* The subscriber does not read (-ENOBUFS) or is gone. Do not queue more for it in
                         * PID 1. Unsubscribe before closing, so that vl_disconnect() finds nothing to drop.
                         * Removing the current entry while iterating is safe. */
                        log_debug_errno(r, "Failed to notify job subscriber, disconnecting: %m");

                        _cleanup_(sd_varlink_unrefp) sd_varlink *dead = sd_varlink_ref(link);
                        (void) varlink_job_unsubscribe(m, dead);
                        (void) sd_varlink_close(dead);
                }
        }
}

static int job_subscriber_send_queued(Manager *m, sd_varlink *link, char **units) {
        Job *j;
        int r;

        assert(m);
        assert(link);

        HASHMAP_FOREACH(j, m->jobs) {
                if (!job_subscriber_wants(link, units, j))
                        continue;

                r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_CALLBACK("job", job_build_json, j));
                if (r < 0)
                        return r;
        }

        return sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("ready", true));
}

int vl_method_subscribe_jobs(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "units", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_strv, 0, SD_JSON_NULLABLE },
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **units = NULL;
        int r;

        assert(link);
        assert(parameters);

        /* SD_VARLINK_REQUIRES_MORE in the IDL rejects calls without the 'more' flag before we get here */
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &units);
        if (r != 0)
                return r;

        STRV_FOREACH(u, units)
                if (!unit_name_is_valid(*u, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE) && !string_is_glob(*u))
                        return sd_varlink_error_invalid_parameter_name(link, "units");

        /* The map value says whether a link is subscribed, hence it is never NULL. An empty list matches
         * the jobs of all units. */
        if (!units) {
                units = new0(char*, 1);
                if (!units)
                        return -ENOMEM;
        }

        r = hashmap_ensure_put(&m->varlink_job_subscribers, &job_subscriber_hash_ops, link, units);
        if (r < 0)
                return r;

        sd_varlink_ref(link);
        char **filter = TAKE_PTR(units);

        /* Report the jobs that are queued already, then conclude with the ready notification. All of this
         * and the registration above happen in one dispatch, no job can change state in between. Hence a
         * client that has seen the ready notification does not miss the job of a unit it enqueues next. */
        r = job_subscriber_send_queued(m, link, filter);
        if (r < 0) {
                (void) varlink_job_unsubscribe(m, link);
                return r;
        }

        return 1;
}
