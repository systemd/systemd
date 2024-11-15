/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "json-util.h"
#include "manager.h"
#include "set.h"
#include "strv.h"
#include "unit.h"
#include "unit-name.h"
#include "varlink-common.h"
#include "varlink-unit.h"
#include "varlink-util.h"

#define JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY(name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(value > EMERGENCY_ACTION_NONE, name, SD_JSON_BUILD_STRING(emergency_action_to_string(value)))

static int unit_dependencies_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata), *other;
        UnitDependency d;
        void *value;
        int r;

        assert(ret);
        assert(name);

        d = unit_dependency_from_string(name);
        if (d < 0)
                return log_debug_errno(d, "Failed to get unit dependency for '%s': %m", name);

        HASHMAP_FOREACH_KEY(value, other, unit_get_dependencies(u, d)) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(other->id));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_mounts_for_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Hashmap **mounts_for = userdata;
        UnitMountDependencyType d;
        const char *p;
        void *value;
        int r;

        assert(ret);
        assert(name);

        if (!mounts_for)
                return 0;

        d = unit_mount_dependency_type_from_string(name);
        if (d < 0)
                return log_debug_errno(d, "Failed to get unit mount dependency for '%s': %m", name);

        HASHMAP_FOREACH_KEY(value, p, mounts_for[d]) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(p));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_conditions_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        bool do_asserts = streq(name, "Asserts");
        Condition *list = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(conditions, c, list) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("type", do_asserts ? assert_type_to_string(c->type)
                                                                             : condition_type_to_string(c->type)),
                                SD_JSON_BUILD_PAIR_BOOLEAN("trigger", c->trigger),
                                SD_JSON_BUILD_PAIR_BOOLEAN("negate", c->negate),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("parameter", c->parameter));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("Type", unit_type_to_string(u->type)),
                        SD_JSON_BUILD_PAIR_STRING("ID", u->id),
                        SD_JSON_BUILD_PAIR_CONDITION(!set_isempty(u->aliases), "Names", JSON_BUILD_STRING_SET(u->aliases)),

                        /* [Unit] Section Options
                         * https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#%5BUnit%5D%20Section%20Options */
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Description", u->description),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Documentation", u->documentation),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Wants", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WantedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Requires", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequiredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Requisite", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequisiteOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BindsTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BoundBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PartOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConsistsOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Upholds", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("UpheldBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Conflicts", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConflictedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Before", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("After", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnFailure", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnFailureOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnSuccess", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnSuccessOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PropagatesReloadTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ReloadPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PropagatesStopTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StopPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("JoinsNamespaceOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequiresMountsFor", unit_mounts_for_build_json, &u->mounts_for),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WantsMountsFor", unit_mounts_for_build_json, &u->mounts_for),
                        SD_JSON_BUILD_PAIR_STRING("OnSuccessJobMode", job_mode_to_string(u->on_success_job_mode)),
                        SD_JSON_BUILD_PAIR_STRING("OnFailureJobMode", job_mode_to_string(u->on_failure_job_mode)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreOnIsolate", u->ignore_on_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("StopWhenUnneeded", u->stop_when_unneeded),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStart", u->refuse_manual_start),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStop", u->refuse_manual_stop),
                        SD_JSON_BUILD_PAIR_BOOLEAN("AllowIsolate", u->allow_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultDependencies", u->default_dependencies),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SurviveFinalKillSignal", u->survive_final_kill_signal),
                        SD_JSON_BUILD_PAIR_STRING("CollectMode", collect_mode_to_string(u->collect_mode)),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("FailureAction", u->failure_action),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("SuccessAction", u->success_action),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("FailureActionExitStatus", u->failure_action_exit_status),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("SuccessActionExitStatus", u->success_action_exit_status),
                        JSON_BUILD_PAIR_FINITE_USEC("JobTimeoutUSec", u->job_timeout),
                        JSON_BUILD_PAIR_FINITE_USEC("JobRunningTimeoutUSec", u->job_running_timeout),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("JobTimeoutAction", u->job_timeout_action),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("JobTimeoutRebootArgument", u->job_timeout_reboot_arg),
                        JSON_BUILD_PAIR_RATELIMIT_ENABLED("StartLimit", &u->start_ratelimit),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("StartLimitAction", u->start_limit_action),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RebootArgument", u->reboot_arg),

                        /* Conditions and Asserts
                         * https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Conditions%20and%20Asserts */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Conditions", unit_conditions_build_json, u->conditions),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Asserts", unit_conditions_build_json, u->asserts),

                        /* Others */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Triggers", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TriggeredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("AccessSELinuxContext", u->access_selinux_context),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("FragmentPath", u->fragment_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SourcePath", u->source_path),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("DropInPaths", u->dropin_paths),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UnitFilePreset", preset_action_past_tense_to_string(unit_get_unit_file_preset(u))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Transient", u->transient),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Perpetual", u->perpetual));

        // TODO follow up PRs:
        // JSON_BUILD_PAIR_CALLBACK_NON_NULL("CGroup", cgroup_context_build_json, u)
        // JSON_BUILD_PAIR_CALLBACK_NON_NULL("Exec", exec_context_build_json, u)
        // JSON_BUILD_PAIR_CALLBACK_NON_NULL("Kill", kill_context_build_json, u)
        // Mount/Automount context
        // Path context
        // Scope context
        // Swap context
        // Timer context
        // Service context
        // Socket context
}

static int list_unit_one(sd_varlink *link, Unit *unit, bool more) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(unit);

        r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_CALLBACK("context", unit_context_build_json, unit));
        if (r < 0)
                return r;

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

int vl_method_list_units(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(parameters);

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        const char *k;
        Unit *u, *previous = NULL;
        HASHMAP_FOREACH_KEY(u, k, m->units) {
                if (k != u->id)
                        continue;

                if (previous) {
                        r = list_unit_one(link, previous, /* more = */ true);
                        if (r < 0)
                                return r;

                }

                previous = u;
        }

        if (previous)
                return list_unit_one(link, previous, /* more = */ false);

        return sd_varlink_error(link, "io.systemd.Manager.NoSuchUnit", NULL);
}
