/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-json.h"

#include "bitfield.h"
#include "bus-polkit.h"
#include "cgroup.h"
#include "condition.h"
#include "dbus-job.h"
#include "execute.h"
#include "format-util.h"
#include "install.h"
#include "job.h"
#include "json-util.h"
#include "locale-util.h"
#include "manager.h"
#include "path-util.h"
#include "pidref.h"
#include "selinux-access.h"
#include "service.h"
#include "set.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"
#include "varlink-automount.h"
#include "varlink-cgroup.h"
#include "varlink-common.h"
#include "varlink-execute.h"
#include "varlink-kill.h"
#include "varlink-mount.h"
#include "varlink-path.h"
#include "varlink-scope.h"
#include "varlink-swap.h"
#include "varlink-unit.h"
#include "varlink-util.h"

#define JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY(name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(value > EMERGENCY_ACTION_NONE, name, JSON_BUILD_STRING_UNDERSCORIFY(emergency_action_to_string(value)))

static int unit_dependencies_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        UnitDependency d;
        int r;

        assert(ret);
        assert(name);

        d = unit_dependency_from_string(name);
        if (d < 0)
                return log_debug_errno(d, "Failed to get unit dependency for '%s': %m", name);

        void *value;
        Unit *other;
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

        if (!mounts_for) {
                *ret = NULL;
                return 0;
        }

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

static int exec_command_list_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecCommand *list = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(command, c, list) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = exec_command_build_json(&entry, /* name= */ NULL, c);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&v, entry);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

/* TODO: This covers only a small subset of a service object's properties. Extend to make more available to
 * consumers like Unit.StartTransient */
static int service_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Service *s = ASSERT_PTR(SERVICE(u));
        assert(ret);

        return sd_json_buildo(
                        ret,
                        JSON_BUILD_PAIR_ENUM("Type", service_type_to_string(s->type)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStart", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START]),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemainAfterExit", s->remain_after_exit));
}

static int unit_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);

        /* The main principle behind context/runtime split is the following:
         * If it make sense to place a property into a config/unit file it belongs to Context.
         * Otherwise it's a 'Runtime'. */

        /* TODO missing callbacks */
        static const sd_json_build_callback_t unit_type_callbacks[_UNIT_TYPE_MAX] = {
                [UNIT_AUTOMOUNT] = automount_context_build_json,
                [UNIT_MOUNT]     = mount_context_build_json,
                [UNIT_PATH]      = path_context_build_json,
                [UNIT_SCOPE]     = scope_context_build_json,
                [UNIT_SERVICE]   = service_context_build_json,
                [UNIT_SWAP]      = swap_context_build_json,
        };

        return sd_json_buildo(
                        ASSERT_PTR(ret),
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
                        JSON_BUILD_PAIR_ENUM("OnSuccessJobMode", job_mode_to_string(u->on_success_job_mode)),
                        JSON_BUILD_PAIR_ENUM("OnFailureJobMode", job_mode_to_string(u->on_failure_job_mode)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreOnIsolate", u->ignore_on_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("StopWhenUnneeded", u->stop_when_unneeded),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStart", u->refuse_manual_start),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStop", u->refuse_manual_stop),
                        SD_JSON_BUILD_PAIR_BOOLEAN("AllowIsolate", u->allow_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultDependencies", u->default_dependencies),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SurviveFinalKillSignal", u->survive_final_kill_signal),
                        JSON_BUILD_PAIR_ENUM("CollectMode", collect_mode_to_string(u->collect_mode)),
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
                        SD_JSON_BUILD_PAIR_BOOLEAN("Perpetual", u->perpetual),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DebugInvocation", u->debug_invocation),

                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CGroup", unit_cgroup_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Exec", unit_exec_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Kill", unit_kill_context_build_json, unit_get_kill_context(u)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(unit_type_to_capitalized_string(u->type), unit_type_callbacks[u->type], u));
}

static int can_clean_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        ExecCleanMask mask;
        int r;

        assert(ret);

        r = unit_can_clean(u, &mask);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if unit can be cleaned: %m");

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                if (!BIT_SET(mask, t))
                        continue;

                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(exec_resource_type_to_string(t)));
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(mask, EXEC_CLEAN_FDSTORE)) {
                r = sd_json_variant_append_arrayb(&v, JSON_BUILD_CONST_STRING("fdstore"));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int markers_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        unsigned *markers = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        BIT_FOREACH(m, *markers) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(unit_marker_to_string(m)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int activation_details_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const ActivationDetails *activation_details = userdata;
        _cleanup_strv_free_ char **pairs = NULL;
        int r;

        assert(ret);

        /* activation_details_append_pair() gracefully takes activation_details==NULL */
        r = activation_details_append_pair(activation_details, &pairs);
        if (r < 0)
                return log_debug_errno(r, "Failed to get activation details: %m");

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("type", *key),
                                SD_JSON_BUILD_PAIR_STRING("name", *value));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Unit *f = unit_following(u);

        /* TODO missing callbacks */
        static const sd_json_build_callback_t unit_type_callbacks[_UNIT_TYPE_MAX] = {
                [UNIT_AUTOMOUNT] = automount_runtime_build_json,
                [UNIT_MOUNT]     = mount_runtime_build_json,
                [UNIT_PATH]      = path_runtime_build_json,
                [UNIT_SCOPE]     = scope_runtime_build_json,
                [UNIT_SWAP]      = swap_runtime_build_json,
        };

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Following", f ? f->id : NULL),
                        SD_JSON_BUILD_PAIR_STRING("LoadState", unit_load_state_to_string(u->load_state)),
                        SD_JSON_BUILD_PAIR_STRING("ActiveState", unit_active_state_to_string(unit_active_state(u))),
                        SD_JSON_BUILD_PAIR_STRING("FreezerState", freezer_state_to_string(u->freezer_state)),
                        SD_JSON_BUILD_PAIR_STRING("SubState", unit_sub_state_to_string(u)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UnitFileState", unit_file_state_to_string(unit_get_unit_file_state(u))),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("StateChangeTimestamp", &u->state_change_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("ActiveEnterTimestamp", &u->active_enter_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("ActiveExitTimestamp", &u->active_exit_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InactiveEnterTimestamp", &u->inactive_enter_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InactiveExitTimestamp", &u->inactive_exit_timestamp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanStart", unit_can_start_refuse_manual(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanStop", unit_can_stop_refuse_manual(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanReload", unit_can_reload(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanIsolate", unit_can_isolate_refuse_manual(u)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CanClean", can_clean_build_json, u),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanFreeze", unit_can_freeze(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanLiveMount", unit_can_live_mount(u, /* reterr_error= */ NULL) >= 0),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("JobId", u->job ? u->job->id : 0),
                        SD_JSON_BUILD_PAIR_BOOLEAN("NeedDaemonReload", unit_need_daemon_reload(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ConditionResult", u->condition_result),
                        SD_JSON_BUILD_PAIR_BOOLEAN("AssertResult", u->assert_result),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("ConditionTimestamp", &u->condition_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("AssertTimestamp", &u->assert_timestamp),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(u->invocation_id), "InvocationID", SD_JSON_BUILD_UUID(u->invocation_id)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Markers", markers_build_json, &u->markers),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ActivationDetails", activation_details_build_json, u->activation_details),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CGroup", unit_cgroup_runtime_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(unit_type_to_capitalized_string(u->type), unit_type_callbacks[u->type], u));
}

static int list_unit_one(sd_varlink *link, Unit *unit) {
        assert(link);
        assert(unit);

        return sd_varlink_replybo(link,
                        SD_JSON_BUILD_PAIR_CALLBACK("context", unit_context_build_json, unit),
                        SD_JSON_BUILD_PAIR_CALLBACK("runtime", unit_runtime_build_json, unit));
}

static int list_unit_one_with_selinux_access_check(sd_varlink *link, Unit *unit) {
        int r;

        assert(link);
        assert(unit);

        r = mac_selinux_unit_access_check_varlink(unit, link, "status");
        if (r < 0)
                /* If mac_selinux_unit_access_check_varlink() returned a error,
                 * it means that SELinux enforce is on. It also does all the logging(). */
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        return list_unit_one(link, unit);
}

static int lookup_unit_by_pidref(sd_varlink *link, Manager *manager, PidRef *pidref, Unit **ret_unit) {
        _cleanup_(pidref_done) PidRef peer = PIDREF_NULL;
        Unit *unit;
        int r;

        assert(link);
        assert(manager);
        assert(ret_unit);

        if (pidref_is_automatic(pidref)) {
                r = varlink_get_peer_pidref(link, &peer);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get peer pidref: %m");

                pidref = &peer;
        } else if (!pidref_is_set(pidref))
                return -EINVAL;

        unit = manager_get_unit_by_pidref(manager, pidref);
        if (!unit)
                return -ESRCH;

        *ret_unit = unit;
        return 0;
}

static int load_unit_and_check(sd_varlink *link, Manager *manager, const char *name, Unit **ret_unit) {
        Unit *unit;
        int r;

        assert(link);
        assert(manager);
        assert(name);
        assert(ret_unit);

        r = manager_load_unit(manager, name, /* path= */ NULL, /* e= */ NULL, &unit);
        if (r < 0)
                return r;

        /* manager_load_unit() will create an object regardless of whether the unit actually exists, so
         * check the state and refuse if it's not in a good state. */
        if (IN_SET(unit->load_state, UNIT_NOT_FOUND, UNIT_STUB, UNIT_MERGED))
                return sd_varlink_error(link, "io.systemd.Unit.NoSuchUnit", NULL);
        if (unit->load_state == UNIT_BAD_SETTING)
                return sd_varlink_error(link, "io.systemd.Unit.UnitError", NULL);
        if (unit->load_state == UNIT_ERROR)
                return sd_varlink_errorbo(
                        link,
                        SD_VARLINK_ERROR_SYSTEM,
                        SD_JSON_BUILD_PAIR_STRING("origin", "linux"),
                        SD_JSON_BUILD_PAIR_INTEGER("errno", unit->load_error),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("errnoName", "io.systemd.Unit.UnitError"));
        if (unit->load_state == UNIT_MASKED)
                return sd_varlink_error(link, "io.systemd.Unit.UnitMasked", NULL);
        assert(UNIT_IS_LOAD_COMPLETE(unit->load_state));

        *ret_unit = unit;
        return 0;
}

typedef struct UnitLookupParameters {
        const char *name, *cgroup;
        PidRef pidref;
        sd_id128_t invocation_id;
} UnitLookupParameters;

static void unit_lookup_parameters_done(UnitLookupParameters *p) {
        assert(p);
        pidref_done(&p->pidref);
}

static int varlink_error_conflict_lookup_parameters(sd_varlink *v, const UnitLookupParameters *p) {
        log_debug("Unit lookup by parameters name='%s' pid='"PID_FMT"' cgroup='%s' invocationID='%s' resulted in multiple different units.",
                  strnull(p->name),
                  pidref_is_automatic(&p->pidref) ? 0 : pidref_is_set(&p->pidref) ? p->pidref.pid : (pid_t) -1,
                  strnull(p->cgroup),
                  sd_id128_is_null(p->invocation_id) ? "" : SD_ID128_TO_UUID_STRING(p->invocation_id));

        return varlink_error_no_such_unit(v, /* name= */ NULL);
}

static int lookup_unit_by_parameters(
                sd_varlink *link,
                Manager *manager,
                UnitLookupParameters *p,
                Unit **ret) {

        /* The function can return ret_unit=NULL if no lookup parameters provided */
        Unit *unit = NULL;
        int r;

        assert(link);
        assert(manager);
        assert(p);
        assert(ret);

        if (p->name) {
                r = load_unit_and_check(link, manager, p->name, &unit);
                if (r < 0)
                        return r;
        }

        if (pidref_is_set_or_automatic(&p->pidref)) {
                Unit *pid_unit;

                r = lookup_unit_by_pidref(link, manager, &p->pidref, &pid_unit);
                if (r == -EINVAL)
                        return sd_varlink_error_invalid_parameter_name(link, "pid");
                if (r == -ESRCH)
                        return varlink_error_no_such_unit(link, "pid");
                if (r < 0)
                        return r;
                if (unit && pid_unit != unit)
                        return varlink_error_conflict_lookup_parameters(link, p);

                unit = pid_unit;
        }

        if (p->cgroup) {
                if (!path_is_absolute(p->cgroup) || !path_is_normalized(p->cgroup))
                        return sd_varlink_error_invalid_parameter_name(link, "cgroup");

                Unit *cgroup_unit = manager_get_unit_by_cgroup(manager, p->cgroup);
                if (!cgroup_unit)
                        return varlink_error_no_such_unit(link, "cgroup");
                if (unit && cgroup_unit != unit)
                        return varlink_error_conflict_lookup_parameters(link, p);

                unit = cgroup_unit;
        }

        if (!sd_id128_is_null(p->invocation_id)) {
                Unit *id128_unit = hashmap_get(manager->units_by_invocation_id, &p->invocation_id);
                if (!id128_unit)
                        return varlink_error_no_such_unit(link, "invocationID");
                if (unit && id128_unit != unit)
                        return varlink_error_conflict_lookup_parameters(link, p);

                unit = id128_unit;
        }

        *ret = unit;
        return !!unit;
}

int vl_method_list_units(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",         SD_JSON_VARIANT_STRING,        json_dispatch_const_unit_name, offsetof(UnitLookupParameters, name),          0 /* allows UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE */ },
                { "pid",          _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref,          offsetof(UnitLookupParameters, pidref),        SD_JSON_RELAX /* allows PID_AUTOMATIC */            },
                { "cgroup",       SD_JSON_VARIANT_STRING,        json_dispatch_const_path,      offsetof(UnitLookupParameters, cgroup),        SD_JSON_STRICT /* require normalized path */        },
                { "invocationID", SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,        offsetof(UnitLookupParameters, invocation_id), 0                                                   },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
         _cleanup_(unit_lookup_parameters_done) UnitLookupParameters p = {
                 .pidref = PIDREF_NULL,
        };
        Unit *unit;
        const char *k;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = lookup_unit_by_parameters(link, manager, &p, &unit);
        if (r < 0)
                return r;
        if (r > 0)
                return list_unit_one_with_selinux_access_check(link, unit);

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = sd_varlink_set_sentinel(link, VARLINK_ERROR_UNIT_NO_SUCH_UNIT);
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(unit, k, manager->units) {
                /* ignore aliases */
                if (k != unit->id)
                        continue;

                r = mac_selinux_unit_access_check_varlink(unit, link, "status");
                if (r < 0)
                        continue; /* silently skip units the caller is not allowed to see */

                r = list_unit_one(link, unit);
                if (r < 0)
                        return r;
        }

        return 0;
}

int varlink_unit_queue_job_one(
                Unit *u,
                JobType type,
                JobMode mode,
                bool reload_if_possible,
                uint32_t *ret_job_id,
                Job **ret_job,
                sd_bus_error *reterr_bus_error) {

        int r;

        assert(u);

        r = unit_queue_job_check_and_mangle_type(u, &type, reload_if_possible, reterr_bus_error);
        if (r < 0)
                return r;

        Job *j;
        r = manager_add_job(u->manager, type, u, mode, reterr_bus_error, &j);
        if (r < 0)
                return r;

        /* Before we send the method reply, force out the announcement JobNew for this job */
        bus_job_send_pending_change_signal(j, /* including_new= */ true);

        if (ret_job_id)
                *ret_job_id = j->id;
        if (ret_job)
                *ret_job = j;

        return 0;
}

int varlink_error_no_such_unit(sd_varlink *v, const char *name) {
        return sd_varlink_errorbo(
                        ASSERT_PTR(v),
                        VARLINK_ERROR_UNIT_NO_SUCH_UNIT,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("parameter", name));
}

void varlink_unit_send_change_signal(Unit *u) {
        assert(u);

        if (!u->varlink_unit_change)
                return;

        (void) sd_varlink_notifybo(
                        u->varlink_unit_change,
                        SD_JSON_BUILD_PAIR_CALLBACK("runtime", unit_runtime_build_json, u));
}

static int job_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Job *j = ASSERT_PTR(userdata);

        /* Note that "Result" is suppressed until the job reaches JOB_FINISHED. */
        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_INTEGER("Id", j->id),
                        JSON_BUILD_PAIR_ENUM("JobType", job_type_to_string(j->type)),
                        JSON_BUILD_PAIR_ENUM("State", job_state_to_string(j->state)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY_UNDERSCORIFY("Result", job_result_to_string(j->result)));
}

void varlink_job_send_change_signal(Job *j) {
        assert(j);

        if (!j->varlink || !j->varlink_notify_job_changes)
                return;

        (void) sd_varlink_notifybo(
                        j->varlink,
                        SD_JSON_BUILD_PAIR_CALLBACK("job", job_build_json, j));
}

void varlink_job_send_removed_signal(Job *j) {
        assert(j);

        if (!j->varlink)
                return;

        /* Send the final reply, which completes the method call */
        (void) sd_varlink_replybo(
                        j->varlink,
                        SD_JSON_BUILD_PAIR_CALLBACK("context", unit_context_build_json, j->unit),
                        SD_JSON_BUILD_PAIR_CALLBACK("runtime", unit_runtime_build_json, j->unit),
                        SD_JSON_BUILD_PAIR_CALLBACK("job", job_build_json, j));

        j->varlink = sd_varlink_unref(j->varlink);
        j->unit->varlink_unit_change = sd_varlink_unref(j->unit->varlink_unit_change);
}

typedef struct TransientExecCommandItem {
        const char *path;
        char **arguments;
} TransientExecCommandItem;

static void transient_exec_command_item_done(TransientExecCommandItem *i) {
        assert(i);
        strv_free(i->arguments);
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_service_type, ServiceType, service_type_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_job_mode, JobMode, job_mode_from_string);

typedef struct TransientServiceParameters {
        ServiceType type;
        TransientExecCommandItem *exec_start;
        size_t n_exec_start;
        int remain_after_exit;
} TransientServiceParameters;

static void transient_service_parameters_done(TransientServiceParameters *p) {
        assert(p);
        FOREACH_ARRAY(i, p->exec_start, p->n_exec_start)
                transient_exec_command_item_done(i);
        free(p->exec_start);
}

static int dispatch_transient_exec_command(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field exec_command_dispatch[] = {
                { "path",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(TransientExecCommandItem, path),      SD_JSON_MANDATORY },
                { "arguments", SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_strv,         offsetof(TransientExecCommandItem, arguments), 0                 },
                {}
        };

        TransientServiceParameters *p = ASSERT_PTR(userdata);
        size_t n;
        int r;

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Expected JSON array for ExecStart.");

        n = sd_json_variant_elements(variant);
        if (n == 0)
                return 0;

        p->exec_start = new0(TransientExecCommandItem, n);
        if (!p->exec_start)
                return -ENOMEM;
        p->n_exec_start = n;

        for (size_t i = 0; i < n; i++) {
                sd_json_variant *element = sd_json_variant_by_index(variant, i);

                r = sd_json_dispatch(element, exec_command_dispatch, /* flags= */ 0, &p->exec_start[i]);
                if (r < 0)
                        return r;
        }
        return 0;
}

typedef struct StartTransientContextParameters {
        const char *id;
        const char *description;
        TransientServiceParameters service;
} StartTransientContextParameters;

static void start_transient_context_parameters_done(StartTransientContextParameters *p) {
        assert(p);
        transient_service_parameters_done(&p->service);
}

typedef struct StartTransientParameters {
        StartTransientContextParameters context;
        JobMode mode;
        int notify_job_changes;
        int notify_unit_changes;
        const char *unsupported_property; /* For error reporting on unknown context fields */
} StartTransientParameters;

static void start_transient_parameters_done(StartTransientParameters *p) {
        assert(p);
        start_transient_context_parameters_done(&p->context);
}

static int dispatch_transient_service(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field service_dispatch[] = {
                { "Type",            SD_JSON_VARIANT_STRING,  dispatch_service_type,           offsetof(TransientServiceParameters, type),              0 },
                { "ExecStart",       SD_JSON_VARIANT_ARRAY,   dispatch_transient_exec_command, 0,                                                       0 },
                { "RemainAfterExit", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,       offsetof(TransientServiceParameters, remain_after_exit), 0 },
                {}
        };

        StartTransientContextParameters *p = ASSERT_PTR(userdata);
        return sd_json_dispatch(variant, service_dispatch, /* flags= */ 0, &p->service);
}

static int dispatch_transient_context(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field context_dispatch[] = {
                { "ID",          SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, offsetof(StartTransientContextParameters, id),          SD_JSON_MANDATORY },
                { "Description", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(StartTransientContextParameters, description), 0                 },
                { "Service",     SD_JSON_VARIANT_OBJECT, dispatch_transient_service,    0,                                                      0                 },
                {}
        };

        StartTransientParameters *p = ASSERT_PTR(userdata);
        const char *bad_field = NULL;
        int r;

        /* Don't propagate the caller's flags (in particular SD_JSON_MANDATORY from the outer 'context'
         * field) into the nested dispatch, otherwise every inner field becomes mandatory. */
        r = sd_json_dispatch_full(variant, context_dispatch, /* bad= */ NULL, /* flags= */ 0, &p->context, &bad_field);
        if (r == -EADDRNOTAVAIL && !isempty(bad_field))
                /* A UnitContext field that exists in the schema but is not settable at creation time: stash
                 * the name so the caller can map this to io.systemd.Unit.PropertyNotSupported. */
                p->unsupported_property = bad_field;
        return r;
}

static int transient_service_apply_properties(Unit *u, TransientServiceParameters *sp) {
        int r;

        Service *s = ASSERT_PTR(SERVICE(u));
        assert(sp);

        if (sp->type >= 0) {
                s->type = sp->type;
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "Type", "Type=%s", service_type_to_string(sp->type));
        }

        if (sp->remain_after_exit >= 0) {
                s->remain_after_exit = sp->remain_after_exit;
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "RemainAfterExit", "RemainAfterExit=%s", yes_no(sp->remain_after_exit));
        }

        FOREACH_ARRAY(item, sp->exec_start, sp->n_exec_start) {
                _cleanup_(exec_command_freep) ExecCommand *c = NULL;
                _cleanup_strv_free_ char **argv = NULL;

                if (!filename_or_absolute_path_is_valid(item->path))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid ExecStart path: %s", item->path);

                if (!strv_isempty(item->arguments)) {
                        argv = strv_copy(item->arguments);
                        if (!argv)
                                return -ENOMEM;
                }

                c = new0(ExecCommand, 1);
                if (!c)
                        return -ENOMEM;

                r = path_simplify_alloc(item->path, &c->path);
                if (r < 0)
                        return r;

                /* If no arguments were provided, default argv[0] to the executable path.
                 * Otherwise the caller is expected to include argv[0] in the arguments array. */
                if (strv_isempty(argv)) {
                        r = strv_extend(&argv, c->path);
                        if (r < 0)
                                return r;
                }

                c->argv = TAKE_PTR(argv);

                exec_command_append_list(&s->exec_command[SERVICE_EXEC_START], TAKE_PTR(c));
        }

        /* Write ExecStart= lines to the transient file */
        if (sp->n_exec_start > 0) {
                UnitWriteFlags esc_flags = UNIT_ESCAPE_SPECIFIERS|UNIT_ESCAPE_EXEC_SYNTAX_ENV;

                LIST_FOREACH(command, c, s->exec_command[SERVICE_EXEC_START]) {
                        _cleanup_free_ char *a = NULL;

                        a = unit_concat_strv(c->argv, esc_flags);
                        if (!a)
                                return -ENOMEM;

                        /* streq() instead path_equal() as argv[0] can be arbitrary and may not be a path */
                        if (streq(c->path, c->argv[0]))
                                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "ExecStart", "ExecStart=%s", a);
                        else {
                                _cleanup_free_ char *t = NULL;
                                const char *p;

                                p = unit_escape_setting(c->path, esc_flags, &t);
                                if (!p)
                                        return -ENOMEM;

                                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "ExecStart", "ExecStart=@%s %s", p, a);
                        }
                }
        }

        return 0;
}

int vl_method_start_transient_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "context",            SD_JSON_VARIANT_OBJECT,  dispatch_transient_context, 0,                                                       SD_JSON_MANDATORY },
                { "mode",               SD_JSON_VARIANT_STRING,  dispatch_job_mode,          offsetof(StartTransientParameters, mode),                0                 },
                { "notifyJobChanges",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,  offsetof(StartTransientParameters, notify_job_changes),  0                 },
                { "notifyUnitChanges",  SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,  offsetof(StartTransientParameters, notify_unit_changes), 0                 },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(start_transient_parameters_done) StartTransientParameters p = {
                .mode = JOB_REPLACE,
                .notify_job_changes = -1,
                .notify_unit_changes = -1,
                .context.service.type = _SERVICE_TYPE_INVALID,
                .context.service.remain_after_exit = -1,
        };
        Manager *manager = ASSERT_PTR(userdata);
        const char *bad_field = NULL;
        Unit *u;
        int r;

        assert(link);
        assert(parameters);

        r = mac_selinux_access_check_varlink(link, "start");
        if (r < 0)
                return r;

        r = sd_json_dispatch_full(parameters, dispatch_table, /* bad= */ NULL, /* flags= */ 0, &p, &bad_field);
        if (r < 0) {
                /* An unknown field in 'context' maps to PropertyNotSupported (the field is defined in the
                 * UnitContext schema but cannot be set at creation time). Anything else is a bad parameter. */
                if (streq_ptr(bad_field, "context") && r == -EADDRNOTAVAIL && p.unsupported_property)
                        return sd_varlink_errorbo(
                                        link,
                                        "io.systemd.Unit.PropertyNotSupported",
                                        SD_JSON_BUILD_PAIR_STRING("property", p.unsupported_property));
                if (bad_field)
                        return sd_varlink_error_invalid_parameter_name(link, bad_field);
                return r;
        }

        /* Pre-check unit type early and return targeted varlink error as manager_setup_transient_unit() the
         * too generic SD_BUS_ERROR_INVALID_ARGS. */
        UnitType t = unit_name_to_type(p.context.id);
        if (t < 0)
                return sd_varlink_error_invalid_parameter_name(link, "context");
        if (!unit_vtable[t]->can_transient)
                return sd_varlink_error(link, VARLINK_ERROR_UNIT_TYPE_NOT_SUPPORTED, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.manage-units",
                        (const char**) STRV_MAKE(
                                        "unit", p.context.id,
                                        "verb", "start",
                                        "polkit.message", N_("Authentication is required to start transient unit '$(unit)'."),
                                        "polkit.gettext_domain", GETTEXT_PACKAGE),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = manager_setup_transient_unit(manager, p.context.id, &u, &bus_error);
        if (r < 0)
                return varlink_reply_bus_error(link, r, &bus_error);

        /* Apply unit-level properties from context */
        if (p.context.description) {
                r = unit_set_description(u, p.context.description);
                if (r < 0)
                        return sd_varlink_error(link, VARLINK_ERROR_UNIT_BAD_SETTING, NULL);
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_ESCAPE_SPECIFIERS, "Description", "Description=%s", p.context.description);
        }

        /* Apply service-specific properties from context.Service */
        if (p.context.service.type >= 0 || p.context.service.n_exec_start > 0 || p.context.service.remain_after_exit >= 0) {
                if (t != UNIT_SERVICE)
                        return sd_varlink_error(link, VARLINK_ERROR_UNIT_TYPE_NOT_SUPPORTED, NULL);

                r = transient_service_apply_properties(u, &p.context.service);
                if (r < 0)
                        return sd_varlink_error(link, VARLINK_ERROR_UNIT_BAD_SETTING, NULL);
        }

        unit_add_to_load_queue(u);
        manager_dispatch_load_queue(manager);

        if (u->load_state == UNIT_BAD_SETTING)
                return sd_varlink_error(link, VARLINK_ERROR_UNIT_BAD_SETTING, NULL);
        if (!UNIT_IS_LOAD_COMPLETE(u->load_state))
                return sd_varlink_error(link, VARLINK_ERROR_UNIT_NO_SUCH_UNIT, NULL);

        Job *j;
        r = varlink_unit_queue_job_one(
                        u,
                        JOB_START,
                        p.mode,
                        /* reload_if_possible= */ false,
                        /* ret_job_id= */ NULL,
                        &j,
                        &bus_error);
        if (r < 0)
                return varlink_reply_bus_error(link, r, &bus_error);

        bool notify_job = p.notify_job_changes > 0;
        bool notify_unit = p.notify_unit_changes > 0;

        /* Non-streaming, or fire-and-forget (no notification flags set): return full unit context
         * and runtime, plus the job object so the caller can correlate with later state. */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE) || (!notify_job && !notify_unit))
                return sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_CALLBACK("context", unit_context_build_json, u),
                                SD_JSON_BUILD_PAIR_CALLBACK("runtime", unit_runtime_build_json, u),
                                SD_JSON_BUILD_PAIR_CALLBACK("job", job_build_json, j));

        /* Streaming: always attach to the job for the final reply, and optionally to the unit for state
         * change notifications. j->varlink owns the stream lifetime, u->varlink_unit_change is just a flag
         * to also send unit state notifications along the way. */
        assert(!j->varlink);
        j->varlink = sd_varlink_ref(link);
        j->varlink_notify_job_changes = notify_job;
        if (notify_unit) {
                assert(!u->varlink_unit_change);
                u->varlink_unit_change = sd_varlink_ref(link);
        }

        /* Send initial job state notification if requested. Unit state change notifications are not sent
         * here; they will arrive via varlink_unit_send_change_signal() when the unit actually transitions,
         * matching D-Bus PropertiesChanged behavior. */
        if (notify_job)
                return sd_varlink_notifybo(
                                link,
                                SD_JSON_BUILD_PAIR_CALLBACK("job", job_build_json, j));

        return 0;
}

typedef struct UnitSetPropertiesParameters {
        const char *unsupported_property; /* For error reporting */
        const char *name;
        bool runtime;

        bool markers_found;
        unsigned markers, markers_mask;
} UnitSetPropertiesParameters;

static int parse_unit_markers(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        UnitSetPropertiesParameters *p = ASSERT_PTR(userdata);
        bool some_plus_minus = false, some_absolute = false;
        unsigned settings = 0, mask = 0;
        sd_json_variant *e;
        int r;

        assert(variant);

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                if (!sd_json_variant_is_string(e))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Marker is not an array of strings.");

                const char *word = sd_json_variant_string(e);

                r = parse_unit_marker(word, &settings, &mask);
                if (r < 0)
                        return json_log(variant, flags, r, "Failed to parse marker '%s'.", word);
                if (r > 0)
                        some_plus_minus = true;
                else
                        some_absolute = true;
        }

        if (some_plus_minus && some_absolute)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Absolute and non-absolute markers in the same setting.");

        if (some_absolute || sd_json_variant_elements(variant) == 0)
                mask = UINT_MAX;

        p->markers = settings;
        p->markers_mask = mask;
        p->markers_found = true;

        return 0;
}

static int unit_dispatch_properties(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "Markers", SD_JSON_VARIANT_ARRAY, parse_unit_markers, 0, 0 },
                {}
        };
        UnitSetPropertiesParameters *p = ASSERT_PTR(userdata);
        const char *bad_field = NULL;
        int r;

        r = sd_json_dispatch_full(variant, dispatch_table, /* bad= */ NULL, flags, userdata, &bad_field);
        if (r == -EADDRNOTAVAIL && !isempty(bad_field))
                /* When properties contains a valid field, but that we don't currently support, make sure to
                 * return the offending property, rather than generic invalid argument. */
                p->unsupported_property = bad_field;
        return r;
}

int vl_method_set_unit_properties(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",       SD_JSON_VARIANT_STRING,  json_dispatch_const_unit_name, offsetof(UnitSetPropertiesParameters, name),    SD_JSON_MANDATORY },
                { "runtime",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(UnitSetPropertiesParameters, runtime), SD_JSON_MANDATORY },
                { "properties", SD_JSON_VARIANT_OBJECT,  unit_dispatch_properties,      0,                                              SD_JSON_MANDATORY },
                {}
        };

        UnitSetPropertiesParameters p = {};
        Manager *manager = ASSERT_PTR(userdata);
        const char *bad_field = NULL;
        Unit *unit;
        int r;

        assert(link);
        assert(parameters);

        r = sd_json_dispatch_full(parameters, dispatch_table, /* bad= */ NULL, /* flags= */ 0, &p, &bad_field);
        if (r < 0) {
                /* When properties contains a valid field, but that we don't currently support, make sure to
                 * return a specific error, rather than generic invalid argument. */
                if (streq_ptr(bad_field, "properties") && r == -EADDRNOTAVAIL)
                        return sd_varlink_errorbo(
                                link,
                                "io.systemd.Unit.PropertyNotSupported",
                                SD_JSON_BUILD_PAIR_CONDITION(!!p.unsupported_property, "property", SD_JSON_BUILD_STRING(p.unsupported_property)));
                if (bad_field)
                        return sd_varlink_error_invalid_parameter_name(link, bad_field);
                return r;
        }

        r = load_unit_and_check(link, manager, p.name, &unit);
        if (r < 0)
                return r;

        r = mac_selinux_unit_access_check_varlink(unit, link, "start");
        if (r < 0)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.manage-units",
                        /* details= */ NULL,
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (p.markers_found)
                unit->markers = unit_normalize_markers((unit->markers & ~p.markers_mask), p.markers);

        return sd_varlink_reply(link, NULL);
}
