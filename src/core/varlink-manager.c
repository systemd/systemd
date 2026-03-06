/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/prctl.h>

#include "sd-bus.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "bitfield.h"
#include "build.h"
#include "bus-error.h"
#include "bus-polkit.h"
#include "confidential-virt.h"
#include "errno-util.h"
#include "glyph-util.h"
#include "json-util.h"
#include "manager.h"
#include "pidref.h"
#include "selinux-access.h"
#include "set.h"
#include "strv.h"
#include "syslog-util.h"
#include "taint.h"
#include "version.h"
#include "varlink-common.h"
#include "varlink-manager.h"
#include "varlink-unit.h"
#include "varlink-util.h"
#include "virt.h"
#include "watchdog.h"

static int manager_environment_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = manager_get_effective_environment(m, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_array_strv(ret, l);
}

static int log_level_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int log_max_level = log_get_max_level();
        int r;

        assert(ret);

        for (LogTarget log_target = 0; log_target < _LOG_TARGET_SINGLE_MAX; log_target++) {
                _cleanup_free_ char *log_level_string = NULL;

                int target_max_level = log_get_target_max_level(log_target);
                const char *log_target_string = log_target_to_string(log_target);

                int log_level = MIN(log_max_level, target_max_level);
                r = log_level_to_string_alloc(log_level, &log_level_string);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field_string(&v, log_target_string, log_level_string);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int manager_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        /* The main principle behind context/runtime split is the following:
         * If it make sense to place a property into a config/unit file it belongs to Context.
         * Otherwise it's a 'Runtime'. */

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ShowStatus", manager_get_show_status_on(m)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogLevel", log_level_build_json, m),
                        SD_JSON_BUILD_PAIR_STRING("LogTarget", log_target_to_string(log_get_target())),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Environment", manager_environment_build_json, m),
                        SD_JSON_BUILD_PAIR_STRING("DefaultStandardOutput", exec_output_to_string(m->defaults.std_output)),
                        SD_JSON_BUILD_PAIR_STRING("DefaultStandardError", exec_output_to_string(m->defaults.std_error)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ServiceWatchdogs", m->service_watchdogs),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimerAccuracyUSec", m->defaults.timer_accuracy_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutStartUSec", m->defaults.timeout_start_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutStopUSec", m->defaults.timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutAbortUSec", manager_default_timeout_abort_usec(m)),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultDeviceTimeoutUSec", m->defaults.device_timeout_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultRestartUSec", m->defaults.restart_usec),
                        JSON_BUILD_PAIR_RATELIMIT("DefaultStartLimit", &m->defaults.start_limit),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultIOAccounting", m->defaults.io_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultIPAccounting", m->defaults.ip_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultMemoryAccounting", m->defaults.memory_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultTasksAccounting", m->defaults.tasks_accounting),
                        SD_JSON_BUILD_PAIR_CALLBACK("DefaultLimits", rlimit_table_build_json, m->defaults.rlimit),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DefaultTasksMax", cgroup_tasks_max_resolve(&m->defaults.tasks_max)),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultMemoryPressureThresholdUSec", m->defaults.memory_pressure_threshold_usec),
                        SD_JSON_BUILD_PAIR_STRING("DefaultMemoryPressureWatch", cgroup_pressure_watch_to_string(m->defaults.memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeWatchdogUSec", manager_get_watchdog(m, WATCHDOG_RUNTIME)),
                        JSON_BUILD_PAIR_FINITE_USEC("RebootWatchdogUSec", manager_get_watchdog(m, WATCHDOG_REBOOT)),
                        JSON_BUILD_PAIR_FINITE_USEC("KExecWatchdogUSec", manager_get_watchdog(m, WATCHDOG_KEXEC)),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeWatchdogPreUSec", manager_get_watchdog(m, WATCHDOG_PRETIMEOUT)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RuntimeWatchdogPreGovernor", m->watchdog_pretimeout_governor),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("WatchdogDevice", watchdog_get_device()),
                        JSON_BUILD_PAIR_FINITE_USEC("TimerSlackNSec", (uint64_t) prctl(PR_GET_TIMERSLACK)),
                        SD_JSON_BUILD_PAIR_STRING("DefaultOOMPolicy", oom_policy_to_string(m->defaults.oom_policy)),
                        SD_JSON_BUILD_PAIR_INTEGER("DefaultOOMScoreAdjust", m->defaults.oom_score_adjust),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultRestrictSUIDSGID", m->defaults.restrict_suid_sgid),
                        SD_JSON_BUILD_PAIR_STRING("CtrlAltDelBurstAction", emergency_action_to_string(m->cad_burst_action)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ConfirmSpawn", manager_get_confirm_spawn(m)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ControlGroup", m->cgroup_root));
}

static int transactions_with_cycle_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const Set *ids = userdata;
        int r;

        assert(ret);

        uint64_t *id;
        SET_FOREACH(id, ids) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_UNSIGNED(*id));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int manager_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        dual_timestamp watchdog_last_ping;
        _cleanup_strv_free_ char **taints = NULL;

        taints = taint_strv();
        if (!taints)
                return -ENOMEM;

        return sd_json_buildo(
                ASSERT_PTR(ret),
                SD_JSON_BUILD_PAIR_STRING("Version", GIT_VERSION),
                SD_JSON_BUILD_PAIR_STRING("Architecture", architecture_to_string(uname_architecture())),
                SD_JSON_BUILD_PAIR_STRING("Features", systemd_features),
                JSON_BUILD_PAIR_STRV_NON_EMPTY("Taints", taints),
                SD_JSON_BUILD_PAIR_STRV("UnitPath", m->lookup_paths.search_path),
                SD_JSON_BUILD_PAIR_STRING("Virtualization", virtualization_to_string(detect_virtualization())),
                SD_JSON_BUILD_PAIR_STRING("ConfidentialVirtualization", confidential_virtualization_to_string(detect_confidential_virtualization())),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("FirmwareTimestamp", &m->timestamps[MANAGER_TIMESTAMP_FIRMWARE]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("LoaderTimestamp", &m->timestamps[MANAGER_TIMESTAMP_LOADER]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("KernelTimestamp", &m->timestamps[MANAGER_TIMESTAMP_KERNEL]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InitRDTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("UserspaceTimestamp", &m->timestamps[MANAGER_TIMESTAMP_USERSPACE]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("FinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("SecurityStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_SECURITY_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("SecurityFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_SECURITY_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("GeneratorsStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_GENERATORS_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("GeneratorsFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_GENERATORS_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("UnitsLoadStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("UnitsLoadFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("UnitsLoadTimestamp", &m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InitRDSecurityStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InitRDSecurityFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InitRDGeneratorsStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InitRDGeneratorsFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InitRDUnitsLoadStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("InitRDUnitsLoadFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH]),
                SD_JSON_BUILD_PAIR_UNSIGNED("NNames", hashmap_size(m->units)),
                SD_JSON_BUILD_PAIR_UNSIGNED("NFailedUnits", set_size(m->failed_units)),
                SD_JSON_BUILD_PAIR_UNSIGNED("NJobs", hashmap_size(m->jobs)),
                SD_JSON_BUILD_PAIR_UNSIGNED("NInstalledJobs", m->n_installed_jobs),
                SD_JSON_BUILD_PAIR_UNSIGNED("NFailedJobs", m->n_failed_jobs),
                JSON_BUILD_PAIR_CALLBACK_NON_NULL("TransactionsWithOrderingCycle", transactions_with_cycle_build_json, m->transactions_with_cycle),
                SD_JSON_BUILD_PAIR_REAL("Progress", manager_get_progress(m)),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("WatchdogLastPingTimestamp", watchdog_get_last_ping_as_dual_timestamp(&watchdog_last_ping)),
                SD_JSON_BUILD_PAIR_STRING("SystemState", manager_state_to_string(manager_state(m))),
                SD_JSON_BUILD_PAIR_UNSIGNED("ExitCode", m->return_value),
                SD_JSON_BUILD_PAIR_UNSIGNED("SoftRebootsCount", m->soft_reboots_count));
}

int vl_method_describe_manager(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_CALLBACK("context", manager_context_build_json, manager),
                        SD_JSON_BUILD_PAIR_CALLBACK("runtime", manager_runtime_build_json, manager));
        if (r < 0)
                return log_error_errno(r, "Failed to build manager JSON data: %m");

        return sd_varlink_reply(link, v);
}

int vl_method_reload_manager(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = mac_selinux_access_check_varlink(link, "reload");
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.reload-daemon",
                        /* details= */ NULL,
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        /* We need at least the pidref, otherwise there's nothing to log about. */
        r = varlink_get_peer_pidref(link, &pidref);
        if (r < 0)
                log_debug_errno(r, "Failed to get peer pidref, ignoring: %m");
        else
                manager_log_caller(manager, &pidref, "Reload");

        /* Check the rate limit after the authorization succeeds, to avoid denial-of-service issues. */
        if (!ratelimit_below(&manager->reload_reexec_ratelimit)) {
                log_warning("Reloading request rejected due to rate limit.");
                return sd_varlink_error(link, VARLINK_ERROR_MANAGER_RATE_LIMIT_REACHED, NULL);
        }

        /* Instead of sending the reply back right away, we just remember that we need to and then send it
         * after the reload is finished. That way the caller knows when the reload finished. */

        assert(!manager->pending_reload_message_vl);
        assert(!manager->pending_reload_message_dbus);
        manager->pending_reload_message_vl = sd_varlink_ref(link);

        manager->objective = MANAGER_RELOAD;

        return 1;
}

int vl_method_reexecute_manager(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = mac_selinux_access_check_varlink(link, "reload");
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.reload-daemon",
                        /* details= */ NULL,
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        /* We need at least the pidref, otherwise there's nothing to log about. */
        r = varlink_get_peer_pidref(link, &pidref);
        if (r < 0)
                log_debug_errno(r, "Failed to get peer pidref, ignoring: %m");
        else
                manager_log_caller(manager, &pidref, "Reexecute");

        /* Check the rate limit after the authorization succeeds, to avoid denial-of-service issues. */
        if (!ratelimit_below(&manager->reload_reexec_ratelimit)) {
                log_warning("Reexecution request rejected due to rate limit.");
                return sd_varlink_error(link, VARLINK_ERROR_MANAGER_RATE_LIMIT_REACHED, NULL);
        }

        /* We don't send a reply back here, the client should just wait for us disconnecting. */

        manager->objective = MANAGER_REEXECUTE;

        return 1;
}

int vl_method_enqueue_marked_jobs_manager(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = mac_selinux_access_check_varlink(link, "start");
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->system_bus,
                        "org.freedesktop.systemd1.manage-units",
                        /* details= */ NULL,
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = varlink_set_sentinel(link, NULL);
        if (r < 0)
                return r;

        log_info("Queuing reload/restart jobs for marked units%s", glyph(GLYPH_ELLIPSIS));

        Unit *u;
        char *k;
        int ret = 0;
        HASHMAP_FOREACH_KEY(u, k, manager->units) {
                _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
                const char *error_id = NULL;
                uint32_t job_id = 0; /* silence 'maybe-uninitialized' compiler warning */
                JobType job;

                /* ignore aliases */
                if (u->id != k)
                        continue;

                if (u->markers == 0)
                        continue;
                if (BIT_SET(u->markers, UNIT_MARKER_NEEDS_STOP))
                        job = JOB_STOP;
                else if (BIT_SET(u->markers, UNIT_MARKER_NEEDS_START))
                        job = JOB_START;
                else
                        job = JOB_TRY_RESTART;

                r = mac_selinux_unit_access_check_varlink(u, link, job_type_to_access_method(job));
                if (r < 0)
                        error_id = SD_VARLINK_ERROR_PERMISSION_DENIED;
                else
                        r = varlink_unit_queue_job_one(
                                        u,
                                        job,
                                        JOB_FAIL,
                                        /* reload_if_possible= */ !BIT_SET(u->markers, UNIT_MARKER_NEEDS_RESTART),
                                        &job_id,
                                        &bus_error);
                if (ERRNO_IS_NEG_RESOURCE(r))
                        return r;
                if (r < 0)
                        RET_GATHER(ret, log_unit_warning_errno(u, r, "Failed to enqueue marked job: %s",
                                                               bus_error_message(&bus_error, r)));

                if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                        continue;

                if (r < 0) {
                        if (!error_id)
                                error_id = varlink_error_id_from_bus_error(&bus_error);

                        const char *error_msg = bus_error.message ?: error_id ? NULL : STRERROR(r);

                        r = sd_varlink_replybo(link,
                                               SD_JSON_BUILD_PAIR_STRING("unitID", u->id),
                                               JSON_BUILD_PAIR_STRING_NON_EMPTY("error", error_id),
                                               JSON_BUILD_PAIR_STRING_NON_EMPTY("errorMessage", error_msg));
                } else
                        r = sd_varlink_replybo(link,
                                               SD_JSON_BUILD_PAIR_STRING("unitID", u->id),
                                               SD_JSON_BUILD_PAIR_INTEGER("jobID", job_id));
                if (r < 0)
                        return r;
        }

        return ret;
}
