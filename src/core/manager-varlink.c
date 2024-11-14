/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/prctl.h>

#include "build.h"
#include "confidential-virt.h"
#include "json-util.h"
#include "manager-varlink.h"
#include "manager.h"
#include "rlimit-util.h"
#include "syslog-util.h"
#include "taint.h"
#include "version.h"
#include "virt.h"
#include "watchdog.h"

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        const struct rlimit *rl = userdata;
        struct rlimit buf = {};
        int r;

        assert(name);
        assert(ret);

        if (!rl) {
                const char *p;
                int z;

                /* Skip over any prefix, such as "Default" */
                assert_se(p = strstrafter(name, "Limit"));

                z = rlimit_from_string(p);
                assert(z >= 0 && z < _RLIMIT_MAX);

                r = getrlimit(z, &buf);
                if (r < 0) {
                        log_debug_errno(errno, "Failed to getrlimit(%s), ignoring: %m", name);
                        return 0;
                }

                rl = &buf;
        }

        if (rl->rlim_cur == RLIM_INFINITY && rl->rlim_max == RLIM_INFINITY)
                return 0;

        /* rlim_t might have different sizes, let's map RLIMIT_INFINITY to UINT64_MAX, so that it is the same
         * on all archs */
        return sd_json_buildo(ret,
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("soft", rl->rlim_cur, RLIM_INFINITY),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("hard", rl->rlim_max, RLIM_INFINITY));
}

int manager_environment_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = manager_get_effective_environment(m, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l))
                return 0;

        return sd_json_variant_new_array_strv(ret, l);
}

static int log_level_build_json(sd_json_variant **ret, const char *name, void *userdata, int log_max_level) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(ret);
        assert(log_max_level >= 0);

        for (int log_target = 0; log_target < _LOG_TARGET_SINGLE_MAX; log_target++) {
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

static int log_level_build_context_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int log_level = m->log_level_overridden ? m->original_log_level : log_get_max_level();
        return log_level_build_json(ret, name, userdata, log_level);
}

static int log_level_build_runtime_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        if (!m->log_level_overridden)
                return 0;

        return log_level_build_json(ret, name, userdata, log_get_max_level());
}

static int manager_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("Version", GIT_VERSION),
                        SD_JSON_BUILD_PAIR_STRING("Architecture", architecture_to_string(uname_architecture())),
                        SD_JSON_BUILD_PAIR_STRING("Features", systemd_features),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ShowStatus", show_status_on(MANAGER_IS_USER(m) ? _SHOW_STATUS_INVALID : m->show_status)),
                        SD_JSON_BUILD_PAIR_STRV("UnitPath", m->lookup_paths.search_path),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogLevel", log_level_build_context_json, m),
                        SD_JSON_BUILD_PAIR_STRING("LogTarget", log_target_to_string(m->log_target_overridden ? m->original_log_target : log_get_target())),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Environment", m->transient_environment),
                        SD_JSON_BUILD_PAIR_STRING("DefaultStandardOutput", exec_output_to_string(m->defaults.std_output)),
                        SD_JSON_BUILD_PAIR_STRING("DefaultStandardError", exec_output_to_string(m->defaults.std_error)),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeWatchdogUSec", manager_get_watchdog(m, WATCHDOG_RUNTIME)),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeWatchdogPreUSec", manager_get_watchdog(m, WATCHDOG_PRETIMEOUT)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RuntimeWatchdogPreGovernor", m->watchdog_pretimeout_governor),
                        JSON_BUILD_PAIR_FINITE_USEC("RebootWatchdogUSec", manager_get_watchdog(m, WATCHDOG_REBOOT)),
                        JSON_BUILD_PAIR_FINITE_USEC("KExecWatchdogUSec", manager_get_watchdog(m, WATCHDOG_KEXEC)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ServiceWatchdogs", m->service_watchdogs),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimerAccuracyUSec", m->defaults.timer_accuracy_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutStartUSec", m->defaults.timeout_start_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutStopUSec", m->defaults.timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutAbortUSec", manager_default_timeout_abort_usec(m)),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultDeviceTimeoutUSec", m->defaults.device_timeout_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultRestartUSec", m->defaults.restart_usec),
                        JSON_BUILD_PAIR_RATELIMIT("DefaultStartLimit", &m->defaults.start_limit),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultCPUAccounting", m->defaults.cpu_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultBlockIOAccounting", m->defaults.blockio_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultIOAccounting", m->defaults.io_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultIPAccounting", m->defaults.ip_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultMemoryAccounting", m->defaults.memory_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultTasksAccounting", m->defaults.tasks_accounting),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitCPU", rlimit_build_json, m->defaults.rlimit[RLIMIT_CPU]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitFSIZE", rlimit_build_json, m->defaults.rlimit[RLIMIT_FSIZE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitDATA", rlimit_build_json, m->defaults.rlimit[RLIMIT_DATA]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitSTACK", rlimit_build_json, m->defaults.rlimit[RLIMIT_STACK]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitCORE", rlimit_build_json, m->defaults.rlimit[RLIMIT_CORE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitRSS", rlimit_build_json, m->defaults.rlimit[RLIMIT_RSS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitNOFILE", rlimit_build_json, m->defaults.rlimit[RLIMIT_NOFILE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitAS", rlimit_build_json, m->defaults.rlimit[RLIMIT_AS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitNPROC", rlimit_build_json, m->defaults.rlimit[RLIMIT_NPROC]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitMEMLOCK", rlimit_build_json, m->defaults.rlimit[RLIMIT_MEMLOCK]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitLOCKS", rlimit_build_json, m->defaults.rlimit[RLIMIT_LOCKS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitSIGPENDING", rlimit_build_json, m->defaults.rlimit[RLIMIT_SIGPENDING]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitMSGQUEUE", rlimit_build_json, m->defaults.rlimit[RLIMIT_MSGQUEUE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitNICE", rlimit_build_json, m->defaults.rlimit[RLIMIT_NICE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitRTPRIO", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTPRIO]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DefaultLimitRTTIME", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTTIME]),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DefaultTasksMax", cgroup_tasks_max_resolve(&m->defaults.tasks_max)),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultMemoryPressureThresholdUSec", m->defaults.memory_pressure_threshold_usec),
                        SD_JSON_BUILD_PAIR_STRING("DefaultMemoryPressureWatch", cgroup_pressure_watch_to_string(m->defaults.memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimerSlackNSec", (uint64_t) prctl(PR_GET_TIMERSLACK)),
                        SD_JSON_BUILD_PAIR_STRING("DefaultOOMPolicy", oom_policy_to_string(m->defaults.oom_policy)),
                        SD_JSON_BUILD_PAIR_INTEGER("DefaultOOMScoreAdjust", m->defaults.oom_score_adjust),
                        SD_JSON_BUILD_PAIR_STRING("CtrlAltDelBurstAction", emergency_action_to_string(m->cad_burst_action)));
}

static int manager_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        dual_timestamp watchdog_last_ping = {
                .monotonic = watchdog_get_last_ping(CLOCK_MONOTONIC),
                .realtime = watchdog_get_last_ping(CLOCK_REALTIME),
        };
        _cleanup_strv_free_ char **taints = NULL;

        taints = taint_strv();
        if (!taints)
                return -ENOMEM;

        return sd_json_buildo(ASSERT_PTR(ret),
                SD_JSON_BUILD_PAIR_STRING("Virtualization", virtualization_to_string(detect_virtualization())),
                SD_JSON_BUILD_PAIR_STRING("ConfidentialVirtualization", confidential_virtualization_to_string(detect_confidential_virtualization())),
                SD_JSON_BUILD_PAIR_STRV("Taints", taints),
                JSON_BUILD_PAIR_STRING_NON_EMPTY("ConfirmSpawn", manager_get_confirm_spawn(m)),
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
                SD_JSON_BUILD_PAIR_CONDITION(m->show_status_overridden != _SHOW_STATUS_INVALID, "ShowStatus", SD_JSON_BUILD_BOOLEAN(manager_get_show_status_on(m))),
                JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogLevel", log_level_build_runtime_json, m),
                SD_JSON_BUILD_PAIR_CONDITION(m->log_target_overridden, "LogTarget", SD_JSON_BUILD_STRING(log_target_to_string(log_get_target()))),
                SD_JSON_BUILD_PAIR_UNSIGNED("NNames", hashmap_size(m->units)),
                SD_JSON_BUILD_PAIR_UNSIGNED("NFailedUnits", set_size(m->failed_units)),
                SD_JSON_BUILD_PAIR_UNSIGNED("NJobs", hashmap_size(m->jobs)),
                SD_JSON_BUILD_PAIR_UNSIGNED("NInstalledJobs", m->n_installed_jobs),
                SD_JSON_BUILD_PAIR_UNSIGNED("NFailedJobs", m->n_failed_jobs),
                SD_JSON_BUILD_PAIR_REAL("Progress", manager_get_progress(m)),
                JSON_BUILD_PAIR_CALLBACK_NON_NULL("Environment", manager_environment_build_json, m),
                JSON_BUILD_PAIR_STRING_NON_EMPTY("WatchdogDevice", watchdog_get_device()),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("WatchdogLastPingTimestamp", &watchdog_last_ping),
                JSON_BUILD_PAIR_STRING_NON_EMPTY("ControlGroup", m->cgroup_root),
                SD_JSON_BUILD_PAIR_STRING("SystemState", manager_state_to_string(manager_state(m))),
                SD_JSON_BUILD_PAIR_UNSIGNED("ExitCode", m->return_value));
}

int vl_method_describe_manager(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(parameters);

        if (sd_json_variant_elements(parameters) > 0)
                return sd_varlink_error_invalid_parameter(link, parameters);

        r = sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR_CALLBACK("Context", manager_context_build_json, manager),
                        SD_JSON_BUILD_PAIR_CALLBACK("Runtime", manager_runtime_build_json, manager));
        if (r < 0)
                return log_error_errno(r, "Failed to build manager JSON data: %m");

        return sd_varlink_reply(link, v);
}
