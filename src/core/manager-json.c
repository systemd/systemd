/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/prctl.h>

#include "build.h"
#include "confidential-virt.h"
#include "json-util.h"
#include "manager-json.h"
#include "manager.h"
#include "manager.h"
#include "rlimit-util.h"
#include "syslog-util.h"
#include "taint.h"
#include "version.h"
#include "virt.h"
#include "watchdog.h"

static int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        struct rlimit *rl = userdata, buf = {};

        assert(name);
        assert(ret);

        if (rl)
                buf = *rl;
        else {
                const char *p;
                int z;

                /* Skip over any prefix, such as "Default" */
                assert_se(p = strstrafter(name, "Limit"));

                z = rlimit_from_string(p);
                assert(z >= 0);

                (void) getrlimit(z, &buf);
        }

        /* rlim_t might have different sizes, let's map RLIMIT_INFINITY to UINT64_MAX, so that it is the same
         * on all archs */
        return sd_json_build(ret, SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR_UNSIGNED("soft", buf.rlim_cur),
                        SD_JSON_BUILD_PAIR_UNSIGNED("hard", buf.rlim_max)));
}

static int manager_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_free_ char **taints = NULL;

        taints = taint_strv();
        if (!taints)
                return -ENOMEM;

        return sd_json_build(ASSERT_PTR(ret), SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR_STRING("version", GIT_VERSION),
                        SD_JSON_BUILD_PAIR_STRING("features", systemd_features),
                        SD_JSON_BUILD_PAIR_STRING("architecture", architecture_to_string(uname_architecture())),
                        SD_JSON_BUILD_PAIR_STRING("virtualization", virtualization_to_string(detect_virtualization())),
                        SD_JSON_BUILD_PAIR_STRING("confidentialVirtualization", confidential_virtualization_to_string(detect_confidential_virtualization())),
                        SD_JSON_BUILD_PAIR_STRV("taints", taints),
                        SD_JSON_BUILD_PAIR_CONDITION(!!manager_get_confirm_spawn(m), "confirmSpawn", SD_JSON_BUILD_STRING(manager_get_confirm_spawn(m))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("showStatus", manager_get_show_status_on(m)),
                        SD_JSON_BUILD_PAIR_STRV("unitPath", m->lookup_paths.search_path),
                        SD_JSON_BUILD_PAIR_STRING("defaultStandardOutput", exec_output_to_string(m->defaults.std_output)),
                        SD_JSON_BUILD_PAIR_STRING("defaultStandardError", exec_output_to_string(m->defaults.std_error)),
                        JSON_BUILD_PAIR_FINITE_USEC("runtimeWatchdogUSec", manager_get_watchdog(m, WATCHDOG_RUNTIME)),
                        JSON_BUILD_PAIR_FINITE_USEC("runtimeWatchdogPreUSec", manager_get_watchdog(m, WATCHDOG_PRETIMEOUT)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->watchdog_pretimeout_governor, "runtimeWatchdogPreGovernor", SD_JSON_BUILD_STRING(m->watchdog_pretimeout_governor)),
                        JSON_BUILD_PAIR_FINITE_USEC("rebootWatchdogUSec", manager_get_watchdog(m, WATCHDOG_REBOOT)),
                        JSON_BUILD_PAIR_FINITE_USEC("kexecWatchdogUSec", manager_get_watchdog(m, WATCHDOG_KEXEC)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("serviceWatchdogs", m->service_watchdogs),
                        JSON_BUILD_PAIR_FINITE_USEC("defaultTimerAccuracyUSec", m->defaults.timer_accuracy_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("defaultTimeoutStartUSec", m->defaults.timeout_start_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("defaultTimeoutStopUSec", m->defaults.timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("defaultTimeoutAbortUSec", manager_default_timeout_abort_usec(m)),
                        JSON_BUILD_PAIR_FINITE_USEC("defaultDeviceTimeoutUSec", m->defaults.device_timeout_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("defaultRestartUSec", m->defaults.restart_usec),
                        JSON_BUILD_PAIR_RATELIMIT("defaultStartLimit", &m->defaults.start_limit),
                        SD_JSON_BUILD_PAIR_BOOLEAN("defaultCPUAccounting", m->defaults.cpu_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("defaultBlockIOAccounting", m->defaults.blockio_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("defaultIOAccounting", m->defaults.io_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("defaultIPAccounting", m->defaults.ip_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("defaultMemoryAccounting", m->defaults.memory_accounting),
                        SD_JSON_BUILD_PAIR_BOOLEAN("defaultTasksAccounting", m->defaults.tasks_accounting),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitCPU", rlimit_build_json, m->defaults.rlimit[RLIMIT_CPU]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitFSIZE", rlimit_build_json, m->defaults.rlimit[RLIMIT_FSIZE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitDATA", rlimit_build_json, m->defaults.rlimit[RLIMIT_DATA]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitSTACK", rlimit_build_json, m->defaults.rlimit[RLIMIT_STACK]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitCORE", rlimit_build_json, m->defaults.rlimit[RLIMIT_CORE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitRSS", rlimit_build_json, m->defaults.rlimit[RLIMIT_RSS]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitNOFILE", rlimit_build_json, m->defaults.rlimit[RLIMIT_NOFILE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitAS", rlimit_build_json, m->defaults.rlimit[RLIMIT_AS]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitNPROC", rlimit_build_json, m->defaults.rlimit[RLIMIT_NPROC]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitMEMLOCK", rlimit_build_json, m->defaults.rlimit[RLIMIT_MEMLOCK]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitLOCKS", rlimit_build_json, m->defaults.rlimit[RLIMIT_LOCKS]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitSIGPENDING", rlimit_build_json, m->defaults.rlimit[RLIMIT_SIGPENDING]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitMSGQUEUE", rlimit_build_json, m->defaults.rlimit[RLIMIT_MSGQUEUE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitNICE", rlimit_build_json, m->defaults.rlimit[RLIMIT_NICE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitRTPRIO", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTPRIO]),
                        SD_JSON_BUILD_PAIR_CALLBACK("defaultLimitRTTIME", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTTIME]),
                        SD_JSON_BUILD_PAIR_UNSIGNED("defaultTasksMax", cgroup_tasks_max_resolve(&m->defaults.tasks_max)),
                        JSON_BUILD_PAIR_FINITE_USEC("defaultMemoryPressureThresholdUSec", m->defaults.memory_pressure_threshold_usec),
                        SD_JSON_BUILD_PAIR_STRING("defaultMemoryPressureWatch", cgroup_pressure_watch_to_string(m->defaults.memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("timerSlackNSec", (uint64_t) prctl(PR_GET_TIMERSLACK)),
                        SD_JSON_BUILD_PAIR_STRING("defaultOOMPolicy", oom_policy_to_string(m->defaults.oom_policy)),
                        SD_JSON_BUILD_PAIR_INTEGER("defaultOOMScoreAdjust", m->defaults.oom_score_adjust),
                        SD_JSON_BUILD_PAIR_STRING("ctrlAltDelBurstAction", emergency_action_to_string(m->cad_burst_action))));
}

static int log_level_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(ret);

        r = log_level_to_string_alloc(log_get_max_level(), &t);
        if (r < 0)
                return r;

        return sd_json_variant_new_string(ret, t);
}

static int manager_environment_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = manager_get_effective_environment(m, &l);
        if (r < 0)
                return r;

        STRV_FOREACH(s, l) {
                _cleanup_free_ char *key = NULL;
                const char *p = *s;

                r = extract_first_word(&p, &key, "=", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;

                r = sd_json_variant_set_field_string(&v, key, *s);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int manager_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        dual_timestamp watchdog_last_ping = {
                .monotonic = watchdog_get_last_ping(CLOCK_MONOTONIC),
                .realtime = watchdog_get_last_ping(CLOCK_REALTIME),
        };

        return sd_json_build(ASSERT_PTR(ret), SD_JSON_BUILD_OBJECT(
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("firmwareTimestamp", &m->timestamps[MANAGER_TIMESTAMP_FIRMWARE]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("loaderTimestamp", &m->timestamps[MANAGER_TIMESTAMP_LOADER]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("kernelTimestamp", &m->timestamps[MANAGER_TIMESTAMP_KERNEL]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("initrdTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("userspaceTimestamp", &m->timestamps[MANAGER_TIMESTAMP_USERSPACE]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("finishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("securityStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_SECURITY_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("securityFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_SECURITY_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("generatorsStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_GENERATORS_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("generatorsFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_GENERATORS_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("unitsLoadStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("unitsLoadFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("unitsLoadTimestamp", &m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("initrdSecurityStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("initrdSecurityFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("initrdGeneratorsStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("initrdGeneratorsFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("initrdUnitsLoadStartTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START]),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("initrdUnitsLoadFinishTimestamp", &m->timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH]),
                SD_JSON_BUILD_PAIR_CALLBACK("logLevel", log_level_build_json, m),
                SD_JSON_BUILD_PAIR_STRING("logTarget", log_target_to_string(log_get_target())),
                SD_JSON_BUILD_PAIR_UNSIGNED("nNames", hashmap_size(m->units)),
                SD_JSON_BUILD_PAIR_UNSIGNED("nFailedUnits", set_size(m->failed_units)),
                SD_JSON_BUILD_PAIR_UNSIGNED("nJobs", hashmap_size(m->jobs)),
                SD_JSON_BUILD_PAIR_UNSIGNED("nInstalledJobs", m->n_installed_jobs),
                SD_JSON_BUILD_PAIR_UNSIGNED("nFailedJobs", m->n_failed_jobs),
                SD_JSON_BUILD_PAIR_REAL("progress", manager_get_progress(m)),
                SD_JSON_BUILD_PAIR_CALLBACK("environment", manager_environment_build_json, m),
                SD_JSON_BUILD_PAIR_CONDITION(!!watchdog_get_device(), "watchdogDevice", SD_JSON_BUILD_STRING(watchdog_get_device())),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("watchdogLastPingTimestamp", &watchdog_last_ping),
                SD_JSON_BUILD_PAIR_CONDITION(!isempty(m->cgroup_root), "controlGroup", SD_JSON_BUILD_STRING(m->cgroup_root)),
                SD_JSON_BUILD_PAIR_STRING("systemState", manager_state_to_string(manager_state(m))),
                SD_JSON_BUILD_PAIR_UNSIGNED("exitCode", m->return_value)));
}

int manager_build_json(Manager *m, sd_json_variant **ret) {
        assert(m);

        return sd_json_build(ASSERT_PTR(ret), SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR_CALLBACK("context", manager_context_build_json, m),
                        SD_JSON_BUILD_PAIR_CALLBACK("runtime", manager_runtime_build_json, m)));
}
