/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syslog.h>

#include "automount.h"
#include "build.h"
#include "confidential-virt.h"
#include "device.h"
#include "exec-credential.h"
#include "fileio.h"
#include "json.h"
#include "dbus-unit.h"
#include "manager-json.h"
#include "in-addr-prefix-util.h"
#include "missing_ioprio.h"
#include "parse-util.h"
#include "rlimit-util.h"
#include "process-util.h"
#include "mount.h"
#include "path.h"
#include "scope.h"
#include "service.h"
#include "signal-util.h"
#include "swap.h"
#include "syslog-util.h"
#include "timer.h"
#include "version.h"
#include "virt.h"
#include "watchdog.h"

#define JSON_BUILD_DUAL_TIMESTAMP(name, t) \
        JSON_BUILD_PAIR_FINITE_USEC(name, t.realtime), \
        JSON_BUILD_PAIR_FINITE_USEC(name "Monotonic", t.monotonic)

static int rlimit_build_json(JsonVariant **ret, const char *name, void *userdata) {
        const char *is_soft;
        struct rlimit *rl = userdata;
        rlim_t x;

        assert(name);
        assert(ret);

        is_soft = endswith(name, "Soft");

        if (rl)
                x = is_soft ? rl->rlim_cur : rl->rlim_max;
        else {
                struct rlimit buf = {};
                const char *s, *p;
                int z;

                /* Chop off "Soft" suffix */
                s = is_soft ? strndupa_safe(name, is_soft - name) : name;

                /* Skip over any prefix, such as "Default" */
                assert_se(p = strstrafter(s, "Limit"));

                z = rlimit_from_string(p);
                assert(z >= 0);

                (void) getrlimit(z, &buf);
                x = is_soft ? buf.rlim_cur : buf.rlim_max;
        }

        /* rlim_t might have different sizes, let's map RLIMIT_INFINITY to UINT64_MAX, so that it is the same
         * on all archs */
        return json_variant_new_unsigned(ret, x == RLIM_INFINITY ? UINT64_MAX : (uint64_t) x);
}

static int manager_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Version", GIT_VERSION),
                        JSON_BUILD_PAIR_STRING("Features", systemd_features),
                        JSON_BUILD_PAIR_STRING("Architecture", architecture_to_string(uname_architecture())),
                        JSON_BUILD_PAIR_STRING("Virtualization", virtualization_to_string(detect_virtualization())),
                        JSON_BUILD_PAIR_STRING("ConfidentialVirtualization", confidential_virtualization_to_string(detect_confidential_virtualization())),
                        JSON_BUILD_PAIR_STRING("Tainted", manager_taint_string(m)),
                        JSON_BUILD_PAIR_BOOLEAN("ConfirmSpawn", manager_get_confirm_spawn(m)),
                        JSON_BUILD_PAIR_BOOLEAN("ShowStatus", manager_get_show_status_on(m)),
                        JSON_BUILD_PAIR_STRV("UnitPath", m->lookup_paths.search_path),
                        JSON_BUILD_PAIR_STRING("DefaultStandardOutput", exec_output_to_string(m->defaults.std_output)),
                        JSON_BUILD_PAIR_STRING("DefaultStandardError", exec_output_to_string(m->defaults.std_error)),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeWatchdogUSec", manager_get_watchdog(m, WATCHDOG_RUNTIME)),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeWatchdogPreUSec", manager_get_watchdog(m, WATCHDOG_PRETIMEOUT)),
                        JSON_BUILD_PAIR_STRING("RuntimeWatchdogPreGovernor", m->watchdog_pretimeout_governor),
                        JSON_BUILD_PAIR_FINITE_USEC("RebootWatchdogUSec", manager_get_watchdog(m, WATCHDOG_REBOOT)),
                        JSON_BUILD_PAIR_FINITE_USEC("KExecWatchdogUSec", manager_get_watchdog(m, WATCHDOG_KEXEC)),
                        JSON_BUILD_PAIR_BOOLEAN("ServiceWatchdogs", m->service_watchdogs),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimerAccuracyUSec", m->defaults.timer_accuracy_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutStartUSec", m->defaults.timeout_start_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutStopUSec", m->defaults.timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultTimeoutAbortUSec", manager_default_timeout_abort_usec(m)),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultDeviceTimeoutUSec", m->defaults.device_timeout_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultRestartUSec", m->defaults.restart_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultStartLimitIntervalUSec", m->defaults.start_limit_interval),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultStartLimitBurst", m->defaults.start_limit_burst),
                        JSON_BUILD_PAIR_BOOLEAN("DefaultCPUAccounting", m->defaults.cpu_accounting),
                        JSON_BUILD_PAIR_BOOLEAN("DefaultBlockIOAccounting", m->defaults.blockio_accounting),
                        JSON_BUILD_PAIR_BOOLEAN("DefaultIOAccounting", m->defaults.io_accounting),
                        JSON_BUILD_PAIR_BOOLEAN("DefaultIPAccounting", m->defaults.ip_accounting),
                        JSON_BUILD_PAIR_BOOLEAN("DefaultMemoryAccounting", m->defaults.memory_accounting),
                        JSON_BUILD_PAIR_BOOLEAN("DefaultTasksAccounting", m->defaults.tasks_accounting),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitCPU", rlimit_build_json, m->defaults.rlimit[RLIMIT_CPU]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitCPUSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_CPU]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitFSIZE", rlimit_build_json, m->defaults.rlimit[RLIMIT_FSIZE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitFSIZESoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_FSIZE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitDATA", rlimit_build_json, m->defaults.rlimit[RLIMIT_DATA]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitDATASoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_DATA]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitSTACK", rlimit_build_json, m->defaults.rlimit[RLIMIT_STACK]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitSTACKSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_STACK]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitCORE", rlimit_build_json, m->defaults.rlimit[RLIMIT_CORE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitCORESoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_CORE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitRSS", rlimit_build_json, m->defaults.rlimit[RLIMIT_RSS]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitRSSSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_RSS]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitNOFILE", rlimit_build_json, m->defaults.rlimit[RLIMIT_NOFILE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitNOFILESoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_NOFILE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitAS", rlimit_build_json, m->defaults.rlimit[RLIMIT_AS]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitASSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_AS]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitNPROC", rlimit_build_json, m->defaults.rlimit[RLIMIT_NPROC]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitNPROCSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_NPROC]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitMEMLOCK", rlimit_build_json, m->defaults.rlimit[RLIMIT_MEMLOCK]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitMEMLOCKSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_MEMLOCK]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitLOCKS", rlimit_build_json, m->defaults.rlimit[RLIMIT_LOCKS]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitLOCKSSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_LOCKS]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitSIGPENDING", rlimit_build_json, m->defaults.rlimit[RLIMIT_SIGPENDING]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitSIGPENDINGSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_SIGPENDING]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitMSGQUEUE", rlimit_build_json, m->defaults.rlimit[RLIMIT_MSGQUEUE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitMSGQUEUESoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_MSGQUEUE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitNICE", rlimit_build_json, m->defaults.rlimit[RLIMIT_NICE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitNICESoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_NICE]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitRTPRIO", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTPRIO]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitRTPRIOSoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTPRIO]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitRTTIME", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTTIME]),
                        JSON_BUILD_PAIR_CALLBACK("DefaultLimitRTTIMESoft", rlimit_build_json, m->defaults.rlimit[RLIMIT_RTTIME]),
                        JSON_BUILD_PAIR_UNSIGNED("DefaultTasksMax", cgroup_tasks_max_resolve(&m->defaults.tasks_max)),
                        JSON_BUILD_PAIR_FINITE_USEC("DefaultMemoryPressureThresholdUSec", m->defaults.memory_pressure_threshold_usec),
                        JSON_BUILD_PAIR_STRING("DefaultMemoryPressureWatch", cgroup_pressure_watch_to_string(m->defaults.memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimerSlackNSec", (uint64_t) prctl(PR_GET_TIMERSLACK)),
                        JSON_BUILD_PAIR_STRING("DefaultOOMPolicy", oom_policy_to_string(m->defaults.oom_policy)),
                        JSON_BUILD_PAIR_INTEGER("DefaultOOMScoreAdjust", m->defaults.oom_score_adjust),
                        JSON_BUILD_PAIR_STRING("CtrlAltDelBurstAction", emergency_action_to_string(m->cad_burst_action))));
}

static int log_level_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(ret);

        r = log_level_to_string_alloc(log_get_max_level(), &t);
        if (r < 0)
                return r;

        return json_variant_new_string(ret, t);
}

static int manager_environment_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = manager_get_effective_environment(m, &l);
        if (r < 0)
                return r;

        return json_variant_new_array_strv(ret, l);
}

static int manager_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                JSON_BUILD_DUAL_TIMESTAMP("FirmwareTimestamp", m->timestamps[MANAGER_TIMESTAMP_FIRMWARE]),
                JSON_BUILD_DUAL_TIMESTAMP("LoaderTimestamp", m->timestamps[MANAGER_TIMESTAMP_LOADER]),
                JSON_BUILD_DUAL_TIMESTAMP("KernelTimestamp", m->timestamps[MANAGER_TIMESTAMP_KERNEL]),
                JSON_BUILD_DUAL_TIMESTAMP("InitRDTimestamp", m->timestamps[MANAGER_TIMESTAMP_INITRD]),
                JSON_BUILD_DUAL_TIMESTAMP("UserspaceTimestamp", m->timestamps[MANAGER_TIMESTAMP_USERSPACE]),
                JSON_BUILD_DUAL_TIMESTAMP("FinishTimestamp", m->timestamps[MANAGER_TIMESTAMP_FINISH]),
                JSON_BUILD_DUAL_TIMESTAMP("SecurityStartTimestamp", m->timestamps[MANAGER_TIMESTAMP_SECURITY_START]),
                JSON_BUILD_DUAL_TIMESTAMP("SecurityFinishTimestamp", m->timestamps[MANAGER_TIMESTAMP_SECURITY_FINISH]),
                JSON_BUILD_DUAL_TIMESTAMP("GeneratorsStartTimestamp", m->timestamps[MANAGER_TIMESTAMP_GENERATORS_START]),
                JSON_BUILD_DUAL_TIMESTAMP("GeneratorsFinishTimestamp", m->timestamps[MANAGER_TIMESTAMP_GENERATORS_FINISH]),
                JSON_BUILD_DUAL_TIMESTAMP("UnitsLoadStartTimestamp", m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_START]),
                JSON_BUILD_DUAL_TIMESTAMP("UnitsLoadFinishTimestamp", m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD_FINISH]),
                JSON_BUILD_DUAL_TIMESTAMP("UnitsLoadTimestamp", m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD]),
                JSON_BUILD_DUAL_TIMESTAMP("InitRDSecurityStartTimestamp", m->timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_START]),
                JSON_BUILD_DUAL_TIMESTAMP("InitRDSecurityFinishTimestamp", m->timestamps[MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH]),
                JSON_BUILD_DUAL_TIMESTAMP("InitRDGeneratorsStartTimestamp", m->timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_START]),
                JSON_BUILD_DUAL_TIMESTAMP("InitRDGeneratorsFinishTimestamp", m->timestamps[MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH]),
                JSON_BUILD_DUAL_TIMESTAMP("InitRDUnitsLoadStartTimestamp", m->timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START]),
                JSON_BUILD_DUAL_TIMESTAMP("InitRDUnitsLoadFinishTimestamp", m->timestamps[MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH]),
                JSON_BUILD_PAIR_CALLBACK("LogLevel", log_level_build_json, m),
                JSON_BUILD_PAIR_STRING("LogTarget", log_target_to_string(log_get_target())),
                JSON_BUILD_PAIR_UNSIGNED("NNames", hashmap_size(m->units)),
                JSON_BUILD_PAIR_UNSIGNED("NFailedUnits", set_size(m->failed_units)),
                JSON_BUILD_PAIR_UNSIGNED("NJobs", hashmap_size(m->jobs)),
                JSON_BUILD_PAIR_UNSIGNED("NInstalledJobs", m->n_installed_jobs),
                JSON_BUILD_PAIR_UNSIGNED("NFailedJobs", m->n_failed_jobs),
                JSON_BUILD_PAIR_REAL("Progress", manager_get_progress(m)),
                JSON_BUILD_PAIR_CALLBACK("Environment", manager_environment_build_json, m),
                JSON_BUILD_PAIR_STRING("WatchdogDevice", watchdog_get_device()),
                JSON_BUILD_PAIR_FINITE_USEC("WatchdogLastPingTimestamp", watchdog_get_last_ping(CLOCK_REALTIME)),
                JSON_BUILD_PAIR_FINITE_USEC("WatchdogLastPingTimestampMonotonic", watchdog_get_last_ping(CLOCK_MONOTONIC)),
                JSON_BUILD_PAIR_STRING("ControlGroup", m->cgroup_root),
                JSON_BUILD_PAIR_STRING("SystemState", manager_state_to_string(manager_state(m))),
                JSON_BUILD_PAIR_UNSIGNED("ExitCode", m->return_value)));
}

static int unit_dependencies_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Unit *u = ASSERT_PTR(userdata), *other;
        UnitDependency d;
        void *value;
        int r;

        assert(name);
        assert(ret);

        d = unit_dependency_from_string(name);
        assert_se(d >= 0);

        HASHMAP_FOREACH_KEY(value, other, unit_get_dependencies(u, d)) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_STRING(other->id));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_requires_mounts_for_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Hashmap *requires_mounts_for = userdata;
        const char *p;
        void *value;
        int r;

        assert(ret);

        HASHMAP_FOREACH_KEY(value, p, requires_mounts_for) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_STRING(p));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_conditions_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Condition *list = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        const char *(*to_string)(ConditionType type) = NULL;
        int r;

        assert(name);
        assert(ret);

        to_string = streq(name, "Asserts") ? assert_type_to_string : condition_type_to_string;

        LIST_FOREACH(conditions, c, list) {
                int tristate;

                tristate =
                        c->result == CONDITION_UNTESTED ? 0 :
                        c->result == CONDITION_SUCCEEDED ? 1 : -1;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Type", to_string(c->type)),
                                JSON_BUILD_PAIR_BOOLEAN("Trigger", c->trigger),
                                JSON_BUILD_PAIR_BOOLEAN("Negate", c->negate),
                                JSON_BUILD_PAIR_STRING("Parameter", c->parameter),
                                JSON_BUILD_PAIR_INTEGER("TriState", tristate)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_mask_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupMask mask = PTR_TO_INT(userdata);
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ret);

        for (CGroupController ctrl = 0; ctrl < _CGROUP_CONTROLLER_MAX; ctrl++) {
                if ((mask & CGROUP_CONTROLLER_TO_MASK(ctrl)) == 0)
                        continue;

                r = json_variant_append_arrayb(&v, JSON_BUILD_STRING(cgroup_controller_to_string(ctrl)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cpu_set_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_free_ uint8_t *array = NULL;
        CPUSet *cpuset = ASSERT_PTR(userdata);
        size_t allocated;
        int r;

        assert(ret);

        r = cpu_set_to_dbus(cpuset, &array, &allocated);
        if (r < 0)
                return r;

        return json_variant_new_array_bytes(ret, array, allocated);
}

static int cgroup_io_device_weights_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupIODeviceWeight *weights = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ret);

        LIST_FOREACH(device_weights, w, weights) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", w->path),
                                JSON_BUILD_PAIR_UNSIGNED("Weight", w->weight)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_io_device_limits_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupIODeviceLimit *limits = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(name);
        assert(ret);

        LIST_FOREACH(device_limits, l, limits) {
                CGroupIOLimitType type;

                type = cgroup_io_limit_type_from_string(name);
                if (type < 0 || l->limits[type] == cgroup_io_limit_defaults[type])
                        continue;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", l->path),
                                JSON_BUILD_PAIR_UNSIGNED("Limit", l->limits[type])));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int cgroup_io_device_latencies_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupIODeviceLatency *latencies = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ret);

        LIST_FOREACH(device_latencies, l, latencies) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", l->path),
                                JSON_BUILD_PAIR_UNSIGNED("TargetUSec", l->target_usec)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_blockio_device_weights_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupBlockIODeviceWeight *weights = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ret);

        LIST_FOREACH(device_weights, w, weights) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", w->path),
                                JSON_BUILD_PAIR_UNSIGNED("Weight", w->weight)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_blockio_device_bandwidths_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupBlockIODeviceBandwidth *bandwiths = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(name);
        assert(ret);

        LIST_FOREACH(device_bandwidths, b, bandwiths) {
                uint64_t value;

                if (streq(name, "BlockIOReadBandwidth"))
                        value = b->rbps;
                else
                        value = b->wbps;

                if (value == CGROUP_LIMIT_MAX)
                        continue;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", b->path),
                                JSON_BUILD_PAIR_UNSIGNED("Bandwith", value)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_device_allow_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupDeviceAllow *allow = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        LIST_FOREACH(device_allow, a, allow) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", a->path),
                                JSON_BUILD_PAIR_STRING("Permissions", cgroup_device_permissions_to_string(a->permissions))));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_ip_address_access_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Set *prefixes = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        struct in_addr_prefix *i;
        int r;

        assert(ret);

        SET_FOREACH(i, prefixes) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", i->family),
                                JSON_BUILD_PAIR_BYTE_ARRAY("Address", &i->address, FAMILY_ADDRESS_SIZE(i->family)),
                                JSON_BUILD_PAIR_UNSIGNED("PrefixLen", i->prefixlen)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_bpf_program_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupBPFForeignProgram *programs = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ret);

        LIST_FOREACH(programs, p, programs) {
                const char *attach_type = bpf_cgroup_attach_type_to_string(p->attach_type);

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("AttachType", attach_type),
                                JSON_BUILD_PAIR_STRING("Path", p->bpffs_path)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_socket_bind_build_json(JsonVariant **ret, const char *name, void *userdata) {
        CGroupSocketBindItem *items = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ret);

        LIST_FOREACH(socket_bind_items, i, items) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", i->address_family),
                                JSON_BUILD_PAIR_INTEGER("Protocol", i->ip_protocol),
                                JSON_BUILD_PAIR_UNSIGNED("NumberOfPorts", i->nr_ports),
                                JSON_BUILD_PAIR_UNSIGNED("MinimumPort", i->port_min)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_nft_set_build_json(JsonVariant **ret, const char *name, void *userdata) {
        NFTSetContext *c = ASSERT_PTR(userdata);
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ret);

        FOREACH_ARRAY(nft_set, c->sets, c->n_sets) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Source", nft_set_source_to_string(nft_set->source)),
                                JSON_BUILD_PAIR_INTEGER("Protocol", nft_set->nfproto),
                                JSON_BUILD_PAIR_STRING("Table", nft_set->table),
                                JSON_BUILD_PAIR_STRING("Set", nft_set->set)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupContext *c;

        assert(ret);

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Slice", unit_slice_name(u)),
                        JSON_BUILD_PAIR_BOOLEAN("Delegate", c->delegate),
                        JSON_BUILD_PAIR_CALLBACK("DelegateControllers", cgroup_mask_build_json, INT_TO_PTR(c->delegate_controllers)),
                        JSON_BUILD_PAIR_STRING("DelegateSubgroup", c->delegate_subgroup),
                        JSON_BUILD_PAIR_BOOLEAN("CPUAccounting", c->cpu_accounting),
                        JSON_BUILD_PAIR_UNSIGNED("CPUWeight", c->cpu_weight),
                        JSON_BUILD_PAIR_UNSIGNED("StartupCPUWeight", c->startup_cpu_weight),
                        JSON_BUILD_PAIR_UNSIGNED("CPUShares", c->cpu_shares),
                        JSON_BUILD_PAIR_UNSIGNED("StartupCPUShares", c->startup_cpu_shares),
                        JSON_BUILD_PAIR_FINITE_USEC("CPUQuotaPerSecUSec", c->cpu_quota_per_sec_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("CPUQuotaPeriodUSec", c->cpu_quota_period_usec),
                        JSON_BUILD_PAIR_CALLBACK("AllowedCPUs", cpu_set_build_json, &c->cpuset_cpus),
                        JSON_BUILD_PAIR_CALLBACK("StartupAllowedCPUs", cpu_set_build_json, &c->startup_cpuset_cpus),
                        JSON_BUILD_PAIR_CALLBACK("AllowedMemoryNodes", cpu_set_build_json, &c->cpuset_mems),
                        JSON_BUILD_PAIR_CALLBACK("StartupAllowedMemoryNodes", cpu_set_build_json, &c->startup_cpuset_mems),
                        JSON_BUILD_PAIR_BOOLEAN("IOAccounting", c->io_accounting),
                        JSON_BUILD_PAIR_UNSIGNED("IOWeight", c->io_weight),
                        JSON_BUILD_PAIR_UNSIGNED("StartupIOWeight", c->startup_io_weight),
                        JSON_BUILD_PAIR_CALLBACK("IODeviceWeight", cgroup_io_device_weights_build_json, c->io_device_weights),
                        JSON_BUILD_PAIR_CALLBACK("IOReadBandwidthMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK("IOWriteBandwidthMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK("IOReadIOPSMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK("IOWriteIOPSMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK("IODeviceLatencyTargetUSec", cgroup_io_device_latencies_build_json, c->io_device_latencies),
                        JSON_BUILD_PAIR_BOOLEAN("BlockIOAccounting", c->blockio_accounting),
                        JSON_BUILD_PAIR_UNSIGNED("BlockIOWeight", c->blockio_weight),
                        JSON_BUILD_PAIR_UNSIGNED("StartupBlockIOWeight", c->startup_blockio_weight),
                        JSON_BUILD_PAIR_CALLBACK("BlockIODeviceWeight", cgroup_blockio_device_weights_build_json, c->blockio_device_weights),
                        JSON_BUILD_PAIR_CALLBACK("BlockIOReadBandwidth", cgroup_blockio_device_bandwidths_build_json, c->blockio_device_bandwidths),
                        JSON_BUILD_PAIR_CALLBACK("BlockIOWriteBandwidth", cgroup_blockio_device_bandwidths_build_json, c->blockio_device_bandwidths),
                        JSON_BUILD_PAIR_BOOLEAN("MemoryAccounting", c->memory_accounting),
                        JSON_BUILD_PAIR_UNSIGNED("DefaultMemoryLow", c->default_memory_low),
                        JSON_BUILD_PAIR_UNSIGNED("DefaultStartupMemoryLow", c->default_startup_memory_low),
                        JSON_BUILD_PAIR_UNSIGNED("DefaultMemoryMin", c->default_memory_min),
                        JSON_BUILD_PAIR_UNSIGNED("MemoryMin", c->memory_min),
                        JSON_BUILD_PAIR_UNSIGNED("MemoryLow", c->memory_low),
                        JSON_BUILD_PAIR_UNSIGNED("StartupMemoryLow", c->startup_memory_low),
                        JSON_BUILD_PAIR_UNSIGNED("MemoryHigh", c->startup_memory_high),
                        JSON_BUILD_PAIR_UNSIGNED("StartupMemoryHigh", c->startup_memory_high),
                        JSON_BUILD_PAIR_UNSIGNED("MemoryMax", c->memory_max),
                        JSON_BUILD_PAIR_UNSIGNED("StartupMemoryMax", c->startup_memory_max),
                        JSON_BUILD_PAIR_UNSIGNED("MemorySwapMax", c->memory_swap_max),
                        JSON_BUILD_PAIR_UNSIGNED("StartupMemorySwapMax", c->startup_memory_swap_max),
                        JSON_BUILD_PAIR_UNSIGNED("MemoryZSwapMax", c->memory_zswap_max),
                        JSON_BUILD_PAIR_UNSIGNED("StartupMemoryZSwapMax", c->startup_memory_zswap_max),
                        JSON_BUILD_PAIR_UNSIGNED("MemoryLimit", c->memory_limit),
                        JSON_BUILD_PAIR_STRING("DevicePolicy", cgroup_device_policy_to_string(c->device_policy)),
                        JSON_BUILD_PAIR_CALLBACK("DeviceAllow", cgroup_device_allow_build_json, c->device_allow),
                        JSON_BUILD_PAIR_BOOLEAN("TasksAccounting", c->tasks_accounting),
                        JSON_BUILD_PAIR_UNSIGNED("TasksMax", cgroup_tasks_max_resolve(&c->tasks_max)),
                        JSON_BUILD_PAIR_BOOLEAN("IPAccounting", c->ip_accounting),
                        JSON_BUILD_PAIR_CALLBACK("IPAddressAllow", cgroup_ip_address_access_build_json, c->ip_address_allow),
                        JSON_BUILD_PAIR_CALLBACK("IPAddressDeny", cgroup_ip_address_access_build_json, c->ip_address_deny),
                        JSON_BUILD_PAIR_STRV("IPIngressFilterPath", c->ip_filters_ingress),
                        JSON_BUILD_PAIR_STRV("IPEgressFilterPath", c->ip_filters_egress),
                        JSON_BUILD_PAIR_CALLBACK("DisableControllers", cgroup_mask_build_json, INT_TO_PTR(c->disable_controllers)),
                        JSON_BUILD_PAIR_STRING("ManagedOOMSwap", managed_oom_mode_to_string(c->moom_swap)),
                        JSON_BUILD_PAIR_STRING("ManagedOOMMemoryPressure", managed_oom_mode_to_string(c->moom_mem_pressure)),
                        JSON_BUILD_PAIR_UNSIGNED("ManagedOOMMemoryPressureLimit", c->moom_mem_pressure_limit),
                        JSON_BUILD_PAIR_STRING("ManagedOOMPreference", managed_oom_preference_to_string(c->moom_preference)),
                        JSON_BUILD_PAIR_CALLBACK("BPFProgram", cgroup_bpf_program_build_json, c->bpf_foreign_programs),
                        JSON_BUILD_PAIR_CALLBACK("SocketBindAllow", cgroup_socket_bind_build_json, c->socket_bind_allow),
                        JSON_BUILD_PAIR_CALLBACK("SocketBindDeny", cgroup_socket_bind_build_json, c->socket_bind_deny),
                        JSON_BUILD_PAIR_OBJECT("RestrictNetworkInterfaces",
                                        JSON_BUILD_PAIR_BOOLEAN("IsAllowList", c->restrict_network_interfaces_is_allow_list),
                                        JSON_BUILD_PAIR_STRING_SET("Interfaces", c->restrict_network_interfaces)),
                        JSON_BUILD_PAIR_STRING("MemoryPressureWatch", cgroup_pressure_watch_to_string(c->memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("MemoryPressureThresholdUSec", c->memory_pressure_threshold_usec),
                        JSON_BUILD_PAIR_CALLBACK("NFTSet", cgroup_nft_set_build_json, &c->nft_set_context)));
}

static int automount_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Automount *a = ASSERT_PTR(AUTOMOUNT(userdata));

        return json_build(ret, "Automount", JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Where", a->where),
                        JSON_BUILD_PAIR_STRING("ExtraOptions", a->extra_options),
                        JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", a->directory_mode),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutIdleUSec", a->timeout_idle_usec)));
}

static int environment_files_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        char **environment_files = userdata;
        int r;

        assert(ret);

        STRV_FOREACH(j, environment_files) {
                const char *fn = *j;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", fn[0] == '-' ? fn + 1 : fn),
                                JSON_BUILD_PAIR_BOOLEAN("Graceful", fn[0] == '-')));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int working_directory_build_json(JsonVariant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        const char *wd;

        assert(ret);

        if (c->working_directory_home)
                wd = "~";
        else
                wd = c->working_directory;

        if (c->working_directory_missing_ok)
                wd = strjoina("!", wd);

        return json_variant_set_field_string(ret, "WorkingDirectory", wd);
}

static int root_image_options_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        MountOptions *root_image_options = userdata;
        int r;

        LIST_FOREACH(mount_options, m, root_image_options) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("PartitionDesignator", partition_designator_to_string(m->partition_designator)),
                                JSON_BUILD_PAIR_STRING("Options", m->options)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int extension_images_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < c->n_extension_images; i++) {
                _cleanup_(json_variant_unrefp) JsonVariant *mo = NULL;

                LIST_FOREACH(mount_options, m, c->extension_images[i].mount_options) {
                        r = json_variant_append_arrayb(&mo, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("PartitionDesignator", partition_designator_to_string(m->partition_designator)),
                                        JSON_BUILD_PAIR_STRING("Options", m->options)));
                        if (r < 0)
                                return r;
                }

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Source", c->extension_images[i].source),
                                JSON_BUILD_PAIR_BOOLEAN("IgnoreEnoent", c->extension_images[i].ignore_enoent),
                                JSON_BUILD_PAIR_VARIANT("MountOptions", mo)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int mount_images_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < c->n_mount_images; i++) {
                _cleanup_(json_variant_unrefp) JsonVariant *mo = NULL;

                LIST_FOREACH(mount_options, m, c->mount_images[i].mount_options) {
                        r = json_variant_append_arrayb(&mo, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("PartitionDesignator", partition_designator_to_string(m->partition_designator)),
                                        JSON_BUILD_PAIR_STRING("Options", m->options)));
                        if (r < 0)
                                return r;
                }

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Source", c->mount_images[i].source),
                                JSON_BUILD_PAIR_STRING("Destination", c->mount_images[i].destination),
                                JSON_BUILD_PAIR_BOOLEAN("IgnoreEnoent", c->mount_images[i].ignore_enoent)),
                                JSON_BUILD_PAIR_VARIANT("MountOptions", mo));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cpu_affinity_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(cpu_set_reset) CPUSet s = {};
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        if (c->cpu_affinity_from_numa) {
                r = numa_to_cpu_set(&c->numa_policy, &s);
                if (r < 0)
                        return r;
        }

        return json_build(ret, JSON_BUILD_CALLBACK(cpu_set_build_json, c->cpu_affinity_from_numa ? &s : &c->cpu_set));
}

static int log_extra_fields_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < c->n_log_extra_fields; i++) {
                r = json_variant_append_arrayb(&v,
                                JSON_BUILD_BYTE_ARRAY(c->log_extra_fields[i].iov_base,
                                                      c->log_extra_fields[i].iov_len));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int log_filter_patterns_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        const char *pattern;
        int r;

        SET_FOREACH(pattern, c->log_filter_allowed_patterns) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_BOOLEAN("IsAllowPattern", true),
                                JSON_BUILD_PAIR_STRING("Pattern", pattern)));
                if (r < 0)
                        return r;
        }

        SET_FOREACH(pattern, c->log_filter_denied_patterns) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_BOOLEAN("IsAllowPattern", false),
                                JSON_BUILD_PAIR_STRING("Pattern", pattern)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int set_credential_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Hashmap *set_credentials = userdata;
        ExecSetCredential *sc;
        int r;

        assert(ret);

        HASHMAP_FOREACH(sc, set_credentials) {
                if (sc->encrypted != streq(name, "SetCredentialEncrypted"))
                        continue;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Id", sc->id),
                                JSON_BUILD_PAIR_BYTE_ARRAY("Value", sc->data, sc->size)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int load_credential_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Hashmap *load_credentials = userdata;
        ExecLoadCredential *lc;
        int r;

        assert(ret);

        HASHMAP_FOREACH(lc, load_credentials) {
                if (lc->encrypted != streq(name, "LoadCredentialEncrypted"))
                        continue;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Id", lc->id),
                                JSON_BUILD_PAIR_STRING("Path", lc->path)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int syscall_filter_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_syscall_filter(c);
        if (!l)
                return -ENOMEM;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_BOOLEAN("IsAllowList", c->syscall_allow_list),
                        JSON_BUILD_PAIR_STRV("SystemCalls", l)));
}

static int syscall_archs_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_syscall_archs(c);
        if (!l)
                return -ENOMEM;

        return json_variant_new_array_strv(ret, l);
}

static int syscall_log_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_syscall_log(c);
        if (!l)
                return -ENOMEM;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_BOOLEAN("IsAllowList", c->syscall_allow_list),
                        JSON_BUILD_PAIR_STRV("SystemCalls", l)));
}

static int address_families_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_address_families(c);
        if (!l)
                return -ENOMEM;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_BOOLEAN("IsAllowList", c->address_families_allow_list),
                        JSON_BUILD_PAIR_STRV("AddressFamilies", l)));
}

static int exec_dir_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecDirectory *dirs = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < dirs->n_items; i++)
                STRV_FOREACH(dst, dirs->items[i].symlinks) {
                        r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("Path", dirs->items[i].path),
                                        JSON_BUILD_PAIR_STRING("Destination", *dst),
                                        JSON_BUILD_PAIR_UNSIGNED("Flags", 0)));
                        if (r < 0)
                                return r;
                }

        *ret = TAKE_PTR(v);
        return 0;
}

static int exec_dir_symlink_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecDirectory *dirs = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < dirs->n_items; i++)
                STRV_FOREACH(dst, dirs->items[i].symlinks) {
                        r = json_variant_append_arrayb(&v, JSON_BUILD_STRING(dirs->items[i].path));
                        if (r < 0)
                                return r;
                }

        *ret = TAKE_PTR(v);
        return 0;
}

static int restrict_filesystems_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_restrict_filesystems(c);
        if (!l)
                return -ENOMEM;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_BOOLEAN("IsAllowList", c->restrict_filesystems_allow_list),
                        JSON_BUILD_PAIR_STRV("Filesystems", l)));
}

static int bind_paths_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        bool ro;
        int r;

        assert(ret);

        ro = strstr(name, "ReadOnly");

        for (size_t i = 0; i < c->n_bind_mounts; i++) {
                if (ro != c->bind_mounts[i].read_only)
                        continue;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Source", c->bind_mounts[i].source),
                                JSON_BUILD_PAIR_STRING("Destination", c->bind_mounts[i].destination),
                                JSON_BUILD_PAIR_BOOLEAN("IgnoreEnoent", c->bind_mounts[i].ignore_enoent),
                                JSON_BUILD_PAIR_UNSIGNED("Flags", c->bind_mounts[i].recursive ? MS_REC : 0)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int temporary_filesystems_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (unsigned i = 0; i < c->n_temporary_filesystems; i++) {
                TemporaryFileSystem *t = c->temporary_filesystems + i;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", t->path),
                                JSON_BUILD_PAIR_STRING("Options", t->options)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int image_policy_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_free_ char *s = NULL;
        ImagePolicy *policy = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = image_policy_to_string(policy ?: &image_policy_service, /* simplify= */ true, &s);
        if (r < 0)
                return r;

        return json_build(ret, JSON_BUILD_STRING(s));
}

static int exec_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        ExecContext *c;

        c = unit_get_exec_context(ASSERT_PTR(userdata));
        if (!c)
                return 0;

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRV("Environment", c->environment),
                        JSON_BUILD_PAIR_CALLBACK("EnvironmentFiles", environment_files_build_json, c->environment_files),
                        JSON_BUILD_PAIR_STRV("PassEnvironment", c->pass_environment),
                        JSON_BUILD_PAIR_STRV("UnsetEnvironment", c->unset_environment),
                        JSON_BUILD_PAIR_UNSIGNED("UMask", c->umask),
                        JSON_BUILD_PAIR_CALLBACK("LimitCPU", rlimit_build_json, c->rlimit[RLIMIT_CPU]),
                        JSON_BUILD_PAIR_CALLBACK("LimitCPUSoft", rlimit_build_json, c->rlimit[RLIMIT_CPU]),
                        JSON_BUILD_PAIR_CALLBACK("LimitFSIZE", rlimit_build_json, c->rlimit[RLIMIT_FSIZE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitFSIZESoft", rlimit_build_json, c->rlimit[RLIMIT_FSIZE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitDATA", rlimit_build_json, c->rlimit[RLIMIT_DATA]),
                        JSON_BUILD_PAIR_CALLBACK("LimitDATASoft", rlimit_build_json, c->rlimit[RLIMIT_DATA]),
                        JSON_BUILD_PAIR_CALLBACK("LimitSTACK", rlimit_build_json, c->rlimit[RLIMIT_STACK]),
                        JSON_BUILD_PAIR_CALLBACK("LimitSTACKSoft", rlimit_build_json, c->rlimit[RLIMIT_STACK]),
                        JSON_BUILD_PAIR_CALLBACK("LimitCORE", rlimit_build_json, c->rlimit[RLIMIT_CORE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitCORESoft", rlimit_build_json, c->rlimit[RLIMIT_CORE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitRSS", rlimit_build_json, c->rlimit[RLIMIT_RSS]),
                        JSON_BUILD_PAIR_CALLBACK("LimitRSSSoft", rlimit_build_json, c->rlimit[RLIMIT_RSS]),
                        JSON_BUILD_PAIR_CALLBACK("LimitNOFILE", rlimit_build_json, c->rlimit[RLIMIT_NOFILE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitNOFILESoft", rlimit_build_json, c->rlimit[RLIMIT_NOFILE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitAS", rlimit_build_json, c->rlimit[RLIMIT_AS]),
                        JSON_BUILD_PAIR_CALLBACK("LimitASSoft", rlimit_build_json, c->rlimit[RLIMIT_AS]),
                        JSON_BUILD_PAIR_CALLBACK("LimitNPROC", rlimit_build_json, c->rlimit[RLIMIT_NPROC]),
                        JSON_BUILD_PAIR_CALLBACK("LimitNPROCSoft", rlimit_build_json, c->rlimit[RLIMIT_NPROC]),
                        JSON_BUILD_PAIR_CALLBACK("LimitMEMLOCK", rlimit_build_json, c->rlimit[RLIMIT_MEMLOCK]),
                        JSON_BUILD_PAIR_CALLBACK("LimitMEMLOCKSoft", rlimit_build_json, c->rlimit[RLIMIT_MEMLOCK]),
                        JSON_BUILD_PAIR_CALLBACK("LimitLOCKS", rlimit_build_json, c->rlimit[RLIMIT_LOCKS]),
                        JSON_BUILD_PAIR_CALLBACK("LimitLOCKSSoft", rlimit_build_json, c->rlimit[RLIMIT_LOCKS]),
                        JSON_BUILD_PAIR_CALLBACK("LimitSIGPENDING", rlimit_build_json, c->rlimit[RLIMIT_SIGPENDING]),
                        JSON_BUILD_PAIR_CALLBACK("LimitSIGPENDINGSoft", rlimit_build_json, c->rlimit[RLIMIT_SIGPENDING]),
                        JSON_BUILD_PAIR_CALLBACK("LimitMSGQUEUE", rlimit_build_json, c->rlimit[RLIMIT_MSGQUEUE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitMSGQUEUESoft", rlimit_build_json, c->rlimit[RLIMIT_MSGQUEUE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitNICE", rlimit_build_json, c->rlimit[RLIMIT_NICE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitNICESoft", rlimit_build_json, c->rlimit[RLIMIT_NICE]),
                        JSON_BUILD_PAIR_CALLBACK("LimitRTPRIO", rlimit_build_json, c->rlimit[RLIMIT_RTPRIO]),
                        JSON_BUILD_PAIR_CALLBACK("LimitRTPRIOSoft", rlimit_build_json, c->rlimit[RLIMIT_RTPRIO]),
                        JSON_BUILD_PAIR_CALLBACK("LimitRTTIME", rlimit_build_json, c->rlimit[RLIMIT_RTTIME]),
                        JSON_BUILD_PAIR_CALLBACK("LimitRTTIMESoft", rlimit_build_json, c->rlimit[RLIMIT_RTTIME]),
                        JSON_BUILD_PAIR_CALLBACK("WorkingDirectory", working_directory_build_json, c),
                        JSON_BUILD_PAIR_STRING("RootDirectory", c->root_directory),
                        JSON_BUILD_PAIR_STRING("RootImage", c->root_image),
                        JSON_BUILD_PAIR_CALLBACK("RootImageOptions", root_image_options_build_json, c->root_image_options),
                        JSON_BUILD_PAIR_BYTE_ARRAY("RootHash", c->root_hash, c->root_hash_size),
                        JSON_BUILD_PAIR_STRING("RootHashPath", c->root_hash_path),
                        JSON_BUILD_PAIR_BYTE_ARRAY("RootHashSignature", c->root_hash_sig, c->root_hash_sig_size),
                        JSON_BUILD_PAIR_STRING("RootHashSignaturePath", c->root_hash_sig_path),
                        JSON_BUILD_PAIR_STRING("RootVerity", c->root_verity),
                        JSON_BUILD_PAIR_BOOLEAN("RootEphemeral", c->root_ephemeral),
                        JSON_BUILD_PAIR_STRV("ExtensionDirectories", c->extension_directories),
                        JSON_BUILD_PAIR_CALLBACK("ExtensionImages", extension_images_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK("MountImages", mount_images_build_json, c),
                        JSON_BUILD_PAIR_INTEGER("OOMScoreAdjust", exec_context_get_oom_score_adjust(c)),
                        JSON_BUILD_PAIR_UNSIGNED("CoredumpFilter", exec_context_get_coredump_filter(c)),
                        JSON_BUILD_PAIR_INTEGER("Nice", exec_context_get_nice(c)),
                        JSON_BUILD_PAIR_INTEGER("IOSchedulingClass", ioprio_prio_class(exec_context_get_effective_ioprio(c))),
                        JSON_BUILD_PAIR_INTEGER("IOSchedulingPriority", ioprio_prio_data(exec_context_get_effective_ioprio(c))),
                        JSON_BUILD_PAIR_INTEGER("CPUSchedulingPolicy", exec_context_get_cpu_sched_policy(c)),
                        JSON_BUILD_PAIR_INTEGER("CPUSchedulingPriority", exec_context_get_cpu_sched_priority(c)),
                        JSON_BUILD_PAIR_CALLBACK("CPUAffinity", cpu_affinity_build_json, c),
                        JSON_BUILD_PAIR_BOOLEAN("CPUAffinityFromNUMA", exec_context_get_cpu_affinity_from_numa(c)),
                        JSON_BUILD_PAIR_INTEGER("NUMAPolicy", numa_policy_get_type(&c->numa_policy)),
                        JSON_BUILD_PAIR_CALLBACK("NUMAMask", cpu_set_build_json, &c->numa_policy.nodes),
                        JSON_BUILD_PAIR_UNSIGNED("TimerSlackNSec", exec_context_get_timer_slack_nsec(c)),
                        JSON_BUILD_PAIR_BOOLEAN("CPUSchedulingResetOnFork", c->cpu_sched_reset_on_fork),
                        JSON_BUILD_PAIR_BOOLEAN("NonBlocking", c->non_blocking),
                        JSON_BUILD_PAIR_STRING("StandardInput", exec_input_to_string(c->std_input)),
                        JSON_BUILD_PAIR_STRING("StandardInputFileDescriptorName", exec_context_fdname(c, STDIN_FILENO)),
                        JSON_BUILD_PAIR_BYTE_ARRAY("StandardInputData", c->stdin_data, c->stdin_data_size),
                        JSON_BUILD_PAIR_STRING("StandardOutput", exec_output_to_string(c->std_output)),
                        JSON_BUILD_PAIR_STRING("StandardOutputFileDescriptorName", exec_context_fdname(c, STDOUT_FILENO)),
                        JSON_BUILD_PAIR_STRING("StandardError", exec_output_to_string(c->std_error)),
                        JSON_BUILD_PAIR_STRING("StandardErrorFileDescriptorName", exec_context_fdname(c, STDERR_FILENO)),
                        JSON_BUILD_PAIR_STRING("TTYPath", c->tty_path),
                        JSON_BUILD_PAIR_BOOLEAN("TTYReset", c->tty_reset),
                        JSON_BUILD_PAIR_BOOLEAN("TTYVHangup", c->tty_vhangup),
                        JSON_BUILD_PAIR_BOOLEAN("TTYVTDisallocate", c->tty_vt_disallocate),
                        JSON_BUILD_PAIR_UNSIGNED("TTYRows", c->tty_rows),
                        JSON_BUILD_PAIR_UNSIGNED("TTYColumns", c->tty_cols),
                        JSON_BUILD_PAIR_INTEGER("SyslogPriority", c->syslog_priority),
                        JSON_BUILD_PAIR_STRING("SyslogIdentifier", c->syslog_identifier),
                        JSON_BUILD_PAIR_BOOLEAN("SyslogLevelPrefix", c->syslog_level_prefix),
                        JSON_BUILD_PAIR_INTEGER("SyslogLevel", LOG_PRI(c->syslog_priority)),
                        JSON_BUILD_PAIR_INTEGER("SyslogFacility", LOG_FAC(c->syslog_priority)),
                        JSON_BUILD_PAIR_INTEGER("LogLevelMax", c->log_level_max),
                        JSON_BUILD_PAIR_FINITE_USEC("LogRateLimitIntervalUSec", c->log_ratelimit_interval_usec),
                        JSON_BUILD_PAIR_UNSIGNED("LogRateLimitBurst", c->log_ratelimit_burst),
                        JSON_BUILD_PAIR_CALLBACK("LogExtraFields", log_extra_fields_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK("LogFilterPatterns", log_filter_patterns_build_json, c),
                        JSON_BUILD_PAIR_STRING("LogNamespace", c->log_namespace),
                        JSON_BUILD_PAIR_INTEGER("SecureBits", c->secure_bits),
                        JSON_BUILD_PAIR_UNSIGNED("CapabilityBoundingSet", c->capability_bounding_set),
                        JSON_BUILD_PAIR_UNSIGNED("AmbientCapabilities", c->capability_ambient_set),
                        JSON_BUILD_PAIR_STRING("User", c->user),
                        JSON_BUILD_PAIR_STRING("Group", c->group),
                        JSON_BUILD_PAIR_BOOLEAN("DynamicUser", c->dynamic_user),
                        JSON_BUILD_PAIR_BOOLEAN("RemoveIPC", c->remove_ipc),
                        JSON_BUILD_PAIR_CALLBACK("SetCredential", set_credential_build_json, c->set_credentials),
                        JSON_BUILD_PAIR_CALLBACK("SetCredentialEncrypted", set_credential_build_json, c->set_credentials),
                        JSON_BUILD_PAIR_CALLBACK("LoadCredential", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_CALLBACK("LoadCredentialEncrypted", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_STRING_SET("ImportCredential", c->import_credentials),
                        JSON_BUILD_PAIR_STRV("SupplementaryGroups", c->supplementary_groups),
                        JSON_BUILD_PAIR_STRING("PAMName", c->pam_name),
                        JSON_BUILD_PAIR_STRV("ReadWritePaths", c->read_write_paths),
                        JSON_BUILD_PAIR_STRV("ReadOnlyPaths", c->read_only_paths),
                        JSON_BUILD_PAIR_STRV("InaccessiblePaths", c->inaccessible_paths),
                        JSON_BUILD_PAIR_STRV("ExecPaths", c->exec_paths),
                        JSON_BUILD_PAIR_STRV("NoExecPaths", c->no_exec_paths),
                        JSON_BUILD_PAIR_STRV("ExecSearchPath", c->exec_search_path),
                        JSON_BUILD_PAIR_UNSIGNED("MountFlags", c->mount_propagation_flag),
                        JSON_BUILD_PAIR_BOOLEAN("PrivateTmp", c->private_tmp),
                        JSON_BUILD_PAIR_BOOLEAN("PrivateDevices", c->private_devices),
                        JSON_BUILD_PAIR_BOOLEAN("ProtectClock", c->protect_clock),
                        JSON_BUILD_PAIR_BOOLEAN("ProtectKernelTunables", c->protect_kernel_tunables),
                        JSON_BUILD_PAIR_BOOLEAN("ProtectKernelModules", c->protect_kernel_modules),
                        JSON_BUILD_PAIR_BOOLEAN("ProtectKernelLogs", c->protect_kernel_logs),
                        JSON_BUILD_PAIR_BOOLEAN("ProtectControlGroups", c->protect_control_groups),
                        JSON_BUILD_PAIR_BOOLEAN("PrivateNetwork", c->private_network),
                        JSON_BUILD_PAIR_BOOLEAN("PrivateUsers", c->private_users),
                        JSON_BUILD_PAIR_BOOLEAN("PrivateMounts", c->private_mounts),
                        JSON_BUILD_PAIR_BOOLEAN("PrivateIPC", c->private_ipc),
                        JSON_BUILD_PAIR_STRING("ProtectHome", protect_home_to_string(c->protect_home)),
                        JSON_BUILD_PAIR_STRING("ProtectSystem", protect_system_to_string(c->protect_system)),
                        JSON_BUILD_PAIR_BOOLEAN("SameProcessGroup", c->same_pgrp),
                        JSON_BUILD_PAIR_STRING("UtmpIdentifier", c->utmp_id),
                        JSON_BUILD_PAIR_STRING("UtmpMode", exec_utmp_mode_to_string(c->utmp_mode)),
                        JSON_BUILD_PAIR_OBJECT("SELinuxContext",
                                        JSON_BUILD_PAIR_BOOLEAN("Ignore", c->selinux_context_ignore),
                                        JSON_BUILD_PAIR_STRING("Context", c->selinux_context)),
                        JSON_BUILD_PAIR_OBJECT("AppArmorProfile",
                                        JSON_BUILD_PAIR_BOOLEAN("Ignore", c->apparmor_profile_ignore),
                                        JSON_BUILD_PAIR_STRING("Profile", c->apparmor_profile)),
                        JSON_BUILD_PAIR_OBJECT("SmackProcessLabel",
                                        JSON_BUILD_PAIR_BOOLEAN("Ignore", c->smack_process_label_ignore),
                                        JSON_BUILD_PAIR_STRING("Label", c->smack_process_label)),
                        JSON_BUILD_PAIR_BOOLEAN("IgnoreSIGPIPE", c->ignore_sigpipe),
                        JSON_BUILD_PAIR_BOOLEAN("NoNewPrivileges", c->no_new_privileges),
                        JSON_BUILD_PAIR_CALLBACK("SystemCallFilter", syscall_filter_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK("SystemCallArchitectures", syscall_archs_build_json, c),
                        JSON_BUILD_PAIR_INTEGER("SystemCallErrorNumber", c->syscall_errno),
                        JSON_BUILD_PAIR_CALLBACK("SystemCallLog", syscall_log_build_json, c),
                        JSON_BUILD_PAIR_STRING("Personality", personality_to_string(c->personality)),
                        JSON_BUILD_PAIR_BOOLEAN("LockPersonality", c->lock_personality),
                        JSON_BUILD_PAIR_CALLBACK("RestrictAddressFamilies", address_families_build_json, c->address_families),
                        JSON_BUILD_PAIR_CALLBACK("RuntimeDirectorySymlink", exec_dir_symlink_build_json, &c->directories[EXEC_DIRECTORY_RUNTIME]),
                        JSON_BUILD_PAIR_STRING("RuntimeDirectoryPreserve", exec_preserve_mode_to_string(c->runtime_directory_preserve_mode)),
                        JSON_BUILD_PAIR_UNSIGNED("RuntimeDirectoryMode", c->directories[EXEC_DIRECTORY_RUNTIME].mode),
                        JSON_BUILD_PAIR_CALLBACK("RuntimeDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_RUNTIME]),
                        JSON_BUILD_PAIR_CALLBACK("StateDirectorySymlink", exec_dir_symlink_build_json, &c->directories[EXEC_DIRECTORY_STATE]),
                        JSON_BUILD_PAIR_UNSIGNED("StateDirectoryMode", c->directories[EXEC_DIRECTORY_STATE].mode),
                        JSON_BUILD_PAIR_CALLBACK("StateDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_STATE]),
                        JSON_BUILD_PAIR_CALLBACK("CacheDirectorySymlink", exec_dir_symlink_build_json, &c->directories[EXEC_DIRECTORY_CACHE]),
                        JSON_BUILD_PAIR_UNSIGNED("CacheDirectoryMode", c->directories[EXEC_DIRECTORY_CACHE].mode),
                        JSON_BUILD_PAIR_CALLBACK("CacheDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CACHE]),
                        JSON_BUILD_PAIR_CALLBACK("LogsDirectorySymlink", exec_dir_symlink_build_json, &c->directories[EXEC_DIRECTORY_LOGS]),
                        JSON_BUILD_PAIR_UNSIGNED("LogsDirectoryMode", c->directories[EXEC_DIRECTORY_LOGS].mode),
                        JSON_BUILD_PAIR_CALLBACK("LogsDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_LOGS]),
                        JSON_BUILD_PAIR_UNSIGNED("ConfigurationDirectoryMode", c->directories[EXEC_DIRECTORY_CONFIGURATION].mode),
                        JSON_BUILD_PAIR_CALLBACK("ConfigurationDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CONFIGURATION]),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutCleanUSec", c->timeout_clean_usec),
                        JSON_BUILD_PAIR_BOOLEAN("MemoryDenyWriteExecute", c->memory_deny_write_execute),
                        JSON_BUILD_PAIR_BOOLEAN("RestrictRealtime", c->restrict_realtime),
                        JSON_BUILD_PAIR_BOOLEAN("RestrictSUIDSGID", c->restrict_suid_sgid),
                        JSON_BUILD_PAIR_UNSIGNED("RestrictNamespaces", c->restrict_namespaces),
                        JSON_BUILD_PAIR_CALLBACK("RestrictFileSystems", restrict_filesystems_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK("BindPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK("BindReadOnlyPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK("TemporaryFileSystem", temporary_filesystems_build_json, c),
                        JSON_BUILD_PAIR_BOOLEAN("MountAPIVFS", c->mount_apivfs),
                        JSON_BUILD_PAIR_STRING("KeyringMode", exec_keyring_mode_to_string(c->keyring_mode)),
                        JSON_BUILD_PAIR_STRING("ProtectProc", protect_proc_to_string(c->protect_proc)),
                        JSON_BUILD_PAIR_STRING("ProcSubset", proc_subset_to_string(c->proc_subset)),
                        JSON_BUILD_PAIR_BOOLEAN("ProtectHostname", c->protect_hostname),
                        JSON_BUILD_PAIR_BOOLEAN("MemoryKSM", c->memory_ksm > 0),
                        JSON_BUILD_PAIR_STRING("NetworkNamespacePath", c->network_namespace_path),
                        JSON_BUILD_PAIR_STRING("IPCNamespacePath", c->ipc_namespace_path),
                        JSON_BUILD_PAIR_CALLBACK("RootImagePolicy", image_policy_build_json, c->root_image_policy),
                        JSON_BUILD_PAIR_CALLBACK("MountImagePolicy", image_policy_build_json, c->mount_image_policy),
                        JSON_BUILD_PAIR_CALLBACK("ExtensionImagePolicy", image_policy_build_json, c->extension_image_policy)));
}

static int kill_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        KillContext *c;

        assert(ret);

        c = unit_get_kill_context(ASSERT_PTR(userdata));
        if (!c)
                return 0;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("KillMode", kill_mode_to_string(c->kill_mode)),
                        JSON_BUILD_PAIR_INTEGER("KillSignal", c->kill_signal),
                        JSON_BUILD_PAIR_INTEGER("RestartKillSignal", c->restart_kill_signal),
                        JSON_BUILD_PAIR_INTEGER("FinalKillSignal", c->final_kill_signal),
                        JSON_BUILD_PAIR_BOOLEAN("SendSIGKILL", c->send_sigkill),
                        JSON_BUILD_PAIR_BOOLEAN("SendSIGHUP", c->send_sighup),
                        JSON_BUILD_PAIR_INTEGER("WatchdogSignal", c->watchdog_signal)));
}

static int mount_what_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Mount *m = ASSERT_PTR(MOUNT(userdata));
        _cleanup_free_ char *escaped = NULL;

        assert(ret);

        escaped = mount_get_what_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return json_variant_new_string(ret, escaped);
}

static int mount_options_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Mount *m = MOUNT(ASSERT_PTR(userdata));
        _cleanup_free_ char *escaped = NULL;

        escaped = mount_get_options_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return json_variant_new_string(ret, escaped);
}

static int exec_command_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **flags = NULL;
        ExecCommand *cmd = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = exec_command_flags_to_strv(cmd->flags, &flags);
        if (r < 0)
                return r;

        return json_build(ret, JSON_BUILD_OBJECT(
                JSON_BUILD_PAIR_BOOLEAN("IgnoreFailure", !!(cmd->flags & EXEC_COMMAND_IGNORE_FAILURE)),
                JSON_BUILD_PAIR_STRING("Path", cmd->path),
                JSON_BUILD_PAIR_STRV("Arguments", cmd->argv)),
                JSON_BUILD_PAIR_STRV("Flags", flags));
}

static int exec_command_list_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        ExecCommand *cmd = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        LIST_FOREACH(command, c, cmd) {
                _cleanup_strv_free_ char **flags = NULL;

                r = exec_command_flags_to_strv(c->flags, &flags);
                if (r < 0)
                        return r;

                r = json_variant_append_arrayb(&v, JSON_BUILD_CALLBACK(exec_command_build_json, c));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int mount_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Mount *m = MOUNT(ASSERT_PTR(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Where", m->where),
                        JSON_BUILD_PAIR_CALLBACK("What", mount_what_build_json, m),
                        JSON_BUILD_PAIR_CALLBACK("Options", mount_options_build_json, m),
                        JSON_BUILD_PAIR_STRING("Type", mount_get_fstype(m)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutUSec", m->timeout_usec),
                        JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", m->directory_mode),
                        JSON_BUILD_PAIR_BOOLEAN("SloppyOptions", m->sloppy_options),
                        JSON_BUILD_PAIR_BOOLEAN("LazyUnmount", m->lazy_unmount),
                        JSON_BUILD_PAIR_BOOLEAN("ForceUnmount", m->force_unmount),
                        JSON_BUILD_PAIR_BOOLEAN("ReadWriteOnly", m->read_write_only),
                        JSON_BUILD_PAIR_CALLBACK("ExecMount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_MOUNT]),
                        JSON_BUILD_PAIR_CALLBACK("ExecUnmount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_UNMOUNT]),
                        JSON_BUILD_PAIR_CALLBACK("ExecRemount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_REMOUNT])));
}

static int path_specs_build_json(JsonVariant **ret, const char *name, void *userdata) {
        PathSpec *specs = userdata;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        LIST_FOREACH(spec, k, specs) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Type", path_type_to_string(k->type)),
                                JSON_BUILD_PAIR_STRING("Path", k->path)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int path_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Path *p = ASSERT_PTR(PATH(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Unit", UNIT_TRIGGER(UNIT(p)) ? UNIT_TRIGGER(UNIT(p))->id : NULL),
                        JSON_BUILD_PAIR_CALLBACK("Paths", path_specs_build_json, p->specs),
                        JSON_BUILD_PAIR_BOOLEAN("MakeDirectory", p->make_directory),
                        JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", p->directory_mode),
                        JSON_BUILD_PAIR_FINITE_USEC("TriggerLimitIntervalUSec", p->trigger_limit.interval),
                        JSON_BUILD_PAIR_UNSIGNED("TriggerLimitBurst", p->trigger_limit.burst)));
}

static int scope_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Scope *s = ASSERT_PTR(SCOPE(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutStopUSec", s->timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeMaxUSec", s->runtime_max_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeRandomizedExtraUSec", s->runtime_rand_extra_usec),
                        JSON_BUILD_PAIR_STRING("OOMPolicy", oom_policy_to_string(s->oom_policy))));
}

static int exit_status_set_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *statuses = NULL, *signals = NULL;
        ExitStatusSet *set = ASSERT_PTR(userdata);
        unsigned n;
        int r;

        assert(ret);

        BITMAP_FOREACH(n, &set->status) {
                assert(n < 256);

                r = json_variant_append_arrayb(&statuses, JSON_BUILD_UNSIGNED(n));
                if (r < 0)
                        return r;
        }

        BITMAP_FOREACH(n, &set->signal) {
                const char *str;

                str = signal_to_string(n);
                if (!str)
                        continue;

                r = json_variant_append_arrayb(&signals, JSON_BUILD_STRING(str));
                if (r < 0)
                        return r;
        }

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_VARIANT("Statuses", statuses),
                                JSON_BUILD_PAIR_VARIANT("Signals", signals)));
}

static int open_files_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        OpenFile *open_files = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(open_files, of, open_files) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Path", of->path),
                                JSON_BUILD_PAIR_STRING("FileDescriptorName", of->fdname),
                                JSON_BUILD_PAIR_UNSIGNED("Flags", of->flags)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int service_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Service *s = ASSERT_PTR(SERVICE(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Type", service_type_to_string(s->type)),
                        JSON_BUILD_PAIR_STRING("ExitType", service_exit_type_to_string(s->exit_type)),
                        JSON_BUILD_PAIR_STRING("Restart", service_restart_mode_to_string(s->restart_mode)),
                        JSON_BUILD_PAIR_STRING("RestartMode", service_restart_mode_to_string(s->restart_mode)),
                        JSON_BUILD_PAIR_STRING("PIDFile", s->pid_file),
                        JSON_BUILD_PAIR_STRING("NotifyAccess", notify_access_to_string(s->notify_access)),
                        JSON_BUILD_PAIR_FINITE_USEC("RestartUSec", s->restart_usec),
                        JSON_BUILD_PAIR_UNSIGNED("RestartSteps", s->restart_steps),
                        JSON_BUILD_PAIR_FINITE_USEC("RestartMaxDelayUSec", s->restart_max_delay_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("RestartUSecNext", service_restart_usec_next(s)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutStartUSec", s->timeout_start_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutStopUSec", s->timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutAbortUSec", s->timeout_abort_usec),
                        JSON_BUILD_PAIR_STRING("TimeoutStartFailureMode", service_timeout_failure_mode_to_string(s->timeout_start_failure_mode)),
                        JSON_BUILD_PAIR_STRING("TimeoutStopFailureMode", service_timeout_failure_mode_to_string(s->timeout_stop_failure_mode)),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeMaxUSec", s->runtime_max_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("RuntimeRandomizedExtraUSec", s->runtime_rand_extra_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("WatchdogUSec", s->watchdog_usec),
                        JSON_BUILD_PAIR_BOOLEAN("PermissionsStartOnly", s->permissions_start_only),
                        JSON_BUILD_PAIR_BOOLEAN("RootDirectoryStartOnly", s->root_directory_start_only),
                        JSON_BUILD_PAIR_BOOLEAN("RemainAfterExit", s->remain_after_exit),
                        JSON_BUILD_PAIR_BOOLEAN("GuessMainPID", s->guess_main_pid),
                        JSON_BUILD_PAIR_CALLBACK("RestartPreventExitStatus", exit_status_set_build_json, &s->restart_prevent_status),
                        JSON_BUILD_PAIR_CALLBACK("RestartForceExitStatus", exit_status_set_build_json, &s->restart_force_status),
                        JSON_BUILD_PAIR_CALLBACK("SuccessExitStatus", exit_status_set_build_json, &s->success_status),
                        JSON_BUILD_PAIR_STRING("BusName", s->bus_name),
                        JSON_BUILD_PAIR_UNSIGNED("FileDescriptorStoreMax", s->n_fd_store_max),
                        JSON_BUILD_PAIR_STRING("FileDescriptorStorePreserve", exec_preserve_mode_to_string(s->fd_store_preserve_mode)),
                        JSON_BUILD_PAIR_STRING("USBFunctionDescriptors", s->usb_function_descriptors),
                        JSON_BUILD_PAIR_STRING("USBFunctionStrings", s->usb_function_strings),
                        JSON_BUILD_PAIR_STRING("OOMPolicy", oom_policy_to_string(s->oom_policy)),
                        JSON_BUILD_PAIR_CALLBACK("OpenFile", open_files_build_json, s->open_files),
                        JSON_BUILD_PAIR_INTEGER("ReloadSignal", s->reload_signal),
                        JSON_BUILD_PAIR_CALLBACK("ExecCondition", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_CONDITION]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStartPre", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START_PRE]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStart", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStartPost", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START_POST]),
                        JSON_BUILD_PAIR_CALLBACK("ExecReload", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_RELOAD]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStop", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_STOP]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStopPost", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_STOP_POST])));
}

static int socket_listen_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Socket *s = ASSERT_PTR(SOCKET(userdata));
        int r;

        assert(ret);

        LIST_FOREACH(port, p, s->ports) {
                _cleanup_free_ char *address = NULL;

                r = socket_port_to_address(p, &address);
                if (r < 0)
                        return r;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Type", socket_port_type_to_string(p)),
                                JSON_BUILD_PAIR_STRING("Address", address)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int socket_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Socket *s = ASSERT_PTR(SOCKET(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("BindIPv6Only", socket_address_bind_ipv6_only_to_string(s->bind_ipv6_only)),
                        JSON_BUILD_PAIR_UNSIGNED("Backlog", s->backlog),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutUSec", s->timeout_usec),
                        JSON_BUILD_PAIR_STRING("BindToDevice", s->bind_to_device),
                        JSON_BUILD_PAIR_STRING("SocketUser", s->user),
                        JSON_BUILD_PAIR_STRING("SocketGroup", s->group),
                        JSON_BUILD_PAIR_UNSIGNED("SocketMode", s->socket_mode),
                        JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", s->directory_mode),
                        JSON_BUILD_PAIR_BOOLEAN("Accept", s->accept),
                        JSON_BUILD_PAIR_BOOLEAN("FlushPending", s->flush_pending),
                        JSON_BUILD_PAIR_BOOLEAN("Writable", s->writable),
                        JSON_BUILD_PAIR_BOOLEAN("KeepAlive", s->keep_alive),
                        JSON_BUILD_PAIR_FINITE_USEC("KeepAliveTimeUSec", s->keep_alive_time),
                        JSON_BUILD_PAIR_FINITE_USEC("KeepAliveIntervalUSec", s->keep_alive_interval),
                        JSON_BUILD_PAIR_UNSIGNED("KeepAliveProbes", s->keep_alive_cnt),
                        JSON_BUILD_PAIR_FINITE_USEC("DeferAcceptUSec", s->defer_accept),
                        JSON_BUILD_PAIR_BOOLEAN("NoDelay", s->no_delay),
                        JSON_BUILD_PAIR_INTEGER("Priority", s->priority),
                        JSON_BUILD_PAIR_UNSIGNED("ReceiveBuffer", s->receive_buffer),
                        JSON_BUILD_PAIR_UNSIGNED("SendBuffer", s->send_buffer),
                        JSON_BUILD_PAIR_INTEGER("IPTOS", s->ip_tos),
                        JSON_BUILD_PAIR_INTEGER("IPTTL", s->ip_ttl),
                        JSON_BUILD_PAIR_UNSIGNED("PipeSize", s->pipe_size),
                        JSON_BUILD_PAIR_BOOLEAN("FreeBind", s->free_bind),
                        JSON_BUILD_PAIR_BOOLEAN("Transparent", s->transparent),
                        JSON_BUILD_PAIR_BOOLEAN("Broadcast", s->broadcast),
                        JSON_BUILD_PAIR_BOOLEAN("PassCredentials", s->pass_cred),
                        JSON_BUILD_PAIR_BOOLEAN("PassSecurity", s->pass_sec),
                        JSON_BUILD_PAIR_BOOLEAN("PassPacketInfo", s->pass_pktinfo),
                        JSON_BUILD_PAIR_STRING("Timestamping", socket_timestamping_to_string(s->timestamping)),
                        JSON_BUILD_PAIR_BOOLEAN("RemoveOnStop", s->remove_on_stop),
                        JSON_BUILD_PAIR_CALLBACK("Listen", socket_listen_build_json, s->ports),
                        JSON_BUILD_PAIR_STRV("Symlinks", s->symlinks),
                        JSON_BUILD_PAIR_INTEGER("Mark", s->mark),
                        JSON_BUILD_PAIR_UNSIGNED("MaxConnections", s->max_connections),
                        JSON_BUILD_PAIR_UNSIGNED("MaxConnectionsPerSource", s->max_connections_per_source),
                        JSON_BUILD_PAIR_INTEGER("MessageQueueMaxMessages", s->mq_maxmsg),
                        JSON_BUILD_PAIR_INTEGER("MessageQueueMessageSize", s->mq_msgsize),
                        JSON_BUILD_PAIR_STRING("TCPCongestion", s->tcp_congestion),
                        JSON_BUILD_PAIR_BOOLEAN("ReusePort", s->reuse_port),
                        JSON_BUILD_PAIR_STRING("SmackLabel", s->smack),
                        JSON_BUILD_PAIR_STRING("SmackLabelIPIn", s->smack_ip_in),
                        JSON_BUILD_PAIR_STRING("SmackLabelIPOut", s->smack_ip_out),
                        JSON_BUILD_PAIR_STRING("FileDescriptorName", socket_fdname(s)),
                        JSON_BUILD_PAIR_INTEGER("SocketProtocol", s->socket_protocol),
                        JSON_BUILD_PAIR_FINITE_USEC("TriggerLimitIntervalUSec", s->trigger_limit.interval),
                        JSON_BUILD_PAIR_UNSIGNED("TriggerLimitBurst", s->trigger_limit.burst),
                        JSON_BUILD_PAIR_FINITE_USEC("PollLimitIntervalUSec", s->poll_limit_interval),
                        JSON_BUILD_PAIR_UNSIGNED("PollLimitBurst", s->poll_limit_burst),
                        JSON_BUILD_PAIR_CALLBACK("ExecStartPre", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_START_PRE]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStartPost", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_START_POST]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStopPre", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_STOP_PRE]),
                        JSON_BUILD_PAIR_CALLBACK("ExecStopPost", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_STOP_POST])));
}

static int swap_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Swap *s = ASSERT_PTR(SWAP(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("What", s->what),
                        JSON_BUILD_PAIR_INTEGER("Priority", swap_get_priority(s)),
                        JSON_BUILD_PAIR_STRING("Options", swap_get_options(s)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutUSec", s->timeout_usec),
                        JSON_BUILD_PAIR_CALLBACK("ExecActivate", exec_command_build_json, &s->exec_command[SWAP_EXEC_ACTIVATE]),
                        JSON_BUILD_PAIR_CALLBACK("ExecDeactivate", exec_command_build_json, &s->exec_command[SWAP_EXEC_DEACTIVATE])));
}

static int monotonic_timers_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        TimerValue *values = userdata;
        int r;

        LIST_FOREACH(value, value, values) {
                _cleanup_free_ char *usec = NULL;

                if (value->base == TIMER_CALENDAR)
                        continue;

                usec = timer_base_to_usec_string(value->base);
                if (!usec)
                        return -ENOMEM;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Base", usec),
                                JSON_BUILD_PAIR_UNSIGNED("Value", value->value),
                                JSON_BUILD_PAIR_UNSIGNED("NextElapse", value->next_elapse)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int calendar_timers_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        TimerValue *values = ASSERT_PTR(userdata);
        int r;

        LIST_FOREACH(value, value, values) {
                _cleanup_free_ char *buf = NULL;

                if (value->base != TIMER_CALENDAR)
                        continue;

                r = calendar_spec_to_string(value->calendar_spec, &buf);
                if (r < 0)
                        return r;

                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Base", timer_base_to_string(value->base)),
                                JSON_BUILD_PAIR_STRING("Value", buf),
                                JSON_BUILD_PAIR_UNSIGNED("NextElapse", value->next_elapse)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int timer_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Timer *t = ASSERT_PTR(TIMER(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Unit", UNIT_TRIGGER(UNIT(t)) ? UNIT_TRIGGER(UNIT(t))->id : NULL),
                        JSON_BUILD_PAIR_CALLBACK("TimersMonotonic", monotonic_timers_build_json, t->values),
                        JSON_BUILD_PAIR_CALLBACK("TimersCalendar", calendar_timers_build_json, t->values),
                        JSON_BUILD_PAIR_BOOLEAN("OnClockChange", t->on_clock_change),
                        JSON_BUILD_PAIR_BOOLEAN("OnTimezoneChange", t->on_timezone_change),
                        JSON_BUILD_PAIR_FINITE_USEC("AccuracyUSec", t->accuracy_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("RandomizedDelayUSec", t->random_usec),
                        JSON_BUILD_PAIR_BOOLEAN("FixedRandomDelay", t->fixed_random_delay),
                        JSON_BUILD_PAIR_BOOLEAN("Persistent", t->persistent),
                        JSON_BUILD_PAIR_BOOLEAN("WakeSystem", t->wake_system),
                        JSON_BUILD_PAIR_BOOLEAN("RemainAfterElapse", t->remain_after_elapse)));
}

static int unit_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        static const JsonBuildCallback callbacks[] = {
                [UNIT_AUTOMOUNT] = automount_context_build_json,
                [UNIT_DEVICE] = NULL,
                [UNIT_MOUNT] = mount_context_build_json,
                [UNIT_PATH] = path_context_build_json,
                [UNIT_SCOPE] = scope_context_build_json,
                [UNIT_SERVICE] = service_context_build_json,
                [UNIT_SLICE] = NULL,
                [UNIT_SOCKET] = socket_context_build_json,
                [UNIT_SWAP] = swap_context_build_json,
                [UNIT_TARGET] = NULL,
                [UNIT_TIMER] = timer_context_build_json,
        };
        Unit *u = ASSERT_PTR(userdata);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Type", unit_type_to_string(u->type)),
                        JSON_BUILD_PAIR_STRING("Id", u->id),
                        JSON_BUILD_PAIR_STRING_SET("Names", u->aliases),
                        JSON_BUILD_PAIR_CALLBACK("Requires", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("Requisite", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("Wants", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("BindsTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("PartOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("Upholds", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("RequiredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("RequisiteOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("WantedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("BoundBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("UpheldBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("ConsistsOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("Conflicts", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("ConflictedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("Before", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("After", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("OnSuccess", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("OnSuccessOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("OnFailure", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("OnFailureOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("Triggers", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("TriggeredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("PropagatesReloadTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("ReloadPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("PropagatesStopTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("StopPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("JoinsNamespaceOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("SliceOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("RequiresMountsFor", unit_requires_mounts_for_build_json, u->requires_mounts_for),
                        JSON_BUILD_PAIR_STRV("Documentation", u->documentation),
                        JSON_BUILD_PAIR_STRING("Description", unit_description(u)),
                        JSON_BUILD_PAIR_STRING("AccessSELinuxContext", u->access_selinux_context),
                        JSON_BUILD_PAIR_STRING("FragmentPath", u->fragment_path),
                        JSON_BUILD_PAIR_STRING("SourcePath", u->source_path),
                        JSON_BUILD_PAIR_STRV("DropInPaths", u->dropin_paths),
                        JSON_BUILD_PAIR_STRING("UnitFilePreset", preset_action_past_tense_to_string(unit_get_unit_file_preset(u))),
                        JSON_BUILD_PAIR_BOOLEAN("StopWhenUnneeded", u->stop_when_unneeded),
                        JSON_BUILD_PAIR_BOOLEAN("RefuseManualStart", u->refuse_manual_start),
                        JSON_BUILD_PAIR_BOOLEAN("RefuseManualStop", u->refuse_manual_stop),
                        JSON_BUILD_PAIR_BOOLEAN("AllowIsolate", u->allow_isolate),
                        JSON_BUILD_PAIR_BOOLEAN("DefaultDependencies", u->default_dependencies),
                        JSON_BUILD_PAIR_STRING("OnSuccessJobMode", job_mode_to_string(u->on_success_job_mode)),
                        JSON_BUILD_PAIR_STRING("OnFailureJobMode", job_mode_to_string(u->on_failure_job_mode)),
                        JSON_BUILD_PAIR_BOOLEAN("IgnoreOnIsolate", u->ignore_on_isolate),
                        JSON_BUILD_PAIR_FINITE_USEC("JobTimeoutUSec", u->job_timeout),
                        JSON_BUILD_PAIR_FINITE_USEC("JobRunningTimeoutUSec", u->job_running_timeout),
                        JSON_BUILD_PAIR_STRING("JobTimeoutAction", emergency_action_to_string(u->job_timeout_action)),
                        JSON_BUILD_PAIR_STRING("JobTimeoutRebootArgument", u->job_timeout_reboot_arg),
                        JSON_BUILD_PAIR_CALLBACK("Conditions", unit_conditions_build_json, u->conditions),
                        JSON_BUILD_PAIR_CALLBACK("Asserts", unit_conditions_build_json, u->asserts),
                        JSON_BUILD_PAIR_BOOLEAN("Transient", u->transient),
                        JSON_BUILD_PAIR_BOOLEAN("Perpetual", u->perpetual),
                        JSON_BUILD_PAIR_FINITE_USEC("StartLimitIntervalUSec", u->start_ratelimit.interval),
                        JSON_BUILD_PAIR_UNSIGNED("StartLimitBurst", u->start_ratelimit.burst),
                        JSON_BUILD_PAIR_STRING("StartLimitAction", emergency_action_to_string(u->start_limit_action)),
                        JSON_BUILD_PAIR_STRING("FailureAction", emergency_action_to_string(u->failure_action)),
                        JSON_BUILD_PAIR_INTEGER("FailureActionExitStatus", u->failure_action_exit_status),
                        JSON_BUILD_PAIR_STRING("SuccessAction", emergency_action_to_string(u->success_action)),
                        JSON_BUILD_PAIR_INTEGER("SuccessActionExitStatus", u->success_action_exit_status),
                        JSON_BUILD_PAIR_STRING("RebootArgument", u->reboot_arg),
                        JSON_BUILD_PAIR_STRING("CollectMode", collect_mode_to_string(u->collect_mode)),
                        JSON_BUILD_PAIR_CALLBACK("CGroup", cgroup_context_build_json, u)),
                        JSON_BUILD_PAIR_CALLBACK("Exec", exec_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("Kill", kill_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK(unit_type_to_capitalized_string(u->type), callbacks[u->type], u));
}

static int unit_can_clean_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        ExecCleanMask mask;
        int r;

        assert(ret);

        r = unit_can_clean(u, &mask);
        if (r < 0)
                return r;

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                if (!FLAGS_SET(mask, 1U << t))
                        continue;

                r = json_variant_append_arrayb(&v, JSON_BUILD_STRING(exec_resource_type_to_string(t)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_job_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        if (u->job) {
                _cleanup_free_ char *p = NULL;

                p = job_dbus_path(u->job);
                if (!p)
                        return -ENOMEM;

                r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR("Id", u->job->id),
                                JSON_BUILD_PAIR("Path", p)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_markers_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (UnitMarker m = 0; m < _UNIT_MARKER_MAX; m++) {
                if (!FLAGS_SET(u->markers, 1u << m))
                        continue;

                r = json_variant_append_arrayb(&v, unit_marker_to_string(m));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_load_error_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        r = bus_unit_validate_load_state(u, &e);
        if (r < 0) {
                r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Name", e.name),
                                JSON_BUILD_PAIR_STRING("Message", e.message)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_refs_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (const char *i = sd_bus_track_first(u->bus_track); i; i = sd_bus_track_next(u->bus_track)) {
                int c;

                c = sd_bus_track_count_name(u->bus_track, i);
                if (c < 0)
                        return c;

                /* Add the item multiple times if the ref count for each is above 1 */
                for (int k = 0; k < c; k++) {
                        r = json_variant_append_arrayb(&v, JSON_BUILD_STRING(i));
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int activation_details_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_strv_free_ char **pairs = NULL;
        ActivationDetails *activation_details = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = activation_details_append_pair(activation_details, &pairs);
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = json_variant_append_arrayb(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Key", *key),
                                JSON_BUILD_PAIR_STRING("Value", *value)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_memory_current_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t sz = UINT64_MAX;
        int r;

        assert(ret);

        r = unit_get_memory_current(u, &sz);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get memory.usage_in_bytes attribute: %m");

        return json_variant_new_unsigned(ret, sz);
}

static int unit_memory_available_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t sz = UINT64_MAX;
        int r;

        assert(ret);

        r = unit_get_memory_available(u, &sz);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get total available memory from cgroup: %m");

        return json_variant_new_unsigned(ret, sz);
}

static int unit_cpu_usage_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        nsec_t ns = NSEC_INFINITY;
        int r;

        assert(ret);

        r = unit_get_cpu_usage(u, &ns);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get cpuacct.usage attribute: %m");

        return json_variant_new_unsigned(ret, ns);
}

static int unit_cpuset_cpus_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(cpu_set_reset) CPUSet cpus = {};
        Unit *u = ASSERT_PTR(userdata);

        assert(ret);

        (void) unit_get_cpuset(u, &cpus, "cpuset.cpus.effective");
        return json_build(ret, JSON_BUILD_CALLBACK(cpu_set_build_json, &cpus));
}

static int unit_cpuset_mems_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(cpu_set_reset) CPUSet cpus = {};
        Unit *u = ASSERT_PTR(userdata);

        assert(ret);

        (void) unit_get_cpuset(u, &cpus, "cpuset.mems.effective");
        return json_build(ret, JSON_BUILD_CALLBACK(cpu_set_build_json, &cpus));
}

static int unit_current_tasks_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t cn = UINT64_MAX;
        int r;

        assert(ret);

        r = unit_get_tasks_current(u, &cn);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get pids.current attribute: %m");

        return json_variant_new_unsigned(ret, cn);
}

static int unit_ip_counter_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupIPAccountingMetric metric;
        uint64_t value;

        assert(name);
        assert(ret);

        assert_se((metric = cgroup_ip_accounting_metric_from_string(name)) >= 0);
        (void) unit_get_ip_accounting(u, metric, &value);
        return json_variant_new_unsigned(ret, value);
}

static int unit_io_counter_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupIOAccountingMetric metric;
        uint64_t value;

        assert(name);
        assert(ret);

        assert_se((metric = cgroup_io_accounting_metric_from_string(name)) >= 0);
        (void) unit_get_io_accounting(u, metric, /* allow_cache= */ false, &value);
        return json_variant_new_unsigned(ret, value);
}

static int cgroup_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);

        assert(ret);

        if (!unit_get_cgroup_context(ASSERT_PTR(userdata)))
                return 0;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("ControlGroup", u->cgroup_path ? empty_to_root(u->cgroup_path) : NULL),
                        JSON_BUILD_PAIR_UNSIGNED("ControlGroupId", u->cgroup_id)),
                        JSON_BUILD_PAIR_CALLBACK("MemoryCurrent", unit_memory_current_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("MemoryAvailable", unit_memory_available_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("CPUUsageNSec", unit_cpu_usage_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("EffectiveCPUs", unit_cpuset_cpus_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("EffectiveMemoryNodes", unit_cpuset_mems_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("TasksCurrent", unit_current_tasks_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IPIngressBytes", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IPIngressPackets", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IPEgressBytes", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IPEgressPackets", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IOReadBytes", unit_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IOReadOperations", unit_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IOWriteBytes", unit_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("IOWriteOperations", unit_io_counter_build_json, u));
}

static int automount_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Automount *a = ASSERT_PTR(AUTOMOUNT(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Result", automount_result_to_string(a->result))));
}

static int device_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Device *d = ASSERT_PTR(DEVICE(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("SysFSPath", d->sysfs)));
}

static int mount_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Mount *m = ASSERT_PTR(MOUNT(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_UNSIGNED("ControlPID", m->control_pid.pid),
                        JSON_BUILD_PAIR_STRING("Result", mount_result_to_string(m->result)),
                        JSON_BUILD_PAIR_UNSIGNED("UID", UNIT(m)->ref_uid),
                        JSON_BUILD_PAIR_UNSIGNED("GID", UNIT(m)->ref_gid)));
}

static int path_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Path *p = ASSERT_PTR(PATH(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Result", path_result_to_string(p->result))));
}

static int scope_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Scope *s = ASSERT_PTR(SCOPE(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Controller", s->controller),
                        JSON_BUILD_PAIR_STRING("Result", scope_result_to_string(s->result))));
}

static int exec_status_build_json(JsonVariant **ret, const char *name, void *userdata) {
        ExecStatus *status = ASSERT_PTR(userdata);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                JSON_BUILD_DUAL_TIMESTAMP("StartTimestamp", status->start_timestamp),
                JSON_BUILD_DUAL_TIMESTAMP("ExitTimestamp", status->exit_timestamp),
                JSON_BUILD_PAIR_UNSIGNED("PID", status->pid),
                JSON_BUILD_PAIR_INTEGER("Code", status->code),
                JSON_BUILD_PAIR_INTEGER("Status", status->status)));
}

static int service_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Service *s = ASSERT_PTR(SERVICE(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_DUAL_TIMESTAMP("WatchdogTimestamp", s->watchdog_timestamp),
                        JSON_BUILD_PAIR_UNSIGNED("MainPID", s->main_pid.pid),
                        JSON_BUILD_PAIR_UNSIGNED("ControlPID", s->control_pid.pid),
                        JSON_BUILD_PAIR_UNSIGNED("NFileDescriptorStore", s->n_fd_store),
                        JSON_BUILD_PAIR_STRING("StatusText", s->status_text),
                        JSON_BUILD_PAIR_INTEGER("StatusErrno", s->status_errno),
                        JSON_BUILD_PAIR_STRING("Result", service_result_to_string(s->result)),
                        JSON_BUILD_PAIR_STRING("ReloadResult", service_result_to_string(s->reload_result)),
                        JSON_BUILD_PAIR_STRING("CleanResult", service_result_to_string(s->clean_result)),
                        JSON_BUILD_PAIR_UNSIGNED("UID", UNIT(s)->ref_uid),
                        JSON_BUILD_PAIR_UNSIGNED("GID", UNIT(s)->ref_gid),
                        JSON_BUILD_PAIR_UNSIGNED("NRestarts", s->n_restarts),
                        JSON_BUILD_PAIR_CALLBACK("ExecMain", exec_status_build_json, &s->main_exec_status)));
}

static int socket_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Socket *s = ASSERT_PTR(SOCKET(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_UNSIGNED("ControlPID", s->control_pid.pid),
                        JSON_BUILD_PAIR_STRING("Result", socket_result_to_string(s->result)),
                        JSON_BUILD_PAIR_UNSIGNED("NConnections", s->n_connections),
                        JSON_BUILD_PAIR_UNSIGNED("NAccepted", s->n_accepted),
                        JSON_BUILD_PAIR_UNSIGNED("NRefused", s->n_refused),
                        JSON_BUILD_PAIR_UNSIGNED("UID", UNIT(s)->ref_uid),
                        JSON_BUILD_PAIR_UNSIGNED("GID", UNIT(s)->ref_gid)));
}

static int swap_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Swap *s = ASSERT_PTR(SWAP(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_UNSIGNED("ControlPID", s->control_pid.pid),
                        JSON_BUILD_PAIR_STRING("Result", swap_result_to_string(s->result)),
                        JSON_BUILD_PAIR_UNSIGNED("UID", UNIT(s)->ref_uid),
                        JSON_BUILD_PAIR_UNSIGNED("GID", UNIT(s)->ref_gid)));
}

static int timer_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Timer *t = ASSERT_PTR(TIMER(userdata));

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_UNSIGNED("NextElapseUSecRealtime", t->next_elapse_realtime),
                        JSON_BUILD_PAIR_UNSIGNED("NextElapseUSecMonotonic", timer_next_elapse_monotonic(t)),
                        JSON_BUILD_DUAL_TIMESTAMP("LastTriggerUSec", t->last_trigger),
                        JSON_BUILD_PAIR_STRING("Result", timer_result_to_string(t->result))));
}

static int unit_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        static const JsonBuildCallback callbacks[] = {
                [UNIT_AUTOMOUNT] = automount_runtime_build_json,
                [UNIT_DEVICE] = device_runtime_build_json,
                [UNIT_MOUNT] = mount_runtime_build_json,
                [UNIT_PATH] = path_runtime_build_json,
                [UNIT_SCOPE] = scope_runtime_build_json,
                [UNIT_SERVICE] = service_runtime_build_json,
                [UNIT_SLICE] = NULL,
                [UNIT_SOCKET] = socket_runtime_build_json,
                [UNIT_SWAP] = swap_runtime_build_json,
                [UNIT_TARGET] = NULL,
                [UNIT_TIMER] = timer_runtime_build_json,
        };
        Unit *u = ASSERT_PTR(userdata);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Following", unit_following(u) ? unit_following(u)->id : NULL),
                        JSON_BUILD_PAIR_STRING("LoadState", unit_load_state_to_string(u->load_state)),
                        JSON_BUILD_PAIR_OBJECT("ActiveState", unit_active_state_to_string(unit_active_state(u))),
                        JSON_BUILD_PAIR_OBJECT("FreezerState", freezer_state_to_string(unit_freezer_state(u))),
                        JSON_BUILD_PAIR_OBJECT("SubState", unit_sub_state_to_string(u)),
                        JSON_BUILD_PAIR_STRING("UnitFileState", unit_file_state_to_string(unit_get_unit_file_state(u))),
                        JSON_BUILD_DUAL_TIMESTAMP("StateChangeTimestamp", u->state_change_timestamp),
                        JSON_BUILD_DUAL_TIMESTAMP("InactiveEnterTimestamp", u->inactive_enter_timestamp),
                        JSON_BUILD_DUAL_TIMESTAMP("InactiveExitTimestamp", u->inactive_exit_timestamp),
                        JSON_BUILD_DUAL_TIMESTAMP("ActiveEnterTimestamp", u->active_enter_timestamp),
                        JSON_BUILD_DUAL_TIMESTAMP("ActiveExitTimestamp", u->active_exit_timestamp),
                        JSON_BUILD_PAIR_BOOLEAN("CanStart", unit_can_start_refuse_manual(u)),
                        JSON_BUILD_PAIR_BOOLEAN("CanStop", unit_can_stop_refuse_manual(u)),
                        JSON_BUILD_PAIR_BOOLEAN("CanReload", unit_can_reload(u)),
                        JSON_BUILD_PAIR_BOOLEAN("CanIsolate", unit_can_isolate_refuse_manual(u)),
                        JSON_BUILD_PAIR_CALLBACK("CanClean", unit_can_clean_build_json, u),
                        JSON_BUILD_PAIR_BOOLEAN("CanFreeze", unit_can_freeze(u)),
                        JSON_BUILD_PAIR_CALLBACK("Job", unit_job_build_json, u),
                        JSON_BUILD_PAIR_BOOLEAN("NeedDaemonReload", unit_need_daemon_reload(u)),
                        JSON_BUILD_PAIR_CALLBACK("Markers", unit_markers_build_json, u),
                        JSON_BUILD_PAIR_BOOLEAN("ConditionResult", u->condition_result),
                        JSON_BUILD_PAIR_BOOLEAN("AssertResult", u->assert_result),
                        JSON_BUILD_DUAL_TIMESTAMP("ConditionTimestamp", u->condition_timestamp),
                        JSON_BUILD_DUAL_TIMESTAMP("AssertTimestamp", u->assert_timestamp),
                        JSON_BUILD_PAIR_CALLBACK("LoadError", unit_load_error_build_json, u),
                        JSON_BUILD_PAIR_ID128("InvocationID", u->invocation_id)),
                        JSON_BUILD_PAIR_CALLBACK("Refs", unit_refs_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK("ActivationDetails", activation_details_build_json, u->activation_details),
                        JSON_BUILD_PAIR_CALLBACK("CGroup", cgroup_runtime_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK(unit_type_to_capitalized_string(u->type), callbacks[u->type], u));
}

static int units_context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ Unit **sorted = NULL;
        Hashmap *units = ASSERT_PTR(userdata);
        size_t n_sorted = 0;
        int r;

        assert(ret);

        r = hashmap_dump_sorted(units, (void***) &sorted, &n_sorted);
        if (r < 0)
                return r;

        FOREACH_ARRAY(unit, sorted, n_sorted) {
                _cleanup_(json_variant_unrefp) JsonVariant *e = NULL;

                r = unit_context_build_json(&e, /* name= */ NULL, *unit);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&v, e);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int context_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_CALLBACK("Manager", manager_context_build_json, m),
                        JSON_BUILD_PAIR_CALLBACK("Units", units_context_build_json, m->units)));
}

static int units_runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ Unit **sorted = NULL;
        Hashmap *units = userdata;
        size_t n_sorted = 0;
        int r;

        assert(ret);

        r = hashmap_dump_sorted(units, (void***) &sorted, &n_sorted);
        if (r < 0)
                return r;

        FOREACH_ARRAY(unit, sorted, n_sorted) {
                _cleanup_(json_variant_unrefp) JsonVariant *e = NULL;

                r = unit_runtime_build_json(&e, /* name= */ NULL, *unit);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&v, e);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int job_unit_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_free_ char *p = NULL;
        Job *j = ASSERT_PTR(userdata);

        assert(ret);

        p = unit_dbus_path(j->unit);
        if (!p)
                return -ENOMEM;

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_STRING("Id", j->unit->id),
                        JSON_BUILD_PAIR_STRING("Path", p)));
}

static int job_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Job *j = ASSERT_PTR(userdata);

        return json_build(ret, JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_UNSIGNED("Id", j->id),
                        JSON_BUILD_PAIR_CALLBACK("Unit", job_unit_build_json, j),
                        JSON_BUILD_PAIR_STRING("JobType", job_type_to_string(j->type)),
                        JSON_BUILD_PAIR_STRING("State", job_state_to_string(j->state)),
                        JSON_BUILD_PAIR_CALLBACK("ActivationDetails", activation_details_build_json, j->activation_details)));
}

static int jobs_build_json(JsonVariant **ret, const char *name, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ Unit **sorted = NULL;
        Hashmap *jobs = userdata;
        size_t n_sorted = 0;
        int r;

        assert(ret);

        r = hashmap_dump_sorted(jobs, (void***) &sorted, &n_sorted);
        if (r < 0)
                return r;

        FOREACH_ARRAY(job, sorted, n_sorted) {
                _cleanup_(json_variant_unrefp) JsonVariant *e = NULL;

                r = job_build_json(&e, /* name= */ NULL, *job);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&v, e);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int runtime_build_json(JsonVariant **ret, const char *name, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_CALLBACK("Manager", manager_runtime_build_json, m),
                        JSON_BUILD_PAIR_CALLBACK("Jobs", jobs_build_json, m->jobs),
                        JSON_BUILD_PAIR_CALLBACK("Units", units_runtime_build_json, m->units)));
}

int manager_build_json(Manager *m, JsonVariant **ret) {
        assert(m);

        return json_build(ASSERT_PTR(ret), JSON_BUILD_OBJECT(
                        JSON_BUILD_PAIR_CALLBACK("Context", context_build_json, m),
                        JSON_BUILD_PAIR_CALLBACK("Runtime", runtime_build_json, m)));
}
