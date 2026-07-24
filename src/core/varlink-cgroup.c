/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "bpf-program.h"
#include "cgroup.h"
#include "json-util.h"
#include "in-addr-prefix-util.h"
#include "ip-protocol-list.h"
#include "limits-util.h"
#include "manager.h"
#include "path-util.h"
#include "percent-util.h"
#include "set.h"
#include "special.h"
#include "string-util.h"
#include "time-util.h"
#include "unit.h"
#include "unit-name.h"
#include "varlink-cgroup.h"
#include "varlink-common.h"

/* The internal value/scale pair is not exposed on the wire: absolute limits are emitted as
 * "TasksMax" (integer), relative ones as "TasksMaxScale" (float, 1.0 == 100%). */
static int tasks_max_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        CGroupTasksMax *tasks_max = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        if (!cgroup_tasks_max_isset(tasks_max) || tasks_max->scale != 0) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_unsigned(ret, tasks_max->value);
}

static int tasks_max_scale_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        CGroupTasksMax *tasks_max = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        if (!cgroup_tasks_max_isset(tasks_max) || tasks_max->scale == 0) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_real(ret, (double) tasks_max->value / tasks_max->scale);
}

static int io_device_weights_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupIODeviceWeight *weights = userdata;
        int r;

        assert(ret);
        assert(name);

        LIST_FOREACH(device_weights, w, weights) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", w->path),
                                SD_JSON_BUILD_PAIR_UNSIGNED("weight", w->weight));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int io_device_limits_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupIODeviceLimit *limits = userdata;
        int r;

        assert(ret);
        assert(name);

        CGroupIOLimitType type = cgroup_io_limit_type_from_string(name);
        assert(type >= 0);

        LIST_FOREACH(device_limits, l, limits) {
                if (l->limits[type] == cgroup_io_limit_defaults[type])
                        continue;

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", l->path),
                                SD_JSON_BUILD_PAIR_UNSIGNED("limit", l->limits[type]));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int io_device_latencies_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupIODeviceLatency *latencies = userdata;
        int r;

        assert(ret);
        assert(name);

        LIST_FOREACH(device_latencies, l, latencies) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", l->path),
                                JSON_BUILD_PAIR_FINITE_USEC("targetUSec", l->target_usec));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int ip_address_access_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Set *prefixes = userdata;
        int r;

        assert(ret);
        assert(name);

        struct in_addr_prefix *i;
        SET_FOREACH(i, prefixes) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_INTEGER("family", i->family),
                                JSON_BUILD_PAIR_IN_ADDR("address", i->family, &i->address),
                                SD_JSON_BUILD_PAIR_UNSIGNED("prefixLength", i->prefixlen));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int socket_bind_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupSocketBindItem *items = userdata;
        int r;

        assert(ret);
        assert(name);

        LIST_FOREACH(socket_bind_items, i, items) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_INTEGER("family", i->address_family),
                                SD_JSON_BUILD_PAIR_STRING("protocol", ip_protocol_to_name(i->ip_protocol)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("numberOfPorts", i->nr_ports),
                                SD_JSON_BUILD_PAIR_UNSIGNED("minimumPort", i->port_min));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int nft_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        NFTSetContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);
        assert(name);

        FOREACH_ARRAY(nft_set, c->sets, c->n_sets) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("source", nft_set_source_to_string(nft_set->source)),
                                SD_JSON_BUILD_PAIR_STRING("protocol", nfproto_to_string(nft_set->nfproto)),
                                SD_JSON_BUILD_PAIR_STRING("table", nft_set->table),
                                SD_JSON_BUILD_PAIR_STRING("set", nft_set->set));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int bpf_program_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupBPFForeignProgram *programs = userdata;
        int r;

        assert(ret);
        assert(name);

        LIST_FOREACH(programs, p, programs) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("attachType", bpf_cgroup_attach_type_to_string(p->attach_type)),
                                SD_JSON_BUILD_PAIR_STRING("path", p->bpffs_path));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int device_allow_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupDeviceAllow *allow = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(device_allow, a, allow) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", a->path),
                                SD_JSON_BUILD_PAIR_STRING("permissions", cgroup_device_permissions_to_string(a->permissions)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int controllers_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupMask *mask = ASSERT_PTR(userdata);
        int r;

        assert(ret);
        assert(name);

        for (CGroupController ctrl = 0; ctrl < _CGROUP_CONTROLLER_MAX; ctrl++) {
                if (!FLAGS_SET(*mask, CGROUP_CONTROLLER_TO_MASK(ctrl)))
                        continue;

                r = sd_json_variant_append_arrayb(&v, JSON_BUILD_STRING_UNDERSCORIFY(cgroup_controller_to_string(ctrl)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int unit_cgroup_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        CGroupContext *c = unit_get_cgroup_context(u);
        if (!c) {
                *ret = NULL;
                return 0;
        }

        /* The main principle behind context/runtime split is the following:
         * If it make sense to place a property into a config/unit file it belongs to Context.
         * Otherwise it's a 'Runtime'. */

        return sd_json_buildo(
                        ret,

                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Slice", unit_slice_name(u)),

                        /* CPU Control */
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("CPUWeight", c->cpu_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("StartupCPUWeight", c->startup_cpu_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_FINITE_USEC("CPUQuotaPerSecUSec", c->cpu_quota_per_sec_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("CPUQuotaPeriodUSec", c->cpu_quota_period_usec),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("AllowedCPUs", cpuset_build_json, &c->cpuset_cpus),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StartupAllowedCPUs", cpuset_build_json, &c->startup_cpuset_cpus),
                        JSON_BUILD_PAIR_ENUM("CPUSetPartition", cpuset_partition_to_string(c->cpuset_partition)),

                        /* Memory Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("MemoryAccounting", c->memory_accounting),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryMin", c->memory_min, CGROUP_LIMIT_MIN),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryLow", c->memory_low, CGROUP_LIMIT_MIN),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_low_set, "StartupMemoryLow", c->startup_memory_low),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryHigh", c->memory_high, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_high_set, "StartupMemoryHigh", c->startup_memory_high),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryMax", c->memory_max, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_max_set, "StartupMemoryMax", c->startup_memory_max),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemorySwapMax", c->memory_swap_max, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_swap_max_set, "StartupMemorySwapMax", c->startup_memory_swap_max),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryZSwapMax", c->memory_zswap_max, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_zswap_max_set, "StartupMemoryZSwapMax", c->startup_memory_zswap_max),
                        SD_JSON_BUILD_PAIR_BOOLEAN("MemoryZSwapWriteback", c->memory_zswap_writeback),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("AllowedMemoryNodes", cpuset_build_json, &c->cpuset_mems),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StartupAllowedMemoryNodes", cpuset_build_json, &c->startup_cpuset_mems),

                        /* Process Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("TasksAccounting", c->tasks_accounting),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TasksMax", tasks_max_build_json, &c->tasks_max),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TasksMaxScale", tasks_max_scale_build_json, &c->tasks_max),

                        /* IO Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("IOAccounting", c->io_accounting),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("IOWeight", c->io_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("StartupIOWeight", c->startup_io_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IODeviceWeight", io_device_weights_build_json, c->io_device_weights),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOReadBandwidthMax", io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOWriteBandwidthMax", io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOReadIOPSMax", io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOWriteIOPSMax", io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IODeviceLatencyTargetUSec", io_device_latencies_build_json, c->io_device_latencies),

                        /* Network Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("IPAccounting", c->ip_accounting),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPAddressAllow", ip_address_access_build_json, c->ip_address_allow),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPAddressDeny", ip_address_access_build_json, c->ip_address_deny),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SocketBindAllow", socket_bind_build_json, c->socket_bind_allow),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SocketBindDeny", socket_bind_build_json, c->socket_bind_deny),
                        SD_JSON_BUILD_PAIR_CONDITION(!set_isempty(c->restrict_network_interfaces), "RestrictNetworkInterfaces",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->restrict_network_interfaces_is_allow_list),
                                                JSON_BUILD_PAIR_STRING_SET("interfaces", c->restrict_network_interfaces))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("BindNetworkInterface", c->bind_network_interface),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("NFTSet", nft_set_build_json, &c->nft_set_context),

                        /* BPF programs */
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("IPIngressFilterPath", c->ip_filters_ingress),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("IPEgressFilterPath", c->ip_filters_egress),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BPFProgram", bpf_program_build_json, c->bpf_foreign_programs),

                        /* Device Access */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DeviceAllow", device_allow_build_json, c->device_allow),
                        JSON_BUILD_PAIR_ENUM("DevicePolicy", cgroup_device_policy_to_string(c->device_policy)),

                        /* Control Group Management */
                        SD_JSON_BUILD_PAIR_BOOLEAN("Delegate", c->delegate),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("DelegateSubgroup", c->delegate_subgroup),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DelegateControllers", controllers_build_json, &c->delegate_controllers),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DisableControllers", controllers_build_json, &c->disable_controllers),

                        /* Memory Pressure Control */
                        JSON_BUILD_PAIR_ENUM("ManagedOOMSwap", managed_oom_mode_to_string(c->moom_swap)),
                        JSON_BUILD_PAIR_ENUM("ManagedOOMMemoryPressure", managed_oom_mode_to_string(c->moom_mem_pressure)),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ManagedOOMMemoryPressureLimit", c->moom_mem_pressure_limit),
                        JSON_BUILD_PAIR_FINITE_USEC("ManagedOOMMemoryPressureDurationUSec", c->moom_mem_pressure_duration_usec),
                        JSON_BUILD_PAIR_ENUM("ManagedOOMPreference", managed_oom_preference_to_string(c->moom_preference)),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("OOMRules", c->moom_rules),
                        JSON_BUILD_PAIR_ENUM("MemoryPressureWatch", cgroup_pressure_watch_to_string(c->pressure[PRESSURE_MEMORY].watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("MemoryPressureThresholdUSec", c->pressure[PRESSURE_MEMORY].threshold_usec),
                        JSON_BUILD_PAIR_ENUM("CPUPressureWatch", cgroup_pressure_watch_to_string(c->pressure[PRESSURE_CPU].watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("CPUPressureThresholdUSec", c->pressure[PRESSURE_CPU].threshold_usec),
                        JSON_BUILD_PAIR_ENUM("IOPressureWatch", cgroup_pressure_watch_to_string(c->pressure[PRESSURE_IO].watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("IOPressureThresholdUSec", c->pressure[PRESSURE_IO].threshold_usec),

                        /* Others */
                        SD_JSON_BUILD_PAIR_BOOLEAN("CoredumpReceive", c->coredump_receive));
}

static int memory_accounting_metric_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupMemoryAccountingMetric metric;
        uint64_t value;
        int r;

        assert(ret);
        assert(name);

        metric = cgroup_memory_accounting_metric_from_string(name);
        assert(metric >= 0);

        r = unit_get_memory_accounting(u, metric, &value);
        if (r == -ENODATA)
                goto empty;
        if (r < 0)
                return log_debug_errno(r, "Failed to get value for '%s': %m", name);

        if (value == UINT64_MAX)
                goto empty;

        return sd_json_variant_new_unsigned(ret, value);

empty:
        *ret = NULL;
        return 0;
}

static int memory_available_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t value;
        int r;

        assert(ret);
        assert(name);

        r = unit_get_memory_available(u, &value);
        if (r == -ENODATA)
                goto empty;
        if (r < 0)
                return log_debug_errno(r, "Failed to get value of available memory: %m");

        if (value == UINT64_MAX)
                goto empty;

        return sd_json_variant_new_unsigned(ret, value);

empty:
        *ret = NULL;
        return 0;
}

static int effective_limit_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupLimitType type;
        uint64_t value;
        int r;

        assert(ret);
        assert(name);

        type = cgroup_effective_limit_type_from_string(name);
        assert(type >= 0);

        r = unit_get_effective_limit(u, type, &value);
        if (r < 0)
                return log_debug_errno(r, "Failed to get value for '%s': %m", name);

        if (value == UINT64_MAX) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_unsigned(ret, value);
}

static int cpu_usage_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        nsec_t ns;
        int r;

        assert(ret);
        assert(name);

        r = unit_get_cpu_usage(u, &ns);
        if (r == -ENODATA)
                goto empty;
        if (r < 0)
                return log_debug_errno(r, "Failed to get cpu usage: %m");

        if (ns == NSEC_INFINITY)
                goto empty;

        return sd_json_variant_new_unsigned(ret, ns);

empty:
        *ret = NULL;
        return 0;
}

static int effective_cpuset_build_json(sd_json_variant **ret, const char *name, void *userdata, const char *cpuset_name) {
        Unit *u = ASSERT_PTR(userdata);
        _cleanup_(cpu_set_done) CPUSet cpus = {};
        int r;

        assert(ret);
        assert(name);
        assert(cpuset_name);

        r = unit_get_cpuset(u, &cpus, cpuset_name);
        if (r == -ENODATA) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to get cpu set '%s': %m", cpuset_name);

        return cpuset_build_json(ret, name, &cpus);
}

static inline int effective_cpus_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        return effective_cpuset_build_json(ret, name, userdata, "cpuset.cpus.effective");
}

static inline int effective_mems_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        return effective_cpuset_build_json(ret, name, userdata, "cpuset.mems.effective");
}

static int tasks_current_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t cn;
        int r;

        assert(ret);
        assert(name);

        r = unit_get_tasks_current(u, &cn);
        if (r == -ENODATA)
                goto empty;
        if (r < 0)
                return log_debug_errno(r, "Failed to get count of current tasks: %m");

        if (cn == UINT64_MAX)
                goto empty;

        return sd_json_variant_new_unsigned(ret, cn);

empty:
        *ret = NULL;
        return 0;
}

static int get_ip_counter_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupIPAccountingMetric metric;
        uint64_t value;
        int r;

        assert(ret);
        assert(name);

        metric = cgroup_ip_accounting_metric_from_string(name);
        assert(metric >= 0);

        r = unit_get_ip_accounting(u, metric, &value);
        if (r == -ENODATA)
                goto empty;
        if (r < 0)
                return log_debug_errno(r, "Failed to get value for '%s': %m", name);

        if (value == UINT64_MAX)
                goto empty;

        return sd_json_variant_new_unsigned(ret, value);

empty:
        *ret = NULL;
        return 0;
}

static int get_io_counter_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupIOAccountingMetric metric;
        uint64_t value;
        int r;

        assert(ret);
        assert(name);

        metric = cgroup_io_accounting_metric_from_string(name);
        assert(metric >= 0);

        r = unit_get_io_accounting(u, metric, &value);
        if (r == -ENODATA)
                goto empty;
        if (r < 0)
                return log_debug_errno(r, "Failed to get value for '%s': %m", name);

        if (value == UINT64_MAX)
                goto empty;

        return sd_json_variant_new_unsigned(ret, value);

empty:
        *ret = NULL;
        return 0;
}

int unit_cgroup_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (!crt) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,

                        /* ID */
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ID", crt->cgroup_id),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Path", crt->cgroup_path ? empty_to_root(crt->cgroup_path) : NULL),

                        /* Memory */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MemoryCurrent", memory_accounting_metric_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MemoryPeak", memory_accounting_metric_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MemorySwapCurrent", memory_accounting_metric_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MemorySwapPeak", memory_accounting_metric_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MemoryZSwapCurrent", memory_accounting_metric_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MemoryAvailable", memory_available_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("EffectiveMemoryMax", effective_limit_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("EffectiveMemoryHigh", effective_limit_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("EffectiveMemoryNodes", effective_mems_build_json, u),

                        /* CPU */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CPUUsageNSec", cpu_usage_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("EffectiveCPUs", effective_cpus_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TasksCurrent", tasks_current_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("EffectiveTasksMax", effective_limit_build_json, u),

                        /* IP */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPIngressBytes", get_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPIngressPackets", get_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPEgressBytes", get_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPEgressPackets", get_ip_counter_build_json, u),

                        /* IO */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOReadBytes", get_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOReadOperations", get_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOWriteBytes", get_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOWriteOperations", get_io_counter_build_json, u),

                        /* OOM */
                        SD_JSON_BUILD_PAIR_UNSIGNED("OOMKills", crt->oom_kill_last),
                        SD_JSON_BUILD_PAIR_UNSIGNED("ManagedOOMKills", crt->managed_oom_kill_last));
}

/* Write side of the CGroup context for StartTransient: descriptor table like the Exec context in
 * varlink-unit.c, validation mirroring bus_cgroup_set_property() (dbus-cgroup.c). */

static int apply_cgroup_slice(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) {
        Unit *slice;
        int r;

        assert(u);
        assert(p);

        if (!p->slice)
                return 0;

        if (u->type == UNIT_SLICE)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Slice may not be set for slice units.");
        if (unit_has_name(u, SPECIAL_INIT_SCOPE))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot set slice for init.scope.");
        if (!unit_name_is_valid(p->slice, UNIT_NAME_PLAIN))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid unit name '%s'.", p->slice);

        /* manager_load_unit_prepare(): don't dispatch the load queue while our own transient unit
         * is still half set up (same as bus_set_transient_slice()). */
        r = manager_load_unit_prepare(u->manager, p->slice, /* path= */ NULL, /* e= */ NULL, &slice);
        if (r < 0)
                return r;

        if (slice->type != UNIT_SLICE)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unit name '%s' is not a slice.", p->slice);

        r = unit_set_slice(u, slice);
        if (r < 0)
                return r;

        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "Slice", "Slice=%s", p->slice);
        return 0;
}

static int apply_cgroup_cpu_quota_per_sec_usec(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) {
        assert(c);
        assert(p);

        if (!p->cpu_quota_per_sec_usec_set)
                return 0;

        usec_t v = p->cpu_quota_per_sec_usec;
        if (v <= 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "CPUQuotaPerSecUSec= value out of range.");

        c->cpu_quota_per_sec_usec = v;
        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (crt)
                crt->warned_clamping_cpu_quota_period = false;
        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

        if (v == USEC_INFINITY)
                unit_write_setting(u, UNIT_RUNTIME|UNIT_PRIVATE, "CPUQuota", "CPUQuota=");
        else
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "CPUQuota",
                                    "CPUQuota=" USEC_FMT ".%02" PRI_USEC "%%",
                                    v / 10000, (v % 10000) / 100);
        return 0;
}

static int apply_cgroup_cpu_quota_period_usec(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) {
        assert(c);
        assert(p);

        if (!p->cpu_quota_period_usec_set)
                return 0;

        c->cpu_quota_period_usec = p->cpu_quota_period_usec;
        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (crt)
                crt->warned_clamping_cpu_quota_period = false;
        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

        if (c->cpu_quota_period_usec == USEC_INFINITY)
                unit_write_setting(u, UNIT_RUNTIME|UNIT_PRIVATE, "CPUQuotaPeriodSec", "CPUQuotaPeriodSec=");
        else
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "CPUQuotaPeriodSec",
                                    "CPUQuotaPeriodSec=%s",
                                    FORMAT_TIMESPAN(c->cpu_quota_period_usec, 1));
        return 0;
}

/* Convert a fraction normalized to 1.0 == 100% into permyriad, the granularity the unit-file
 * percent syntax can express (and hence a reload of the written fragment reproduces). */
static int fraction_to_permyriad(double f, uint64_t *ret) {
        assert(ret);

        if (!(f > 0.0 && f <= 1.0)) /* also catches NaN */
                return -ERANGE;

        uint64_t permyriad = (uint64_t) (f * 10000.0 + 0.5);
        if (permyriad < 1 || permyriad > 10000)
                return -ERANGE;

        *ret = permyriad;
        return 0;
}

static int apply_cgroup_tasks_max(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) {
        assert(c);
        assert(p);

        if (!p->tasks_max_set)
                return 0;

        if (p->tasks_max_scale_set)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TasksMax= and TasksMaxScale= may not be combined.");
        if (p->tasks_max < 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TasksMax= value out of range.");

        c->tasks_max = (CGroupTasksMax) { .value = p->tasks_max };
        unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);

        if (p->tasks_max == CGROUP_LIMIT_MAX)
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "TasksMax", "TasksMax=infinity");
        else
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "TasksMax", "TasksMax=%" PRIu64, p->tasks_max);
        return 0;
}

static int apply_cgroup_tasks_max_scale(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) {
        uint64_t permyriad;

        assert(c);
        assert(p);

        if (!p->tasks_max_scale_set)
                return 0;

        /* Mirroring the D-Bus TasksMaxScale property, 100% is rejected (not an actual limit). */
        if (fraction_to_permyriad(p->tasks_max_scale, &permyriad) < 0 || permyriad == 10000)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TasksMaxScale= value out of range.");

        c->tasks_max = (CGroupTasksMax) { .value = permyriad, .scale = 10000 };
        unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);

        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "TasksMax",
                            "TasksMax=" PERMYRIAD_AS_PERCENT_FORMAT_STR,
                            PERMYRIAD_AS_PERCENT_FORMAT_VAL((int) permyriad));
        return 0;
}

/* Weight apply fn; CPU weights additionally accept "idle" (= 0), matching the D-Bus setters. */
#define DEFINE_APPLY_CGROUP_WEIGHT(field, JsonName, mask, allow_idle)                                \
        static int apply_cgroup_##field(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) { \
                assert(c);                                                                           \
                assert(p);                                                                           \
                if (!p->field##_set)                                                                 \
                        return 0;                                                                    \
                uint64_t v = p->field;                                                               \
                if (!CGROUP_WEIGHT_IS_OK(v) && !(allow_idle && v == CGROUP_WEIGHT_IDLE))             \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), JsonName "= value out of range."); \
                c->field = v;                                                                        \
                unit_invalidate_cgroup(u, mask);                                                     \
                if (v == CGROUP_WEIGHT_INVALID)                                                      \
                        unit_write_setting(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName, JsonName "=");    \
                else if (v == CGROUP_WEIGHT_IDLE)                                                    \
                        unit_write_setting(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName, JsonName "=idle"); \
                else                                                                                 \
                        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName,                  \
                                            JsonName "=%" PRIu64, v);                                \
                return 0;                                                                            \
        }

DEFINE_APPLY_CGROUP_WEIGHT(cpu_weight,         "CPUWeight",        CGROUP_MASK_CPU, /* allow_idle= */ true);
DEFINE_APPLY_CGROUP_WEIGHT(startup_cpu_weight, "StartupCPUWeight", CGROUP_MASK_CPU, /* allow_idle= */ true);
DEFINE_APPLY_CGROUP_WEIGHT(io_weight,          "IOWeight",         CGROUP_MASK_IO,  /* allow_idle= */ false);
DEFINE_APPLY_CGROUP_WEIGHT(startup_io_weight,  "StartupIOWeight",  CGROUP_MASK_IO,  /* allow_idle= */ false);

/* Memory limit apply fn; min_one rejects 0 where D-Bus does (MemoryHigh/MemoryMax). */
#define DEFINE_APPLY_CGROUP_LIMIT(field, JsonName, min_one)                                          \
        static int apply_cgroup_##field(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) { \
                assert(c);                                                                           \
                assert(p);                                                                           \
                if (!p->field##_set)                                                                 \
                        return 0;                                                                    \
                uint64_t v = p->field;                                                               \
                if (min_one && v < 1)                                                                \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), JsonName "= value out of range."); \
                c->field = v;                                                                        \
                unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);                                       \
                if (v == CGROUP_LIMIT_MAX)                                                           \
                        unit_write_setting(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName, JsonName "=infinity"); \
                else                                                                                 \
                        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName,                  \
                                            JsonName "=%" PRIu64, v);                                \
                return 0;                                                                            \
        }

DEFINE_APPLY_CGROUP_LIMIT(memory_min,       "MemoryMin",      /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT(memory_low,       "MemoryLow",      /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT(memory_high,      "MemoryHigh",     /* min_one= */ true);
DEFINE_APPLY_CGROUP_LIMIT(memory_max,       "MemoryMax",      /* min_one= */ true);
DEFINE_APPLY_CGROUP_LIMIT(memory_swap_max,  "MemorySwapMax",  /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT(memory_zswap_max, "MemoryZSwapMax", /* min_one= */ false);

/* Relative memory limit: converted to absolute bytes via physical_memory_scale() like the D-Bus
 * *Scale properties, and written as permyriad percent (which the unit-file parser round-trips). */
#define DEFINE_APPLY_CGROUP_LIMIT_SCALE(field, JsonName, min_one)                                    \
        static int apply_cgroup_##field##_scale(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) { \
                uint64_t permyriad, v;                                                               \
                assert(c);                                                                           \
                assert(p);                                                                           \
                if (!p->field##_scale_set)                                                           \
                        return 0;                                                                    \
                if (p->field##_set)                                                                  \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), JsonName "= and " JsonName "Scale= may not be combined."); \
                if (fraction_to_permyriad(p->field##_scale, &permyriad) < 0)                         \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), JsonName "Scale= value out of range."); \
                v = physical_memory_scale(permyriad, 10000);                                         \
                if ((min_one && v < 1) || v == UINT64_MAX)                                           \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), JsonName "Scale= value out of range."); \
                c->field = v;                                                                        \
                unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);                                       \
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName,                          \
                                    JsonName "=" PERMYRIAD_AS_PERCENT_FORMAT_STR,                    \
                                    PERMYRIAD_AS_PERCENT_FORMAT_VAL((int) permyriad));               \
                return 0;                                                                            \
        }

DEFINE_APPLY_CGROUP_LIMIT_SCALE(memory_min,       "MemoryMin",      /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT_SCALE(memory_low,       "MemoryLow",      /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT_SCALE(memory_high,      "MemoryHigh",     /* min_one= */ true);
DEFINE_APPLY_CGROUP_LIMIT_SCALE(memory_max,       "MemoryMax",      /* min_one= */ true);
DEFINE_APPLY_CGROUP_LIMIT_SCALE(memory_swap_max,  "MemorySwapMax",  /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT_SCALE(memory_zswap_max, "MemoryZSwapMax", /* min_one= */ false);

/* Startup* limits additionally flip the context's <field>_set flag, which gates both the read-side
 * JSON and the STARTUP_MASK fallback logic — mirrors the D-Bus streq branches. */
#define DEFINE_APPLY_CGROUP_LIMIT_STARTUP(field, JsonName, min_one)                                  \
        static int apply_cgroup_##field(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) { \
                assert(c);                                                                           \
                assert(p);                                                                           \
                if (!p->field##_set)                                                                 \
                        return 0;                                                                    \
                uint64_t v = p->field;                                                               \
                if (min_one && v < 1)                                                                \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), JsonName "= value out of range."); \
                c->field = v;                                                                        \
                c->field##_set = true;                                                               \
                unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);                                       \
                if (v == CGROUP_LIMIT_MAX)                                                           \
                        unit_write_setting(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName, JsonName "=infinity"); \
                else                                                                                 \
                        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName,                  \
                                            JsonName "=%" PRIu64, v);                                \
                return 0;                                                                            \
        }

DEFINE_APPLY_CGROUP_LIMIT_STARTUP(startup_memory_low,       "StartupMemoryLow",      /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT_STARTUP(startup_memory_high,      "StartupMemoryHigh",     /* min_one= */ true);
DEFINE_APPLY_CGROUP_LIMIT_STARTUP(startup_memory_max,       "StartupMemoryMax",      /* min_one= */ true);
DEFINE_APPLY_CGROUP_LIMIT_STARTUP(startup_memory_swap_max,  "StartupMemorySwapMax",  /* min_one= */ false);
DEFINE_APPLY_CGROUP_LIMIT_STARTUP(startup_memory_zswap_max, "StartupMemoryZSwapMax", /* min_one= */ false);

/* Generate an apply fn for a cgroup accounting tristate bool. */
#define DEFINE_APPLY_CGROUP_TRISTATE_BOOL(field, JsonName, mask)                                     \
        static int apply_cgroup_##field(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p) { \
                assert(c);                                                                           \
                assert(p);                                                                           \
                if (p->field < 0)                                                                    \
                        return 0;                                                                    \
                c->field = p->field;                                                                 \
                unit_invalidate_cgroup(u, mask);                                                     \
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, JsonName,                          \
                                    JsonName "=%s", yes_no(p->field));                               \
                return 0;                                                                            \
        }

DEFINE_APPLY_CGROUP_TRISTATE_BOOL(memory_accounting,      "MemoryAccounting",     CGROUP_MASK_MEMORY);
DEFINE_APPLY_CGROUP_TRISTATE_BOOL(memory_zswap_writeback, "MemoryZSwapWriteback", CGROUP_MASK_MEMORY);
DEFINE_APPLY_CGROUP_TRISTATE_BOOL(tasks_accounting,       "TasksAccounting",      CGROUP_MASK_PIDS);
DEFINE_APPLY_CGROUP_TRISTATE_BOOL(io_accounting,          "IOAccounting",         CGROUP_MASK_IO);

/* Parse wrapper flipping <field>_set, as DEFINE_TRANSIENT_EXEC_SETTABLE in varlink-unit.c. */
#define DEFINE_TRANSIENT_CGROUP_SETTABLE(field)                              \
        static int dispatch_transient_cgroup_##field(                        \
                        const char *name,                                    \
                        sd_json_variant *variant,                            \
                        sd_json_dispatch_flags_t flags,                      \
                        void *userdata) {                                    \
                TransientCGroupContextParameters *p = ASSERT_PTR(userdata);  \
                p->field##_set = true;                                       \
                return sd_json_dispatch_uint64(name, variant, flags, &p->field); \
        }

DEFINE_TRANSIENT_CGROUP_SETTABLE(cpu_weight);
DEFINE_TRANSIENT_CGROUP_SETTABLE(startup_cpu_weight);
DEFINE_TRANSIENT_CGROUP_SETTABLE(cpu_quota_per_sec_usec);
DEFINE_TRANSIENT_CGROUP_SETTABLE(cpu_quota_period_usec);
DEFINE_TRANSIENT_CGROUP_SETTABLE(memory_min);
DEFINE_TRANSIENT_CGROUP_SETTABLE(memory_low);
DEFINE_TRANSIENT_CGROUP_SETTABLE(startup_memory_low);
DEFINE_TRANSIENT_CGROUP_SETTABLE(memory_high);
DEFINE_TRANSIENT_CGROUP_SETTABLE(startup_memory_high);
DEFINE_TRANSIENT_CGROUP_SETTABLE(memory_max);
DEFINE_TRANSIENT_CGROUP_SETTABLE(startup_memory_max);
DEFINE_TRANSIENT_CGROUP_SETTABLE(memory_swap_max);
DEFINE_TRANSIENT_CGROUP_SETTABLE(startup_memory_swap_max);
DEFINE_TRANSIENT_CGROUP_SETTABLE(memory_zswap_max);
DEFINE_TRANSIENT_CGROUP_SETTABLE(startup_memory_zswap_max);
DEFINE_TRANSIENT_CGROUP_SETTABLE(io_weight);
DEFINE_TRANSIENT_CGROUP_SETTABLE(startup_io_weight);

DEFINE_TRANSIENT_CGROUP_SETTABLE(tasks_max);

/* As above, but for float fields (fractions normalized to 1.0 == 100%). */
#define DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(field)                       \
        static int dispatch_transient_cgroup_##field(                        \
                        const char *name,                                    \
                        sd_json_variant *variant,                            \
                        sd_json_dispatch_flags_t flags,                      \
                        void *userdata) {                                    \
                TransientCGroupContextParameters *p = ASSERT_PTR(userdata);  \
                p->field##_set = true;                                       \
                return sd_json_dispatch_double(name, variant, flags, &p->field); \
        }

DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(tasks_max_scale);
DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(memory_min_scale);
DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(memory_low_scale);
DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(memory_high_scale);
DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(memory_max_scale);
DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(memory_swap_max_scale);
DEFINE_TRANSIENT_CGROUP_SETTABLE_DOUBLE(memory_zswap_max_scale);

/* Per-property descriptor, mirroring TransientExecProperty in varlink-unit.c; tristate ints are
 * seeded to -1 by transient_cgroup_context_parameters_init(). */
typedef struct TransientCGroupProperty {
        const char *json_name;
        const char *err_field;
        sd_json_variant_type_t json_type;
        sd_json_dispatch_callback_t dispatch;
        size_t parse_offset;
        int (*apply)(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p);
        bool tristate;
} TransientCGroupProperty;

#define CGROUP_PROPERTY(json, type, dispatch_fn, parse_offset, apply_fn) \
        { json, "CGroup." json, type, dispatch_fn, parse_offset, apply_fn }

#define CGROUP_PROPERTY_UINT64(json, field)                              \
        { json, "CGroup." json, _SD_JSON_VARIANT_TYPE_INVALID,           \
          dispatch_transient_cgroup_##field, 0, apply_cgroup_##field }

#define CGROUP_PROPERTY_DOUBLE(json, field)                              \
        { json, "CGroup." json, _SD_JSON_VARIANT_TYPE_INVALID,           \
          dispatch_transient_cgroup_##field, 0, apply_cgroup_##field }

#define CGROUP_PROPERTY_TRISTATE_BOOL(json, field)                       \
        { json, "CGroup." json, SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, \
          offsetof(TransientCGroupContextParameters, field), apply_cgroup_##field, true }

static const TransientCGroupProperty cgroup_properties[] = {
        CGROUP_PROPERTY              ("Slice", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(TransientCGroupContextParameters, slice), apply_cgroup_slice),

        CGROUP_PROPERTY_UINT64       ("CPUWeight",          cpu_weight),
        CGROUP_PROPERTY_UINT64       ("StartupCPUWeight",   startup_cpu_weight),
        CGROUP_PROPERTY_UINT64       ("CPUQuotaPerSecUSec", cpu_quota_per_sec_usec),
        CGROUP_PROPERTY_UINT64       ("CPUQuotaPeriodUSec", cpu_quota_period_usec),

        CGROUP_PROPERTY_TRISTATE_BOOL("MemoryAccounting", memory_accounting),
        CGROUP_PROPERTY_UINT64       ("MemoryMin",             memory_min),
        CGROUP_PROPERTY_DOUBLE       ("MemoryMinScale", memory_min_scale),
        CGROUP_PROPERTY_UINT64       ("MemoryLow",             memory_low),
        CGROUP_PROPERTY_DOUBLE       ("MemoryLowScale", memory_low_scale),
        CGROUP_PROPERTY_UINT64       ("StartupMemoryLow",      startup_memory_low),
        CGROUP_PROPERTY_UINT64       ("MemoryHigh",            memory_high),
        CGROUP_PROPERTY_DOUBLE       ("MemoryHighScale", memory_high_scale),
        CGROUP_PROPERTY_UINT64       ("StartupMemoryHigh",     startup_memory_high),
        CGROUP_PROPERTY_UINT64       ("MemoryMax",             memory_max),
        CGROUP_PROPERTY_DOUBLE       ("MemoryMaxScale", memory_max_scale),
        CGROUP_PROPERTY_UINT64       ("StartupMemoryMax",      startup_memory_max),
        CGROUP_PROPERTY_UINT64       ("MemorySwapMax",         memory_swap_max),
        CGROUP_PROPERTY_DOUBLE       ("MemorySwapMaxScale", memory_swap_max_scale),
        CGROUP_PROPERTY_UINT64       ("StartupMemorySwapMax",  startup_memory_swap_max),
        CGROUP_PROPERTY_UINT64       ("MemoryZSwapMax",        memory_zswap_max),
        CGROUP_PROPERTY_DOUBLE       ("MemoryZSwapMaxScale", memory_zswap_max_scale),
        CGROUP_PROPERTY_UINT64       ("StartupMemoryZSwapMax", startup_memory_zswap_max),
        CGROUP_PROPERTY_TRISTATE_BOOL("MemoryZSwapWriteback",  memory_zswap_writeback),

        CGROUP_PROPERTY_TRISTATE_BOOL("TasksAccounting", tasks_accounting),
        CGROUP_PROPERTY_UINT64       ("TasksMax",      tasks_max),
        CGROUP_PROPERTY_DOUBLE       ("TasksMaxScale", tasks_max_scale),

        CGROUP_PROPERTY_TRISTATE_BOOL("IOAccounting",    io_accounting),
        CGROUP_PROPERTY_UINT64       ("IOWeight",        io_weight),
        CGROUP_PROPERTY_UINT64       ("StartupIOWeight", startup_io_weight),
};
#undef CGROUP_PROPERTY
#undef CGROUP_PROPERTY_UINT64
#undef CGROUP_PROPERTY_TRISTATE_BOOL

void transient_cgroup_context_parameters_init(TransientCGroupContextParameters *p) {
        assert(p);

        *p = (TransientCGroupContextParameters) {};
        FOREACH_ELEMENT(prop, cgroup_properties)
                if (prop->tristate)
                        *(int*) ((uint8_t*) p + prop->parse_offset) = -1;
}

int transient_cgroup_context_dispatch(sd_json_variant *variant, TransientCGroupContextParameters *p, const char **reterr_bad_field) {
        /* Build dispatch table only once, its constant. */
        static sd_json_dispatch_field cgroup_dispatch[ELEMENTSOF(cgroup_properties) + 1] = {};
        static bool cgroup_dispatch_set = false;

        assert(p);

        if (!cgroup_dispatch_set) {
                FOREACH_ELEMENT(prop, cgroup_properties)
                        cgroup_dispatch[prop - cgroup_properties] = (sd_json_dispatch_field) {
                                .name = prop->json_name,
                                .type = prop->json_type,
                                .callback = prop->dispatch,
                                .offset = prop->parse_offset,
                        };
                cgroup_dispatch_set = true;
        }

        return sd_json_dispatch_full(variant, cgroup_dispatch, /* bad= */ NULL, /* flags= */ 0, p, reterr_bad_field);
}

int transient_cgroup_context_apply_properties(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p, const char **reterr_field) {
        int r;

        assert(u);
        assert(c);
        assert(p);

        FOREACH_ELEMENT(prop, cgroup_properties) {
                r = prop->apply(u, c, p);
                if (r < 0) {
                        if (reterr_field)
                                *reterr_field = r == -EINVAL ? prop->err_field : NULL;
                        return r;
                }
        }

        return 0;
}
