/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "bpf-program.h"
#include "cgroup.h"
#include "json-util.h"
#include "in-addr-prefix-util.h"
#include "ip-protocol-list.h"
#include "path-util.h"
#include "set.h"
#include "unit.h"
#include "varlink-cgroup.h"
#include "varlink-common.h"

static int tasks_max_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        CGroupTasksMax *tasks_max = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        if (!cgroup_tasks_max_isset(tasks_max)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("value", tasks_max->value),
                        SD_JSON_BUILD_PAIR_UNSIGNED("scale", tasks_max->scale));
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

                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(cgroup_controller_to_string(ctrl)));
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
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("NFTSet", nft_set_build_json, &c->nft_set_context),

                        /* BPF programs */
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("IPIngressFilterPath", c->ip_filters_ingress),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("IPEgressFilterPath", c->ip_filters_egress),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BPFProgram", bpf_program_build_json, c->bpf_foreign_programs),

                        /* Device Access */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DeviceAllow", device_allow_build_json, c->device_allow),
                        SD_JSON_BUILD_PAIR_STRING("DevicePolicy", cgroup_device_policy_to_string(c->device_policy)),

                        /* Control Group Management */
                        SD_JSON_BUILD_PAIR_BOOLEAN("Delegate", c->delegate),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("DelegateSubgroup", c->delegate_subgroup),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DelegateControllers", controllers_build_json, &c->delegate_controllers),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DisableControllers", controllers_build_json, &c->disable_controllers),

                        /* Memory Pressure Control */
                        SD_JSON_BUILD_PAIR_STRING("ManagedOOMSwap", managed_oom_mode_to_string(c->moom_swap)),
                        SD_JSON_BUILD_PAIR_STRING("ManagedOOMMemoryPressure", managed_oom_mode_to_string(c->moom_mem_pressure)),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ManagedOOMMemoryPressureLimit", c->moom_mem_pressure_limit),
                        JSON_BUILD_PAIR_FINITE_USEC("ManagedOOMMemoryPressureDurationUSec", c->moom_mem_pressure_duration_usec),
                        SD_JSON_BUILD_PAIR_STRING("ManagedOOMPreference", managed_oom_preference_to_string(c->moom_preference)),
                        SD_JSON_BUILD_PAIR_STRING("MemoryPressureWatch", cgroup_pressure_watch_to_string(c->memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("MemoryPressureThresholdUSec", c->memory_pressure_threshold_usec),

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
