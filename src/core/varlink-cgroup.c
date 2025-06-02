/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "bpf-program.h"
#include "cgroup.h"
#include "cpu-set-util.h"
#include "json-util.h"
#include "in-addr-prefix-util.h"
#include "ip-protocol-list.h"
#include "set.h"
#include "unit.h"
#include "varlink-cgroup.h"

#define JSON_BUILD_PAIR_CONDITION_UNSIGNED(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(condition, name, SD_JSON_BUILD_UNSIGNED(value))

static int cpu_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_free_ uint8_t *array = NULL;
        CPUSet *cpuset = ASSERT_PTR(userdata);
        size_t allocated;
        int r;

        assert(ret);
        assert(name);

        if (!cpuset->set)
                goto empty;

        r = cpu_set_to_dbus(cpuset, &array, &allocated);
        if (r < 0)
                return log_debug_errno(r, "Failed to call cpu_set_to_dbus(): %m");

        if (allocated == 0)
                goto empty;

        return sd_json_variant_new_array_bytes(ret, array, allocated);

empty:
        *ret = NULL;
        return 0;
}

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
                                JSON_BUILD_PAIR_IN_ADDR("address", &i->address, i->family),
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
        assert(ret);
        assert(name);

        CGroupContext *c = userdata;
        if (!c) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,

                        /* CPU Control */
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("CPUWeight", c->cpu_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("StartupCPUWeight", c->startup_cpu_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_FINITE_USEC("CPUQuotaPerSecUSec", c->cpu_quota_per_sec_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("CPUQuotaPeriodUSec", c->cpu_quota_period_usec),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("AllowedCPUs", cpu_set_build_json, &c->cpuset_cpus),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StartupAllowedCPUs", cpu_set_build_json, &c->startup_cpuset_cpus),

                        /* Memory Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("MemoryAccounting", c->memory_accounting),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->memory_min_set, "MemoryMin", c->memory_min),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->default_memory_min_set, "DefaultMemoryMin", c->default_memory_min),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->memory_low_set, "MemoryLow", c->memory_low),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->default_memory_low_set, "DefaultMemoryLow", c->default_memory_low),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_low_set, "StartupMemoryLow", c->startup_memory_low),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->default_startup_memory_low_set, "DefaultStartupMemoryLow", c->default_startup_memory_low),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryHigh", c->memory_high, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_high_set, "StartupMemoryHigh", c->startup_memory_high),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryMax", c->memory_max, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_max_set, "StartupMemoryMax", c->startup_memory_max),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemorySwapMax", c->memory_swap_max, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_swap_max_set, "StartupMemorySwapMax", c->startup_memory_swap_max),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("MemoryZSwapMax", c->memory_zswap_max, CGROUP_LIMIT_MAX),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->startup_memory_zswap_max_set, "StartupMemoryZSwapMax", c->startup_memory_zswap_max),
                        SD_JSON_BUILD_PAIR_BOOLEAN("MemoryZSwapWriteback", c->memory_zswap_writeback),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("AllowedMemoryNodes", cpu_set_build_json, &c->cpuset_mems),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StartupAllowedMemoryNodes", cpu_set_build_json, &c->startup_cpuset_mems),

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
