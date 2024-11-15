/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "af-list.h"
#include "json-util.h"
#include "in-addr-prefix-util.h"
#include "ip-protocol-list.h"
#include "unit.h"
#include "unit-varlink.h"
#include "varlink-common.h"

#define JSON_BUILD_PAIR_CONDITION_BOOLEAN(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(condition, name, SD_JSON_BUILD_BOOLEAN(value))
#define JSON_BUILD_PAIR_CONDITION_INTEGER(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(condition, name, SD_JSON_BUILD_INTEGER(value))
#define JSON_BUILD_PAIR_CONDITION_UNSIGNED(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(condition, name, SD_JSON_BUILD_UNSIGNED(value))
#define JSON_BUILD_PAIR_CONDITION_STRING(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(condition, name, SD_JSON_BUILD_STRING(value))
#define JSON_BUILD_PAIR_CONDITION_STRING_NON_EMPTY(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION((condition) && !isempty(value), name, SD_JSON_BUILD_STRING(value))
#define JSON_BUILD_STRING_FROM_TABLE_ABOVE_MIN(name, value, value_min, value_str) \
        SD_JSON_BUILD_PAIR_CONDITION(value > value_min, name, SD_JSON_BUILD_STRING(value_str))

static int unit_dependencies_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata), *other;
        UnitDependency d;
        void *value;
        int r;

        assert(ret);
        assert(name);

        d = unit_dependency_from_string(name);
        assert(d >= 0);

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
        assert_se(d >= 0);

        HASHMAP_FOREACH_KEY(value, p, mounts_for[d]) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(p));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_conditions_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Condition *list = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        bool do_asserts = streq(name, "asserts");
        int r;

        assert(ret);

        LIST_FOREACH(conditions, c, list) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("type", do_asserts ? assert_type_to_string(c->type)
                                                                             : condition_type_to_string(c->type)),
                                SD_JSON_BUILD_PAIR_BOOLEAN("trigger", c->trigger),
                                SD_JSON_BUILD_PAIR_BOOLEAN("negate", c->negate),
                                SD_JSON_BUILD_PAIR_STRING("parameter", c->parameter));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_mask_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupMask mask = PTR_TO_INT(userdata);
        int r;

        assert(ret);

        for (CGroupController ctrl = 0; ctrl < _CGROUP_CONTROLLER_MAX; ctrl++) {
                if ((mask & CGROUP_CONTROLLER_TO_MASK(ctrl)) == 0)
                        continue;

                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(cgroup_controller_to_string(ctrl)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cpu_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_free_ uint8_t *array = NULL;
        CPUSet *cpuset = ASSERT_PTR(userdata);
        size_t allocated;
        int r;

        assert(ret);

        if (!cpuset->set)
                return 0;

        r = cpu_set_to_dbus(cpuset, &array, &allocated);
        if (r < 0)
                return log_debug_errno(r, "Failed to call cpu_set_to_dbus(): %m");

        if (allocated == 0)
                return 0;

        return sd_json_variant_new_array_bytes(ret, array, allocated);
}

static int cgroup_io_device_weights_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupIODeviceWeight *weights = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(device_weights, w, weights) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", w->path),
                                SD_JSON_BUILD_PAIR_UNSIGNED("weight", w->weight));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_io_device_limits_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupIODeviceLimit *limits = userdata;
        int r;

        assert(ret);
        assert(name);

        LIST_FOREACH(device_limits, l, limits) {
                CGroupIOLimitType type;

                type = cgroup_io_limit_type_from_string(name);
                if (type < 0 || l->limits[type] == cgroup_io_limit_defaults[type])
                        continue;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", l->path),
                                SD_JSON_BUILD_PAIR_UNSIGNED("limit", l->limits[type]));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int cgroup_io_device_latencies_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupIODeviceLatency *latencies = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(device_latencies, l, latencies) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", l->path),
                                SD_JSON_BUILD_PAIR_UNSIGNED("targetUSec", l->target_usec));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_device_allow_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupDeviceAllow *allow = userdata;
        int r;

        LIST_FOREACH(device_allow, a, allow) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", a->path),
                                SD_JSON_BUILD_PAIR_STRING("permissions", cgroup_device_permissions_to_string(a->permissions)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_tasks_max_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        CGroupTasksMax *tasks_max = ASSERT_PTR(userdata);

        assert(ret);

        if (!cgroup_tasks_max_isset(tasks_max))
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("value", tasks_max->value),
                        SD_JSON_BUILD_PAIR_UNSIGNED("scale", tasks_max->scale));
}

static int cgroup_ip_address_access_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Set *prefixes = userdata;
        struct in_addr_prefix *i;
        int r;

        assert(ret);

        SET_FOREACH(i, prefixes) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("family", af_to_name(i->family)),
                                SD_JSON_BUILD_PAIR_BYTE_ARRAY("address", &i->address, FAMILY_ADDRESS_SIZE(i->family)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("prefixLen", i->prefixlen));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_bpf_program_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupBPFForeignProgram *programs = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(programs, p, programs) {
                const char *attach_type = bpf_cgroup_attach_type_to_string(p->attach_type);

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("attachType", attach_type),
                                SD_JSON_BUILD_PAIR_STRING("path", p->bpffs_path));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_socket_bind_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        CGroupSocketBindItem *items = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(socket_bind_items, i, items) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("family", af_to_name(i->address_family)),
                                SD_JSON_BUILD_PAIR_STRING("protocol", ip_protocol_to_name(i->ip_protocol)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("numberOfPorts", i->nr_ports),
                                SD_JSON_BUILD_PAIR_UNSIGNED("minimumPort", i->port_min));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cgroup_nft_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        NFTSetContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        FOREACH_ARRAY(nft_set, c->sets, c->n_sets) {
                r = sd_json_variant_append_arraybo(&v,
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

static int cgroup_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupContext *c;

        assert(ret);

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        return sd_json_buildo(ret,
                        /* CPU Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("CPUAccounting", c->cpu_accounting),
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
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TasksMax", cgroup_tasks_max_build_json, &c->tasks_max),

                        /* IO Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("IOAccounting", c->io_accounting),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("IOWeight", c->io_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("StartupIOWeight", c->startup_io_weight, CGROUP_WEIGHT_INVALID),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IODeviceWeight", cgroup_io_device_weights_build_json, c->io_device_weights),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOReadBandwidthMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOWriteBandwidthMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOReadIOPSMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOWriteIOPSMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IODeviceLatencyTargetUSec", cgroup_io_device_latencies_build_json, c->io_device_latencies),

                        /* Network Accounting and Control */
                        SD_JSON_BUILD_PAIR_BOOLEAN("IPAccounting", c->ip_accounting),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPAddressAllow", cgroup_ip_address_access_build_json, c->ip_address_allow),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IPAddressDeny", cgroup_ip_address_access_build_json, c->ip_address_deny),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SocketBindAllow", cgroup_socket_bind_build_json, c->socket_bind_allow),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SocketBindDeny", cgroup_socket_bind_build_json, c->socket_bind_deny),
                        SD_JSON_BUILD_PAIR_CONDITION(!set_isempty(c->restrict_network_interfaces), "RestrictNetworkInterfaces",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->restrict_network_interfaces_is_allow_list),
                                                JSON_BUILD_PAIR_STRING_SET("interfaces", c->restrict_network_interfaces))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("NFTSet", cgroup_nft_set_build_json, &c->nft_set_context),

                        /* BPF programs */
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("IPIngressFilterPath", c->ip_filters_ingress),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("IPEgressFilterPath", c->ip_filters_egress),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BPFProgram", cgroup_bpf_program_build_json, c->bpf_foreign_programs),

                        /* Device Access */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DeviceAllow", cgroup_device_allow_build_json, c->device_allow),
                        SD_JSON_BUILD_PAIR_STRING("DevicePolicy", cgroup_device_policy_to_string(c->device_policy)),

                        /* Control Group Management */
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Slice", unit_slice_name(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Delegate", c->delegate),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("DelegateSubgroup", c->delegate_subgroup),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DelegateControllers", cgroup_mask_build_json, INT_TO_PTR(c->delegate_controllers)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DisableControllers", cgroup_mask_build_json, INT_TO_PTR(c->disable_controllers)),

                        /* Memory Pressure Control */
                        SD_JSON_BUILD_PAIR_STRING("ManagedOOMSwap", managed_oom_mode_to_string(c->moom_swap)),
                        SD_JSON_BUILD_PAIR_STRING("ManagedOOMMemoryPressure", managed_oom_mode_to_string(c->moom_mem_pressure)),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ManagedOOMMemoryPressureLimit", c->moom_mem_pressure_limit),
                        JSON_BUILD_STRING_FROM_TABLE_ABOVE_MIN(
                                        "ManagedOOMPreference",
                                        c->moom_preference,
                                        MANAGED_OOM_PREFERENCE_NONE,
                                        managed_oom_preference_to_string(c->moom_preference)),
                        SD_JSON_BUILD_PAIR_STRING("MemoryPressureWatch", cgroup_pressure_watch_to_string(c->memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("MemoryPressureThresholdUSec", c->memory_pressure_threshold_usec));
}

#define JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY(name, value) \
        JSON_BUILD_STRING_FROM_TABLE_ABOVE_MIN(name, value, EMERGENCY_ACTION_NONE, emergency_action_to_string(value))

static int unit_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("Type", unit_type_to_string(u->type)),
                        SD_JSON_BUILD_PAIR_STRING("ID", u->id),
                        SD_JSON_BUILD_PAIR_CONDITION(!set_isempty(u->aliases), "Names", JSON_BUILD_STRING_SET(u->aliases)),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Documentation", u->documentation),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Description", u->description),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Requires", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Requisite", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Wants", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BindsTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Upholds", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PartOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Conflicts", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequiredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequisiteOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WantedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BoundBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("UpheldBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConsistsOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConflictedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Before", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("After", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnSuccess", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnSuccessOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnFailure", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OnFailureOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Triggers", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TriggeredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PropagatesReloadTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ReloadPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("PropagatesStopTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StopPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("JoinsNamespaceOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RequiresMountsFor", unit_mounts_for_build_json, &u->mounts_for),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WantsMountsFor", unit_mounts_for_build_json, &u->mounts_for),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("AccessSELinuxContext", u->access_selinux_context),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("FragmentPath", u->fragment_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SourcePath", u->source_path),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("DropInPaths", u->dropin_paths),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UnitFilePreset", preset_action_past_tense_to_string(unit_get_unit_file_preset(u))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("StopWhenUnneeded", u->stop_when_unneeded),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStart", u->refuse_manual_start),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RefuseManualStop", u->refuse_manual_stop),
                        SD_JSON_BUILD_PAIR_BOOLEAN("AllowIsolate", u->allow_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DefaultDependencies", u->default_dependencies),
                        SD_JSON_BUILD_PAIR_STRING("OnSuccessJobMode", job_mode_to_string(u->on_success_job_mode)),
                        SD_JSON_BUILD_PAIR_STRING("OnFailureJobMode", job_mode_to_string(u->on_failure_job_mode)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreOnIsolate", u->ignore_on_isolate),
                        JSON_BUILD_PAIR_FINITE_USEC("JobTimeoutUSec", u->job_timeout),
                        JSON_BUILD_PAIR_FINITE_USEC("JobRunningTimeoutUSec", u->job_running_timeout),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("JobTimeoutAction", u->job_timeout_action),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("JobTimeoutRebootArgument", u->job_timeout_reboot_arg),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Conditions", unit_conditions_build_json, u->conditions),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Asserts", unit_conditions_build_json, u->asserts),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Transient", u->transient),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Perpetual", u->perpetual),
                        JSON_BUILD_PAIR_RATELIMIT_ENABLED("StartLimit", &u->start_ratelimit),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("StartLimitAction", u->start_limit_action),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("FailureAction", u->failure_action),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("FailureActionExitStatus", u->failure_action_exit_status),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("SuccessAction", u->success_action),
                        JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY("SuccessActionExitStatus", u->success_action_exit_status),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RebootArgument", u->reboot_arg),
                        SD_JSON_BUILD_PAIR_STRING("CollectMode", collect_mode_to_string(u->collect_mode)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CGroup", cgroup_context_build_json, u));
}

static int list_unit_one(sd_varlink *link, Unit *unit, bool more) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(unit);

        r = sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR_CALLBACK("Context", unit_context_build_json, unit));
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

                /* if (unit_is_filtered(u, p.states, p.patterns)) */
                        /* continue; */

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
