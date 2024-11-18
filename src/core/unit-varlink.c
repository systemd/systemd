/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "af-list.h"
#include "automount.h"
#include "cap-list.h"
#include "exec-credential.h"
#include "json-util.h"
#include "mount.h"
#include "mountpoint-util.h"
#include "in-addr-prefix-util.h"
#include "ioprio-util.h"
#include "ip-protocol-list.h"
#include "path.h"
#include "seccomp-util.h"
#include "securebits-util.h"
#include "signal-util.h"
#include "syslog-util.h"
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

static int environment_files_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        char **environment_files = userdata;
        int r;

        assert(ret);

        STRV_FOREACH(j, environment_files) {
                const char *fn = *j;
                if (isempty(fn))
                        continue;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", fn[0] == '-' ? fn + 1 : fn),
                                SD_JSON_BUILD_PAIR_BOOLEAN("graceful", fn[0] == '-'));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int working_directory_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        const char *wd = c->working_directory_home ? "~" : c->working_directory;
        if (!wd)
                return 0;

        assert(ret);

        return sd_json_buildo(ret,
                SD_JSON_BUILD_PAIR_STRING("path", wd),
                SD_JSON_BUILD_PAIR_BOOLEAN("missingOK", c->working_directory_missing_ok));
}

static int root_image_options_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        MountOptions *root_image_options = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(mount_options, m, root_image_options) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("partitionDesignator", partition_designator_to_string(m->partition_designator)),
                                SD_JSON_BUILD_PAIR_STRING("options", m->options));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int extension_images_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < c->n_extension_images; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mo = NULL;

                LIST_FOREACH(mount_options, m, c->extension_images[i].mount_options) {
                        r = sd_json_variant_append_arraybo(&mo,
                                        SD_JSON_BUILD_PAIR_STRING("partitionDesignator", partition_designator_to_string(m->partition_designator)),
                                        SD_JSON_BUILD_PAIR_STRING("options", m->options));
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("source", c->extension_images[i].source),
                                SD_JSON_BUILD_PAIR_BOOLEAN("ignoreEnoent", c->extension_images[i].ignore_enoent),
                                SD_JSON_BUILD_PAIR_VARIANT("mountOptions", mo));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int mount_images_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < c->n_mount_images; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mo = NULL;

                LIST_FOREACH(mount_options, m, c->mount_images[i].mount_options) {
                        r = sd_json_variant_append_arraybo(&mo,
                                        SD_JSON_BUILD_PAIR_STRING("partitionDesignator", partition_designator_to_string(m->partition_designator)),
                                        SD_JSON_BUILD_PAIR_STRING("options", m->options));
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("source", c->mount_images[i].source),
                                SD_JSON_BUILD_PAIR_STRING("destination", c->mount_images[i].destination),
                                SD_JSON_BUILD_PAIR_BOOLEAN("ignoreEnoent", c->mount_images[i].ignore_enoent),
                                SD_JSON_BUILD_PAIR_VARIANT("mountOptions", mo));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int ioprio_class_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);

        if (!c->ioprio_set)
                return 0;

        r = ioprio_class_to_string_alloc(ioprio_prio_class(exec_context_get_effective_ioprio(c)), &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert IOPrio class to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int cpu_sched_class_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);

        if (!c->cpu_sched_set)
                return 0;

        r = sched_policy_to_string_alloc(exec_context_get_cpu_sched_policy(c), &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert shed policy to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int cpu_affinity_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        if (exec_context_get_cpu_affinity_from_numa(c)) {
                _cleanup_(cpu_set_reset) CPUSet s = {};

                r = numa_to_cpu_set(&c->numa_policy, &s);
                if (r < 0)
                        return log_debug_errno(r, "Failed to call numa_to_cpu_set(): %m");

                return cpu_set_build_json(ret, /* name= */ NULL, &s);
        }

        return cpu_set_build_json(ret, /* name= */ NULL, &c->cpu_set);
}

static int numa_policy_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        int t = numa_policy_get_type(&c->numa_policy);
        if (!mpol_is_valid(t))
                return 0;

        return sd_json_variant_new_string(ret, mpol_to_string(t));
}

static int numa_mask_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        int t = numa_policy_get_type(&c->numa_policy);
        if (!mpol_is_valid(t))
                return 0;

        return cpu_set_build_json(ret, /* name= */ NULL, &c->numa_policy.nodes);
}

static int log_level_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int log_level = PTR_TO_INT(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        if (log_level < 0)
                return 0;

        r = log_level_to_string_alloc(log_level, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert log level to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int syslog_facility_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int log_facility = PTR_TO_INT(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        r = log_facility_unshifted_to_string_alloc(log_facility << 3, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert log facility to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int log_extra_fields_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (size_t i = 0; i < c->n_log_extra_fields; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *s = NULL;

                r = sd_json_variant_new_stringn(&s, c->log_extra_fields[i].iov_base, c->log_extra_fields[i].iov_len);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&v, s);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int log_filter_patterns_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        const char *pattern;
        int r;

        SET_FOREACH(pattern, c->log_filter_allowed_patterns) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_BOOLEAN("isAllowPattern", true),
                                SD_JSON_BUILD_PAIR_STRING("pattern", pattern));
                if (r < 0)
                        return r;
        }

        SET_FOREACH(pattern, c->log_filter_denied_patterns) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_BOOLEAN("isAllowPattern", false),
                                SD_JSON_BUILD_PAIR_STRING("pattern", pattern));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int secure_bits_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int secure_bits = PTR_TO_INT(userdata);
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        r = secure_bits_to_string_alloc(secure_bits, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert secure bits to string: %m");

        if (strlen(s) == 0)
                return 0;

        l = strv_split(s, NULL);
        if (!l)
                return -ENOMEM;

        return sd_json_variant_new_array_strv(ret, l);
}

static int capability_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        uint64_t *capability_set = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;
        int r;

        r = capability_set_to_strv(*capability_set, &l);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert capability set to string[]: %m");

        if (strv_length(l) == 0)
                return 0;

        return sd_json_variant_new_array_strv(ret, l);
}

static int set_credential_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Hashmap *set_credentials = userdata;
        ExecSetCredential *sc;
        int r;

        assert(ret);

        HASHMAP_FOREACH(sc, set_credentials) {
                if (sc->encrypted != streq(name, "setCredentialEncrypted"))
                        continue;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("id", sc->id),
                                SD_JSON_BUILD_PAIR_BASE64("value", sc->data, sc->size));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int load_credential_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Hashmap *load_credentials = userdata;
        ExecLoadCredential *lc;
        int r;

        assert(ret);

        HASHMAP_FOREACH(lc, load_credentials) {
                if (lc->encrypted != streq(name, "loadCredentialEncrypted"))
                        continue;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("id", lc->id),
                                SD_JSON_BUILD_PAIR_STRING("path", lc->path));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int import_credential_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        OrderedSet *import_credentials = userdata;
        ExecImportCredential *ic;
        int r;

        assert(ret);

        ORDERED_SET_FOREACH(ic, import_credentials) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("glob", ic->glob),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("rename", ic->rename));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int syscall_filter_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_syscall_filter(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l))
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->syscall_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("systemCalls", l));
}

static int syscall_archs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_syscall_archs(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l))
                return 0;

        return sd_json_variant_new_array_strv(ret, l);
}

static int syscall_error_number_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        int syscall_error_number = c->syscall_errno;
        if (syscall_error_number == 0)
                return 0;
        if (syscall_error_number == SECCOMP_ERROR_NUMBER_KILL)
                return sd_json_variant_new_string(ret, "kill");
        if (errno_to_name(syscall_error_number))
                return sd_json_variant_new_string(ret, errno_to_name(syscall_error_number));

        char buf[DECIMAL_STR_MAX(int) + 1];
        xsprintf(buf, "%i", syscall_error_number);

        return sd_json_variant_new_string(ret, buf);
}

static int syscall_log_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_syscall_log(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l))
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->syscall_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("systemCalls", l));
}

static int address_families_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);

        l = exec_context_get_address_families(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l))
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->address_families_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("addressFamilies", l));
}

static int exec_dir_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecDirectory *exec_dir = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        FOREACH_ARRAY(dir, exec_dir->items, exec_dir->n_items) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", dir->path),
                                SD_JSON_BUILD_PAIR_UNSIGNED("mode", exec_dir->mode),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("symlinks", dir->symlinks));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int namespace_flags_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = namespace_flags_to_strv(c->restrict_namespaces, &l);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert namespace flags to string[]: %m");

        if (strv_isempty(l))
                return 0;

        return sd_json_variant_new_array_strv(ret, l);
}

static int restrict_filesystems_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;

        assert(ret);

        l = exec_context_get_restrict_filesystems(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l))
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->restrict_filesystems_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("filesystems", l));
}

static int bind_paths_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        bool ro = strstr(name, "ReadOnly");
        int r;

        assert(ret);

        for (size_t i = 0; i < c->n_bind_mounts; i++) {
                if (ro != c->bind_mounts[i].read_only)
                        continue;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("source", c->bind_mounts[i].source),
                                SD_JSON_BUILD_PAIR_STRING("destination", c->bind_mounts[i].destination),
                                SD_JSON_BUILD_PAIR_BOOLEAN("ignoreEnoent", c->bind_mounts[i].ignore_enoent),
                                SD_JSON_BUILD_PAIR_STRV("options", STRV_MAKE(c->bind_mounts[i].recursive ? "rbind" : "norbind")));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int temporary_filesystems_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        FOREACH_ARRAY(t, c->temporary_filesystems, c->n_temporary_filesystems) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", t->path),
                                SD_JSON_BUILD_PAIR_STRING("options", t->options));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int image_policy_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_free_ char *s = NULL;
        ImagePolicy *policy = userdata;
        int r;

        assert(ret);

        r = image_policy_to_string(policy ?: &image_policy_service, /* simplify= */ true, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert image policy to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int exec_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c;

        c = unit_get_exec_context(ASSERT_PTR(userdata));
        if (!c)
                return 0;

        return sd_json_buildo(ASSERT_PTR(ret),
                        /* Paths */
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ExecSearchPath", c->exec_search_path),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WorkingDirectory", working_directory_build_json, c),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootDirectory", c->root_directory),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootImage", c->root_image),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RootImageOptions", root_image_options_build_json, c->root_image_options),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RootEphemeral", c->root_ephemeral),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("RootHash", c->root_hash, c->root_hash_size),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootHashPath", c->root_hash_path),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("RootHashSignature", c->root_hash_sig, c->root_hash_sig_size),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootHashSignaturePath", c->root_hash_sig_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootVerity", c->root_verity),
                        SD_JSON_BUILD_PAIR_CALLBACK("RootImagePolicy", image_policy_build_json, c->root_image_policy),
                        SD_JSON_BUILD_PAIR_CALLBACK("MountImagePolicy", image_policy_build_json, c->mount_image_policy),
                        SD_JSON_BUILD_PAIR_CALLBACK("ExtensionImagePolicy", image_policy_build_json, c->extension_image_policy),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("MountAPIVFS", c->mount_apivfs),
                        SD_JSON_BUILD_PAIR_STRING("ProtectProc", protect_proc_to_string(c->protect_proc)),
                        SD_JSON_BUILD_PAIR_STRING("ProcSubset", proc_subset_to_string(c->proc_subset)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BindPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BindReadOnlyPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MountImages", mount_images_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExtensionImages", extension_images_build_json, c),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ExtensionDirectories", c->extension_directories),

                        /* User/Group Identity */
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("User", c->user),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Group", c->group),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DynamicUser", c->dynamic_user),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("SupplementaryGroups", c->supplementary_groups),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("SetLoginEnvironment", c->set_login_environment),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("PAMName", c->pam_name),

                        /* Capabilities */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CapabilityBoundingSet", capability_set_build_json, &c->capability_bounding_set),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("AmbientCapabilities", capability_set_build_json, &c->capability_ambient_set),

                        /* Security */
                        SD_JSON_BUILD_PAIR_BOOLEAN("NoNewPrivileges", c->no_new_privileges),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SecureBits", secure_bits_build_json, INT_TO_PTR(c->secure_bits)),

                        /* Mandatory Access Control */
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->selinux_context, "SELinuxContext",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("Ignore", c->selinux_context_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("Context", c->selinux_context))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->apparmor_profile, "AppArmorProfile",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("Ignore", c->apparmor_profile_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("Profile", c->apparmor_profile))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->smack_process_label, "SmackProcessLabel",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("Ignore", c->smack_process_label_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("Label", c->smack_process_label))),

                        /* Process Properties */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitCPU", rlimit_build_json, c->rlimit[RLIMIT_CPU]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitFSIZE", rlimit_build_json, c->rlimit[RLIMIT_FSIZE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitDATA", rlimit_build_json, c->rlimit[RLIMIT_DATA]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitSTACK", rlimit_build_json, c->rlimit[RLIMIT_STACK]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitCORE", rlimit_build_json, c->rlimit[RLIMIT_CORE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitRSS", rlimit_build_json, c->rlimit[RLIMIT_RSS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitNOFILE", rlimit_build_json, c->rlimit[RLIMIT_NOFILE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitAS", rlimit_build_json, c->rlimit[RLIMIT_AS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitNPROC", rlimit_build_json, c->rlimit[RLIMIT_NPROC]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitMEMLOCK", rlimit_build_json, c->rlimit[RLIMIT_MEMLOCK]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitLOCKS", rlimit_build_json, c->rlimit[RLIMIT_LOCKS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitSIGPENDING", rlimit_build_json, c->rlimit[RLIMIT_SIGPENDING]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitMSGQUEUE", rlimit_build_json, c->rlimit[RLIMIT_MSGQUEUE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitNICE", rlimit_build_json, c->rlimit[RLIMIT_NICE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitRTPRIO", rlimit_build_json, c->rlimit[RLIMIT_RTPRIO]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LimitRTTIME", rlimit_build_json, c->rlimit[RLIMIT_RTTIME]),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("UMask", c->umask),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(c->coredump_filter_set, "CoredumpFilter", exec_context_get_coredump_filter(c)),
                        SD_JSON_BUILD_PAIR_STRING("KeyringMode", exec_keyring_mode_to_string(c->keyring_mode)),
                        JSON_BUILD_PAIR_CONDITION_INTEGER(c->oom_score_adjust_set, "OOMScoreAdjust", exec_context_get_oom_score_adjust(c)),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("TimerSlackNSec", c->timer_slack_nsec, NSEC_INFINITY),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Personality", personality_to_string(c->personality)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreSIGPIPE", c->ignore_sigpipe),

                        /* Scheduling */
                        JSON_BUILD_PAIR_CONDITION_INTEGER(c->nice_set, "Nice", exec_context_get_nice(c)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CPUSchedulingPolicy", cpu_sched_class_build_json, c),
                        JSON_BUILD_PAIR_CONDITION_INTEGER(c->cpu_sched_set, "CPUSchedulingPriority", exec_context_get_cpu_sched_priority(c)),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(c->cpu_sched_set, "CPUSchedulingResetOnFork", c->cpu_sched_reset_on_fork),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CPUAffinity", cpu_affinity_build_json, c),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(!!c->cpu_set.set, "CPUAffinityFromNUMA", exec_context_get_cpu_affinity_from_numa(c)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("NUMAPolicy", numa_policy_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("NUMAMask", numa_mask_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("IOSchedulingClass", ioprio_class_build_json, c),
                        JSON_BUILD_PAIR_CONDITION_INTEGER(c->ioprio_set, "IOSchedulingPriority", ioprio_prio_data(exec_context_get_effective_ioprio(c))),

                        /* Sandboxing */
                        SD_JSON_BUILD_PAIR_STRING("ProtectSystem", protect_system_to_string(c->protect_system)),
                        SD_JSON_BUILD_PAIR_STRING("ProtectHome", protect_home_to_string(c->protect_home)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RuntimeDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_RUNTIME]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StateDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_STATE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CacheDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CACHE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogsDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_LOGS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConfigurationDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CONFIGURATION]),
                        SD_JSON_BUILD_PAIR_STRING("RuntimeDirectoryPreserve", exec_preserve_mode_to_string(c->runtime_directory_preserve_mode)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutCleanUSec", c->timeout_clean_usec),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ReadWritePaths", c->read_write_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ReadOnlyPaths", c->read_only_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("InaccessiblePaths", c->inaccessible_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ExecPaths", c->exec_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("NoExecPaths", c->no_exec_paths),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TemporaryFileSystem", temporary_filesystems_build_json, c),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PrivateTmp", c->private_tmp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PrivateDevices", c->private_devices),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PrivateNetwork", c->private_network),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("NetworkNamespacePath", c->network_namespace_path),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PrivateIPC", c->private_ipc),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("IPCNamespacePath", c->ipc_namespace_path),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("MemoryKSM", c->memory_ksm),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PrivateUsers", c->private_users),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ProtectHostname", c->protect_hostname),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ProtectClock", c->protect_clock),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ProtectKernelTunables", c->protect_kernel_tunables),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ProtectKernelModules", c->protect_kernel_modules),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ProtectKernelLogs", c->protect_kernel_logs),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ProtectControlGroups", c->protect_control_groups),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictAddressFamilies", address_families_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictFileSystems", restrict_filesystems_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictNamespaces", namespace_flags_build_json, c),
                        SD_JSON_BUILD_PAIR_BOOLEAN("LockPersonality", c->lock_personality),
                        SD_JSON_BUILD_PAIR_BOOLEAN("MemoryDenyWriteExecute", c->memory_deny_write_execute),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RestrictRealtime", c->restrict_realtime),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RestrictSUIDSGID", c->restrict_suid_sgid),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemoveIPC", c->remove_ipc),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("PrivateMounts", c->private_mounts),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("MountFlags", mount_propagation_flag_to_string(c->mount_propagation_flag)),

                        /* System Call Filtering */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallFilter", syscall_filter_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallErrorNumber", syscall_error_number_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallArchitectures", syscall_archs_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallLog", syscall_log_build_json, c),

                        /* Environment */
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Environment", c->environment),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("EnvironmentFiles", environment_files_build_json, c->environment_files),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("PassEnvironment", c->pass_environment),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("UnsetEnvironment", c->unset_environment),

                        /* Logging and Standard Input/Output */
                        SD_JSON_BUILD_PAIR_STRING("StandardInput", exec_input_to_string(c->std_input)),
                        SD_JSON_BUILD_PAIR_STRING("StandardOutput", exec_output_to_string(c->std_output)),
                        SD_JSON_BUILD_PAIR_STRING("StandardError", exec_output_to_string(c->std_error)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StandardInputFileDescriptorName", exec_context_fdname(c, STDIN_FILENO)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StandardOutputFileDescriptorName", exec_context_fdname(c, STDOUT_FILENO)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StandardErrorFileDescriptorName", exec_context_fdname(c, STDERR_FILENO)),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("StandardInputData", c->stdin_data, c->stdin_data_size),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogLevelMax", log_level_build_json, INT_TO_PTR(c->log_level_max)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogExtraFields", log_extra_fields_build_json, c),
                        JSON_BUILD_PAIR_RATELIMIT_ENABLED("LogRateLimit", &c->log_ratelimit),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogFilterPatterns", log_filter_patterns_build_json, c),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("LogNamespace", c->log_namespace),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SyslogIdentifier", c->syslog_identifier),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SyslogFacility", syslog_facility_build_json, INT_TO_PTR(LOG_FAC(c->syslog_priority))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SyslogLevel", log_level_build_json, INT_TO_PTR(LOG_PRI(c->syslog_priority))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SyslogLevelPrefix", c->syslog_level_prefix),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("TTYPath", c->tty_path),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(!!c->tty_path, "TTYReset", c->tty_reset),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(!!c->tty_path, "TTYVHangup", c->tty_vhangup),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(!!c->tty_path, "TTYRows", c->tty_rows),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(!!c->tty_path, "TTYColumns", c->tty_cols),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(!!c->tty_path, "TTYVTDisallocate", c->tty_vt_disallocate),

                        /* Credentials */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LoadCredential", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LoadCredentialEncrypted", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ImportCredential", import_credential_build_json, c->import_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SetCredential", set_credential_build_json, c->set_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SetCredentialEncrypted", set_credential_build_json, c->set_credentials),

                        /* System V Compatibility */
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UtmpIdentifier", c->utmp_id),
                        SD_JSON_BUILD_PAIR_STRING("UtmpMode", exec_utmp_mode_to_string(c->utmp_mode)),

                        /* Others */
                        SD_JSON_BUILD_PAIR_BOOLEAN("SameProcessGroup", c->same_pgrp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("NonBlocking", c->non_blocking));
}

static int kill_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        KillContext *c;

        assert(ret);

        c = unit_get_kill_context(ASSERT_PTR(userdata));
        if (!c)
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_STRING("KillMode", kill_mode_to_string(c->kill_mode)),
                        SD_JSON_BUILD_PAIR_STRING("KillSignal", signal_to_string(c->kill_signal)),
                        SD_JSON_BUILD_PAIR_STRING("RestartKillSignal", signal_to_string(restart_kill_signal(c))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGHUP", c->send_sighup),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGKILL", c->send_sigkill),
                        SD_JSON_BUILD_PAIR_STRING("FinalKillSignal", signal_to_string(c->final_kill_signal)),
                        SD_JSON_BUILD_PAIR_STRING("WatchdogSignal", signal_to_string(c->watchdog_signal)));
}

static int automount_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Automount *a = ASSERT_PTR(AUTOMOUNT(userdata));
        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("Where", a->where),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ExtraOptions", a->extra_options),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", a->directory_mode),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutIdleUSec", a->timeout_idle_usec));
}

static int mount_what_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = ASSERT_PTR(MOUNT(userdata));
        _cleanup_free_ char *escaped = NULL;

        escaped = mount_get_what_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return sd_json_variant_new_string(ASSERT_PTR(ret), escaped);
}

static int mount_options_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = MOUNT(ASSERT_PTR(userdata));
        _cleanup_free_ char *escaped = NULL;

        escaped = mount_get_options_escaped(m);
        if (!escaped)
                return -ENOMEM;
        if (isempty(escaped))
                return 0;

        return sd_json_variant_new_string(ASSERT_PTR(ret), escaped);
}

static int exec_command_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecCommand *cmd = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **flags = NULL;
        int r;

        if (strv_isempty(cmd->argv))
                return 0;

        r = exec_command_flags_to_strv(cmd->flags, &flags);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert exec command flags to string: %m");

        return sd_json_buildo(ASSERT_PTR(ret),
                SD_JSON_BUILD_PAIR_STRING("path", cmd->path),
                JSON_BUILD_PAIR_STRV_NON_EMPTY("arguments", cmd->argv),
                JSON_BUILD_PAIR_STRV_NON_EMPTY("flags", flags));
}

static int mount_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = MOUNT(ASSERT_PTR(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_CALLBACK("What", mount_what_build_json, m),
                        SD_JSON_BUILD_PAIR_STRING("Where", m->where),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Type", mount_get_fstype(m)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Options", mount_options_build_json, m),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SloppyOptions", m->sloppy_options),
                        SD_JSON_BUILD_PAIR_BOOLEAN("LazyUnmount", m->lazy_unmount),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ReadWriteOnly", m->read_write_only),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ForceUnmount", m->force_unmount),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", m->directory_mode),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutUSec", m->timeout_usec),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecMount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_MOUNT]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecUnmount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_UNMOUNT]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecRemount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_REMOUNT]));
}

static int path_specs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        PathSpec *specs = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(spec, k, specs) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("type", path_type_to_string(k->type)),
                                SD_JSON_BUILD_PAIR_STRING("path", k->path));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int path_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Path *p = ASSERT_PTR(PATH(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Paths", path_specs_build_json, p->specs),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Unit", UNIT_TRIGGER(UNIT(p)) ? UNIT_TRIGGER(UNIT(p))->id : NULL),
                        SD_JSON_BUILD_PAIR_BOOLEAN("MakeDirectory", p->make_directory),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", p->directory_mode),
                        JSON_BUILD_PAIR_RATELIMIT("TriggerLimit", &p->trigger_limit));
}

#define JSON_BUILD_EMERGENCY_ACTION_NON_EMPTY(name, value) \
        JSON_BUILD_STRING_FROM_TABLE_ABOVE_MIN(name, value, EMERGENCY_ACTION_NONE, emergency_action_to_string(value))

static int unit_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        static const sd_json_build_callback_t callbacks[] = {
                [UNIT_AUTOMOUNT] = automount_context_build_json,
                [UNIT_DEVICE] = NULL,
                [UNIT_MOUNT] = mount_context_build_json,
                [UNIT_PATH] = path_context_build_json,
                [UNIT_SCOPE] = NULL,
                [UNIT_SERVICE] = NULL,
                [UNIT_SLICE] = NULL,
                [UNIT_SOCKET] = NULL,
                [UNIT_SWAP] = NULL,
                [UNIT_TARGET] = NULL,
                [UNIT_TIMER] = NULL,
        };

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
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CGroup", cgroup_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Exec", exec_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Kill", kill_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(unit_type_to_capitalized_string(u->type), callbacks[u->type], u));
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
