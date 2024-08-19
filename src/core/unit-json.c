/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syslog.h>

#include "sd-json.h"

#include "af-list.h"
#include "automount.h"
#include "cap-list.h"
#include "device.h"
#include "exec-credential.h"
#include "dbus-unit.h"
#include "json-util.h"
#include "manager-json.h"
#include "mountpoint-util.h"
#include "in-addr-prefix-util.h"
#include "ioprio-util.h"
#include "ip-protocol-list.h"
#include "missing_ioprio.h"
#include "process-util.h"
#include "mount.h"
#include "path.h"
#include "scope.h"
#include "seccomp-util.h"
#include "securebits-util.h"
#include "service.h"
#include "signal-util.h"
#include "swap.h"
#include "syslog-util.h"
#include "timer.h"
#include "unit-json.h"
#include "version.h"

static int unit_dependencies_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata), *other;
        UnitDependency d;
        void *value;
        int r;

        assert(name);
        assert(ret);

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

        assert(name);
        assert(ret);

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
        const char *(*to_string)(ConditionType type) = NULL;
        int r;

        assert(name);
        assert(ret);

        to_string = streq(name, "Asserts") ? assert_type_to_string : condition_type_to_string;

        LIST_FOREACH(conditions, c, list) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("type", to_string(c->type)),
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
        CGroupMask mask = PTR_TO_INT(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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

        r = cpu_set_to_dbus(cpuset, &array, &allocated);
        if (r < 0)
                return r;

        if (allocated == 0)
                return 0;

        return sd_json_variant_new_array_bytes(ret, array, allocated);
}

static int cgroup_io_device_weights_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        CGroupIODeviceWeight *weights = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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
        CGroupIODeviceLimit *limits = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(name);
        assert(ret);

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
        CGroupIODeviceLatency *latencies = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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

static int cgroup_limit_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        uint64_t *limit = ASSERT_PTR(userdata);

        if (*limit == CGROUP_LIMIT_MAX)
                return 0;

        return sd_json_variant_new_unsigned(ret, *limit);
}

static int cgroup_device_allow_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        CGroupDeviceAllow *allow = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        assert(ret);

        if (!cgroup_tasks_max_isset(tasks_max))
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("value", tasks_max->value),
                        SD_JSON_BUILD_PAIR_UNSIGNED("scale", tasks_max->scale));
}

static int cgroup_ip_address_access_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Set *prefixes = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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
        CGroupBPFForeignProgram *programs = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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
        CGroupSocketBindItem *items = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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
        NFTSetContext *c = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("slice", unit_slice_name(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("delegate", c->delegate),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("delegateControllers", cgroup_mask_build_json, INT_TO_PTR(c->delegate_controllers)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("delegateSubgroup", c->delegate_subgroup),
                        SD_JSON_BUILD_PAIR_BOOLEAN("cpuAccounting", c->cpu_accounting),
                        SD_JSON_BUILD_PAIR_CONDITION(c->cpu_weight != CGROUP_WEIGHT_INVALID, "cpuWeight", SD_JSON_BUILD_UNSIGNED(c->cpu_weight)),
                        SD_JSON_BUILD_PAIR_CONDITION(c->startup_cpu_weight != CGROUP_WEIGHT_INVALID, "startupCPUWeight", SD_JSON_BUILD_UNSIGNED(c->startup_cpu_weight)),
                        JSON_BUILD_PAIR_FINITE_USEC("cpuQuotaPerSecUSec", c->cpu_quota_per_sec_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("cpuQuotaPeriodUSec", c->cpu_quota_period_usec),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("allowedCPUs", cpu_set_build_json, &c->cpuset_cpus),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("startupAllowedCPUs", cpu_set_build_json, &c->startup_cpuset_cpus),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("allowedMemoryNodes", cpu_set_build_json, &c->cpuset_mems),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("startupAllowedMemoryNodes", cpu_set_build_json, &c->startup_cpuset_mems),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ioAccounting", c->io_accounting),
                        SD_JSON_BUILD_PAIR_CONDITION(c->io_weight != CGROUP_WEIGHT_INVALID, "ioWeight", SD_JSON_BUILD_UNSIGNED(c->io_weight)),
                        SD_JSON_BUILD_PAIR_CONDITION(c->startup_io_weight != CGROUP_WEIGHT_INVALID, "startupIOWeight", SD_JSON_BUILD_UNSIGNED(c->startup_io_weight)),
                        SD_JSON_BUILD_PAIR_CALLBACK("ioDeviceWeight", cgroup_io_device_weights_build_json, c->io_device_weights),
                        SD_JSON_BUILD_PAIR_CALLBACK("ioReadBandwidthMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        SD_JSON_BUILD_PAIR_CALLBACK("ioWriteBandwidthMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        SD_JSON_BUILD_PAIR_CALLBACK("ioReadIOPSMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        SD_JSON_BUILD_PAIR_CALLBACK("ioWriteIOPSMax", cgroup_io_device_limits_build_json, c->io_device_limits),
                        SD_JSON_BUILD_PAIR_CALLBACK("ioDeviceLatencyTargetUSec", cgroup_io_device_latencies_build_json, c->io_device_latencies),
                        SD_JSON_BUILD_PAIR_BOOLEAN("memoryAccounting", c->memory_accounting),
                        SD_JSON_BUILD_PAIR_CONDITION(c->default_memory_low_set, "defaultMemoryLow", SD_JSON_BUILD_UNSIGNED(c->default_memory_low)),
                        SD_JSON_BUILD_PAIR_CONDITION(c->default_startup_memory_low_set, "defaultStartupMemoryLow", SD_JSON_BUILD_UNSIGNED(c->default_startup_memory_low)),
                        SD_JSON_BUILD_PAIR_CONDITION(c->default_memory_min_set, "defaultMemoryMin", SD_JSON_BUILD_UNSIGNED(c->default_memory_min)),
                        SD_JSON_BUILD_PAIR_CONDITION(c->memory_min_set, "memoryMin", SD_JSON_BUILD_UNSIGNED(c->memory_min)),
                        SD_JSON_BUILD_PAIR_CONDITION(c->memory_low_set, "memoryLow", SD_JSON_BUILD_UNSIGNED(c->memory_low)),
                        SD_JSON_BUILD_PAIR_CONDITION(c->startup_memory_low_set, "startupMemoryLow", SD_JSON_BUILD_UNSIGNED(c->startup_memory_low)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("memoryHigh", cgroup_limit_build_json, &c->memory_high),
                        SD_JSON_BUILD_PAIR_CONDITION(c->startup_memory_high_set, "startupMemoryHigh", SD_JSON_BUILD_UNSIGNED(c->startup_memory_high)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("memoryMax", cgroup_limit_build_json, &c->memory_max),
                        SD_JSON_BUILD_PAIR_CONDITION(c->startup_memory_max_set, "startupMemoryMax", SD_JSON_BUILD_UNSIGNED(c->startup_memory_max)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("memorySwapMax", cgroup_limit_build_json, &c->memory_swap_max),
                        SD_JSON_BUILD_PAIR_CONDITION(c->startup_memory_swap_max_set, "startupMemorySwapMax", SD_JSON_BUILD_UNSIGNED(c->startup_memory_swap_max)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("memoryZSwapMax", cgroup_limit_build_json, &c->memory_zswap_max),
                        SD_JSON_BUILD_PAIR_CONDITION(c->startup_memory_zswap_max_set, "startupMemoryZSwapMax", SD_JSON_BUILD_UNSIGNED(c->startup_memory_zswap_max)),
                        SD_JSON_BUILD_PAIR_STRING("devicePolicy", cgroup_device_policy_to_string(c->device_policy)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("deviceAllow", cgroup_device_allow_build_json, c->device_allow),
                        SD_JSON_BUILD_PAIR_BOOLEAN("tasksAccounting", c->tasks_accounting),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("tasksMax", cgroup_tasks_max_build_json, &c->tasks_max),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ipAccounting", c->ip_accounting),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ipAddressAllow", cgroup_ip_address_access_build_json, c->ip_address_allow),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ipAddressDeny", cgroup_ip_address_access_build_json, c->ip_address_deny),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ipIngressFilterPath", c->ip_filters_ingress),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ipEgressFilterPath", c->ip_filters_egress),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("disableControllers", cgroup_mask_build_json, INT_TO_PTR(c->disable_controllers)),
                        SD_JSON_BUILD_PAIR_STRING("managedOOMSwap", managed_oom_mode_to_string(c->moom_swap)),
                        SD_JSON_BUILD_PAIR_STRING("managedOOMMemoryPressure", managed_oom_mode_to_string(c->moom_mem_pressure)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("managedOOMMemoryPressureLimit", c->moom_mem_pressure_limit),
                        SD_JSON_BUILD_PAIR_STRING("managedOOMPreference", managed_oom_preference_to_string(c->moom_preference)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("bpfProgram", cgroup_bpf_program_build_json, c->bpf_foreign_programs),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("socketBindAllow", cgroup_socket_bind_build_json, c->socket_bind_allow),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("socketBindDeny", cgroup_socket_bind_build_json, c->socket_bind_deny),
                        SD_JSON_BUILD_PAIR_CONDITION(!set_isempty(c->restrict_network_interfaces), "restrictNetworkInterfaces",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->restrict_network_interfaces_is_allow_list),
                                                JSON_BUILD_PAIR_STRING_SET("interfaces", c->restrict_network_interfaces))),
                        SD_JSON_BUILD_PAIR_STRING("memoryPressureWatch", cgroup_pressure_watch_to_string(c->memory_pressure_watch)),
                        JSON_BUILD_PAIR_FINITE_USEC("memoryPressureThresholdUSec", c->memory_pressure_threshold_usec),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("nftSet", cgroup_nft_set_build_json, &c->nft_set_context));
}

static int automount_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Automount *a = ASSERT_PTR(AUTOMOUNT(userdata));

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_STRING("where", a->where),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("extraOptions", a->extra_options),
                        SD_JSON_BUILD_PAIR_UNSIGNED("directoryMode", a->directory_mode),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutIdleUSec", a->timeout_idle_usec));
}

static int environment_files_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        char **environment_files = userdata;
        int r;

        assert(ret);

        STRV_FOREACH(j, environment_files) {
                const char *fn = *j;

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
        const char *wd;

        assert(ret);

        if (c->working_directory_home)
                wd = "~";
        else
                wd = c->working_directory;

        if (!wd)
                return 0;

        return sd_json_buildo(ret,
                SD_JSON_BUILD_PAIR_STRING("path", wd),
                SD_JSON_BUILD_PAIR_BOOLEAN("missingOK", c->working_directory_missing_ok));
}

static int root_image_options_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        MountOptions *root_image_options = userdata;
        int r;

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
                return r;

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
                return r;

        return sd_json_variant_new_string(ret, s);
}

static int cpu_affinity_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(cpu_set_reset) CPUSet s = {};
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        if (c->cpu_affinity_from_numa) {
                r = numa_to_cpu_set(&c->numa_policy, &s);
                if (r < 0)
                        return r;
        }

        return cpu_set_build_json(ret, /* name= */ NULL, c->cpu_affinity_from_numa ? &s : &c->cpu_set);
}

static int log_level_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int log_level = PTR_TO_INT(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        r = log_level_to_string_alloc(log_level, &s);
        if (r < 0)
                return r;

        return sd_json_variant_new_string(ret, s);
}

static int syslog_facility_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int log_facility = PTR_TO_INT(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        r = log_facility_unshifted_to_string_alloc(log_facility << 3, &s);
        if (r < 0)
                return r;

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
                return r;

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
                return r;

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
        int syscall_error_number = PTR_TO_INT(userdata);

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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_strv_free_ char **l = NULL;
        unsigned long nsflags = PTR_TO_ULONG(userdata);

        l = namespace_flags_to_strv(nsflags);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l))
                return 0;

        return sd_json_variant_new_array_strv(ret, l);
}

static int restrict_filesystems_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

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
        bool ro;
        int r;

        assert(ret);

        ro = strstr(name, "ReadOnly");

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

        for (unsigned i = 0; i < c->n_temporary_filesystems; i++) {
                TemporaryFileSystem *t = c->temporary_filesystems + i;

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
                return r;

        return sd_json_variant_new_string(ret, s);
}

static int exec_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c;

        c = unit_get_exec_context(ASSERT_PTR(userdata));
        if (!c)
                return 0;

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("environment", environment_build_json, c->environment),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("environmentFiles", environment_files_build_json, c->environment_files),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("passEnvironment", c->pass_environment),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("unsetEnvironment", c->unset_environment),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("umask", c->umask),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitCPU", rlimit_build_json, c->rlimit[RLIMIT_CPU]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitFSIZE", rlimit_build_json, c->rlimit[RLIMIT_FSIZE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitDATA", rlimit_build_json, c->rlimit[RLIMIT_DATA]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitSTACK", rlimit_build_json, c->rlimit[RLIMIT_STACK]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitCORE", rlimit_build_json, c->rlimit[RLIMIT_CORE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitRSS", rlimit_build_json, c->rlimit[RLIMIT_RSS]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitNOFILE", rlimit_build_json, c->rlimit[RLIMIT_NOFILE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitAS", rlimit_build_json, c->rlimit[RLIMIT_AS]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitNPROC", rlimit_build_json, c->rlimit[RLIMIT_NPROC]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitMEMLOCK", rlimit_build_json, c->rlimit[RLIMIT_MEMLOCK]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitLOCKS", rlimit_build_json, c->rlimit[RLIMIT_LOCKS]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitSIGPENDING", rlimit_build_json, c->rlimit[RLIMIT_SIGPENDING]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitMSGQUEUE", rlimit_build_json, c->rlimit[RLIMIT_MSGQUEUE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitNICE", rlimit_build_json, c->rlimit[RLIMIT_NICE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitRTPRIO", rlimit_build_json, c->rlimit[RLIMIT_RTPRIO]),
                        SD_JSON_BUILD_PAIR_CALLBACK("limitRTTIME", rlimit_build_json, c->rlimit[RLIMIT_RTTIME]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("workingDirectory", working_directory_build_json, c),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("rootDirectory", c->root_directory),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("rootImage", c->root_image),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("rootImageOptions", root_image_options_build_json, c->root_image_options),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("rootHash", c->root_hash, c->root_hash_size),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("rootHashPath", c->root_hash_path),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("rootHashSignature", c->root_hash_sig, c->root_hash_sig_size),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("rootHashSignaturePath", c->root_hash_sig_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("rootVerity", c->root_verity),
                        SD_JSON_BUILD_PAIR_BOOLEAN("rootEphemeral", c->root_ephemeral),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("extensionDirectories", c->extension_directories),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("extensionImages", extension_images_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("mountImages", mount_images_build_json, c),
                        SD_JSON_BUILD_PAIR_CONDITION(c->oom_score_adjust_set, "oomScoreAdjust", SD_JSON_BUILD_INTEGER(exec_context_get_oom_score_adjust(c))),
                        SD_JSON_BUILD_PAIR_CONDITION(c->coredump_filter_set, "coredumpFilter", SD_JSON_BUILD_UNSIGNED(exec_context_get_coredump_filter(c))),
                        SD_JSON_BUILD_PAIR_CONDITION(c->nice_set, "nice", SD_JSON_BUILD_INTEGER(exec_context_get_nice(c))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ioSchedulingClass", ioprio_class_build_json, c),
                        SD_JSON_BUILD_PAIR_CONDITION(c->ioprio_set, "ioSchedulingPriority", SD_JSON_BUILD_INTEGER(ioprio_prio_data(exec_context_get_effective_ioprio(c)))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("cpuSchedulingPolicy", cpu_sched_class_build_json, c),
                        SD_JSON_BUILD_PAIR_CONDITION(c->cpu_sched_set, "cpuSchedulingPriority", SD_JSON_BUILD_INTEGER(exec_context_get_cpu_sched_priority(c))),
                        SD_JSON_BUILD_PAIR_CALLBACK("cpuAffinity", cpu_affinity_build_json, c),
                        SD_JSON_BUILD_PAIR_BOOLEAN("cpuAffinityFromNUMA", exec_context_get_cpu_affinity_from_numa(c)),
                        SD_JSON_BUILD_PAIR_CONDITION(numa_policy_get_type(&c->numa_policy) >= 0, "numaPolicy", mpol_to_string(numa_policy_get_type(&c->numa_policy))),
                        SD_JSON_BUILD_PAIR_CALLBACK("numaMask", cpu_set_build_json, &c->numa_policy.nodes),
                        SD_JSON_BUILD_PAIR_CONDITION(c->timer_slack_nsec != NSEC_INFINITY, "timerSlackNSec", SD_JSON_BUILD_UNSIGNED(exec_context_get_timer_slack_nsec(c))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("cpuSchedulingResetOnFork", c->cpu_sched_reset_on_fork),
                        SD_JSON_BUILD_PAIR_BOOLEAN("nonBlocking", c->non_blocking),
                        SD_JSON_BUILD_PAIR_STRING("standardInput", exec_input_to_string(c->std_input)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("standardInputFileDescriptorName", exec_context_fdname(c, STDIN_FILENO)),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("standardInputData", c->stdin_data, c->stdin_data_size),
                        SD_JSON_BUILD_PAIR_STRING("standardOutput", exec_output_to_string(c->std_output)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("standardOutputFileDescriptorName", exec_context_fdname(c, STDOUT_FILENO)),
                        SD_JSON_BUILD_PAIR_STRING("standardError", exec_output_to_string(c->std_error)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("standardErrorFileDescriptorName", exec_context_fdname(c, STDERR_FILENO)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ttyPath", c->tty_path),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ttyReset", c->tty_reset),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ttyVHangup", c->tty_vhangup),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ttyVTDisallocate", c->tty_vt_disallocate),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ttyRows", c->tty_rows),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ttyColumns", c->tty_cols),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("syslogIdentifier", c->syslog_identifier),
                        SD_JSON_BUILD_PAIR_BOOLEAN("syslogLevelPrefix", c->syslog_level_prefix),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("syslogLevel", log_level_build_json, INT_TO_PTR(LOG_PRI(c->syslog_priority))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("syslogFacility", syslog_facility_build_json, INT_TO_PTR(LOG_FAC(c->syslog_priority))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("logLevelMax", log_level_build_json, INT_TO_PTR(c->log_level_max)),
                        JSON_BUILD_PAIR_RATELIMIT_NON_NULL("logRateLimit", &c->log_ratelimit),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("logExtraFields", log_extra_fields_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("logFilterPatterns", log_filter_patterns_build_json, c),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("logNamespace", c->log_namespace),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("secureBits", secure_bits_build_json, INT_TO_PTR(c->secure_bits)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("capabilityBoundingSet", capability_set_build_json, &c->capability_bounding_set),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ambientCapabilities", capability_set_build_json, &c->capability_ambient_set),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("user", c->user),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("group", c->group),
                        SD_JSON_BUILD_PAIR_BOOLEAN("dynamicUser", c->dynamic_user),
                        SD_JSON_BUILD_PAIR_BOOLEAN("removeIPC", c->remove_ipc),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("setCredential", set_credential_build_json, c->set_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("setCredentialEncrypted", set_credential_build_json, c->set_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("loadCredential", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("loadCredentialEncrypted", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("importCredential", import_credential_build_json, c->import_credentials),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("supplementaryGroups", c->supplementary_groups),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("pamName", c->pam_name),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("readWritePaths", c->read_write_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("readOnlyPaths", c->read_only_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("inaccessiblePaths", c->inaccessible_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("execPaths", c->exec_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("noExecPaths", c->no_exec_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("execSearchPath", c->exec_search_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("mountFlags", mount_propagation_flag_to_string(c->mount_propagation_flag)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("privateTmp", c->private_tmp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("privateDevices", c->private_devices),
                        SD_JSON_BUILD_PAIR_BOOLEAN("protectClock", c->protect_clock),
                        SD_JSON_BUILD_PAIR_BOOLEAN("protectKernelTunables", c->protect_kernel_tunables),
                        SD_JSON_BUILD_PAIR_BOOLEAN("protectKernelModules", c->protect_kernel_modules),
                        SD_JSON_BUILD_PAIR_BOOLEAN("protectKernelLogs", c->protect_kernel_logs),
                        SD_JSON_BUILD_PAIR_BOOLEAN("protectControlGroups", c->protect_control_groups),
                        SD_JSON_BUILD_PAIR_BOOLEAN("privateNetwork", c->private_network),
                        SD_JSON_BUILD_PAIR_BOOLEAN("privateUsers", c->private_users),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("privateMounts", c->private_mounts),
                        SD_JSON_BUILD_PAIR_BOOLEAN("privateIPC", c->private_ipc),
                        SD_JSON_BUILD_PAIR_STRING("protectHome", protect_home_to_string(c->protect_home)),
                        SD_JSON_BUILD_PAIR_STRING("protectSystem", protect_system_to_string(c->protect_system)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("sameProcessGroup", c->same_pgrp),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("utmpIdentifier", c->utmp_id),
                        SD_JSON_BUILD_PAIR_STRING("utmpMode", exec_utmp_mode_to_string(c->utmp_mode)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->selinux_context, "selinuxContext",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("ignore", c->selinux_context_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("context", c->selinux_context))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->apparmor_profile, "appArmorProfile",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("ignore", c->apparmor_profile_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("profile", c->apparmor_profile))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->smack_process_label, "smackProcessLabel",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("ignore", c->smack_process_label_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("label", c->smack_process_label))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ignoreSIGPIPE", c->ignore_sigpipe),
                        SD_JSON_BUILD_PAIR_BOOLEAN("noNewPrivileges", c->no_new_privileges),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("systemCallFilter", syscall_filter_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("systemCallArchitectures", syscall_archs_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("systemCallErrorNumber", syscall_error_number_build_json, INT_TO_PTR(c->syscall_errno)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("systemCallLog", syscall_log_build_json, c),
                        SD_JSON_BUILD_PAIR_STRING("personality", personality_to_string(c->personality)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("lockPersonality", c->lock_personality),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("restrictAddressFamilies", address_families_build_json, c->address_families),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("runtimeDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_RUNTIME]),
                        SD_JSON_BUILD_PAIR_STRING("runtimeDirectoryPreserve", exec_preserve_mode_to_string(c->runtime_directory_preserve_mode)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("stateDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_STATE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("cacheDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CACHE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("logsDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_LOGS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("configurationDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CONFIGURATION]),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutCleanUSec", c->timeout_clean_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("memoryDenyWriteExecute", c->memory_deny_write_execute),
                        SD_JSON_BUILD_PAIR_BOOLEAN("restrictRealtime", c->restrict_realtime),
                        SD_JSON_BUILD_PAIR_BOOLEAN("restrictSUIDSGID", c->restrict_suid_sgid),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("restrictNamespaces", namespace_flags_build_json, ULONG_TO_PTR(c->restrict_namespaces)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("restrictFileSystems", restrict_filesystems_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("bindPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("bindReadOnlyPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("temporaryFileSystem", temporary_filesystems_build_json, c),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("mountAPIVFS", c->mount_apivfs),
                        SD_JSON_BUILD_PAIR_STRING("keyringMode", exec_keyring_mode_to_string(c->keyring_mode)),
                        SD_JSON_BUILD_PAIR_STRING("protectProc", protect_proc_to_string(c->protect_proc)),
                        SD_JSON_BUILD_PAIR_STRING("procSubset", proc_subset_to_string(c->proc_subset)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("protectHostname", c->protect_hostname),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("memoryKSM", c->memory_ksm),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("networkNamespacePath", c->network_namespace_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ipcNamespacePath", c->ipc_namespace_path),
                        SD_JSON_BUILD_PAIR_CALLBACK("rootImagePolicy", image_policy_build_json, c->root_image_policy),
                        SD_JSON_BUILD_PAIR_CALLBACK("mountImagePolicy", image_policy_build_json, c->mount_image_policy),
                        SD_JSON_BUILD_PAIR_CALLBACK("extensionImagePolicy", image_policy_build_json, c->extension_image_policy));
}

static int kill_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        KillContext *c;

        assert(ret);

        c = unit_get_kill_context(ASSERT_PTR(userdata));
        if (!c)
                return 0;

        return sd_json_buildo(ret,
                        SD_JSON_BUILD_PAIR_STRING("killMode", kill_mode_to_string(c->kill_mode)),
                        SD_JSON_BUILD_PAIR_INTEGER("killSignal", c->kill_signal),
                        SD_JSON_BUILD_PAIR_INTEGER("restartKillSignal", c->restart_kill_signal),
                        SD_JSON_BUILD_PAIR_INTEGER("finalKillSignal", c->final_kill_signal),
                        SD_JSON_BUILD_PAIR_BOOLEAN("sendSIGKILL", c->send_sigkill),
                        SD_JSON_BUILD_PAIR_BOOLEAN("sendSIGHUP", c->send_sighup),
                        SD_JSON_BUILD_PAIR_INTEGER("watchdogSignal", c->watchdog_signal));
}

static int mount_what_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = ASSERT_PTR(MOUNT(userdata));
        _cleanup_free_ char *escaped = NULL;

        assert(ret);

        escaped = mount_get_what_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return sd_json_variant_new_string(ret, escaped);
}

static int mount_options_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = MOUNT(ASSERT_PTR(userdata));
        _cleanup_free_ char *escaped = NULL;

        escaped = mount_get_options_escaped(m);
        if (!escaped)
                return -ENOMEM;

        return sd_json_variant_new_string(ret, escaped);
}

static int exec_command_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **flags = NULL;
        ExecCommand *cmd = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = exec_command_flags_to_strv(cmd->flags, &flags);
        if (r < 0)
                return r;

        return sd_json_buildo(ret,
                SD_JSON_BUILD_PAIR_BOOLEAN("ignoreFailure", !!(cmd->flags & EXEC_COMMAND_IGNORE_FAILURE)),
                SD_JSON_BUILD_PAIR_STRING("path", cmd->path),
                SD_JSON_BUILD_PAIR_STRV("arguments", cmd->argv),
                SD_JSON_BUILD_PAIR_STRV("flags", flags));
}

static int exec_command_list_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecCommand *cmd = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        LIST_FOREACH(command, c, cmd) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_CALLBACK(exec_command_build_json, c));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int mount_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = MOUNT(ASSERT_PTR(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("where", m->where),
                        SD_JSON_BUILD_PAIR_CALLBACK("what", mount_what_build_json, m),
                        SD_JSON_BUILD_PAIR_CALLBACK("options", mount_options_build_json, m),
                        SD_JSON_BUILD_PAIR_STRING("type", mount_get_fstype(m)),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutUSec", m->timeout_usec),
                        SD_JSON_BUILD_PAIR_UNSIGNED("directoryMode", m->directory_mode),
                        SD_JSON_BUILD_PAIR_BOOLEAN("sloppyOptions", m->sloppy_options),
                        SD_JSON_BUILD_PAIR_BOOLEAN("lazyUnmount", m->lazy_unmount),
                        SD_JSON_BUILD_PAIR_BOOLEAN("forceUnmount", m->force_unmount),
                        SD_JSON_BUILD_PAIR_BOOLEAN("readWriteOnly", m->read_write_only),
                        SD_JSON_BUILD_PAIR_CALLBACK("execMount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_MOUNT]),
                        SD_JSON_BUILD_PAIR_CALLBACK("execUnmount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_UNMOUNT]),
                        SD_JSON_BUILD_PAIR_CALLBACK("execRemount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_REMOUNT]));
}

static int path_specs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        PathSpec *specs = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

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
                        SD_JSON_BUILD_PAIR_STRING("unit", UNIT_TRIGGER(UNIT(p)) ? UNIT_TRIGGER(UNIT(p))->id : NULL),
                        SD_JSON_BUILD_PAIR_CALLBACK("paths", path_specs_build_json, p->specs),
                        SD_JSON_BUILD_PAIR_BOOLEAN("makeDirectory", p->make_directory),
                        SD_JSON_BUILD_PAIR_UNSIGNED("directoryMode", p->directory_mode),
                        JSON_BUILD_PAIR_RATELIMIT_NON_NULL("triggerLimit", &p->trigger_limit));
}

static int scope_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Scope *s = ASSERT_PTR(SCOPE(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutStopUSec", s->timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("runtimeMaxUSec", s->runtime_max_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("runtimeRandomizedExtraUSec", s->runtime_rand_extra_usec),
                        SD_JSON_BUILD_PAIR_STRING("oomPolicy", oom_policy_to_string(s->oom_policy)));
}

static int exit_status_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *statuses = NULL, *signals = NULL;
        ExitStatusSet *set = ASSERT_PTR(userdata);
        unsigned n;
        int r;

        assert(ret);

        if (exit_status_set_is_empty(set))
                return 0;

        BITMAP_FOREACH(n, &set->status) {
                assert(n < 256);

                r = sd_json_variant_append_arrayb(&statuses, SD_JSON_BUILD_UNSIGNED(n));
                if (r < 0)
                        return r;
        }

        BITMAP_FOREACH(n, &set->signal) {
                const char *str;

                str = signal_to_string(n);
                if (!str)
                        continue;

                r = sd_json_variant_append_arrayb(&signals, SD_JSON_BUILD_STRING(str));
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(ret,
                                SD_JSON_BUILD_PAIR_VARIANT("statuses", statuses),
                                SD_JSON_BUILD_PAIR_VARIANT("signals", signals));
}

static int open_files_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        OpenFile *open_files = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(open_files, of, open_files) {
                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("path", of->path),
                                SD_JSON_BUILD_PAIR_STRING("fileDescriptorName", of->fdname),
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("flags", of->flags));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int service_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Service *s = ASSERT_PTR(SERVICE(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("type", service_type_to_string(s->type)),
                        SD_JSON_BUILD_PAIR_STRING("exitType", service_exit_type_to_string(s->exit_type)),
                        SD_JSON_BUILD_PAIR_STRING("restart", service_restart_mode_to_string(s->restart_mode)),
                        SD_JSON_BUILD_PAIR_STRING("restartMode", service_restart_mode_to_string(s->restart_mode)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("pidFile", s->pid_file),
                        SD_JSON_BUILD_PAIR_STRING("notifyAccess", notify_access_to_string(s->notify_access)),
                        JSON_BUILD_PAIR_FINITE_USEC("restartUSec", s->restart_usec),
                        SD_JSON_BUILD_PAIR_UNSIGNED("restartSteps", s->restart_steps),
                        JSON_BUILD_PAIR_FINITE_USEC("restartMaxDelayUSec", s->restart_max_delay_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutStartUSec", s->timeout_start_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutStopUSec", s->timeout_stop_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutAbortUSec", service_timeout_abort_usec(s)),
                        SD_JSON_BUILD_PAIR_STRING("timeoutStartFailureMode", service_timeout_failure_mode_to_string(s->timeout_start_failure_mode)),
                        SD_JSON_BUILD_PAIR_STRING("timeoutStopFailureMode", service_timeout_failure_mode_to_string(s->timeout_stop_failure_mode)),
                        JSON_BUILD_PAIR_FINITE_USEC("runtimeMaxUSec", s->runtime_max_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("runtimeRandomizedExtraUSec", s->runtime_rand_extra_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("watchdogUSec", s->watchdog_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("permissionsStartOnly", s->permissions_start_only),
                        SD_JSON_BUILD_PAIR_BOOLEAN("rootDirectoryStartOnly", s->root_directory_start_only),
                        SD_JSON_BUILD_PAIR_BOOLEAN("remainAfterExit", s->remain_after_exit),
                        SD_JSON_BUILD_PAIR_BOOLEAN("guessMainPID", s->guess_main_pid),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("restartPreventExitStatus", exit_status_set_build_json, &s->restart_prevent_status),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("restartForceExitStatus", exit_status_set_build_json, &s->restart_force_status),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("successExitStatus", exit_status_set_build_json, &s->success_status),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("busName", s->bus_name),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("fileDescriptorStoreMax", s->n_fd_store_max),
                        SD_JSON_BUILD_PAIR_STRING("fileDescriptorStorePreserve", exec_preserve_mode_to_string(s->fd_store_preserve_mode)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("usbFunctionDescriptors", s->usb_function_descriptors),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("usbFunctionStrings", s->usb_function_strings),
                        SD_JSON_BUILD_PAIR_STRING("oomPolicy", oom_policy_to_string(s->oom_policy)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("openFile", open_files_build_json, s->open_files),
                        SD_JSON_BUILD_PAIR_INTEGER("reloadSignal", s->reload_signal),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execCondition", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_CONDITION]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStartPre", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START_PRE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStart", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStartPost", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START_POST]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execReload", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_RELOAD]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStop", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_STOP]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStopPost", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_STOP_POST]));
}

static int socket_listen_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Socket *s = ASSERT_PTR(SOCKET(userdata));
        int r;

        assert(ret);

        LIST_FOREACH(port, p, s->ports) {
                _cleanup_free_ char *address = NULL;

                r = socket_port_to_address(p, &address);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("type", socket_port_type_to_string(p)),
                                SD_JSON_BUILD_PAIR_STRING("address", address));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int socket_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Socket *s = ASSERT_PTR(SOCKET(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("bindIPv6Only", socket_address_bind_ipv6_only_to_string(s->bind_ipv6_only)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("backlog", s->backlog),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutUSec", s->timeout_usec),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("bindToDevice", s->bind_to_device),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("socketUser", s->user),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("socketGroup", s->group),
                        SD_JSON_BUILD_PAIR_UNSIGNED("socketMode", s->socket_mode),
                        SD_JSON_BUILD_PAIR_UNSIGNED("directoryMode", s->directory_mode),
                        SD_JSON_BUILD_PAIR_BOOLEAN("accept", s->accept),
                        SD_JSON_BUILD_PAIR_BOOLEAN("flushPending", s->flush_pending),
                        SD_JSON_BUILD_PAIR_BOOLEAN("writable", s->writable),
                        SD_JSON_BUILD_PAIR_BOOLEAN("keepAlive", s->keep_alive),
                        JSON_BUILD_PAIR_FINITE_USEC("keepAliveTimeUSec", s->keep_alive_time),
                        JSON_BUILD_PAIR_FINITE_USEC("keepAliveIntervalUSec", s->keep_alive_interval),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("keepAliveProbes", s->keep_alive_cnt),
                        JSON_BUILD_PAIR_FINITE_USEC("deferAcceptUSec", s->defer_accept),
                        SD_JSON_BUILD_PAIR_BOOLEAN("noDelay", s->no_delay),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("priority", s->priority),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("receiveBuffer", s->receive_buffer),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("sendBuffer", s->send_buffer),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("iptos", s->ip_tos),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("ipttl", s->ip_ttl),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("pipeSize", s->pipe_size),
                        SD_JSON_BUILD_PAIR_BOOLEAN("freeBind", s->free_bind),
                        SD_JSON_BUILD_PAIR_BOOLEAN("transparent", s->transparent),
                        SD_JSON_BUILD_PAIR_BOOLEAN("broadcast", s->broadcast),
                        SD_JSON_BUILD_PAIR_BOOLEAN("passCredentials", s->pass_cred),
                        SD_JSON_BUILD_PAIR_BOOLEAN("passSecurity", s->pass_sec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("passPacketInfo", s->pass_pktinfo),
                        SD_JSON_BUILD_PAIR_STRING("timestamping", socket_timestamping_to_string(s->timestamping)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("removeOnStop", s->remove_on_stop),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("listen", socket_listen_build_json, s->ports),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("symlinks", s->symlinks),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("mark", s->mark),
                        SD_JSON_BUILD_PAIR_UNSIGNED("maxConnections", s->max_connections),
                        SD_JSON_BUILD_PAIR_UNSIGNED("maxConnectionsPerSource", s->max_connections_per_source),
                        JSON_BUILD_PAIR_INTEGER_NON_ZERO("messageQueueMaxMessages", s->mq_maxmsg),
                        JSON_BUILD_PAIR_INTEGER_NON_ZERO("messageQueueMessageSize", s->mq_msgsize),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("tcpCongestion", s->tcp_congestion),
                        SD_JSON_BUILD_PAIR_BOOLEAN("reusePort", s->reuse_port),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("smackLabel", s->smack),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("smackLabelIPIn", s->smack_ip_in),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("smackLabelIPOut", s->smack_ip_out),
                        SD_JSON_BUILD_PAIR_STRING("fileDescriptorName", socket_fdname(s)),
                        SD_JSON_BUILD_PAIR_INTEGER("socketProtocol", s->socket_protocol),
                        JSON_BUILD_PAIR_RATELIMIT_NON_NULL("triggerLimit", &s->trigger_limit),
                        JSON_BUILD_PAIR_RATELIMIT_NON_NULL("pollLimit", &s->poll_limit),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStartPre", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_START_PRE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStartPost", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_START_POST]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStopPre", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_STOP_PRE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execStopPost", exec_command_list_build_json, s->exec_command[SOCKET_EXEC_STOP_POST]));
}

static int swap_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Swap *s = ASSERT_PTR(SWAP(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("what", s->what),
                        SD_JSON_BUILD_PAIR_INTEGER("priority", swap_get_priority(s)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("options", swap_get_options(s)),
                        JSON_BUILD_PAIR_FINITE_USEC("timeoutUSec", s->timeout_usec),
                        SD_JSON_BUILD_PAIR_CALLBACK("execActivate", exec_command_build_json, &s->exec_command[SWAP_EXEC_ACTIVATE]),
                        SD_JSON_BUILD_PAIR_CALLBACK("execDeactivate", exec_command_build_json, &s->exec_command[SWAP_EXEC_DEACTIVATE]));
}

static int monotonic_timers_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        TimerValue *values = userdata;
        int r;

        LIST_FOREACH(value, value, values) {
                _cleanup_free_ char *usec = NULL;

                if (value->base == TIMER_CALENDAR)
                        continue;

                usec = timer_base_to_usec_string(value->base);
                if (!usec)
                        return -ENOMEM;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("base", usec),
                                SD_JSON_BUILD_PAIR_UNSIGNED("value", value->value),
                                SD_JSON_BUILD_PAIR_UNSIGNED("nextElapse", value->next_elapse));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int calendar_timers_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        TimerValue *values = ASSERT_PTR(userdata);
        int r;

        LIST_FOREACH(value, value, values) {
                _cleanup_free_ char *buf = NULL;

                if (value->base != TIMER_CALENDAR)
                        continue;

                r = calendar_spec_to_string(value->calendar_spec, &buf);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_arraybo(&v,
                                SD_JSON_BUILD_PAIR_STRING("base", timer_base_to_string(value->base)),
                                SD_JSON_BUILD_PAIR_STRING("value", buf),
                                SD_JSON_BUILD_PAIR_UNSIGNED("nextElapse", value->next_elapse));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int timer_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Timer *t = ASSERT_PTR(TIMER(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("unit", UNIT_TRIGGER(UNIT(t)) ? UNIT_TRIGGER(UNIT(t))->id : NULL),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("timersMonotonic", monotonic_timers_build_json, t->values),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("timersCalendar", calendar_timers_build_json, t->values),
                        SD_JSON_BUILD_PAIR_BOOLEAN("onClockChange", t->on_clock_change),
                        SD_JSON_BUILD_PAIR_BOOLEAN("onTimezoneChange", t->on_timezone_change),
                        JSON_BUILD_PAIR_FINITE_USEC("accuracyUSec", t->accuracy_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("randomizedDelayUSec", t->random_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("fixedRandomDelay", t->fixed_random_delay),
                        SD_JSON_BUILD_PAIR_BOOLEAN("persistent", t->persistent),
                        SD_JSON_BUILD_PAIR_BOOLEAN("wakeSystem", t->wake_system),
                        SD_JSON_BUILD_PAIR_BOOLEAN("remainAfterElapse", t->remain_after_elapse));
}

static int unit_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        static const sd_json_build_callback_t callbacks[] = {
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

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("type", unit_type_to_string(u->type)),
                        SD_JSON_BUILD_PAIR_STRING("id", u->id),
                        JSON_BUILD_PAIR_STRING_SET("names", u->aliases),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("requires", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("requisite", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("wants", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("bindsTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("upholds", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("partOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("conflicts", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("requiredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("requisiteOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("wantedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("boundBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("upheldBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("consistsOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("conflictedBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("before", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("after", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("onSuccess", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("onSuccessOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("onFailure", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("onFailureOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("triggers", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("triggeredBy", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("propagatesReloadTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("reloadPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("propagatesStopTo", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("stopPropagatedFrom", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("joinsNamespaceOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("sliceOf", unit_dependencies_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("requiresMountsFor", unit_mounts_for_build_json, u->mounts_for),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("wantsMountsFor", unit_mounts_for_build_json, u->mounts_for),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("documentation", u->documentation),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("description", u->description),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("accessSELinuxContext", u->access_selinux_context),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("fragmentPath", u->fragment_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("sourcePath", u->source_path),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("dropInPaths", u->dropin_paths),
                        SD_JSON_BUILD_PAIR_STRING("unitFilePreset", preset_action_past_tense_to_string(unit_get_unit_file_preset(u))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("stopWhenUnneeded", u->stop_when_unneeded),
                        SD_JSON_BUILD_PAIR_BOOLEAN("refuseManualStart", u->refuse_manual_start),
                        SD_JSON_BUILD_PAIR_BOOLEAN("refuseManualStop", u->refuse_manual_stop),
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowIsolate", u->allow_isolate),
                        SD_JSON_BUILD_PAIR_BOOLEAN("defaultDependencies", u->default_dependencies),
                        SD_JSON_BUILD_PAIR_STRING("onSuccessJobMode", job_mode_to_string(u->on_success_job_mode)),
                        SD_JSON_BUILD_PAIR_STRING("onFailureJobMode", job_mode_to_string(u->on_failure_job_mode)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ignoreOnIsolate", u->ignore_on_isolate),
                        JSON_BUILD_PAIR_FINITE_USEC("jobTimeoutUSec", u->job_timeout),
                        JSON_BUILD_PAIR_FINITE_USEC("jobRunningTimeoutUSec", u->job_running_timeout),
                        SD_JSON_BUILD_PAIR_STRING("jobTimeoutAction", emergency_action_to_string(u->job_timeout_action)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("jobTimeoutRebootArgument", u->job_timeout_reboot_arg),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("conditions", unit_conditions_build_json, u->conditions),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("asserts", unit_conditions_build_json, u->asserts),
                        SD_JSON_BUILD_PAIR_BOOLEAN("transient", u->transient),
                        SD_JSON_BUILD_PAIR_BOOLEAN("perpetual", u->perpetual),
                        JSON_BUILD_PAIR_RATELIMIT_NON_NULL("startLimit", &u->start_ratelimit),
                        SD_JSON_BUILD_PAIR_STRING("startLimitAction", emergency_action_to_string(u->start_limit_action)),
                        SD_JSON_BUILD_PAIR_STRING("failureAction", emergency_action_to_string(u->failure_action)),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("failureActionExitStatus", u->failure_action_exit_status),
                        SD_JSON_BUILD_PAIR_STRING("successAction", emergency_action_to_string(u->success_action)),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("successActionExitStatus", u->success_action_exit_status),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("rebootArgument", u->reboot_arg),
                        SD_JSON_BUILD_PAIR_STRING("collectMode", collect_mode_to_string(u->collect_mode)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("cgroup", cgroup_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("exec", exec_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("kill", kill_context_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(unit_type_to_string(u->type), callbacks[u->type], u));
}

static int unit_can_clean_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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

                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(exec_resource_type_to_string(t)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_job_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *p = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        if (!u->job)
                return 0;

        p = job_dbus_path(u->job);
        if (!p)
                return -ENOMEM;

        r = sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR("id", u->job->id),
                        SD_JSON_BUILD_PAIR("path", p));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_markers_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (UnitMarker m = 0; m < _UNIT_MARKER_MAX; m++) {
                if (!FLAGS_SET(u->markers, 1u << m))
                        continue;

                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(unit_marker_to_string(m)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_load_error_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        r = bus_unit_validate_load_state(u, &e);
        if (r >= 0)
                return 0;

        r = sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR_STRING("name", e.name),
                        SD_JSON_BUILD_PAIR_STRING("message", e.message));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_refs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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
                        r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(i));
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int unit_memory_current_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t sz = UINT64_MAX;
        int r;

        assert(ret);

        r = unit_get_memory_current(u, &sz);
        if (r >= 0)
                return sd_json_variant_new_unsigned(ret, sz);

        if (r < 0)
                log_unit_warning_errno(u, r, "Failed to get memory.usage_in_bytes attribute, ignoring: %m");

        return 0;
}

static int unit_memory_available_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t sz = UINT64_MAX;
        int r;

        assert(ret);

        r = unit_get_memory_available(u, &sz);
        if (r >= 0)
                return sd_json_variant_new_unsigned(ret, sz);

        if (r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get total available memory from cgroup, ignoring: %m");

        return 0;
}

static int unit_cpu_usage_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        nsec_t ns = NSEC_INFINITY;
        int r;

        assert(ret);

        r = unit_get_cpu_usage(u, &ns);
        if (r >= 0)
                return sd_json_variant_new_unsigned(ret, ns);

        if (r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get cpuacct.usage attribute: %m");

        return 0;
}

static int unit_cpuset_cpus_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(cpu_set_reset) CPUSet cpus = {};
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = unit_get_cpuset(u, &cpus, "cpuset.cpus.effective");
        if (r >= 0)
                return cpu_set_build_json(ret, /* name= */ NULL, &cpus);

        if (r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get cpuset.cpus.effective attribute, ignoring: %m");

        return 0;
}

static int unit_cpuset_mems_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(cpu_set_reset) CPUSet cpus = {};
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        r = unit_get_cpuset(u, &cpus, "cpuset.mems.effective");
        if (r >= 0)
                return cpu_set_build_json(ret, /* name= */ NULL, &cpus);

        if (r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get cpuset.mems.effective attribute, ignoring: %m");

        return 0;
}

static int unit_current_tasks_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        uint64_t cn = UINT64_MAX;
        int r;

        assert(ret);

        r = unit_get_tasks_current(u, &cn);
        if (r >= 0)
                return sd_json_variant_new_unsigned(ret, cn);

        if (r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get pids.current attribute, ignoring: %m");

        return 0;
}

static int unit_ip_counter_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupIPAccountingMetric metric;
        uint64_t value;
        int r;

        assert(name);
        assert(ret);

        assert_se((metric = cgroup_ip_accounting_metric_from_string(name)) >= 0);

        r = unit_get_ip_accounting(u, metric, &value);
        if (r >= 0)
                return sd_json_variant_new_unsigned(ret, value);

        if (r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get %s accounting data, ignoring: %m", name);

        return 0;
}

static int unit_io_counter_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupIOAccountingMetric metric;
        uint64_t value;
        int r;

        assert(name);
        assert(ret);

        assert_se((metric = cgroup_io_accounting_metric_from_string(name)) >= 0);

        r = unit_get_io_accounting(u, metric, /* allow_cache= */ false, &value);
        if (r >= 0)
                return sd_json_variant_new_unsigned(ret, value);

        if (r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get %s accounting data, ignoring: %m", name);

        return 0;
}

static int cgroup_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        CGroupRuntime *c;

        assert(ret);

        c = unit_get_cgroup_runtime(u);
        if (!c)
                return 0;

        return sd_json_buildo(ret,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("controlGroup", c->cgroup_path ? empty_to_root(c->cgroup_path) : NULL),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("controlGroupId", c->cgroup_id),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("memoryCurrent", unit_memory_current_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("memoryAvailable", unit_memory_available_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("cpuUsageNSec", unit_cpu_usage_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("effectiveCPUs", unit_cpuset_cpus_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("effectiveMemoryNodes", unit_cpuset_mems_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("tasksCurrent", unit_current_tasks_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ipIngressBytes", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ipIngressPackets", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ipEgressBytes", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ipEgressPackets", unit_ip_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ioReadBytes", unit_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ioReadOperations", unit_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ioWriteBytes", unit_io_counter_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ioWriteOperations", unit_io_counter_build_json, u));
}

static int automount_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Automount *a = ASSERT_PTR(AUTOMOUNT(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("result", automount_result_to_string(a->result)));
}

static int device_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Device *d = ASSERT_PTR(DEVICE(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("sysfsPath", d->sysfs));
}

static int mount_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = ASSERT_PTR(MOUNT(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("controlPID", m->control_pid.pid),
                        SD_JSON_BUILD_PAIR_STRING("result", mount_result_to_string(m->result)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("uid", UNIT(m)->ref_uid),
                        SD_JSON_BUILD_PAIR_UNSIGNED("gid", UNIT(m)->ref_gid));
}

static int path_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Path *p = ASSERT_PTR(PATH(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("result", path_result_to_string(p->result)));
}

static int scope_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Scope *s = ASSERT_PTR(SCOPE(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("controller", s->controller),
                        SD_JSON_BUILD_PAIR_STRING("result", scope_result_to_string(s->result)));
}

static int exec_status_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecStatus *s = ASSERT_PTR(userdata);

        if (s->pid <= 0 || !dual_timestamp_is_set(&s->exit_timestamp))
                return 0;

        return sd_json_buildo(ASSERT_PTR(ret),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP("startTimestamp", &s->start_timestamp),
                JSON_BUILD_PAIR_DUAL_TIMESTAMP("exitTimestamp", &s->exit_timestamp),
                SD_JSON_BUILD_PAIR_UNSIGNED("pid", s->pid),
                SD_JSON_BUILD_PAIR_INTEGER("code", s->code),
                SD_JSON_BUILD_PAIR_INTEGER("status", s->status));
}

static int service_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Service *s = ASSERT_PTR(SERVICE(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("watchdogTimestamp", &s->watchdog_timestamp),
                        JSON_BUILD_PAIR_FINITE_USEC("restartUSecNext", service_restart_usec_next(s)),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("mainPID", s->main_pid.pid),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("controlPID", s->control_pid.pid),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("nFileDescriptorStore", s->n_fd_store),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("statusText", s->status_text),
                        SD_JSON_BUILD_PAIR_INTEGER("statusErrno", s->status_errno),
                        SD_JSON_BUILD_PAIR_STRING("result", service_result_to_string(s->result)),
                        SD_JSON_BUILD_PAIR_STRING("reloadResult", service_result_to_string(s->reload_result)),
                        SD_JSON_BUILD_PAIR_STRING("cleanResult", service_result_to_string(s->clean_result)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("uid", UNIT(s)->ref_uid),
                        SD_JSON_BUILD_PAIR_UNSIGNED("gid", UNIT(s)->ref_gid),
                        SD_JSON_BUILD_PAIR_UNSIGNED("nRestarts", s->n_restarts),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("execMain", exec_status_build_json, &s->main_exec_status));
}

static int socket_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Socket *s = ASSERT_PTR(SOCKET(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("controlPID", s->control_pid.pid),
                        SD_JSON_BUILD_PAIR_STRING("result", socket_result_to_string(s->result)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("nConnections", s->n_connections),
                        SD_JSON_BUILD_PAIR_UNSIGNED("nAccepted", s->n_accepted),
                        SD_JSON_BUILD_PAIR_UNSIGNED("nRefused", s->n_refused),
                        SD_JSON_BUILD_PAIR_UNSIGNED("uid", UNIT(s)->ref_uid),
                        SD_JSON_BUILD_PAIR_UNSIGNED("gid", UNIT(s)->ref_gid));
}

static int swap_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Swap *s = ASSERT_PTR(SWAP(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("controlPID", s->control_pid.pid),
                        SD_JSON_BUILD_PAIR_STRING("result", swap_result_to_string(s->result)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("uid", UNIT(s)->ref_uid),
                        SD_JSON_BUILD_PAIR_UNSIGNED("gid", UNIT(s)->ref_gid));
}

static int timer_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Timer *t = ASSERT_PTR(TIMER(userdata));

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_UNSIGNED("nextElapseUSecRealtime", t->next_elapse_realtime),
                        SD_JSON_BUILD_PAIR_UNSIGNED("nextElapseUSecMonotonic", timer_next_elapse_monotonic(t)),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("lastTriggerUSec", &t->last_trigger),
                        SD_JSON_BUILD_PAIR_STRING("result", timer_result_to_string(t->result)));
}

static int unit_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        static const sd_json_build_callback_t callbacks[] = {
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

        return sd_json_buildo(ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("following", unit_following(u) ? unit_following(u)->id : NULL),
                        SD_JSON_BUILD_PAIR_STRING("loadState", unit_load_state_to_string(u->load_state)),
                        SD_JSON_BUILD_PAIR_STRING("activeState", unit_active_state_to_string(unit_active_state(u))),
                        SD_JSON_BUILD_PAIR_STRING("freezerState", freezer_state_to_string(u->freezer_state)),
                        SD_JSON_BUILD_PAIR_STRING("subState", unit_sub_state_to_string(u)),
                        SD_JSON_BUILD_PAIR_STRING("unitFileState", unit_file_state_to_string(unit_get_unit_file_state(u))),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("stateChangeTimestamp", &u->state_change_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("inactiveEnterTimestamp", &u->inactive_enter_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("inactiveExitTimestamp", &u->inactive_exit_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("activeEnterTimestamp", &u->active_enter_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("activeExitTimestamp", &u->active_exit_timestamp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("canStart", unit_can_start_refuse_manual(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("canStop", unit_can_stop_refuse_manual(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("canReload", unit_can_reload(u)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("canIsolate", unit_can_isolate_refuse_manual(u)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("canClean", unit_can_clean_build_json, u),
                        SD_JSON_BUILD_PAIR_BOOLEAN("canFreeze", unit_can_freeze(u)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("job", unit_job_build_json, u),
                        SD_JSON_BUILD_PAIR_BOOLEAN("needDaemonReload", unit_need_daemon_reload(u)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("markers", unit_markers_build_json, u),
                        SD_JSON_BUILD_PAIR_BOOLEAN("conditionResult", u->condition_result),
                        SD_JSON_BUILD_PAIR_BOOLEAN("assertResult", u->assert_result),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("conditionTimestamp", &u->condition_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("assertTimestamp", &u->assert_timestamp),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("loadError", unit_load_error_build_json, u),
                        SD_JSON_BUILD_PAIR_ID128("invocationID", u->invocation_id),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("refs", unit_refs_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("activationDetails", activation_details_build_json, u->activation_details),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("cgroup", cgroup_runtime_build_json, u),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(unit_type_to_string(u->type), callbacks[u->type], u));
}

int unit_build_json(Unit *u, sd_json_variant **ret) {
        assert(u);

        return sd_json_buildo(ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_CALLBACK("context", unit_context_build_json, u),
                        SD_JSON_BUILD_PAIR_CALLBACK("runtime", unit_runtime_build_json, u));
}
