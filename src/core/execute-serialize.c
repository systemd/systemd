/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "af-list.h"
#include "capability-util.h"
#include "cgroup.h"
#include "dissect-image.h"
#include "dynamic-user.h"
#include "escape.h"
#include "exec-credential.h"
#include "execute.h"
#include "execute-serialize.h"
#include "extract-word.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "image-policy.h"
#include "in-addr-prefix-util.h"
#include "log.h"
#include "nsflags.h"
#include "open-file.h"
#include "ordered-set.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "serialize.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

static int exec_cgroup_context_serialize(const CGroupContext *c, FILE *f) {
        _cleanup_free_ char *disable_controllers_str = NULL, *delegate_controllers_str = NULL,
                            *cpuset_cpus = NULL, *cpuset_mems = NULL, *startup_cpuset_cpus = NULL,
                            *startup_cpuset_mems = NULL;
        char *iface;
        struct in_addr_prefix *iaai;
        int r;

        assert(f);

        if (!c)
                return 0;

        r = serialize_bool_elide(f, "exec-cgroup-context-io-accounting", c->io_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-accounting", c->memory_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-tasks-accounting", c->tasks_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-ip-accounting", c->ip_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-oom-group", c->memory_oom_group);
        if (r < 0)
                return r;

        if (c->cpu_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-cpu-weight", "%" PRIu64, c->cpu_weight);
                if (r < 0)
                        return r;
        }

        if (c->startup_cpu_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-cpu-weight", "%" PRIu64, c->startup_cpu_weight);
                if (r < 0)
                        return r;
        }

        if (c->cpu_quota_per_sec_usec != USEC_INFINITY) {
                r = serialize_usec(f, "exec-cgroup-context-cpu-quota-per-sec-usec", c->cpu_quota_per_sec_usec);
                if (r < 0)
                        return r;
        }

        if (c->cpu_quota_period_usec != USEC_INFINITY) {
                r = serialize_usec(f, "exec-cgroup-context-cpu-quota-period-usec", c->cpu_quota_period_usec);
                if (r < 0)
                        return r;
        }

        cpuset_cpus = cpu_set_to_range_string(&c->cpuset_cpus);
        if (!cpuset_cpus)
                return log_oom_debug();

        r = serialize_item(f, "exec-cgroup-context-allowed-cpus", cpuset_cpus);
        if (r < 0)
                return r;

        startup_cpuset_cpus = cpu_set_to_range_string(&c->startup_cpuset_cpus);
        if (!startup_cpuset_cpus)
                return log_oom_debug();

        r = serialize_item(f, "exec-cgroup-context-startup-allowed-cpus", startup_cpuset_cpus);
        if (r < 0)
                return r;

        cpuset_mems = cpu_set_to_range_string(&c->cpuset_mems);
        if (!cpuset_mems)
                return log_oom_debug();

        r = serialize_item(f, "exec-cgroup-context-allowed-memory-nodes", cpuset_mems);
        if (r < 0)
                return r;

        startup_cpuset_mems = cpu_set_to_range_string(&c->startup_cpuset_mems);
        if (!startup_cpuset_mems)
                return log_oom_debug();

        r = serialize_item(f, "exec-cgroup-context-startup-allowed-memory-nodes", startup_cpuset_mems);
        if (r < 0)
                return r;

        if (c->io_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-io-weight", "%" PRIu64, c->io_weight);
                if (r < 0)
                        return r;
        }

        if (c->startup_io_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-io-weight", "%" PRIu64, c->startup_io_weight);
                if (r < 0)
                        return r;
        }

        if (c->default_memory_min > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-default-memory-min", "%" PRIu64, c->default_memory_min);
                if (r < 0)
                        return r;
        }

        if (c->default_memory_low > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-default-memory-low", "%" PRIu64, c->default_memory_low);
                if (r < 0)
                        return r;
        }

        if (c->memory_min > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-min", "%" PRIu64, c->memory_min);
                if (r < 0)
                        return r;
        }

        if (c->memory_low > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-low", "%" PRIu64, c->memory_low);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_low > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-low", "%" PRIu64, c->startup_memory_low);
                if (r < 0)
                        return r;
        }

        if (c->memory_high != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-high", "%" PRIu64, c->memory_high);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_high != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-high", "%" PRIu64, c->startup_memory_high);
                if (r < 0)
                        return r;
        }

        if (c->memory_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-max", "%" PRIu64, c->memory_max);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-max", "%" PRIu64, c->startup_memory_max);
                if (r < 0)
                        return r;
        }

        if (c->memory_swap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-swap-max", "%" PRIu64, c->memory_swap_max);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_swap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-swap-max", "%" PRIu64, c->startup_memory_swap_max);
                if (r < 0)
                        return r;
        }

        if (c->memory_zswap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-zswap-max", "%" PRIu64, c->memory_zswap_max);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_zswap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-zswap-max", "%" PRIu64, c->startup_memory_zswap_max);
                if (r < 0)
                        return r;
        }

        r = serialize_bool(f, "exec-cgroup-context-memory-zswap-writeback", c->memory_zswap_writeback);
        if (r < 0)
                return r;

        if (c->tasks_max.value != UINT64_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-tasks-max-value", "%" PRIu64, c->tasks_max.value);
                if (r < 0)
                        return r;
        }

        if (c->tasks_max.scale > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-tasks-max-scale", "%" PRIu64, c->tasks_max.scale);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-cgroup-context-default-memory-min-set", c->default_memory_min_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-default-memory-low-set", c->default_memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-default-startup-memory-low-set", c->default_startup_memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-min-set", c->memory_min_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-low-set", c->memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-low-set", c->startup_memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-high-set", c->startup_memory_high_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-max-set", c->startup_memory_max_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-swap-max-set", c->startup_memory_swap_max_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-zswap-max-set", c->startup_memory_zswap_max_set);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-device-policy", cgroup_device_policy_to_string(c->device_policy));
        if (r < 0)
                return r;

        r = cg_mask_to_string(c->disable_controllers, &disable_controllers_str);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-disable-controllers", disable_controllers_str);
        if (r < 0)
                return r;

        r = cg_mask_to_string(c->delegate_controllers, &delegate_controllers_str);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-delegate-controllers", delegate_controllers_str);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-delegate", c->delegate);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-managed-oom-swap", managed_oom_mode_to_string(c->moom_swap));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-managed-oom-memory-pressure", managed_oom_mode_to_string(c->moom_mem_pressure));
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-cgroup-context-managed-oom-memory-pressure-limit", "%" PRIu32, c->moom_mem_pressure_limit);
        if (r < 0)
                return r;

        r = serialize_usec(f, "exec-cgroup-context-managed-oom-memory-pressure-duration-usec", c->moom_mem_pressure_duration_usec);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-managed-oom-preference", managed_oom_preference_to_string(c->moom_preference));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-memory-pressure-watch", cgroup_pressure_watch_to_string(c->memory_pressure_watch));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-delegate-subgroup", c->delegate_subgroup);
        if (r < 0)
                return r;

        if (c->memory_pressure_threshold_usec != USEC_INFINITY) {
                r = serialize_usec(f, "exec-cgroup-context-memory-pressure-threshold-usec", c->memory_pressure_threshold_usec);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_allow, a, c->device_allow) {
                r = serialize_item_format(f, "exec-cgroup-context-device-allow", "%s %s",
                                          a->path,
                                          cgroup_device_permissions_to_string(a->permissions));
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_weights, iw, c->io_device_weights) {
                r = serialize_item_format(f, "exec-cgroup-context-io-device-weight", "%s %" PRIu64,
                                          iw->path,
                                          iw->weight);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_latencies, l, c->io_device_latencies) {
                r = serialize_item_format(f, "exec-cgroup-context-io-device-latency-target-usec", "%s " USEC_FMT,
                                          l->path,
                                          l->target_usec);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_limits, il, c->io_device_limits)
                for (CGroupIOLimitType type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++) {
                        _cleanup_free_ char *key = NULL;

                        if (il->limits[type] == cgroup_io_limit_defaults[type])
                                continue;

                        key = strjoin("exec-cgroup-context-io-device-limit-", cgroup_io_limit_type_to_string(type));
                        if (!key)
                                return -ENOMEM;

                        r = serialize_item_format(f, key, "%s %" PRIu64, il->path, il->limits[type]);
                        if (r < 0)
                                return r;
                }

        SET_FOREACH(iaai, c->ip_address_allow) {
                r = serialize_item(f,
                                   "exec-cgroup-context-ip-address-allow",
                                   IN_ADDR_PREFIX_TO_STRING(iaai->family, &iaai->address, iaai->prefixlen));
                if (r < 0)
                        return r;
        }
        SET_FOREACH(iaai, c->ip_address_deny) {
                r = serialize_item(f,
                                   "exec-cgroup-context-ip-address-deny",
                                   IN_ADDR_PREFIX_TO_STRING(iaai->family, &iaai->address, iaai->prefixlen));
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-cgroup-context-ip-address-allow-reduced", c->ip_address_allow_reduced);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-ip-address-deny-reduced", c->ip_address_deny_reduced);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-cgroup-context-ip-ingress-filter-path", c->ip_filters_ingress);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-cgroup-context-ip-egress-filter-path", c->ip_filters_egress);
        if (r < 0)
                return r;

        LIST_FOREACH(programs, p, c->bpf_foreign_programs) {
                r = serialize_item_format(f, "exec-cgroup-context-bpf-program", "%" PRIu32 " %s",
                                          p->attach_type,
                                          p->bpffs_path);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(socket_bind_items, bi, c->socket_bind_allow) {
                fprintf(f, "exec-cgroup-context-socket-bind-allow=");
                cgroup_context_dump_socket_bind_item(bi, f);
                fputc('\n', f);
        }

        LIST_FOREACH(socket_bind_items, bi, c->socket_bind_deny) {
                fprintf(f, "exec-cgroup-context-socket-bind-deny=");
                cgroup_context_dump_socket_bind_item(bi, f);
                fputc('\n', f);
        }

        SET_FOREACH(iface, c->restrict_network_interfaces) {
                r = serialize_item(f, "exec-cgroup-context-restrict-network-interfaces", iface);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(
                        f,
                        "exec-cgroup-context-restrict-network-interfaces-is-allow-list",
                        c->restrict_network_interfaces_is_allow_list);
        if (r < 0)
                return r;

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_cgroup_context_deserialize(CGroupContext *c, FILE *f) {
        int r;

        assert(f);

        if (!c)
                return 0;

        for (;;) {
                _cleanup_free_ char *l = NULL;
                const char *val;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                if ((val = startswith(l, "exec-cgroup-context-io-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->io_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-tasks-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tasks_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ip_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-oom-group="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_oom_group = r;
                } else if ((val = startswith(l, "exec-cgroup-context-cpu-weight="))) {
                        r = safe_atou64(val, &c->cpu_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-cpu-weight="))) {
                        r = safe_atou64(val, &c->startup_cpu_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-cpu-quota-per-sec-usec="))) {
                        r = deserialize_usec(val, &c->cpu_quota_per_sec_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-cpu-quota-period-usec="))) {
                        r = deserialize_usec(val, &c->cpu_quota_period_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-allowed-cpus="))) {
                        if (c->cpuset_cpus.set)
                                return -EINVAL; /* duplicated */

                        r = parse_cpu_set(val, &c->cpuset_cpus);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-allowed-cpus="))) {
                        if (c->startup_cpuset_cpus.set)
                                return -EINVAL; /* duplicated */

                        r = parse_cpu_set(val, &c->startup_cpuset_cpus);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-allowed-memory-nodes="))) {
                        if (c->cpuset_mems.set)
                                return -EINVAL; /* duplicated */

                        r = parse_cpu_set(val, &c->cpuset_mems);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-allowed-memory-nodes="))) {
                        if (c->startup_cpuset_mems.set)
                                return -EINVAL; /* duplicated */

                        r = parse_cpu_set(val, &c->startup_cpuset_mems);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-weight="))) {
                        r = safe_atou64(val, &c->io_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-io-weight="))) {
                        r = safe_atou64(val, &c->startup_io_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-min="))) {
                        r = safe_atou64(val, &c->default_memory_min);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-low="))) {
                        r = safe_atou64(val, &c->default_memory_low);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-min="))) {
                        r = safe_atou64(val, &c->memory_min);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-low="))) {
                        r = safe_atou64(val, &c->memory_low);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-low="))) {
                        r = safe_atou64(val, &c->startup_memory_low);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-high="))) {
                        r = safe_atou64(val, &c->memory_high);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-high="))) {
                        r = safe_atou64(val, &c->startup_memory_high);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-max="))) {
                        r = safe_atou64(val, &c->memory_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-max="))) {
                        r = safe_atou64(val, &c->startup_memory_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-swap-max="))) {
                        r = safe_atou64(val, &c->memory_swap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-swap-max="))) {
                        r = safe_atou64(val, &c->startup_memory_swap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-zswap-max="))) {
                        r = safe_atou64(val, &c->memory_zswap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-zswap-max="))) {
                        r = safe_atou64(val, &c->startup_memory_zswap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-zswap-writeback="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_zswap_writeback = r;
                } else if ((val = startswith(l, "exec-cgroup-context-tasks-max-value="))) {
                        r = safe_atou64(val, &c->tasks_max.value);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-tasks-max-scale="))) {
                        r = safe_atou64(val, &c->tasks_max.scale);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-min-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->default_memory_min_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->default_memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-startup-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->default_startup_memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-min-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_min_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-high-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_high_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-max-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_max_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-swap-max-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_swap_max_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-zswap-max-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_zswap_max_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-device-policy="))) {
                        c->device_policy = cgroup_device_policy_from_string(val);
                        if (c->device_policy < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-disable-controllers="))) {
                        r = cg_mask_from_string(val, &c->disable_controllers);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-delegate-controllers="))) {
                        r = cg_mask_from_string(val, &c->delegate_controllers);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-delegate="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->delegate = r;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-swap="))) {
                        c->moom_swap = managed_oom_mode_from_string(val);
                        if (c->moom_swap < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-memory-pressure="))) {
                        c->moom_mem_pressure = managed_oom_mode_from_string(val);
                        if (c->moom_mem_pressure < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-memory-pressure-limit="))) {
                        r = safe_atou32(val, &c->moom_mem_pressure_limit);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-preference="))) {
                        c->moom_preference = managed_oom_preference_from_string(val);
                        if (c->moom_preference < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-memory-pressure-duration-usec="))) {
                        r = deserialize_usec(val, &c->moom_mem_pressure_duration_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-pressure-watch="))) {
                        c->memory_pressure_watch = cgroup_pressure_watch_from_string(val);
                        if (c->memory_pressure_watch < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-delegate-subgroup="))) {
                        r = free_and_strdup(&c->delegate_subgroup, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-pressure-threshold-usec="))) {
                        r = deserialize_usec(val, &c->memory_pressure_threshold_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-device-allow="))) {
                        _cleanup_free_ char *path = NULL, *rwm = NULL;
                        CGroupDevicePermissions p;

                        r = extract_many_words(&val, " ", 0, &path, &rwm);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        p = isempty(rwm) ? 0 : cgroup_device_permissions_from_string(rwm);
                        if (p < 0)
                                return p;

                        r = cgroup_context_add_or_update_device_allow(c, path, p);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-device-weight="))) {
                        _cleanup_free_ char *path = NULL, *weight = NULL;
                        CGroupIODeviceWeight *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &weight);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                return -EINVAL;

                        LIST_FOREACH(device_weights, b, c->io_device_weights)
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        break;
                                }

                        if (!a) {
                                a = new0(CGroupIODeviceWeight, 1);
                                if (!a)
                                        return log_oom_debug();

                                a->path = TAKE_PTR(path);

                                LIST_PREPEND(device_weights, c->io_device_weights, a);
                        }

                        r = safe_atou64(weight, &a->weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-device-latency-target-usec="))) {
                        _cleanup_free_ char *path = NULL, *target = NULL;
                        CGroupIODeviceLatency *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &target);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                return -EINVAL;

                        LIST_FOREACH(device_latencies, b, c->io_device_latencies)
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        break;
                                }

                        if (!a) {
                                a = new0(CGroupIODeviceLatency, 1);
                                if (!a)
                                        return log_oom_debug();

                                a->path = TAKE_PTR(path);

                                LIST_PREPEND(device_latencies, c->io_device_latencies, a);
                        }

                        r = deserialize_usec(target, &a->target_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-device-limit-"))) {
                        _cleanup_free_ char *type = NULL, *path = NULL, *limits = NULL;
                        CGroupIODeviceLimit *limit = NULL;
                        CGroupIOLimitType t;

                        r = extract_many_words(&val, "= ", 0, &type, &path, &limits);
                        if (r < 0)
                                return r;
                        if (r != 3)
                                return -EINVAL;

                        t = cgroup_io_limit_type_from_string(type);
                        if (t < 0)
                                return t;

                        LIST_FOREACH(device_limits, i, c->io_device_limits)
                                if (path_equal(path, i->path)) {
                                        limit = i;
                                        break;
                                }

                        if (!limit) {
                                limit = new0(CGroupIODeviceLimit, 1);
                                if (!limit)
                                        return log_oom_debug();

                                limit->path = TAKE_PTR(path);
                                for (CGroupIOLimitType i = 0; i < _CGROUP_IO_LIMIT_TYPE_MAX; i++)
                                        limit->limits[i] = cgroup_io_limit_defaults[i];

                                LIST_PREPEND(device_limits, c->io_device_limits, limit);
                        }

                        r = safe_atou64(limits, &limit->limits[t]);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-allow="))) {
                        struct in_addr_prefix a;

                        r = in_addr_prefix_from_string_auto(val, &a.family, &a.address, &a.prefixlen);
                        if (r < 0)
                                return r;

                        r = in_addr_prefix_add(&c->ip_address_allow, &a);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-deny="))) {
                        struct in_addr_prefix a;

                        r = in_addr_prefix_from_string_auto(val, &a.family, &a.address, &a.prefixlen);
                        if (r < 0)
                                return r;

                        r = in_addr_prefix_add(&c->ip_address_deny, &a);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-allow-reduced="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ip_address_allow_reduced = r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-deny-reduced="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ip_address_deny_reduced = r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-ingress-filter-path="))) {
                        r = deserialize_strv(val, &c->ip_filters_ingress);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-egress-filter-path="))) {
                        r = deserialize_strv(val, &c->ip_filters_egress);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-bpf-program="))) {
                        _cleanup_free_ char *type = NULL, *path = NULL;
                        uint32_t t;

                        r = extract_many_words(&val, " ", 0, &type, &path);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                return -EINVAL;

                        r = safe_atou32(type, &t);
                        if (r < 0)
                                return r;

                        r = cgroup_context_add_bpf_foreign_program(c, t, path);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-socket-bind-allow="))) {
                        CGroupSocketBindItem *item;
                        uint16_t nr_ports, port_min;
                        int af, ip_protocol;

                        r = parse_socket_bind_item(val, &af, &ip_protocol, &nr_ports, &port_min);
                        if (r < 0)
                                return r;

                        item = new(CGroupSocketBindItem, 1);
                        if (!item)
                                return log_oom_debug();
                        *item = (CGroupSocketBindItem) {
                                .address_family = af,
                                .ip_protocol = ip_protocol,
                                .nr_ports = nr_ports,
                                .port_min = port_min,
                        };

                        LIST_PREPEND(socket_bind_items, c->socket_bind_allow, item);
                } else if ((val = startswith(l, "exec-cgroup-context-socket-bind-deny="))) {
                        CGroupSocketBindItem *item;
                        uint16_t nr_ports, port_min;
                        int af, ip_protocol;

                        r = parse_socket_bind_item(val, &af, &ip_protocol, &nr_ports, &port_min);
                        if (r < 0)
                                return r;

                        item = new(CGroupSocketBindItem, 1);
                        if (!item)
                                return log_oom_debug();
                        *item = (CGroupSocketBindItem) {
                                .address_family = af,
                                .ip_protocol = ip_protocol,
                                .nr_ports = nr_ports,
                                .port_min = port_min,
                        };

                        LIST_PREPEND(socket_bind_items, c->socket_bind_deny, item);
                } else if ((val = startswith(l, "exec-cgroup-context-restrict-network-interfaces="))) {
                        r = set_put_strdup(&c->restrict_network_interfaces, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-restrict-network-interfaces-is-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_network_interfaces_is_allow_list = r;
                } else
                        log_warning("Failed to parse serialized line, ignoring: %s", l);
        }

        return 0;
}

static int exec_runtime_serialize(const ExecRuntime *rt, FILE *f, FDSet *fds) {
        int r;

        assert(f);
        assert(fds);

        if (!rt) {
                fputc('\n', f); /* End marker */
                return 0;
        }

        if (rt->shared) {
                r = serialize_item(f, "exec-runtime-id", rt->shared->id);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-runtime-tmp-dir", rt->shared->tmp_dir);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-runtime-var-tmp-dir", rt->shared->var_tmp_dir);
                if (r < 0)
                        return r;

                if (rt->shared->netns_storage_socket[0] >= 0 && rt->shared->netns_storage_socket[1] >= 0) {
                        r = serialize_fd_many(f, fds, "exec-runtime-netns-storage-socket", rt->shared->netns_storage_socket, 2);
                        if (r < 0)
                                return r;
                }

                if (rt->shared->ipcns_storage_socket[0] >= 0 && rt->shared->ipcns_storage_socket[1] >= 0) {
                        r = serialize_fd_many(f, fds, "exec-runtime-ipcns-storage-socket", rt->shared->ipcns_storage_socket, 2);
                        if (r < 0)
                                return r;
                }
        }

        if (rt->dynamic_creds) {
                r = dynamic_user_serialize_one(rt->dynamic_creds->user, "exec-runtime-dynamic-creds-user", f, fds);
                if (r < 0)
                        return r;
        }

        if (rt->dynamic_creds && rt->dynamic_creds->group && rt->dynamic_creds->group == rt->dynamic_creds->user) {
                r = serialize_bool(f, "exec-runtime-dynamic-creds-group-copy", true);
                if (r < 0)
                        return r;
        } else if (rt->dynamic_creds) {
                r = dynamic_user_serialize_one(rt->dynamic_creds->group, "exec-runtime-dynamic-creds-group", f, fds);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-runtime-ephemeral-copy", rt->ephemeral_copy);
        if (r < 0)
                return r;

        if (rt->ephemeral_storage_socket[0] >= 0 && rt->ephemeral_storage_socket[1] >= 0) {
                r = serialize_fd_many(f, fds, "exec-runtime-ephemeral-storage-socket", rt->ephemeral_storage_socket, 2);
                if (r < 0)
                        return r;
        }

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_runtime_deserialize(ExecRuntime *rt, FILE *f, FDSet *fds) {
        int r;

        assert(rt);
        assert(rt->shared);
        assert(rt->dynamic_creds);
        assert(f);
        assert(fds);

        for (;;) {
                _cleanup_free_ char *l = NULL;
                const char *val;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                if ((val = startswith(l, "exec-runtime-id="))) {
                        r = free_and_strdup(&rt->shared->id, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-tmp-dir="))) {
                        r = free_and_strdup(&rt->shared->tmp_dir, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-var-tmp-dir="))) {
                        r = free_and_strdup(&rt->shared->var_tmp_dir, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-netns-storage-socket="))) {

                        r = deserialize_fd_many(fds, val, 2, rt->shared->netns_storage_socket);
                        if (r < 0)
                                continue;

                } else if ((val = startswith(l, "exec-runtime-ipcns-storage-socket="))) {

                        r = deserialize_fd_many(fds, val, 2, rt->shared->ipcns_storage_socket);
                        if (r < 0)
                                continue;

                } else if ((val = startswith(l, "exec-runtime-dynamic-creds-user=")))
                        dynamic_user_deserialize_one(/* m= */ NULL, val, fds, &rt->dynamic_creds->user);
                else if ((val = startswith(l, "exec-runtime-dynamic-creds-group=")))
                        dynamic_user_deserialize_one(/* m= */ NULL, val, fds, &rt->dynamic_creds->group);
                else if ((val = startswith(l, "exec-runtime-dynamic-creds-group-copy="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        if (!r)
                                continue; /* Nothing to do */

                        if (!rt->dynamic_creds->user)
                                return -EINVAL;

                        rt->dynamic_creds->group = dynamic_user_ref(rt->dynamic_creds->user);
                } else if ((val = startswith(l, "exec-runtime-ephemeral-copy="))) {
                        r = free_and_strdup(&rt->ephemeral_copy, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-ephemeral-storage-socket="))) {

                        r = deserialize_fd_many(fds, val, 2, rt->ephemeral_storage_socket);
                        if (r < 0)
                                continue;
                } else
                        log_warning("Failed to parse serialized line, ignoring: %s", l);
        }

        return 0;
}

static bool exec_parameters_is_idle_pipe_set(const ExecParameters *p) {
        assert(p);

        return p->idle_pipe &&
                p->idle_pipe[0] >= 0 &&
                p->idle_pipe[1] >= 0 &&
                p->idle_pipe[2] >= 0 &&
                p->idle_pipe[3] >= 0;
}

static int exec_parameters_serialize(const ExecParameters *p, const ExecContext *c, FILE *f, FDSet *fds) {
        int r;

        assert(f);
        assert(fds);

        if (!p)
                return 0;

        r = serialize_item(f, "exec-parameters-runtime-scope", runtime_scope_to_string(p->runtime_scope));
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-parameters-environment", p->environment);
        if (r < 0)
                return r;

        if (p->fds) {
                if (p->n_socket_fds > 0) {
                        r = serialize_item_format(f, "exec-parameters-n-socket-fds", "%zu", p->n_socket_fds);
                        if (r < 0)
                                return r;
                }

                if (p->n_storage_fds > 0) {
                        r = serialize_item_format(f, "exec-parameters-n-storage-fds", "%zu", p->n_storage_fds);
                        if (r < 0)
                                return r;
                }

                if (p->n_extra_fds > 0) {
                        r = serialize_item_format(f, "exec-parameters-n-extra-fds", "%zu", p->n_extra_fds);
                        if (r < 0)
                                return r;
                }

                r = serialize_fd_many(f, fds, "exec-parameters-fds", p->fds, p->n_socket_fds + p->n_storage_fds + p->n_extra_fds);
                if (r < 0)
                        return r;
        }

        r = serialize_strv(f, "exec-parameters-fd-names", p->fd_names);
        if (r < 0)
                return r;

        if (p->flags != 0) {
                r = serialize_item_format(f, "exec-parameters-flags", "%u", (unsigned) p->flags);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-parameters-selinux-context-net", p->selinux_context_net);
        if (r < 0)
                return r;

        if (p->cgroup_supported != 0) {
                r = serialize_item_format(f, "exec-parameters-cgroup-supported", "%u", (unsigned) p->cgroup_supported);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-parameters-cgroup-path", p->cgroup_path);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-parameters-cgroup-id", "%" PRIu64, p->cgroup_id);
        if (r < 0)
                return r;

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                _cleanup_free_ char *key = NULL;

                key = strjoin("exec-parameters-prefix-directories-", exec_directory_type_to_string(dt));
                if (!key)
                        return log_oom_debug();

                /* Always serialize, even an empty prefix, as this is a fixed array and we always expect
                 * to have all elements (unless fuzzing is happening, hence the NULL check). */
                r = serialize_item(f, key, strempty(p->prefix ? p->prefix[dt] : NULL));
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-parameters-received-credentials-directory", p->received_credentials_directory);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-received-encrypted-credentials-directory", p->received_encrypted_credentials_directory);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-confirm-spawn", p->confirm_spawn);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-parameters-shall-confirm-spawn", p->shall_confirm_spawn);
        if (r < 0)
                return r;

        if (p->watchdog_usec > 0) {
                r = serialize_usec(f, "exec-parameters-watchdog-usec", p->watchdog_usec);
                if (r < 0)
                        return r;
        }

        if (exec_parameters_is_idle_pipe_set(p)) {
                r = serialize_fd_many(f, fds, "exec-parameters-idle-pipe", p->idle_pipe, 4);
                if (r < 0)
                        return r;
        }

        r = serialize_fd(f, fds, "exec-parameters-stdin-fd", p->stdin_fd);
        if (r < 0)
                return r;

        r = serialize_fd(f, fds, "exec-parameters-stdout-fd", p->stdout_fd);
        if (r < 0)
                return r;

        r = serialize_fd(f, fds, "exec-parameters-stderr-fd", p->stderr_fd);
        if (r < 0)
                return r;

        r = serialize_fd(f, fds, "exec-parameters-exec-fd", p->exec_fd);
        if (r < 0)
                return r;

        r = serialize_fd(f, fds, "exec-parameters-handoff-timestamp-fd", p->handoff_timestamp_fd);
        if (r < 0)
                return r;

        r = serialize_fd(f, fds, "exec-parameters-pidref-transport-fd", p->pidref_transport_fd);
        if (r < 0)
                return r;

        if (c && exec_context_restrict_filesystems_set(c)) {
                r = serialize_fd(f, fds, "exec-parameters-bpf-outer-map-fd", p->bpf_restrict_fs_map_fd);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-parameters-notify-socket", p->notify_socket);
        if (r < 0)
                return r;

        LIST_FOREACH(open_files, file, p->open_files) {
                _cleanup_free_ char *ofs = NULL;

                r = open_file_to_string(file, &ofs);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-parameters-open-file", ofs);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-parameters-fallback-smack-process-label", p->fallback_smack_process_label);
        if (r < 0)
                return r;

        r = serialize_fd(f, fds, "exec-parameters-user-lookup-fd", p->user_lookup_fd);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-parameters-files-env", p->files_env);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-unit-id", p->unit_id);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-invocation-id-string", p->invocation_id_string);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-parameters-debug-invocation", p->debug_invocation);
        if (r < 0)
                return r;

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_parameters_deserialize(ExecParameters *p, FILE *f, FDSet *fds) {
        int r;

        assert(p);
        assert(f);
        assert(fds);

        unsigned nr_open = MAX(read_nr_open(), NR_OPEN_MINIMUM);

        for (;;) {
                _cleanup_free_ char *l = NULL;
                const char *val;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                if ((val = startswith(l, "exec-parameters-runtime-scope="))) {
                        p->runtime_scope = runtime_scope_from_string(val);
                        if (p->runtime_scope < 0)
                                return p->runtime_scope;
                } else if ((val = startswith(l, "exec-parameters-environment="))) {
                        r = deserialize_strv(val, &p->environment);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-n-socket-fds="))) {
                        if (p->fds)
                                return -EINVAL; /* Already received */

                        r = safe_atozu(val, &p->n_socket_fds);
                        if (r < 0)
                                return r;

                        if (p->n_socket_fds > nr_open)
                                return -EINVAL; /* too many, someone is playing games with us */
                } else if ((val = startswith(l, "exec-parameters-n-storage-fds="))) {
                        if (p->fds)
                                return -EINVAL; /* Already received */

                        r = safe_atozu(val, &p->n_storage_fds);
                        if (r < 0)
                                return r;

                        if (p->n_storage_fds > nr_open)
                                return -EINVAL; /* too many, someone is playing games with us */
                } else if ((val = startswith(l, "exec-parameters-n-extra-fds="))) {
                        if (p->fds)
                                return -EINVAL; /* Already received */

                        r = safe_atozu(val, &p->n_extra_fds);
                        if (r < 0)
                                return r;

                        if (p->n_extra_fds > nr_open)
                                return -EINVAL; /* too many, someone is playing games with us */
                } else if ((val = startswith(l, "exec-parameters-fds="))) {
                        if (p->n_socket_fds + p->n_storage_fds + p->n_extra_fds == 0)
                                return log_warning_errno(
                                                SYNTHETIC_ERRNO(EINVAL),
                                                "Got exec-parameters-fds= without "
                                                "prior exec-parameters-n-socket-fds= or exec-parameters-n-storage-fds= or exec-parameters-n-extra-fds=");
                        if (p->n_socket_fds + p->n_storage_fds + p->n_extra_fds > nr_open)
                                return -EINVAL; /* too many, someone is playing games with us */

                        if (p->fds)
                                return -EINVAL; /* duplicated */

                        p->fds = new(int, p->n_socket_fds + p->n_storage_fds + p->n_extra_fds);
                        if (!p->fds)
                                return log_oom_debug();

                        /* Ensure we don't leave any FD uninitialized on error, it makes the fuzzer sad */
                        FOREACH_ARRAY(i, p->fds, p->n_socket_fds + p->n_storage_fds + p->n_extra_fds)
                                *i = -EBADF;

                        r = deserialize_fd_many(fds, val, p->n_socket_fds + p->n_storage_fds + p->n_extra_fds, p->fds);
                        if (r < 0)
                                continue;

                } else if ((val = startswith(l, "exec-parameters-fd-names="))) {
                        r = deserialize_strv(val, &p->fd_names);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-flags="))) {
                        unsigned flags;

                        r = safe_atou(val, &flags);
                        if (r < 0)
                                return r;
                        p->flags = flags;
                } else if ((val = startswith(l, "exec-parameters-selinux-context-net="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;

                        p->selinux_context_net = r;
                } else if ((val = startswith(l, "exec-parameters-cgroup-supported="))) {
                        unsigned cgroup_supported;

                        r = safe_atou(val, &cgroup_supported);
                        if (r < 0)
                                return r;
                        p->cgroup_supported = cgroup_supported;
                } else if ((val = startswith(l, "exec-parameters-cgroup-path="))) {
                        r = free_and_strdup(&p->cgroup_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-cgroup-id="))) {
                        r = safe_atou64(val, &p->cgroup_id);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-prefix-directories-"))) {
                        _cleanup_free_ char *type = NULL, *prefix = NULL;
                        ExecDirectoryType dt;

                        r = extract_many_words(&val, "= ", 0, &type, &prefix);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        dt = exec_directory_type_from_string(type);
                        if (dt < 0)
                                return -EINVAL;

                        if (!p->prefix) {
                                p->prefix = new0(char*, _EXEC_DIRECTORY_TYPE_MAX+1);
                                if (!p->prefix)
                                        return log_oom_debug();
                        }

                        if (isempty(prefix))
                                p->prefix[dt] = mfree(p->prefix[dt]);
                        else
                                free_and_replace(p->prefix[dt], prefix);
                } else if ((val = startswith(l, "exec-parameters-received-credentials-directory="))) {
                        r = free_and_strdup(&p->received_credentials_directory, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-received-encrypted-credentials-directory="))) {
                        r = free_and_strdup(&p->received_encrypted_credentials_directory, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-confirm-spawn="))) {
                        r = free_and_strdup(&p->confirm_spawn, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-shall-confirm-spawn="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;

                        p->shall_confirm_spawn = r;
                } else if ((val = startswith(l, "exec-parameters-watchdog-usec="))) {
                        r = deserialize_usec(val, &p->watchdog_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-idle-pipe="))) {
                        if (p->idle_pipe)
                                return -EINVAL; /* duplicated */

                        p->idle_pipe = new(int, 4);
                        if (!p->idle_pipe)
                                return log_oom_debug();

                        p->idle_pipe[0] = p->idle_pipe[1] = p->idle_pipe[2] = p->idle_pipe[3] = -EBADF;

                        r = deserialize_fd_many(fds, val, 4, p->idle_pipe);
                        if (r < 0)
                                continue;

                } else if ((val = startswith(l, "exec-parameters-stdin-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->stdin_fd, fd);

                } else if ((val = startswith(l, "exec-parameters-stdout-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->stdout_fd, fd);

                } else if ((val = startswith(l, "exec-parameters-stderr-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->stderr_fd, fd);
                } else if ((val = startswith(l, "exec-parameters-exec-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->exec_fd, fd);
                } else if ((val = startswith(l, "exec-parameters-handoff-timestamp-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->handoff_timestamp_fd, fd);
                } else if ((val = startswith(l, "exec-parameters-pidref-transport-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->pidref_transport_fd, fd);
                } else if ((val = startswith(l, "exec-parameters-bpf-outer-map-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->bpf_restrict_fs_map_fd, fd);
                } else if ((val = startswith(l, "exec-parameters-notify-socket="))) {
                        r = free_and_strdup(&p->notify_socket, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-open-file="))) {
                        OpenFile *of;

                        r = open_file_parse(val, &of);
                        if (r < 0)
                                return r;

                        LIST_APPEND(open_files, p->open_files, of);
                } else if ((val = startswith(l, "exec-parameters-fallback-smack-process-label="))) {
                        r = free_and_strdup(&p->fallback_smack_process_label, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-user-lookup-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd < 0)
                                continue;

                        close_and_replace(p->user_lookup_fd, fd);
                } else if ((val = startswith(l, "exec-parameters-files-env="))) {
                        r = deserialize_strv(val, &p->files_env);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-unit-id="))) {
                        r = free_and_strdup(&p->unit_id, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-invocation-id-string="))) {
                        if (strlen(val) > SD_ID128_STRING_MAX - 1)
                                return -EINVAL;

                        r = sd_id128_from_string(val, &p->invocation_id);
                        if (r < 0)
                                return r;

                        sd_id128_to_string(p->invocation_id, p->invocation_id_string);
                } else if ((val = startswith(l, "exec-parameters-debug-invocation="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;

                        p->debug_invocation = r;
                } else
                        log_warning("Failed to parse serialized line, ignoring: %s", l);
        }

        /* Bail out if we got exec-parameters-n-{socket/storage}-fds= but no corresponding
         * exec-parameters-fds= */
        if (p->n_socket_fds + p->n_storage_fds > 0 && !p->fds)
                return -EINVAL;

        return 0;
}

static int serialize_std_out_err(const ExecContext *c, FILE *f, int fileno) {
        char *key, *value;
        const char *type;

        assert(c);
        assert(f);
        assert(IN_SET(fileno, STDOUT_FILENO, STDERR_FILENO));

        type = fileno == STDOUT_FILENO ? "output" : "error";

        switch (fileno == STDOUT_FILENO ? c->std_output : c->std_error) {
        case EXEC_OUTPUT_NAMED_FD:
                key = strjoina("exec-context-std-", type, "-fd-name");
                value = c->stdio_fdname[fileno];

                break;

        case EXEC_OUTPUT_FILE:
                key = strjoina("exec-context-std-", type, "-file");
                value = c->stdio_file[fileno];

                break;

        case EXEC_OUTPUT_FILE_APPEND:
                key = strjoina("exec-context-std-", type, "-file-append");
                value = c->stdio_file[fileno];

                break;

        case EXEC_OUTPUT_FILE_TRUNCATE:
                key = strjoina("exec-context-std-", type, "-file-truncate");
                value = c->stdio_file[fileno];

                break;

        default:
                return 0;
        }

        return serialize_item(f, key, value);
}

static int exec_context_serialize(const ExecContext *c, FILE *f) {
        int r;

        assert(f);

        if (!c)
                return 0;

        r = serialize_strv(f, "exec-context-environment", c->environment);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-environment-files", c->environment_files);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-pass-environment", c->pass_environment);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-unset-environment", c->unset_environment);
        if (r < 0)
                return r;

        r = serialize_item_escaped(f, "exec-context-working-directory", c->working_directory);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-working-directory-missing-ok", c->working_directory_missing_ok);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-working-directory-home", c->working_directory_home);
        if (r < 0)
                return r;

        r = serialize_item_escaped(f, "exec-context-root-directory", c->root_directory);
        if (r < 0)
                return r;

        r = serialize_item_escaped(f, "exec-context-root-image", c->root_image);
        if (r < 0)
                return r;

        if (c->root_image_options) {
                _cleanup_free_ char *options = NULL;

                LIST_FOREACH(mount_options, o, c->root_image_options) {
                        if (isempty(o->options))
                                continue;

                        _cleanup_free_ char *escaped = NULL;
                        escaped = shell_escape(o->options, ":");
                        if (!escaped)
                                return log_oom_debug();

                        if (!strextend(&options,
                                        " ",
                                        partition_designator_to_string(o->partition_designator),
                                               ":",
                                               escaped))
                                        return log_oom_debug();
                }

                r = serialize_item(f, "exec-context-root-image-options", options);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-root-verity", c->root_verity);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-root-hash-path", c->root_hash_path);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-root-hash-sig-path", c->root_hash_sig_path);
        if (r < 0)
                return r;

        r = serialize_item_hexmem(f, "exec-context-root-hash", c->root_hash, c->root_hash_size);
        if (r < 0)
                return r;

        r = serialize_item_base64mem(f, "exec-context-root-hash-sig", c->root_hash_sig, c->root_hash_sig_size);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-root-ephemeral", c->root_ephemeral);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-umask", "%04o", c->umask);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-non-blocking", c->non_blocking);
        if (r < 0)
                return r;

        r = serialize_item_tristate(f, "exec-context-private-mounts", c->private_mounts);
        if (r < 0)
                return r;

        r = serialize_item_tristate(f, "exec-context-mount-api-vfs", c->mount_apivfs);
        if (r < 0)
                return r;

        r = serialize_item_tristate(f, "exec-context-bind-log-sockets", c->bind_log_sockets);
        if (r < 0)
                return r;

        r = serialize_item_tristate(f, "exec-context-memory-ksm", c->memory_ksm);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-private-tmp", private_tmp_to_string(c->private_tmp));
        if (r < 0)
                return r;

        /* This must be set in unit_patch_contexts() before executing a command. */
        assert(c->private_var_tmp >= 0 && c->private_var_tmp < _PRIVATE_TMP_MAX);
        r = serialize_item(f, "exec-context-private-var-tmp", private_tmp_to_string(c->private_var_tmp));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-devices", c->private_devices);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-kernel-tunables", c->protect_kernel_tunables);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-kernel-modules", c->protect_kernel_modules);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-kernel-logs", c->protect_kernel_logs);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-clock", c->protect_clock);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-control-groups", protect_control_groups_to_string(c->protect_control_groups));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-network", c->private_network);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-private-users", private_users_to_string(c->private_users));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-ipc", c->private_ipc);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-private-pids", private_pids_to_string(c->private_pids));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-remove-ipc", c->remove_ipc);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-home", protect_home_to_string(c->protect_home));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-system", protect_system_to_string(c->protect_system));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-same-pgrp", c->same_pgrp);
        if (r < 0)
                return r;

        r = serialize_bool(f, "exec-context-ignore-sigpipe", c->ignore_sigpipe);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-memory-deny-write-execute", c->memory_deny_write_execute);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-restrict-realtime", c->restrict_realtime);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-restrict-suid-sgid", c->restrict_suid_sgid);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-keyring-mode", exec_keyring_mode_to_string(c->keyring_mode));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-hostname", protect_hostname_to_string(c->protect_hostname));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-private-hostname", c->private_hostname);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-proc", protect_proc_to_string(c->protect_proc));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-proc-subset", proc_subset_to_string(c->proc_subset));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-private-bpf", private_bpf_to_string(c->private_bpf));
        if (r < 0)
                return r;

        if (c->bpf_delegate_commands != 0) {
                r = serialize_item_format(f, "exec-context-bpf-delegate-commands", "0x%"PRIx64, c->bpf_delegate_commands);
                if (r < 0)
                        return r;
        }

        if (c->bpf_delegate_maps != 0) {
                r = serialize_item_format(f, "exec-context-bpf-delegate-maps", "0x%"PRIx64, c->bpf_delegate_maps);
                if (r < 0)
                        return r;
        }

        if (c->bpf_delegate_programs != 0) {
                r = serialize_item_format(f, "exec-context-bpf-delegate-programs", "0x%"PRIx64, c->bpf_delegate_programs);
                if (r < 0)
                        return r;
        }

        if (c->bpf_delegate_attachments != 0) {
                r = serialize_item_format(f, "exec-context-bpf-delegate-attachments", "0x%"PRIx64, c->bpf_delegate_attachments);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-runtime-directory-preserve-mode", exec_preserve_mode_to_string(c->runtime_directory_preserve_mode));
        if (r < 0)
                return r;

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                _cleanup_free_ char *key = NULL, *value = NULL;

                key = strjoin("exec-context-directories-", exec_directory_type_to_string(dt));
                if (!key)
                        return log_oom_debug();

                if (asprintf(&value, "%04o", c->directories[dt].mode) < 0)
                        return log_oom_debug();

                FOREACH_ARRAY(i, c->directories[dt].items, c->directories[dt].n_items) {
                        _cleanup_free_ char *path_escaped = NULL;

                        path_escaped = shell_escape(i->path, ":" WHITESPACE);
                        if (!path_escaped)
                                return log_oom_debug();

                        if (!strextend(&value, " ", path_escaped))
                                return log_oom_debug();

                        if (!strextend(&value, ":", yes_no(FLAGS_SET(i->flags, EXEC_DIRECTORY_ONLY_CREATE))))
                                return log_oom_debug();

                        if (!strextend(&value, ":", yes_no(FLAGS_SET(i->flags, EXEC_DIRECTORY_READ_ONLY))))
                                return log_oom_debug();

                        STRV_FOREACH(d, i->symlinks) {
                                _cleanup_free_ char *link_escaped = NULL;

                                link_escaped = shell_escape(*d, ":" WHITESPACE);
                                if (!link_escaped)
                                        return log_oom_debug();

                                if (!strextend(&value, ":", link_escaped))
                                        return log_oom_debug();
                        }
                }

                r = serialize_item(f, key, value);
                if (r < 0)
                        return r;

                if (c->directories[dt].exec_quota.quota_enforce) {
                        _cleanup_free_ char *key_quota = NULL;
                        key_quota = strjoin("exec-context-quota-directories-", exec_directory_type_to_string(dt));
                        if (!key_quota)
                                return log_oom_debug();

                        r = serialize_item_format(f, key_quota, "%" PRIu64 " %" PRIu32, c->directories[dt].exec_quota.quota_absolute,
                                                                                        c->directories[dt].exec_quota.quota_scale);
                        if (r < 0)
                                return r;

                } else if (c->directories[dt].exec_quota.quota_accounting) {
                        _cleanup_free_ char *key_quota = NULL;
                        key_quota = strjoin("exec-context-quota-accounting-directories-", exec_directory_type_to_string(dt));
                        if (!key_quota)
                                return log_oom_debug();

                        r = serialize_bool(f, key_quota, c->directories[dt].exec_quota.quota_accounting);
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_usec(f, "exec-context-timeout-clean-usec", c->timeout_clean_usec);
        if (r < 0)
                return r;

        if (c->nice_set) {
                r = serialize_item_format(f, "exec-context-nice", "%i", c->nice);
                if (r < 0)
                        return r;
        }

        if (c->oom_score_adjust_set) {
                r = serialize_item_format(f, "exec-context-oom-score-adjust", "%i", c->oom_score_adjust);
                if (r < 0)
                        return r;
        }

        if (c->coredump_filter_set) {
                r = serialize_item_format(f, "exec-context-coredump-filter", "%"PRIx64, c->coredump_filter);
                if (r < 0)
                        return r;
        }

        for (unsigned i = 0; i < RLIM_NLIMITS; i++) {
                _cleanup_free_ char *key = NULL, *limit = NULL;

                if (!c->rlimit[i])
                        continue;

                key = strjoin("exec-context-limit-", rlimit_to_string(i));
                if (!key)
                        return log_oom_debug();

                r = rlimit_format(c->rlimit[i], &limit);
                if (r < 0)
                        return r;

                r = serialize_item(f, key, limit);
                if (r < 0)
                        return r;
        }

        if (c->ioprio_is_set) {
                r = serialize_item_format(f, "exec-context-ioprio", "%d", c->ioprio);
                if (r < 0)
                        return r;
        }

        if (c->cpu_sched_set) {
                _cleanup_free_ char *policy_str = NULL;

                r = sched_policy_to_string_alloc(c->cpu_sched_policy, &policy_str);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-context-cpu-scheduling-policy", policy_str);
                if (r < 0)
                        return r;

                r = serialize_item_format(f, "exec-context-cpu-scheduling-priority", "%i", c->cpu_sched_priority);
                if (r < 0)
                        return r;

                r = serialize_bool_elide(f, "exec-context-cpu-scheduling-reset-on-fork", c->cpu_sched_reset_on_fork);
                if (r < 0)
                        return r;
        }

        if (c->cpu_set.set) {
                _cleanup_free_ char *affinity = NULL;

                affinity = cpu_set_to_range_string(&c->cpu_set);
                if (!affinity)
                        return log_oom_debug();

                r = serialize_item(f, "exec-context-cpu-affinity", affinity);
                if (r < 0)
                        return r;
        }

        if (mpol_is_valid(numa_policy_get_type(&c->numa_policy))) {
                _cleanup_free_ char *nodes = NULL;

                nodes = cpu_set_to_range_string(&c->numa_policy.nodes);
                if (!nodes)
                        return log_oom_debug();

                if (nodes) {
                        r = serialize_item(f, "exec-context-numa-mask", nodes);
                        if (r < 0)
                                return r;
                }

                r = serialize_item_format(f, "exec-context-numa-policy", "%d", c->numa_policy.type);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-cpu-affinity-from-numa", c->cpu_affinity_from_numa);
        if (r < 0)
                return r;

        if (c->timer_slack_nsec != NSEC_INFINITY) {
                r = serialize_item_format(f, "exec-context-timer-slack-nsec", NSEC_FMT, c->timer_slack_nsec);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-std-input", exec_input_to_string(c->std_input));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-std-output", exec_output_to_string(c->std_output));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-std-error", exec_output_to_string(c->std_error));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-stdio-as-fds", c->stdio_as_fds);
        if (r < 0)
                return r;

        switch (c->std_input) {
        case EXEC_INPUT_NAMED_FD:
                r = serialize_item(f, "exec-context-std-input-fd-name", c->stdio_fdname[STDIN_FILENO]);
                if (r < 0)
                        return r;
                break;

        case EXEC_INPUT_FILE:
                r = serialize_item(f, "exec-context-std-input-file", c->stdio_file[STDIN_FILENO]);
                if (r < 0)
                        return r;
                break;

        default:
                ;
        }

        r = serialize_std_out_err(c, f, STDOUT_FILENO);
        if (r < 0)
                return r;

        r = serialize_std_out_err(c, f, STDERR_FILENO);
        if (r < 0)
                return r;

        r = serialize_item_base64mem(f, "exec-context-stdin-data", c->stdin_data, c->stdin_data_size);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-tty-path", c->tty_path);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-tty-reset", c->tty_reset);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-tty-vhangup", c->tty_vhangup);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-tty-vt-disallocate", c->tty_vt_disallocate);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-tty-rows", "%u", c->tty_rows);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-tty-columns", "%u", c->tty_cols);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-syslog-priority", "%i", c->syslog_priority);
        if (r < 0)
                return r;

        r = serialize_bool(f, "exec-context-syslog-level-prefix", c->syslog_level_prefix);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-syslog-identifier", c->syslog_identifier);
        if (r < 0)
                return r;

        /* This is also passed to executor as an argument. So, the information should be redundant in general.
         * But, let's keep this as is for consistency with other elements of ExecContext. See exec_spawn(). */
        r = serialize_item_format(f, "exec-context-log-level-max", "%d", c->log_level_max);
        if (r < 0)
                return r;

        if (c->log_ratelimit.interval > 0) {
                r = serialize_usec(f, "exec-context-log-ratelimit-interval-usec", c->log_ratelimit.interval);
                if (r < 0)
                        return r;
        }

        if (c->log_ratelimit.burst > 0) {
                r = serialize_item_format(f, "exec-context-log-ratelimit-burst", "%u", c->log_ratelimit.burst);
                if (r < 0)
                        return r;
        }

        r = serialize_string_set(f, "exec-context-log-filter-allowed-patterns", c->log_filter_allowed_patterns);
        if (r < 0)
                return r;

        r = serialize_string_set(f, "exec-context-log-filter-denied-patterns", c->log_filter_denied_patterns);
        if (r < 0)
                return r;

        FOREACH_ARRAY(field, c->log_extra_fields, c->n_log_extra_fields) {
                r = serialize_item(f, "exec-context-log-extra-fields", field->iov_base);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-log-namespace", c->log_namespace);
        if (r < 0)
                return r;

        if (c->secure_bits != 0) {
                r = serialize_item_format(f, "exec-context-secure-bits", "%d", c->secure_bits);
                if (r < 0)
                        return r;
        }

        if (c->capability_bounding_set != CAP_MASK_UNSET) {
                r = serialize_item_format(f, "exec-context-capability-bounding-set", "%" PRIu64, c->capability_bounding_set);
                if (r < 0)
                        return r;
        }

        if (c->capability_ambient_set != 0) {
                r = serialize_item_format(f, "exec-context-capability-ambient-set", "%" PRIu64, c->capability_ambient_set);
                if (r < 0)
                        return r;
        }

        if (c->user) {
                r = serialize_item(f, "exec-context-user", c->user);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-group", c->group);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-dynamic-user", c->dynamic_user);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-supplementary-groups", c->supplementary_groups);
        if (r < 0)
                return r;

        r = serialize_item_tristate(f, "exec-context-set-login-environment", c->set_login_environment);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-pam-name", c->pam_name);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-read-write-paths", c->read_write_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-read-only-paths", c->read_only_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-inaccessible-paths", c->inaccessible_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-exec-paths", c->exec_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-no-exec-paths", c->no_exec_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-exec-search-path", c->exec_search_path);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-mount-propagation-flag", "%lu", c->mount_propagation_flag);
        if (r < 0)
                return r;

        FOREACH_ARRAY(mount, c->bind_mounts, c->n_bind_mounts) {
                _cleanup_free_ char *src_escaped = NULL, *dst_escaped = NULL;

                src_escaped = shell_escape(mount->source, ":" WHITESPACE);
                if (!src_escaped)
                        return log_oom_debug();

                dst_escaped = shell_escape(mount->destination, ":" WHITESPACE);
                if (!dst_escaped)
                        return log_oom_debug();

                r = serialize_item_format(f,
                                          mount->read_only ? "exec-context-bind-read-only-path" : "exec-context-bind-path",
                                          "%s%s:%s:%s",
                                          mount->ignore_enoent ? "-" : "",
                                          src_escaped,
                                          dst_escaped,
                                          mount->recursive ? "rbind" : "norbind");
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(tmpfs, c->temporary_filesystems, c->n_temporary_filesystems) {
                _cleanup_free_ char *escaped = NULL;

                if (!isempty(tmpfs->options)) {
                        escaped = shell_escape(tmpfs->options, ":");
                        if (!escaped)
                                return log_oom_debug();
                }

                r = serialize_item_format(f, "exec-context-temporary-filesystems", "%s%s%s",
                                          tmpfs->path,
                                          isempty(escaped) ? "" : ":",
                                          strempty(escaped));
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-utmp-id", c->utmp_id);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-utmp-mode", exec_utmp_mode_to_string(c->utmp_mode));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-no-new-privileges", c->no_new_privileges);
        if (r < 0)
                return r;

        if (c->selinux_context) {
                r = serialize_item_format(f, "exec-context-selinux-context",
                                          "%s%s",
                                          c->selinux_context_ignore ? "-" : "",
                                          c->selinux_context);
                if (r < 0)
                        return r;
        }

        if (c->apparmor_profile) {
                r = serialize_item_format(f, "exec-context-apparmor-profile",
                                          "%s%s",
                                          c->apparmor_profile_ignore ? "-" : "",
                                          c->apparmor_profile);
                if (r < 0)
                        return r;
        }

        if (c->smack_process_label) {
                r = serialize_item_format(f, "exec-context-smack-process-label",
                                          "%s%s",
                                          c->smack_process_label_ignore ? "-" : "",
                                          c->smack_process_label);
                if (r < 0)
                        return r;
        }

        if (c->personality != PERSONALITY_INVALID) {
                r = serialize_item(f, "exec-context-personality", personality_to_string(c->personality));
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-lock-personality", c->lock_personality);
        if (r < 0)
                return r;

#if HAVE_SECCOMP
        if (!hashmap_isempty(c->syscall_filter)) {
                void *errno_num, *id;
                HASHMAP_FOREACH_KEY(errno_num, id, c->syscall_filter) {
                        r = serialize_item_format(f, "exec-context-syscall-filter", "%d %d", PTR_TO_INT(id) - 1, PTR_TO_INT(errno_num));
                        if (r < 0)
                                return r;
                }
        }

        if (!set_isempty(c->syscall_archs)) {
                void *id;
                SET_FOREACH(id, c->syscall_archs) {
                        r = serialize_item_format(f, "exec-context-syscall-archs", "%u", PTR_TO_UINT(id) - 1);
                        if (r < 0)
                                return r;
                }
        }

        if (c->syscall_errno > 0) {
                r = serialize_item_format(f, "exec-context-syscall-errno", "%d", c->syscall_errno);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-syscall-allow-list", c->syscall_allow_list);
        if (r < 0)
                return r;

        if (!hashmap_isempty(c->syscall_log)) {
                void *errno_num, *id;
                HASHMAP_FOREACH_KEY(errno_num, id, c->syscall_log) {
                        r = serialize_item_format(f, "exec-context-syscall-log", "%d %d", PTR_TO_INT(id) - 1, PTR_TO_INT(errno_num));
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_bool_elide(f, "exec-context-syscall-log-allow-list", c->syscall_log_allow_list);
        if (r < 0)
                return r;
#endif

        if (c->restrict_namespaces != NAMESPACE_FLAGS_INITIAL) {
                r = serialize_item_format(f, "exec-context-restrict-namespaces", "%lu", c->restrict_namespaces);
                if (r < 0)
                        return r;
        }

        if (c->delegate_namespaces != NAMESPACE_FLAGS_INITIAL) {
                r = serialize_item_format(f, "exec-context-delegate-namespaces", "%lu", c->delegate_namespaces);
                if (r < 0)
                        return r;
        }

#if HAVE_LIBBPF
        if (exec_context_restrict_filesystems_set(c)) {
                char *fs;
                SET_FOREACH(fs, c->restrict_filesystems) {
                        r = serialize_item(f, "exec-context-restrict-filesystems", fs);
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_bool_elide(f, "exec-context-restrict-filesystems-allow-list", c->restrict_filesystems_allow_list);
        if (r < 0)
                return r;
#endif

        if (!set_isempty(c->address_families)) {
                void *afp;

                SET_FOREACH(afp, c->address_families) {
                        int af = PTR_TO_INT(afp);

                        if (af <= 0 || af >= af_max())
                                continue;

                        r = serialize_item_format(f, "exec-context-address-families", "%d", af);
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_bool_elide(f, "exec-context-address-families-allow-list", c->address_families_allow_list);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-network-namespace-path", c->network_namespace_path);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-ipc-namespace-path", c->ipc_namespace_path);
        if (r < 0)
                return r;

        FOREACH_ARRAY(mount, c->mount_images, c->n_mount_images) {
                _cleanup_free_ char *s = NULL, *source_escaped = NULL, *dest_escaped = NULL;

                source_escaped = shell_escape(mount->source, WHITESPACE);
                if (!source_escaped)
                        return log_oom_debug();

                dest_escaped = shell_escape(mount->destination, WHITESPACE);
                if (!dest_escaped)
                        return log_oom_debug();

                s = strjoin(mount->ignore_enoent ? "-" : "",
                            source_escaped,
                            " ",
                            dest_escaped);
                if (!s)
                        return log_oom_debug();

                LIST_FOREACH(mount_options, o, mount->mount_options) {
                        _cleanup_free_ char *escaped = NULL;

                        if (isempty(o->options))
                                continue;

                        escaped = shell_escape(o->options, ":");
                        if (!escaped)
                                return log_oom_debug();

                        if (!strextend(&s,
                                       " ",
                                       partition_designator_to_string(o->partition_designator),
                                       ":",
                                       escaped))
                                return log_oom_debug();
                }

                r = serialize_item(f, "exec-context-mount-image", s);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(mount, c->extension_images, c->n_extension_images) {
                _cleanup_free_ char *s = NULL, *source_escaped = NULL;

                source_escaped = shell_escape(mount->source, ":" WHITESPACE);
                if (!source_escaped)
                        return log_oom_debug();

                s = strjoin(mount->ignore_enoent ? "-" : "",
                            source_escaped);
                if (!s)
                        return log_oom_debug();

                LIST_FOREACH(mount_options, o, mount->mount_options) {
                        _cleanup_free_ char *escaped = NULL;

                        if (isempty(o->options))
                                continue;

                        escaped = shell_escape(o->options, ":");
                        if (!escaped)
                                return log_oom_debug();

                        if (!strextend(&s,
                                       " ",
                                       partition_designator_to_string(o->partition_designator),
                                       ":",
                                       escaped))
                                return log_oom_debug();
                }

                r = serialize_item(f, "exec-context-extension-image", s);
                if (r < 0)
                        return r;
        }

        r = serialize_strv(f, "exec-context-extension-directories", c->extension_directories);
        if (r < 0)
                return r;

        ExecSetCredential *sc;
        HASHMAP_FOREACH(sc, c->set_credentials) {
                _cleanup_free_ char *data = NULL;

                if (base64mem(sc->data, sc->size, &data) < 0)
                        return log_oom_debug();

                r = serialize_item_format(f, "exec-context-set-credentials", "%s %s %s", sc->id, data, yes_no(sc->encrypted));
                if (r < 0)
                        return r;
        }

        ExecLoadCredential *lc;
        HASHMAP_FOREACH(lc, c->load_credentials) {
                r = serialize_item_format(f, "exec-context-load-credentials", "%s %s %s", lc->id, lc->path, yes_no(lc->encrypted));
                if (r < 0)
                        return r;
        }

        ExecImportCredential *ic;
        ORDERED_SET_FOREACH(ic, c->import_credentials) {
                r = serialize_item_format(f, "exec-context-import-credentials", "%s%s%s",
                                          ic->glob,
                                          ic->rename ? " " : "",
                                          strempty(ic->rename));
                if (r < 0)
                        return r;
        }

        r = serialize_image_policy(f, "exec-context-root-image-policy", c->root_image_policy);
        if (r < 0)
                return r;

        r = serialize_image_policy(f, "exec-context-mount-image-policy", c->mount_image_policy);
        if (r < 0)
                return r;

        r = serialize_image_policy(f, "exec-context-extension-image-policy", c->extension_image_policy);
        if (r < 0)
                return r;

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_context_deserialize(ExecContext *c, FILE *f) {
        int r;

        assert(f);

        if (!c)
                return 0;

        for (;;) {
                _cleanup_free_ char *l = NULL;
                const char *val;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                if ((val = startswith(l, "exec-context-environment="))) {
                        r = deserialize_strv(val, &c->environment);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-environment-files="))) {
                        r = deserialize_strv(val, &c->environment_files);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-pass-environment="))) {
                        r = deserialize_strv(val, &c->pass_environment);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-unset-environment="))) {
                        r = deserialize_strv(val, &c->unset_environment);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-working-directory="))) {
                        ssize_t k;
                        char *p;

                        k = cunescape(val, 0, &p);
                        if (k < 0)
                                return k;
                        free_and_replace(c->working_directory, p);
                } else if ((val = startswith(l, "exec-context-root-directory="))) {
                        ssize_t k;
                        char *p;

                        k = cunescape(val, 0, &p);
                        if (k < 0)
                                return k;
                        free_and_replace(c->root_directory, p);
                } else if ((val = startswith(l, "exec-context-root-image="))) {
                        ssize_t k;
                        char *p;

                        k = cunescape(val, 0, &p);
                        if (k < 0)
                                return k;
                        free_and_replace(c->root_image, p);
                } else if ((val = startswith(l, "exec-context-root-image-options="))) {
                        for (;;) {
                                _cleanup_free_ char *word = NULL, *mount_options = NULL, *partition = NULL;
                                PartitionDesignator partition_designator;
                                MountOptions *o = NULL;
                                const char *p;

                                r = extract_first_word(&val, &word, NULL, 0);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = word;
                                r = extract_many_words(&p, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                partition_designator = partition_designator_from_string(partition);
                                if (partition_designator < 0)
                                        return -EINVAL;

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom_debug();
                                *o = (MountOptions) {
                                        .partition_designator = partition_designator,
                                        .options = TAKE_PTR(mount_options),
                                };
                                LIST_APPEND(mount_options, c->root_image_options, o);
                        }
                } else if ((val = startswith(l, "exec-context-root-verity="))) {
                        r = free_and_strdup(&c->root_verity, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash-path="))) {
                        r = free_and_strdup(&c->root_hash_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash-sig-path="))) {
                        r = free_and_strdup(&c->root_hash_sig_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash="))) {
                        c->root_hash = mfree(c->root_hash);
                        r = unhexmem(val, &c->root_hash, &c->root_hash_size);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash-sig="))) {
                        c->root_hash_sig = mfree(c->root_hash_sig);
                        r= unbase64mem(val, &c->root_hash_sig, &c->root_hash_sig_size);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-ephemeral="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->root_ephemeral = r;
                } else if ((val = startswith(l, "exec-context-umask="))) {
                        r = parse_mode(val, &c->umask);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-private-non-blocking="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->non_blocking = r;
                } else if ((val = startswith(l, "exec-context-private-mounts="))) {
                        r = safe_atoi(val, &c->private_mounts);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-mount-api-vfs="))) {
                        r = safe_atoi(val, &c->mount_apivfs);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-bind-log-sockets="))) {
                        r = safe_atoi(val, &c->bind_log_sockets);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-memory-ksm="))) {
                        r = safe_atoi(val, &c->memory_ksm);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-private-tmp="))) {
                        c->private_tmp = private_tmp_from_string(val);
                        if (c->private_tmp < 0)
                                return c->private_tmp;
                } else if ((val = startswith(l, "exec-context-private-var-tmp="))) {
                        c->private_var_tmp = private_tmp_from_string(val);
                        if (c->private_var_tmp < 0)
                                return c->private_var_tmp;
                } else if ((val = startswith(l, "exec-context-private-devices="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_devices = r;
                } else if ((val = startswith(l, "exec-context-protect-kernel-tunables="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_kernel_tunables = r;
                } else if ((val = startswith(l, "exec-context-protect-kernel-modules="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_kernel_modules = r;
                } else if ((val = startswith(l, "exec-context-protect-kernel-logs="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_kernel_logs = r;
                } else if ((val = startswith(l, "exec-context-protect-clock="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_clock = r;
                } else if ((val = startswith(l, "exec-context-protect-control-groups="))) {
                        r = protect_control_groups_from_string(val);
                        if (r < 0)
                                return r;
                        c->protect_control_groups = r;
                } else if ((val = startswith(l, "exec-context-private-network="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_network = r;
                } else if ((val = startswith(l, "exec-context-private-users="))) {
                        c->private_users = private_users_from_string(val);
                        if (c->private_users < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-private-ipc="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_ipc = r;
                } else if ((val = startswith(l, "exec-context-private-pids="))) {
                        c->private_pids = private_pids_from_string(val);
                        if (c->private_pids < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-remove-ipc="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->remove_ipc = r;
                } else if ((val = startswith(l, "exec-context-protect-home="))) {
                        c->protect_home = protect_home_from_string(val);
                        if (c->protect_home < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-protect-system="))) {
                        c->protect_system = protect_system_from_string(val);
                        if (c->protect_system < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-same-pgrp="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->same_pgrp = r;
                } else if ((val = startswith(l, "exec-context-non-blocking="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->non_blocking = r;
                } else if ((val = startswith(l, "exec-context-ignore-sigpipe="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ignore_sigpipe = r;
                } else if ((val = startswith(l, "exec-context-memory-deny-write-execute="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_deny_write_execute = r;
                } else if ((val = startswith(l, "exec-context-restrict-realtime="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_realtime = r;
                } else if ((val = startswith(l, "exec-context-restrict-suid-sgid="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_suid_sgid = r;
                } else if ((val = startswith(l, "exec-context-keyring-mode="))) {
                        c->keyring_mode = exec_keyring_mode_from_string(val);
                        if (c->keyring_mode < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-protect-hostname="))) {
                        c->protect_hostname = protect_hostname_from_string(val);
                        if (c->protect_hostname < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-private-hostname="))) {
                        r = free_and_strdup(&c->private_hostname, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-protect-proc="))) {
                        c->protect_proc = protect_proc_from_string(val);
                        if (c->protect_proc < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-proc-subset="))) {
                        c->proc_subset = proc_subset_from_string(val);
                        if (c->proc_subset < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-private-bpf="))) {
                        c->private_bpf = private_bpf_from_string(val);
                        if (c->private_bpf < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-bpf-delegate-commands="))) {
                        r = safe_atoux64(val, &c->bpf_delegate_commands);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-bpf-delegate-maps="))) {
                        r = safe_atoux64(val, &c->bpf_delegate_maps);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-bpf-delegate-programs="))) {
                        r = safe_atoux64(val, &c->bpf_delegate_programs);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-bpf-delegate-attachments="))) {
                        r = safe_atoux64(val, &c->bpf_delegate_attachments);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-runtime-directory-preserve-mode="))) {
                        c->runtime_directory_preserve_mode = exec_preserve_mode_from_string(val);
                        if (c->runtime_directory_preserve_mode < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-directories-"))) {
                        _cleanup_free_ char *type = NULL, *mode = NULL;
                        ExecDirectoryType dt;

                        r = extract_many_words(&val, "= ", 0, &type, &mode);
                        if (r < 0)
                                return r;
                        if (r == 0 || !mode)
                                return -EINVAL;

                        dt = exec_directory_type_from_string(type);
                        if (dt < 0)
                                return dt;

                        r = parse_mode(mode, &c->directories[dt].mode);
                        if (r < 0)
                                return r;

                        for (;;) {
                                _cleanup_free_ char *tuple = NULL, *path = NULL, *only_create = NULL, *read_only = NULL;
                                ExecDirectoryFlags exec_directory_flags = 0;
                                const char *p;

                                /* Use EXTRACT_UNESCAPE_RELAX here, as we unescape the colons in subsequent calls */
                                r = extract_first_word(&val, &tuple, WHITESPACE, EXTRACT_UNESCAPE_SEPARATORS|EXTRACT_UNESCAPE_RELAX);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = tuple;
                                r = extract_many_words(&p, ":", EXTRACT_UNESCAPE_SEPARATORS, &path, &only_create, &read_only);
                                if (r < 0)
                                        return r;
                                if (r < 2)
                                        continue;

                                r = parse_boolean(only_create);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        exec_directory_flags |= EXEC_DIRECTORY_ONLY_CREATE;

                                r = parse_boolean(read_only);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        exec_directory_flags |= EXEC_DIRECTORY_READ_ONLY;

                                r = exec_directory_add(&c->directories[dt], path, /* symlink= */ NULL, exec_directory_flags);
                                if (r < 0)
                                        return r;

                                if (isempty(p))
                                        continue;

                                for (;;) {
                                        _cleanup_free_ char *link = NULL;

                                        r = extract_first_word(&p, &link, ":", EXTRACT_UNESCAPE_SEPARATORS);
                                        if (r < 0)
                                                return r;
                                        if (r == 0)
                                                break;

                                        r = strv_consume(&c->directories[dt].items[c->directories[dt].n_items - 1].symlinks, TAKE_PTR(link));
                                        if (r < 0)
                                                return r;
                                }
                        }
                } else if ((val = startswith(l, "exec-context-quota-accounting-directories-"))) {
                        _cleanup_free_ char *type = NULL, *quota_accounting = NULL;
                        ExecDirectoryType dt;

                        r = split_pair(val, "=", &type, &quota_accounting);
                        if (r < 0)
                                return r;

                        dt = exec_directory_type_from_string(type);
                        if (dt < 0)
                                return dt;

                        r = parse_boolean(quota_accounting);
                        if (r < 0)
                                return r;

                        c->directories[dt].exec_quota.quota_accounting = r;
                } else if ((val = startswith(l, "exec-context-quota-directories-"))) {
                        _cleanup_free_ char *type = NULL, *quota_info = NULL, *quota_absolute = NULL, *quota_scale = NULL;
                        ExecDirectoryType dt;

                        r = split_pair(val, "=", &type, &quota_info);
                        if (r < 0)
                                return r;

                        r = split_pair(quota_info, " ", &quota_absolute, &quota_scale);
                        if (r < 0)
                                return r;

                        dt = exec_directory_type_from_string(type);
                        if (dt < 0)
                                return dt;

                        r = safe_atou64(quota_absolute, &c->directories[dt].exec_quota.quota_absolute);
                        if (r < 0)
                               return r;

                        r = safe_atou32(quota_scale, &c->directories[dt].exec_quota.quota_scale);
                        if (r < 0)
                               return r;

                        c->directories[dt].exec_quota.quota_enforce = true;
                } else if ((val = startswith(l, "exec-context-timeout-clean-usec="))) {
                        r = deserialize_usec(val, &c->timeout_clean_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-nice="))) {
                        r = safe_atoi(val, &c->nice);
                        if (r < 0)
                                return r;
                        c->nice_set = true;
                } else if ((val = startswith(l, "exec-context-working-directory-missing-ok="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->working_directory_missing_ok = r;
                } else if ((val = startswith(l, "exec-context-working-directory-home="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->working_directory_home = r;
                } else if ((val = startswith(l, "exec-context-oom-score-adjust="))) {
                        r = safe_atoi(val, &c->oom_score_adjust);
                        if (r < 0)
                                return r;
                        c->oom_score_adjust_set = true;
                } else if ((val = startswith(l, "exec-context-coredump-filter="))) {
                        r = safe_atoux64(val, &c->coredump_filter);
                        if (r < 0)
                                return r;
                        c->coredump_filter_set = true;
                } else if ((val = startswith(l, "exec-context-limit-"))) {
                        _cleanup_free_ struct rlimit *rlimit = NULL;
                        _cleanup_free_ char *limit = NULL;
                        int type;

                        r = extract_first_word(&val, &limit, "=", 0);
                        if (r < 0)
                                return r;
                        if (r == 0 || !val)
                                return -EINVAL;

                        type = rlimit_from_string(limit);
                        if (type < 0)
                                return -EINVAL;

                        if (!c->rlimit[type]) {
                                rlimit = new0(struct rlimit, 1);
                                if (!rlimit)
                                        return log_oom_debug();

                                r = rlimit_parse(type, val, rlimit);
                                if (r < 0)
                                        return r;

                                c->rlimit[type] = TAKE_PTR(rlimit);
                        } else {
                                r = rlimit_parse(type, val, c->rlimit[type]);
                                if (r < 0)
                                        return r;
                        }
                } else if ((val = startswith(l, "exec-context-ioprio="))) {
                        r = safe_atoi(val, &c->ioprio);
                        if (r < 0)
                                return r;
                        c->ioprio_is_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-scheduling-policy="))) {
                        c->cpu_sched_policy = sched_policy_from_string(val);
                        if (c->cpu_sched_policy < 0)
                                return -EINVAL;
                        c->cpu_sched_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-scheduling-priority="))) {
                        r = safe_atoi(val, &c->cpu_sched_priority);
                        if (r < 0)
                                return r;
                        c->cpu_sched_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-scheduling-reset-on-fork="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->cpu_sched_reset_on_fork = r;
                        c->cpu_sched_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-affinity="))) {
                        if (c->cpu_set.set)
                                return -EINVAL; /* duplicated */

                        r = parse_cpu_set(val, &c->cpu_set);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-numa-mask="))) {
                        if (c->numa_policy.nodes.set)
                                return -EINVAL; /* duplicated */

                        r = parse_cpu_set(val, &c->numa_policy.nodes);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-numa-policy="))) {
                        r = safe_atoi(val, &c->numa_policy.type);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-cpu-affinity-from-numa="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->cpu_affinity_from_numa = r;
                } else if ((val = startswith(l, "exec-context-timer-slack-nsec="))) {
                        r = deserialize_usec(val, (usec_t *)&c->timer_slack_nsec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-input="))) {
                        c->std_input = exec_input_from_string(val);
                        if (c->std_input < 0)
                                return c->std_input;
                } else if ((val = startswith(l, "exec-context-std-output="))) {
                        c->std_output = exec_output_from_string(val);
                        if (c->std_output < 0)
                                return c->std_output;
                } else if ((val = startswith(l, "exec-context-std-error="))) {
                        c->std_error = exec_output_from_string(val);
                        if (c->std_error < 0)
                                return c->std_error;
                } else if ((val = startswith(l, "exec-context-stdio-as-fds="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->stdio_as_fds = r;
                } else if ((val = startswith(l, "exec-context-std-input-fd-name="))) {
                        r = free_and_strdup(&c->stdio_fdname[STDIN_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-fd-name="))) {
                        r = free_and_strdup(&c->stdio_fdname[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-fd-name="))) {
                        r = free_and_strdup(&c->stdio_fdname[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-input-file="))) {
                        r = free_and_strdup(&c->stdio_file[STDIN_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-file="))) {
                        r = free_and_strdup(&c->stdio_file[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-file-append="))) {
                        r = free_and_strdup(&c->stdio_file[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-file-truncate="))) {
                        r = free_and_strdup(&c->stdio_file[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-file="))) {
                        r = free_and_strdup(&c->stdio_file[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-file-append="))) {
                        r = free_and_strdup(&c->stdio_file[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-file-truncate="))) {
                        r = free_and_strdup(&c->stdio_file[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-stdin-data="))) {
                        if (c->stdin_data)
                                return -EINVAL; /* duplicated */

                        r = unbase64mem(val, &c->stdin_data, &c->stdin_data_size);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-tty-path="))) {
                        r = free_and_strdup(&c->tty_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-tty-reset="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tty_reset = r;
                } else if ((val = startswith(l, "exec-context-tty-vhangup="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tty_vhangup = r;
                } else if ((val = startswith(l, "exec-context-tty-vt-disallocate="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tty_vt_disallocate = r;
                } else if ((val = startswith(l, "exec-context-tty-rows="))) {
                        r = safe_atou(val, &c->tty_rows);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-tty-columns="))) {
                        r = safe_atou(val, &c->tty_cols);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syslog-priority="))) {
                        r = safe_atoi(val, &c->syslog_priority);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syslog-level-prefix="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->syslog_level_prefix = r;
                } else if ((val = startswith(l, "exec-context-syslog-identifier="))) {
                        r = free_and_strdup(&c->syslog_identifier, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-level-max="))) {
                        /* See comment in serialization. */
                        r = safe_atoi(val, &c->log_level_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-ratelimit-interval-usec="))) {
                        r = deserialize_usec(val, &c->log_ratelimit.interval);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-ratelimit-burst="))) {
                        r = safe_atou(val, &c->log_ratelimit.burst);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-filter-allowed-patterns="))) {
                        r = set_put_strdup(&c->log_filter_allowed_patterns, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-filter-denied-patterns="))) {
                        r = set_put_strdup(&c->log_filter_denied_patterns, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-extra-fields="))) {
                        if (!GREEDY_REALLOC(c->log_extra_fields, c->n_log_extra_fields + 1))
                                return log_oom_debug();

                        c->log_extra_fields[c->n_log_extra_fields++].iov_base = strdup(val);
                        if (!c->log_extra_fields[c->n_log_extra_fields-1].iov_base)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-context-log-namespace="))) {
                        r = free_and_strdup(&c->log_namespace, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-secure-bits="))) {
                        r = safe_atoi(val, &c->secure_bits);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-capability-bounding-set="))) {
                        r = safe_atou64(val, &c->capability_bounding_set);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-capability-ambient-set="))) {
                        r = safe_atou64(val, &c->capability_ambient_set);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-user="))) {
                        r = free_and_strdup(&c->user, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-group="))) {
                        r = free_and_strdup(&c->group, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-dynamic-user="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->dynamic_user = r;
                } else if ((val = startswith(l, "exec-context-supplementary-groups="))) {
                        r = deserialize_strv(val, &c->supplementary_groups);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-set-login-environment="))) {
                        r = safe_atoi(val, &c->set_login_environment);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-pam-name="))) {
                        r = free_and_strdup(&c->pam_name, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-read-write-paths="))) {
                        r = deserialize_strv(val, &c->read_write_paths);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-read-only-paths="))) {
                        r = deserialize_strv(val, &c->read_only_paths);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-inaccessible-paths="))) {
                        r = deserialize_strv(val, &c->inaccessible_paths);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-exec-paths="))) {
                        r = deserialize_strv(val, &c->exec_paths);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-no-exec-paths="))) {
                        r = deserialize_strv(val, &c->no_exec_paths);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-exec-search-path="))) {
                        r = deserialize_strv(val, &c->exec_search_path);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-mount-propagation-flag="))) {
                        r = safe_atolu(val, &c->mount_propagation_flag);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-bind-read-only-path="))) {
                        _cleanup_free_ char *source = NULL, *destination = NULL;
                        bool rbind = true, ignore_enoent = false;
                        char *s = NULL, *d = NULL;

                        r = extract_first_word(&val,
                                               &source,
                                               ":" WHITESPACE,
                                               EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        s = source;
                        if (s[0] == '-') {
                                ignore_enoent = true;
                                s++;
                        }

                        if (val && val[-1] == ':') {
                                r = extract_first_word(&val,
                                                       &destination,
                                                       ":" WHITESPACE,
                                                       EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                d = destination;

                                if (val && val[-1] == ':') {
                                        _cleanup_free_ char *options = NULL;

                                        r = extract_first_word(&val, &options, NULL, EXTRACT_UNQUOTE);
                                        if (r < 0)
                                                return -r;

                                        if (isempty(options) || streq(options, "rbind"))
                                                rbind = true;
                                        else if (streq(options, "norbind"))
                                                rbind = false;
                                        else
                                                continue;
                                }
                        } else
                                d = s;

                        r = bind_mount_add(&c->bind_mounts, &c->n_bind_mounts,
                                        &(BindMount) {
                                                .source = s,
                                                .destination = d,
                                                .read_only = true,
                                                .recursive = rbind,
                                                .ignore_enoent = ignore_enoent,
                                        });
                        if (r < 0)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-context-bind-path="))) {
                        _cleanup_free_ char *source = NULL, *destination = NULL;
                        bool rbind = true, ignore_enoent = false;
                        char *s = NULL, *d = NULL;

                        r = extract_first_word(&val,
                                               &source,
                                               ":" WHITESPACE,
                                               EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        s = source;
                        if (s[0] == '-') {
                                ignore_enoent = true;
                                s++;
                        }

                        if (val && val[-1] == ':') {
                                r = extract_first_word(&val,
                                                       &destination,
                                                       ":" WHITESPACE,
                                                       EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                d = destination;

                                if (val && val[-1] == ':') {
                                        _cleanup_free_ char *options = NULL;

                                        r = extract_first_word(&val, &options, NULL, EXTRACT_UNQUOTE);
                                        if (r < 0)
                                                return -r;

                                        if (isempty(options) || streq(options, "rbind"))
                                                rbind = true;
                                        else if (streq(options, "norbind"))
                                                rbind = false;
                                        else
                                                continue;
                                }
                        } else
                                d = s;

                        r = bind_mount_add(&c->bind_mounts, &c->n_bind_mounts,
                                        &(BindMount) {
                                                .source = s,
                                                .destination = d,
                                                .read_only = false,
                                                .recursive = rbind,
                                                .ignore_enoent = ignore_enoent,
                                        });
                        if (r < 0)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-context-temporary-filesystems="))) {
                        _cleanup_free_ char *path = NULL, *options = NULL;

                        r = extract_many_words(&val, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &path, &options);
                        if (r < 0)
                                return r;
                        if (r < 1)
                                continue;

                        r = temporary_filesystem_add(&c->temporary_filesystems, &c->n_temporary_filesystems, path, options);
                        if (r < 0)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-context-utmp-id="))) {
                        r = free_and_strdup(&c->utmp_id, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-utmp-mode="))) {
                        c->utmp_mode = exec_utmp_mode_from_string(val);
                        if (c->utmp_mode < 0)
                                return c->utmp_mode;
                } else if ((val = startswith(l, "exec-context-no-new-privileges="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->no_new_privileges = r;
                } else if ((val = startswith(l, "exec-context-selinux-context="))) {
                        if (val[0] == '-') {
                                c->selinux_context_ignore = true;
                                val++;
                        } else
                                c->selinux_context_ignore = false;

                        r = free_and_strdup(&c->selinux_context, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-apparmor-profile="))) {
                        if (val[0] == '-') {
                                c->apparmor_profile_ignore = true;
                                val++;
                        } else
                                c->apparmor_profile_ignore = false;

                        r = free_and_strdup(&c->apparmor_profile, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-smack-process-label="))) {
                        if (val[0] == '-') {
                                c->smack_process_label_ignore = true;
                                val++;
                        } else
                                c->smack_process_label_ignore = false;

                        r = free_and_strdup(&c->smack_process_label, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-personality="))) {
                        c->personality = personality_from_string(val);
                        if (c->personality == PERSONALITY_INVALID)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-lock-personality="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->lock_personality = r;
#if HAVE_SECCOMP
                } else if ((val = startswith(l, "exec-context-syscall-filter="))) {
                        _cleanup_free_ char *s_id = NULL, *s_errno_num = NULL;
                        int id, errno_num;

                        r = extract_many_words(&val, NULL, 0, &s_id, &s_errno_num);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        r = safe_atoi(s_id, &id);
                        if (r < 0)
                                return r;

                        r = safe_atoi(s_errno_num, &errno_num);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&c->syscall_filter, NULL, INT_TO_PTR(id + 1), INT_TO_PTR(errno_num));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-archs="))) {
                        unsigned id;

                        r = safe_atou(val, &id);
                        if (r < 0)
                                return r;

                        r = set_ensure_put(&c->syscall_archs, NULL, UINT_TO_PTR(id + 1));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-errno="))) {
                        r = safe_atoi(val, &c->syscall_errno);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->syscall_allow_list = r;
                } else if ((val = startswith(l, "exec-context-syscall-log="))) {
                        _cleanup_free_ char *s_id = NULL, *s_errno_num = NULL;
                        int id, errno_num;

                        r = extract_many_words(&val, " ", 0, &s_id, &s_errno_num);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        r = safe_atoi(s_id, &id);
                        if (r < 0)
                                return r;

                        r = safe_atoi(s_errno_num, &errno_num);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&c->syscall_log, NULL, INT_TO_PTR(id + 1), INT_TO_PTR(errno_num));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-log-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->syscall_log_allow_list = r;
#endif
                } else if ((val = startswith(l, "exec-context-restrict-namespaces="))) {
                        r = safe_atolu(val, &c->restrict_namespaces);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-delegate-namespaces="))) {
                        r = safe_atolu(val, &c->delegate_namespaces);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-restrict-filesystems="))) {
                        r = set_put_strdup(&c->restrict_filesystems, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-restrict-filesystems-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_filesystems_allow_list = r;
                } else if ((val = startswith(l, "exec-context-address-families="))) {
                        int af;

                        r = safe_atoi(val, &af);
                        if (r < 0)
                                return r;

                        r = set_ensure_put(&c->address_families, NULL, INT_TO_PTR(af));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-address-families-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->address_families_allow_list = r;
                } else if ((val = startswith(l, "exec-context-network-namespace-path="))) {
                        r = free_and_strdup(&c->network_namespace_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-ipc-namespace-path="))) {
                        r = free_and_strdup(&c->ipc_namespace_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-mount-image="))) {
                        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
                        _cleanup_free_ char *source = NULL, *destination = NULL;
                        bool permissive = false;
                        char *s;

                        r = extract_many_words(&val,
                                               NULL,
                                               EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS,
                                               &source,
                                               &destination);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        s = source;
                        if (s[0] == '-') {
                                permissive = true;
                                s++;
                        }

                        if (isempty(destination))
                                continue;

                        for (;;) {
                                _cleanup_free_ char *tuple = NULL, *partition = NULL, *opts = NULL;
                                PartitionDesignator partition_designator;
                                MountOptions *o = NULL;
                                const char *p;

                                r = extract_first_word(&val, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = tuple;
                                r = extract_many_words(&p,
                                                       ":",
                                                       EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS,
                                                       &partition,
                                                       &opts);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;
                                if (r == 1) {
                                        o = new(MountOptions, 1);
                                        if (!o)
                                                return log_oom_debug();
                                        *o = (MountOptions) {
                                                .partition_designator = PARTITION_ROOT,
                                                .options = TAKE_PTR(partition),
                                        };
                                        LIST_APPEND(mount_options, options, o);

                                        continue;
                                }

                                partition_designator = partition_designator_from_string(partition);
                                if (partition_designator < 0)
                                        continue;

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom_debug();
                                *o = (MountOptions) {
                                        .partition_designator = partition_designator,
                                        .options = TAKE_PTR(opts),
                                };
                                LIST_APPEND(mount_options, options, o);
                        }

                        r = mount_image_add(&c->mount_images, &c->n_mount_images,
                                        &(MountImage) {
                                                .source = s,
                                                .destination = destination,
                                                .mount_options = options,
                                                .ignore_enoent = permissive,
                                                .type = MOUNT_IMAGE_DISCRETE,
                                        });
                        if (r < 0)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-context-extension-image="))) {
                        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
                        _cleanup_free_ char *source = NULL;
                        bool permissive = false;
                        char *s;

                        r = extract_first_word(&val,
                                               &source,
                                               NULL,
                                               EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        s = source;
                        if (s[0] == '-') {
                                permissive = true;
                                s++;
                        }

                        for (;;) {
                                _cleanup_free_ char *tuple = NULL, *partition = NULL, *opts = NULL;
                                PartitionDesignator partition_designator;
                                MountOptions *o = NULL;
                                const char *p;

                                r = extract_first_word(&val, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = tuple;
                                r = extract_many_words(&p,
                                                       ":",
                                                       EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS,
                                                       &partition,
                                                       &opts);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;
                                if (r == 1) {
                                        o = new(MountOptions, 1);
                                        if (!o)
                                                return log_oom_debug();
                                        *o = (MountOptions) {
                                                .partition_designator = PARTITION_ROOT,
                                                .options = TAKE_PTR(partition),
                                        };
                                        LIST_APPEND(mount_options, options, o);

                                        continue;
                                }

                                partition_designator = partition_designator_from_string(partition);
                                if (partition_designator < 0)
                                        continue;

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom_debug();
                                *o = (MountOptions) {
                                        .partition_designator = partition_designator,
                                        .options = TAKE_PTR(opts),
                                };
                                LIST_APPEND(mount_options, options, o);
                        }

                        r = mount_image_add(&c->extension_images, &c->n_extension_images,
                                        &(MountImage) {
                                                .source = s,
                                                .mount_options = options,
                                                .ignore_enoent = permissive,
                                                .type = MOUNT_IMAGE_EXTENSION,
                                        });
                        if (r < 0)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-context-extension-directories="))) {
                        r = deserialize_strv(val, &c->extension_directories);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-set-credentials="))) {
                        _cleanup_free_ char *id = NULL, *data = NULL, *encrypted = NULL;

                        r = extract_many_words(&val, " ", EXTRACT_DONT_COALESCE_SEPARATORS, &id, &data, &encrypted);
                        if (r < 0)
                                return r;
                        if (r != 3)
                                return -EINVAL;

                        r = parse_boolean(encrypted);
                        if (r < 0)
                                return r;
                        bool e = r;

                        _cleanup_free_ void *d = NULL;
                        size_t size;

                        r = unbase64mem_full(data, SIZE_MAX, /* secure = */ true, &d, &size);
                        if (r < 0)
                                return r;

                        r = exec_context_put_set_credential(c, id, TAKE_PTR(d), size, e);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-load-credentials="))) {
                        _cleanup_free_ char *id = NULL, *path = NULL, *encrypted = NULL;

                        r = extract_many_words(&val, " ", EXTRACT_DONT_COALESCE_SEPARATORS, &id, &path, &encrypted);
                        if (r < 0)
                                return r;
                        if (r != 3)
                                return -EINVAL;

                        r = parse_boolean(encrypted);
                        if (r < 0)
                                return r;

                        r = exec_context_put_load_credential(c, id, path, r > 0);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-import-credentials="))) {
                        _cleanup_free_ char *glob = NULL, *rename = NULL;

                        r = extract_many_words(&val, " ", EXTRACT_DONT_COALESCE_SEPARATORS, &glob, &rename);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        r = exec_context_put_import_credential(c, glob, rename);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-image-policy="))) {
                        if (c->root_image_policy)
                                return -EINVAL; /* duplicated */

                        r = image_policy_from_string(val, /* graceful= */ true, &c->root_image_policy);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-mount-image-policy="))) {
                        if (c->mount_image_policy)
                                return -EINVAL; /* duplicated */

                        r = image_policy_from_string(val, /* graceful= */ true, &c->mount_image_policy);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-extension-image-policy="))) {
                        if (c->extension_image_policy)
                                return -EINVAL; /* duplicated */

                        r = image_policy_from_string(val, /* graceful= */ true, &c->extension_image_policy);
                        if (r < 0)
                                return r;
                } else
                        log_warning("Failed to parse serialized line, ignoring: %s", l);
        }

        return 0;
}

static int exec_command_serialize(const ExecCommand *c, FILE *f) {
        int r;

        assert(c);
        assert(f);

        r = serialize_item(f, "exec-command-path", c->path);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-command-argv", c->argv);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-command-flags", "%d", (int) c->flags);
        if (r < 0)
                return r;

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_command_deserialize(ExecCommand *c, FILE *f) {
        int r;

        assert(c);
        assert(f);

        for (;;) {
                _cleanup_free_ char *l = NULL;
                const char *val;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                if ((val = startswith(l, "exec-command-path="))) {
                        r = free_and_strdup(&c->path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-command-argv="))) {
                        r = deserialize_strv(val, &c->argv);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-command-flags="))) {
                        r = safe_atoi(val, &c->flags);
                        if (r < 0)
                                return r;
                } else
                        log_warning("Failed to parse serialized line, ignoring: %s", l);

        }

        return 0;
}

int exec_serialize_invocation(
                FILE *f,
                FDSet *fds,
                const ExecContext *ctx,
                const ExecCommand *cmd,
                const ExecParameters *p,
                const ExecRuntime *rt,
                const CGroupContext *cg) {

        int r;

        assert(f);
        assert(fds);

        r = exec_context_serialize(ctx, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize context: %m");

        r = exec_command_serialize(cmd, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize command: %m");

        r = exec_parameters_serialize(p, ctx, f, fds);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize parameters: %m");

        r = exec_runtime_serialize(rt, f, fds);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize runtime: %m");

        r = exec_cgroup_context_serialize(cg, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize cgroup context: %m");

        return 0;
}

int exec_deserialize_invocation(
                FILE *f,
                FDSet *fds,
                ExecContext *ctx,
                ExecCommand *cmd,
                ExecParameters *p,
                ExecRuntime *rt,
                CGroupContext *cg) {

        int r;

        assert(f);
        assert(fds);

        r = exec_context_deserialize(ctx, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize context: %m");

        r = exec_command_deserialize(cmd, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize command: %m");

        r = exec_parameters_deserialize(p, f, fds);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize parameters: %m");

        r = exec_runtime_deserialize(rt, f, fds);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize runtime: %m");

        r = exec_cgroup_context_deserialize(cg, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize cgroup context: %m");

        return 0;
}
