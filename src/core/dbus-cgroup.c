/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>

#include "af-list.h"
#include "alloc-util.h"
#include "bpf-firewall.h"
#include "bpf-foreign.h"
#include "bus-get-properties.h"
#include "bus-message-util.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "cgroup.h"
#include "core-varlink.h"
#include "dbus-cgroup.h"
#include "dbus-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "firewall-util.h"
#include "in-addr-prefix-util.h"
#include "ip-protocol-list.h"
#include "limits-util.h"
#include "memstream-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "socket-util.h"

BUS_DEFINE_PROPERTY_GET(bus_property_get_tasks_max, "t", CGroupTasksMax, cgroup_tasks_max_resolve);
BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_cgroup_pressure_watch, cgroup_pressure_watch, CGroupPressureWatch);

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_cgroup_device_policy, cgroup_device_policy, CGroupDevicePolicy);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_managed_oom_mode, managed_oom_mode, ManagedOOMMode);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_managed_oom_preference, managed_oom_preference, ManagedOOMPreference);

static int property_get_cgroup_mask(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupMask *mask = userdata;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        for (CGroupController ctrl = 0; ctrl < _CGROUP_CONTROLLER_MAX; ctrl++) {
                if ((*mask & CGROUP_CONTROLLER_TO_MASK(ctrl)) == 0)
                        continue;

                r = sd_bus_message_append(reply, "s", cgroup_controller_to_string(ctrl));
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_delegate_controllers(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        if (!c->delegate)
                return sd_bus_message_append(reply, "as", 0);

        return property_get_cgroup_mask(bus, path, interface, property, reply, &c->delegate_controllers, error);
}

static int property_get_cpuset(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CPUSet *cpus = ASSERT_PTR(userdata);
        _cleanup_free_ uint8_t *array = NULL;
        size_t allocated;

        assert(bus);
        assert(reply);

        (void) cpu_set_to_dbus(cpus, &array, &allocated);
        return sd_bus_message_append_array(reply, 'y', array, allocated);
}

static int property_get_io_device_weight(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(st)");
        if (r < 0)
                return r;

        LIST_FOREACH(device_weights, w, c->io_device_weights) {
                r = sd_bus_message_append(reply, "(st)", w->path, w->weight);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_io_device_limits(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(st)");
        if (r < 0)
                return r;

        LIST_FOREACH(device_limits, l, c->io_device_limits) {
                CGroupIOLimitType type;

                type = cgroup_io_limit_type_from_string(property);
                if (type < 0 || l->limits[type] == cgroup_io_limit_defaults[type])
                        continue;

                r = sd_bus_message_append(reply, "(st)", l->path, l->limits[type]);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_io_device_latency(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(st)");
        if (r < 0)
                return r;

        LIST_FOREACH(device_latencies, l, c->io_device_latencies) {
                r = sd_bus_message_append(reply, "(st)", l->path, l->target_usec);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_blockio_device_weight(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(st)");
        if (r < 0)
                return r;

        LIST_FOREACH(device_weights, w, c->blockio_device_weights) {
                r = sd_bus_message_append(reply, "(st)", w->path, w->weight);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_blockio_device_bandwidths(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(st)");
        if (r < 0)
                return r;

        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                uint64_t v;

                if (streq(property, "BlockIOReadBandwidth"))
                        v = b->rbps;
                else
                        v = b->wbps;

                if (v == CGROUP_LIMIT_MAX)
                        continue;

                r = sd_bus_message_append(reply, "(st)", b->path, v);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_device_allow(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        LIST_FOREACH(device_allow, a, c->device_allow) {
                r = sd_bus_message_append(reply, "(ss)", a->path, cgroup_device_permissions_to_string(a->permissions));
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_ip_address_access(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Set **prefixes = ASSERT_PTR(userdata);
        struct in_addr_prefix *i;
        int r;

        r = sd_bus_message_open_container(reply, 'a', "(iayu)");
        if (r < 0)
                return r;

        SET_FOREACH(i, *prefixes) {

                r = sd_bus_message_open_container(reply, 'r', "iayu");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "i", i->family);
                if (r < 0)
                        return r;

                r = sd_bus_message_append_array(reply, 'y', &i->address, FAMILY_ADDRESS_SIZE(i->family));
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "u", (uint32_t) i->prefixlen);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_bpf_foreign_program(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        CGroupContext *c = userdata;
        int r;

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        LIST_FOREACH(programs, p, c->bpf_foreign_programs) {
                const char *attach_type = bpf_cgroup_attach_type_to_string(p->attach_type);

                r = sd_bus_message_append(reply, "(ss)", attach_type, p->bpffs_path);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_socket_bind(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupSocketBindItem **items = ASSERT_PTR(userdata);
        int r;

        r = sd_bus_message_open_container(reply, 'a', "(iiqq)");
        if (r < 0)
                return r;

        LIST_FOREACH(socket_bind_items, i, *items) {
                r = sd_bus_message_append(reply, "(iiqq)", i->address_family, i->ip_protocol, i->nr_ports, i->port_min);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_restrict_network_interfaces(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'r', "bas");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "b", c->restrict_network_interfaces_is_allow_list);
        if (r < 0)
                return r;

        r = bus_message_append_string_set(reply, c->restrict_network_interfaces);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

static int property_get_cgroup_nft_set(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        int r;
        CGroupContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        r = sd_bus_message_open_container(reply, 'a', "(iiss)");
        if (r < 0)
                return r;

        FOREACH_ARRAY(nft_set, c->nft_set_context.sets, c->nft_set_context.n_sets) {
                r = sd_bus_message_append(reply, "(iiss)", nft_set->source, nft_set->nfproto, nft_set->table, nft_set->set);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

const sd_bus_vtable bus_cgroup_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Delegate", "b", bus_property_get_bool, offsetof(CGroupContext, delegate), 0),
        SD_BUS_PROPERTY("DelegateControllers", "as", property_get_delegate_controllers, 0, 0),
        SD_BUS_PROPERTY("DelegateSubgroup", "s", NULL, offsetof(CGroupContext, delegate_subgroup), 0),
        SD_BUS_PROPERTY("CPUAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, cpu_accounting), 0),
        SD_BUS_PROPERTY("CPUWeight", "t", NULL, offsetof(CGroupContext, cpu_weight), 0),
        SD_BUS_PROPERTY("StartupCPUWeight", "t", NULL, offsetof(CGroupContext, startup_cpu_weight), 0),
        SD_BUS_PROPERTY("CPUShares", "t", NULL, offsetof(CGroupContext, cpu_shares), 0),
        SD_BUS_PROPERTY("StartupCPUShares", "t", NULL, offsetof(CGroupContext, startup_cpu_shares), 0),
        SD_BUS_PROPERTY("CPUQuotaPerSecUSec", "t", bus_property_get_usec, offsetof(CGroupContext, cpu_quota_per_sec_usec), 0),
        SD_BUS_PROPERTY("CPUQuotaPeriodUSec", "t", bus_property_get_usec, offsetof(CGroupContext, cpu_quota_period_usec), 0),
        SD_BUS_PROPERTY("AllowedCPUs", "ay", property_get_cpuset, offsetof(CGroupContext, cpuset_cpus), 0),
        SD_BUS_PROPERTY("StartupAllowedCPUs", "ay", property_get_cpuset, offsetof(CGroupContext, startup_cpuset_cpus), 0),
        SD_BUS_PROPERTY("AllowedMemoryNodes", "ay", property_get_cpuset, offsetof(CGroupContext, cpuset_mems), 0),
        SD_BUS_PROPERTY("StartupAllowedMemoryNodes", "ay", property_get_cpuset, offsetof(CGroupContext, startup_cpuset_mems), 0),
        SD_BUS_PROPERTY("IOAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, io_accounting), 0),
        SD_BUS_PROPERTY("IOWeight", "t", NULL, offsetof(CGroupContext, io_weight), 0),
        SD_BUS_PROPERTY("StartupIOWeight", "t", NULL, offsetof(CGroupContext, startup_io_weight), 0),
        SD_BUS_PROPERTY("IODeviceWeight", "a(st)", property_get_io_device_weight, 0, 0),
        SD_BUS_PROPERTY("IOReadBandwidthMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("IOWriteBandwidthMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("IOReadIOPSMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("IOWriteIOPSMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("IODeviceLatencyTargetUSec", "a(st)", property_get_io_device_latency, 0, 0),
        SD_BUS_PROPERTY("BlockIOAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, blockio_accounting), 0),
        SD_BUS_PROPERTY("BlockIOWeight", "t", NULL, offsetof(CGroupContext, blockio_weight), 0),
        SD_BUS_PROPERTY("StartupBlockIOWeight", "t", NULL, offsetof(CGroupContext, startup_blockio_weight), 0),
        SD_BUS_PROPERTY("BlockIODeviceWeight", "a(st)", property_get_blockio_device_weight, 0, 0),
        SD_BUS_PROPERTY("BlockIOReadBandwidth", "a(st)", property_get_blockio_device_bandwidths, 0, 0),
        SD_BUS_PROPERTY("BlockIOWriteBandwidth", "a(st)", property_get_blockio_device_bandwidths, 0, 0),
        SD_BUS_PROPERTY("MemoryAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, memory_accounting), 0),
        SD_BUS_PROPERTY("DefaultMemoryLow", "t", NULL, offsetof(CGroupContext, default_memory_low), 0),
        SD_BUS_PROPERTY("DefaultStartupMemoryLow", "t", NULL, offsetof(CGroupContext, default_startup_memory_low), 0),
        SD_BUS_PROPERTY("DefaultMemoryMin", "t", NULL, offsetof(CGroupContext, default_memory_min), 0),
        SD_BUS_PROPERTY("MemoryMin", "t", NULL, offsetof(CGroupContext, memory_min), 0),
        SD_BUS_PROPERTY("MemoryLow", "t", NULL, offsetof(CGroupContext, memory_low), 0),
        SD_BUS_PROPERTY("StartupMemoryLow", "t", NULL, offsetof(CGroupContext, startup_memory_low), 0),
        SD_BUS_PROPERTY("MemoryHigh", "t", NULL, offsetof(CGroupContext, memory_high), 0),
        SD_BUS_PROPERTY("StartupMemoryHigh", "t", NULL, offsetof(CGroupContext, startup_memory_high), 0),
        SD_BUS_PROPERTY("MemoryMax", "t", NULL, offsetof(CGroupContext, memory_max), 0),
        SD_BUS_PROPERTY("StartupMemoryMax", "t", NULL, offsetof(CGroupContext, startup_memory_max), 0),
        SD_BUS_PROPERTY("MemorySwapMax", "t", NULL, offsetof(CGroupContext, memory_swap_max), 0),
        SD_BUS_PROPERTY("StartupMemorySwapMax", "t", NULL, offsetof(CGroupContext, startup_memory_swap_max), 0),
        SD_BUS_PROPERTY("MemoryZSwapMax", "t", NULL, offsetof(CGroupContext, memory_zswap_max), 0),
        SD_BUS_PROPERTY("StartupMemoryZSwapMax", "t", NULL, offsetof(CGroupContext, startup_memory_zswap_max), 0),
        SD_BUS_PROPERTY("MemoryZSwapWriteback", "b", bus_property_get_bool, offsetof(CGroupContext, memory_zswap_writeback), 0),
        SD_BUS_PROPERTY("MemoryLimit", "t", NULL, offsetof(CGroupContext, memory_limit), 0),
        SD_BUS_PROPERTY("DevicePolicy", "s", property_get_cgroup_device_policy, offsetof(CGroupContext, device_policy), 0),
        SD_BUS_PROPERTY("DeviceAllow", "a(ss)", property_get_device_allow, 0, 0),
        SD_BUS_PROPERTY("TasksAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, tasks_accounting), 0),
        SD_BUS_PROPERTY("TasksMax", "t", bus_property_get_tasks_max, offsetof(CGroupContext, tasks_max), 0),
        SD_BUS_PROPERTY("IPAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, ip_accounting), 0),
        SD_BUS_PROPERTY("IPAddressAllow", "a(iayu)", property_get_ip_address_access, offsetof(CGroupContext, ip_address_allow), 0),
        SD_BUS_PROPERTY("IPAddressDeny", "a(iayu)", property_get_ip_address_access, offsetof(CGroupContext, ip_address_deny), 0),
        SD_BUS_PROPERTY("IPIngressFilterPath", "as", NULL, offsetof(CGroupContext, ip_filters_ingress), 0),
        SD_BUS_PROPERTY("IPEgressFilterPath", "as", NULL, offsetof(CGroupContext, ip_filters_egress), 0),
        SD_BUS_PROPERTY("DisableControllers", "as", property_get_cgroup_mask, offsetof(CGroupContext, disable_controllers), 0),
        SD_BUS_PROPERTY("ManagedOOMSwap", "s", property_get_managed_oom_mode, offsetof(CGroupContext, moom_swap), 0),
        SD_BUS_PROPERTY("ManagedOOMMemoryPressure", "s", property_get_managed_oom_mode, offsetof(CGroupContext, moom_mem_pressure), 0),
        SD_BUS_PROPERTY("ManagedOOMMemoryPressureLimit", "u", NULL, offsetof(CGroupContext, moom_mem_pressure_limit), 0),
        SD_BUS_PROPERTY("ManagedOOMMemoryPressureDurationUSec", "t", bus_property_get_usec, offsetof(CGroupContext, moom_mem_pressure_duration_usec), 0),
        SD_BUS_PROPERTY("ManagedOOMPreference", "s", property_get_managed_oom_preference, offsetof(CGroupContext, moom_preference), 0),
        SD_BUS_PROPERTY("BPFProgram", "a(ss)", property_get_bpf_foreign_program, 0, 0),
        SD_BUS_PROPERTY("SocketBindAllow", "a(iiqq)", property_get_socket_bind, offsetof(CGroupContext, socket_bind_allow), 0),
        SD_BUS_PROPERTY("SocketBindDeny", "a(iiqq)", property_get_socket_bind, offsetof(CGroupContext, socket_bind_deny), 0),
        SD_BUS_PROPERTY("RestrictNetworkInterfaces", "(bas)", property_get_restrict_network_interfaces, 0, 0),
        SD_BUS_PROPERTY("MemoryPressureWatch", "s", bus_property_get_cgroup_pressure_watch, offsetof(CGroupContext, memory_pressure_watch), 0),
        SD_BUS_PROPERTY("MemoryPressureThresholdUSec", "t", bus_property_get_usec, offsetof(CGroupContext, memory_pressure_threshold_usec), 0),
        SD_BUS_PROPERTY("NFTSet", "a(iiss)", property_get_cgroup_nft_set, 0, 0),
        SD_BUS_PROPERTY("CoredumpReceive", "b", bus_property_get_bool, offsetof(CGroupContext, coredump_receive), 0),
        SD_BUS_VTABLE_END
};

static int bus_cgroup_set_transient_property(
                Unit *u,
                CGroupContext *c,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        int r;

        assert(u);
        assert(c);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "Delegate")) {
                int b;

                if (!UNIT_VTABLE(u)->can_delegate)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Delegation not available for unit type");

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->delegate = b;
                        c->delegate_controllers = b ? CGROUP_MASK_DELEGATE : 0;

                        unit_write_settingf(u, flags, name, "Delegate=%s", yes_no(b));
                }

                return 1;

        } else if (streq(name, "DelegateSubgroup")) {
                const char *s;

                if (!UNIT_VTABLE(u)->can_delegate)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Delegation not available for unit type");

                r = sd_bus_message_read(message, "s", &s);
                if (r < 0)
                        return r;

                if (!isempty(s) && cg_needs_escape(s))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid control group name: %s", s);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (isempty(s))
                                c->delegate_subgroup = mfree(c->delegate_subgroup);
                        else {
                                r = free_and_strdup_warn(&c->delegate_subgroup, s);
                                if (r < 0)
                                        return r;
                        }

                        unit_write_settingf(u, flags, name, "DelegateSubgroup=%s", s);
                }

                return 1;

        } else if (STR_IN_SET(name, "DelegateControllers", "DisableControllers")) {
                CGroupMask mask = 0;

                if (streq(name, "DelegateControllers") && !UNIT_VTABLE(u)->can_delegate)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Delegation not available for unit type");

                r = sd_bus_message_enter_container(message, 'a', "s");
                if (r < 0)
                        return r;

                for (;;) {
                        CGroupController cc;
                        const char *t;

                        r = sd_bus_message_read(message, "s", &t);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        cc = cgroup_controller_from_string(t);
                        if (cc < 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown cgroup controller '%s'", t);

                        mask |= CGROUP_CONTROLLER_TO_MASK(cc);
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *t = NULL;

                        r = cg_mask_to_string(mask, &t);
                        if (r < 0)
                                return r;

                        if (streq(name, "DelegateControllers")) {

                                c->delegate = true;
                                if (mask == 0)
                                        c->delegate_controllers = 0;
                                else
                                        c->delegate_controllers |= mask;

                                unit_write_settingf(u, flags, name, "Delegate=%s", strempty(t));

                        } else if (streq(name, "DisableControllers")) {

                                if (mask == 0)
                                        c->disable_controllers = 0;
                                else
                                        c->disable_controllers |= mask;

                                unit_write_settingf(u, flags, name, "%s=%s", name, strempty(t));
                        }
                }

                return 1;
        } else if (STR_IN_SET(name, "IPIngressFilterPath", "IPEgressFilterPath")) {
                char ***filters;
                size_t n = 0;

                filters = streq(name, "IPIngressFilterPath") ? &c->ip_filters_ingress : &c->ip_filters_egress;
                r = sd_bus_message_enter_container(message, 'a', "s");
                if (r < 0)
                        return r;

                for (;;) {
                        const char *path;

                        r = sd_bus_message_read(message, "s", &path);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        if (!path_is_normalized(path) || !path_is_absolute(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s= expects a normalized absolute path.", name);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags) && !strv_contains(*filters, path)) {
                                r = strv_extend(filters, path);
                                if (r < 0)
                                        return log_oom();
                        }
                        n++;
                }
                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                *filters = strv_free(*filters);

                        unit_invalidate_cgroup_bpf(u);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        fputs(name, f);
                        fputs("=\n", f);

                        STRV_FOREACH(entry, *filters)
                                fprintf(f, "%s=%s\n", name, *entry);

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);

                        if (*filters) {
                                r = bpf_firewall_supported();
                                if (r < 0)
                                        return r;
                                if (r != BPF_FIREWALL_SUPPORTED_WITH_MULTI) {
                                        static bool warned = false;

                                        log_full(warned ? LOG_DEBUG : LOG_WARNING,
                                                 "Transient unit %s configures an IP firewall with BPF, but the local system does not support BPF/cgroup firewalling with multiple filters.\n"
                                                 "Starting this unit will fail! (This warning is only shown for the first started transient unit using IP firewalling.)", u->id);
                                        warned = true;
                                }
                        }
                }

                return 1;
        } else if (streq(name, "BPFProgram")) {
                const char *a, *p;
                size_t n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(ss)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(ss)", &a, &p)) > 0) {
                        int attach_type = bpf_cgroup_attach_type_from_string(a);
                        if (attach_type < 0)
                                return sd_bus_error_setf(
                                                error,
                                                SD_BUS_ERROR_INVALID_ARGS,
                                                "%s expects a valid BPF attach type, got '%s'.",
                                                name, a);

                        if (!path_is_normalized(p) || !path_is_absolute(p))
                                return sd_bus_error_setf(
                                                error,
                                                SD_BUS_ERROR_INVALID_ARGS,
                                                "%s= expects a normalized absolute path.",
                                                name);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                r = cgroup_context_add_bpf_foreign_program(c, attach_type, p);
                                if (r < 0)
                                        return r;
                        }
                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                while (c->bpf_foreign_programs)
                                        cgroup_context_remove_bpf_foreign_program(c, c->bpf_foreign_programs);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        fputs(name, f);
                        fputs("=\n", f);

                        LIST_FOREACH(programs, fp, c->bpf_foreign_programs)
                                fprintf(f, "%s=%s:%s\n", name,
                                                bpf_cgroup_attach_type_to_string(fp->attach_type),
                                                fp->bpffs_path);

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);

                        if (c->bpf_foreign_programs) {
                                r = bpf_foreign_supported();
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        log_full(LOG_DEBUG,
                                                 "Transient unit %s configures a BPF program pinned to BPF "
                                                 "filesystem, but the local system does not support that.\n"
                                                 "Starting this unit will fail!", u->id);
                        }
                }

                return 1;

        } else if (streq(name, "MemoryPressureWatch")) {
                CGroupPressureWatch p;
                const char *t;

                r = sd_bus_message_read(message, "s", &t);
                if (r < 0)
                        return r;

                if (isempty(t))
                        p = _CGROUP_PRESSURE_WATCH_INVALID;
                else {
                        p = cgroup_pressure_watch_from_string(t);
                        if (p < 0)
                                return p;
                }

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->memory_pressure_watch = p;
                        unit_write_settingf(u, flags, name, "MemoryPressureWatch=%s", strempty(cgroup_pressure_watch_to_string(p)));
                }

                return 1;

        } else if (streq(name, "MemoryPressureThresholdUSec")) {
                uint64_t t;

                r = sd_bus_message_read(message, "t", &t);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->memory_pressure_threshold_usec = t;

                        if (t == UINT64_MAX)
                                unit_write_setting(u, flags, name, "MemoryPressureThresholdUSec=");
                        else
                                unit_write_settingf(u, flags, name, "MemoryPressureThresholdUSec=%" PRIu64, t);
                }

                return 1;
        } else if (streq(name, "CoredumpReceive")) {
                int b;

                if (!UNIT_VTABLE(u)->can_delegate)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Delegation not available for unit type");

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->coredump_receive = b;

                        unit_write_settingf(u, flags, name, "CoredumpReceive=%s", yes_no(b));
                }

                return 1;
        }

        return 0;
}

static int bus_cgroup_set_boolean(
                Unit *u,
                const char *name,
                bool *p,
                CGroupMask mask,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        int b, r;

        assert(p);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = b;
                unit_invalidate_cgroup(u, mask);
                unit_write_settingf(u, flags, name, "%s=%s", name, yes_no(b));
        }

        return 1;
}

#define BUS_DEFINE_SET_CGROUP_WEIGHT(function, mask, check, val)        \
        static int bus_cgroup_set_##function(                           \
                        Unit *u,                                        \
                        const char *name,                               \
                        uint64_t *p,                                    \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                uint64_t v;                                             \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "t", &v);              \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (!check(v))                                          \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Value specified in %s is out of range", name); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = v;                                         \
                        unit_invalidate_cgroup(u, mask);                \
                                                                        \
                        if (v == (val))                                 \
                                unit_write_settingf(u, flags, name,     \
                                                    "%s=", name);       \
                        else                                            \
                                unit_write_settingf(u, flags, name,     \
                                                    "%s=%" PRIu64, name, v); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }

#define BUS_DEFINE_SET_CGROUP_LIMIT(function, mask, scale, minimum)     \
        static int bus_cgroup_set_##function(                           \
                        Unit *u,                                        \
                        const char *name,                               \
                        uint64_t *p,                                    \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                uint64_t v;                                             \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "t", &v);              \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (v < minimum)                                        \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Value specified in %s is out of range", name); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = v;                                         \
                        unit_invalidate_cgroup(u, mask);                \
                                                                        \
                        if (v == CGROUP_LIMIT_MAX)                      \
                                unit_write_settingf(u, flags, name,     \
                                                    "%s=infinity", name); \
                        else                                            \
                                unit_write_settingf(u, flags, name,     \
                                                    "%s=%" PRIu64, name, v); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        static int bus_cgroup_set_##function##_scale(                   \
                        Unit *u,                                        \
                        const char *name,                               \
                        uint64_t *p,                                    \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                uint64_t v;                                             \
                uint32_t raw;                                           \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "u", &raw);            \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                v = scale(raw, UINT32_MAX);                             \
                if (v < minimum || v >= UINT64_MAX)                     \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Value specified in %s is out of range", name); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = v;                                         \
                        unit_invalidate_cgroup(u, mask);                \
                                                                        \
                        /* Prepare to chop off suffix */                \
                        assert_se(endswith(name, "Scale"));             \
                                                                        \
                        int scaled = UINT32_SCALE_TO_PERMYRIAD(raw);    \
                        unit_write_settingf(u, flags, name, "%.*s=" PERMYRIAD_AS_PERCENT_FORMAT_STR, \
                                            (int)(strlen(name) - strlen("Scale")), name, \
                                            PERMYRIAD_AS_PERCENT_FORMAT_VAL(scaled)); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }

DISABLE_WARNING_TYPE_LIMITS;
BUS_DEFINE_SET_CGROUP_WEIGHT(cpu_shares, CGROUP_MASK_CPU, CGROUP_CPU_SHARES_IS_OK, CGROUP_CPU_SHARES_INVALID);
BUS_DEFINE_SET_CGROUP_WEIGHT(io_weight, CGROUP_MASK_IO, CGROUP_WEIGHT_IS_OK, CGROUP_WEIGHT_INVALID);
BUS_DEFINE_SET_CGROUP_WEIGHT(blockio_weight, CGROUP_MASK_BLKIO, CGROUP_BLKIO_WEIGHT_IS_OK, CGROUP_BLKIO_WEIGHT_INVALID);
BUS_DEFINE_SET_CGROUP_LIMIT(memory, CGROUP_MASK_MEMORY, physical_memory_scale, 1);
BUS_DEFINE_SET_CGROUP_LIMIT(memory_protection, CGROUP_MASK_MEMORY, physical_memory_scale, 0);
BUS_DEFINE_SET_CGROUP_LIMIT(swap, CGROUP_MASK_MEMORY, physical_memory_scale, 0);
BUS_DEFINE_SET_CGROUP_LIMIT(zswap, CGROUP_MASK_MEMORY, physical_memory_scale, 0);
REENABLE_WARNING;

static int bus_cgroup_set_cpu_weight(
                Unit *u,
                const char *name,
                uint64_t *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {
        uint64_t v;
        int r;
        assert(p);
        r = sd_bus_message_read(message, "t", &v);
        if (r < 0)
                return r;
        if (!CGROUP_WEIGHT_IS_OK(v) && v != CGROUP_WEIGHT_IDLE)
                return sd_bus_error_setf(
                                error, SD_BUS_ERROR_INVALID_ARGS, "Value specified in %s is out of range", name);
        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = v;
                unit_invalidate_cgroup(u, CGROUP_MASK_CPU);
                if (v == CGROUP_WEIGHT_INVALID)
                        unit_write_settingf(u, flags, name, "%s=", name);
                else if (v == CGROUP_WEIGHT_IDLE)
                        unit_write_settingf(u, flags, name, "%s=idle", name);
                else
                        unit_write_settingf(u, flags, name, "%s=%" PRIu64, name, v);
        }
        return 1;
}

static int bus_cgroup_set_tasks_max(
                Unit *u,
                const char *name,
                CGroupTasksMax *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        uint64_t v;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "t", &v);
        if (r < 0)
                return r;

        if (v < 1)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Value specified in %s is out of range", name);

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = (CGroupTasksMax) { .value = v, .scale = 0 }; /* When .scale==0, .value is the absolute value */
                unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);

                if (v == CGROUP_LIMIT_MAX)
                        unit_write_settingf(u, flags, name,
                                            "%s=infinity", name);
                else
                        unit_write_settingf(u, flags, name,
                                            "%s=%" PRIu64, name, v);
        }

        return 1;
}

static int bus_cgroup_set_tasks_max_scale(
                Unit *u,
                const char *name,
                CGroupTasksMax *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        uint32_t v;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "u", &v);
        if (r < 0)
                return r;

        if (v < 1 || v >= UINT32_MAX)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Value specified in %s is out of range", name);

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = (CGroupTasksMax) { v, UINT32_MAX }; /* .scale is not 0, so this is interpreted as v/UINT32_MAX. */
                unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);

                uint32_t scaled = DIV_ROUND_UP((uint64_t) v * 100U, (uint64_t) UINT32_MAX);
                unit_write_settingf(u, flags, name, "%s=%" PRIu32 ".%" PRIu32 "%%", "TasksMax",
                                    scaled / 10, scaled % 10);
        }

        return 1;
}

int bus_cgroup_set_property(
                Unit *u,
                CGroupContext *c,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        CGroupIOLimitType iol_type;
        int r;

        assert(u);
        assert(c);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "CPUAccounting"))
                return bus_cgroup_set_boolean(u, name, &c->cpu_accounting, get_cpu_accounting_mask(), message, flags, error);

        if (streq(name, "CPUWeight"))
                return bus_cgroup_set_cpu_weight(u, name, &c->cpu_weight, message, flags, error);

        if (streq(name, "StartupCPUWeight"))
                return bus_cgroup_set_cpu_weight(u, name, &c->startup_cpu_weight, message, flags, error);

        if (streq(name, "CPUShares"))
                return bus_cgroup_set_cpu_shares(u, name, &c->cpu_shares, message, flags, error);

        if (streq(name, "StartupCPUShares"))
                return bus_cgroup_set_cpu_shares(u, name, &c->startup_cpu_shares, message, flags, error);

        if (streq(name, "IOAccounting"))
                return bus_cgroup_set_boolean(u, name, &c->io_accounting, CGROUP_MASK_IO, message, flags, error);

        if (streq(name, "IOWeight"))
                return bus_cgroup_set_io_weight(u, name, &c->io_weight, message, flags, error);

        if (streq(name, "StartupIOWeight"))
                return bus_cgroup_set_io_weight(u, name, &c->startup_io_weight, message, flags, error);

        if (streq(name, "BlockIOAccounting"))
                return bus_cgroup_set_boolean(u, name, &c->blockio_accounting, CGROUP_MASK_BLKIO, message, flags, error);

        if (streq(name, "BlockIOWeight"))
                return bus_cgroup_set_blockio_weight(u, name, &c->blockio_weight, message, flags, error);

        if (streq(name, "StartupBlockIOWeight"))
                return bus_cgroup_set_blockio_weight(u, name, &c->startup_blockio_weight, message, flags, error);

        if (streq(name, "MemoryAccounting"))
                return bus_cgroup_set_boolean(u, name, &c->memory_accounting, CGROUP_MASK_MEMORY, message, flags, error);

        if (streq(name, "MemoryMin")) {
                r = bus_cgroup_set_memory_protection(u, name, &c->memory_min, message, flags, error);
                if (r > 0)
                        c->memory_min_set = true;
                return r;
        }

        if (streq(name, "MemoryLow")) {
                r = bus_cgroup_set_memory_protection(u, name, &c->memory_low, message, flags, error);
                if (r > 0)
                        c->memory_low_set = true;
                return r;
        }

        if (streq(name, "StartupMemoryLow")) {
                r = bus_cgroup_set_memory_protection(u, name, &c->startup_memory_low, message, flags, error);
                if (r > 0)
                        c->startup_memory_low_set = true;
                return r;
        }

        if (streq(name, "DefaultMemoryMin")) {
                r = bus_cgroup_set_memory_protection(u, name, &c->default_memory_min, message, flags, error);
                if (r > 0)
                        c->default_memory_min_set = true;
                return r;
        }

        if (streq(name, "DefaultMemoryLow")) {
                r = bus_cgroup_set_memory_protection(u, name, &c->default_memory_low, message, flags, error);
                if (r > 0)
                        c->default_memory_low_set = true;
                return r;
        }

        if (streq(name, "DefaultStartupMemoryLow")) {
                r = bus_cgroup_set_memory_protection(u, name, &c->default_startup_memory_low, message, flags, error);
                if (r > 0)
                        c->default_startup_memory_low_set = true;
                return r;
        }

        if (streq(name, "MemoryHigh"))
                return bus_cgroup_set_memory(u, name, &c->memory_high, message, flags, error);

        if (streq(name, "StartupMemoryHigh")) {
                r = bus_cgroup_set_memory(u, name, &c->startup_memory_high, message, flags, error);
                if (r > 0)
                        c->startup_memory_high_set = true;
                return r;
        }

        if (streq(name, "MemorySwapMax"))
                return bus_cgroup_set_swap(u, name, &c->memory_swap_max, message, flags, error);

        if (streq(name, "StartupMemorySwapMax")) {
                r = bus_cgroup_set_swap(u, name, &c->startup_memory_swap_max, message, flags, error);
                if (r > 0)
                        c->startup_memory_swap_max_set = true;
                return r;
        }

        if (streq(name, "MemoryZSwapMax"))
                return bus_cgroup_set_zswap(u, name, &c->memory_zswap_max, message, flags, error);

        if (streq(name, "StartupMemoryZSwapMax")) {
                r = bus_cgroup_set_zswap(u, name, &c->startup_memory_zswap_max, message, flags, error);
                if (r > 0)
                        c->startup_memory_zswap_max_set = true;
                return r;
        }

        if (streq(name, "MemoryMax"))
                return bus_cgroup_set_memory(u, name, &c->memory_max, message, flags, error);

        if (streq(name, "StartupMemoryMax")) {
                r = bus_cgroup_set_memory(u, name, &c->startup_memory_max, message, flags, error);
                if (r > 0)
                        c->startup_memory_max_set = true;
                return r;
        }

        if (streq(name, "MemoryLimit"))
                return bus_cgroup_set_memory(u, name, &c->memory_limit, message, flags, error);

        if (streq(name, "MemoryMinScale")) {
                r = bus_cgroup_set_memory_protection_scale(u, name, &c->memory_min, message, flags, error);
                if (r > 0)
                        c->memory_min_set = true;
                return r;
        }

        if (streq(name, "MemoryLowScale")) {
                r = bus_cgroup_set_memory_protection_scale(u, name, &c->memory_low, message, flags, error);
                if (r > 0)
                        c->memory_low_set = true;
                return r;
        }

        if (streq(name, "DefaultMemoryMinScale")) {
                r = bus_cgroup_set_memory_protection_scale(u, name, &c->default_memory_min, message, flags, error);
                if (r > 0)
                        c->default_memory_min_set = true;
                return r;
        }

        if (streq(name, "DefaultMemoryLowScale")) {
                r = bus_cgroup_set_memory_protection_scale(u, name, &c->default_memory_low, message, flags, error);
                if (r > 0)
                        c->default_memory_low_set = true;
                return r;
        }

        if (streq(name, "MemoryHighScale"))
                return bus_cgroup_set_memory_scale(u, name, &c->memory_high, message, flags, error);

        if (streq(name, "MemorySwapMaxScale"))
                return bus_cgroup_set_swap_scale(u, name, &c->memory_swap_max, message, flags, error);

        if (streq(name, "MemoryZSwapMaxScale"))
                return bus_cgroup_set_zswap_scale(u, name, &c->memory_zswap_max, message, flags, error);

        if (streq(name, "MemoryMaxScale"))
                return bus_cgroup_set_memory_scale(u, name, &c->memory_max, message, flags, error);

        if (streq(name, "MemoryLimitScale"))
                return bus_cgroup_set_memory_scale(u, name, &c->memory_limit, message, flags, error);

        if (streq(name, "MemoryZSwapWriteback"))
                return bus_cgroup_set_boolean(u, name, &c->memory_zswap_writeback, CGROUP_MASK_MEMORY, message, flags, error);

        if (streq(name, "TasksAccounting"))
                return bus_cgroup_set_boolean(u, name, &c->tasks_accounting, CGROUP_MASK_PIDS, message, flags, error);

        if (streq(name, "TasksMax"))
                return bus_cgroup_set_tasks_max(u, name, &c->tasks_max, message, flags, error);

        if (streq(name, "TasksMaxScale"))
                return bus_cgroup_set_tasks_max_scale(u, name, &c->tasks_max, message, flags, error);

        if (streq(name, "CPUQuotaPerSecUSec")) {
                uint64_t u64;

                r = sd_bus_message_read(message, "t", &u64);
                if (r < 0)
                        return r;

                if (u64 <= 0)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "CPUQuotaPerSecUSec= value out of range");

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->cpu_quota_per_sec_usec = u64;
                        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
                        if (crt)
                                crt->warned_clamping_cpu_quota_period = false;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

                        if (c->cpu_quota_per_sec_usec == USEC_INFINITY)
                                unit_write_setting(u, flags, "CPUQuota", "CPUQuota=");
                        else
                                unit_write_settingf(u, flags, "CPUQuota",
                                                    "CPUQuota=" USEC_FMT ".%02" PRI_USEC "%%",
                                                    c->cpu_quota_per_sec_usec / 10000,
                                                    (c->cpu_quota_per_sec_usec % 10000) / 100);
                }

                return 1;

        } else if (streq(name, "CPUQuotaPeriodUSec")) {
                uint64_t u64;

                r = sd_bus_message_read(message, "t", &u64);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->cpu_quota_period_usec = u64;
                        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
                        if (crt)
                                crt->warned_clamping_cpu_quota_period = false;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);
                        if (c->cpu_quota_period_usec == USEC_INFINITY)
                                unit_write_setting(u, flags, "CPUQuotaPeriodSec", "CPUQuotaPeriodSec=");
                        else
                                unit_write_settingf(u, flags, "CPUQuotaPeriodSec",
                                                    "CPUQuotaPeriodSec=%s",
                                                    FORMAT_TIMESPAN(c->cpu_quota_period_usec, 1));
                }

                return 1;

        } else if (STR_IN_SET(name, "AllowedCPUs", "StartupAllowedCPUs", "AllowedMemoryNodes", "StartupAllowedMemoryNodes")) {
                const void *a;
                size_t n;
                _cleanup_(cpu_set_reset) CPUSet new_set = {};

                r = sd_bus_message_read_array(message, 'y', &a, &n);
                if (r < 0)
                        return r;

                r = cpu_set_from_dbus(a, n, &new_set);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *setstr = NULL;
                        CPUSet *set = NULL;

                        setstr = cpu_set_to_range_string(&new_set);
                        if (!setstr)
                                return -ENOMEM;

                        if (streq(name, "AllowedCPUs"))
                                set = &c->cpuset_cpus;
                        else if (streq(name, "StartupAllowedCPUs"))
                                set = &c->startup_cpuset_cpus;
                        else if (streq(name, "AllowedMemoryNodes"))
                                set = &c->cpuset_mems;
                        else if (streq(name, "StartupAllowedMemoryNodes"))
                                set = &c->startup_cpuset_mems;

                        assert(set);

                        cpu_set_reset(set);
                        *set = new_set;
                        new_set = (CPUSet) {};

                        unit_invalidate_cgroup(u, CGROUP_MASK_CPUSET);
                        unit_write_settingf(u, flags, name, "%s=\n%s=%s", name, name, setstr);
                }

                return 1;

        } else if ((iol_type = cgroup_io_limit_type_from_string(name)) >= 0) {
                const char *path;
                unsigned n = 0;
                uint64_t u64;

                r = sd_bus_message_enter_container(message, 'a', "(st)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(st)", &path, &u64)) > 0) {

                        if (!path_is_normalized(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path '%s' specified in %s= is not normalized.", name, path);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupIODeviceLimit *a = NULL;

                                LIST_FOREACH(device_limits, b, c->io_device_limits)
                                        if (path_equal(path, b->path)) {
                                                a = b;
                                                break;
                                        }

                                if (!a) {
                                        CGroupIOLimitType type;

                                        a = new0(CGroupIODeviceLimit, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }

                                        for (type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
                                                a->limits[type] = cgroup_io_limit_defaults[type];

                                        LIST_APPEND(device_limits, c->io_device_limits, a);
                                }

                                a->limits[iol_type] = u64;
                        }

                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                LIST_FOREACH(device_limits, a, c->io_device_limits)
                                        a->limits[iol_type] = cgroup_io_limit_defaults[iol_type];

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        fprintf(f, "%s=\n", name);
                        LIST_FOREACH(device_limits, a, c->io_device_limits)
                                if (a->limits[iol_type] != cgroup_io_limit_defaults[iol_type])
                                        fprintf(f, "%s=%s %" PRIu64 "\n", name, a->path, a->limits[iol_type]);

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;

        } else if (streq(name, "IODeviceWeight")) {
                const char *path;
                uint64_t weight;
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(st)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(st)", &path, &weight)) > 0) {

                        if (!path_is_normalized(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path '%s' specified in %s= is not normalized.", name, path);

                        if (!CGROUP_WEIGHT_IS_OK(weight) || weight == CGROUP_WEIGHT_INVALID)
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "IODeviceWeight= value out of range");

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupIODeviceWeight *a = NULL;

                                LIST_FOREACH(device_weights, b, c->io_device_weights)
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                break;
                                        }

                                if (!a) {
                                        a = new0(CGroupIODeviceWeight, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }
                                        LIST_APPEND(device_weights, c->io_device_weights, a);
                                }

                                a->weight = weight;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                while (c->io_device_weights)
                                        cgroup_context_free_io_device_weight(c, c->io_device_weights);

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        fputs("IODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->io_device_weights)
                                fprintf(f, "IODeviceWeight=%s %" PRIu64 "\n", a->path, a->weight);

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;

        } else if (streq(name, "IODeviceLatencyTargetUSec")) {
                const char *path;
                uint64_t target;
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(st)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(st)", &path, &target)) > 0) {

                        if (!path_is_normalized(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path '%s' specified in %s= is not normalized.", name, path);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupIODeviceLatency *a = NULL;

                                LIST_FOREACH(device_latencies, b, c->io_device_latencies)
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                break;
                                        }

                                if (!a) {
                                        a = new0(CGroupIODeviceLatency, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }
                                        LIST_APPEND(device_latencies, c->io_device_latencies, a);
                                }

                                a->target_usec = target;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                while (c->io_device_latencies)
                                        cgroup_context_free_io_device_latency(c, c->io_device_latencies);

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        fputs("IODeviceLatencyTargetSec=\n", f);
                        LIST_FOREACH(device_latencies, a, c->io_device_latencies)
                                fprintf(f, "IODeviceLatencyTargetSec=%s %s\n",
                                        a->path, FORMAT_TIMESPAN(a->target_usec, 1));

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;

        } else if (STR_IN_SET(name, "BlockIOReadBandwidth", "BlockIOWriteBandwidth")) {
                const char *path;
                unsigned n = 0;
                uint64_t u64;
                bool read;

                read = streq(name, "BlockIOReadBandwidth");

                r = sd_bus_message_enter_container(message, 'a', "(st)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(st)", &path, &u64)) > 0) {

                        if (!path_is_normalized(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path '%s' specified in %s= is not normalized.", name, path);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupBlockIODeviceBandwidth *a = NULL;

                                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths)
                                        if (path_equal(path, b->path)) {
                                                a = b;
                                                break;
                                        }

                                if (!a) {
                                        a = new0(CGroupBlockIODeviceBandwidth, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->rbps = CGROUP_LIMIT_MAX;
                                        a->wbps = CGROUP_LIMIT_MAX;
                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }

                                        LIST_APPEND(device_bandwidths, c->blockio_device_bandwidths, a);
                                }

                                if (read)
                                        a->rbps = u64;
                                else
                                        a->wbps = u64;
                        }

                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths) {
                                        if (read)
                                                a->rbps = CGROUP_LIMIT_MAX;
                                        else
                                                a->wbps = CGROUP_LIMIT_MAX;
                                }

                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        if (read) {
                                fputs("BlockIOReadBandwidth=\n", f);
                                LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths)
                                        if (a->rbps != CGROUP_LIMIT_MAX)
                                                fprintf(f, "BlockIOReadBandwidth=%s %" PRIu64 "\n", a->path, a->rbps);
                        } else {
                                fputs("BlockIOWriteBandwidth=\n", f);
                                LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths)
                                        if (a->wbps != CGROUP_LIMIT_MAX)
                                                fprintf(f, "BlockIOWriteBandwidth=%s %" PRIu64 "\n", a->path, a->wbps);
                        }

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;

        } else if (streq(name, "BlockIODeviceWeight")) {
                const char *path;
                uint64_t weight;
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(st)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(st)", &path, &weight)) > 0) {

                        if (!path_is_normalized(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path '%s' specified in %s= is not normalized.", name, path);

                        if (!CGROUP_BLKIO_WEIGHT_IS_OK(weight) || weight == CGROUP_BLKIO_WEIGHT_INVALID)
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "BlockIODeviceWeight= out of range");

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupBlockIODeviceWeight *a = NULL;

                                LIST_FOREACH(device_weights, b, c->blockio_device_weights)
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                break;
                                        }

                                if (!a) {
                                        a = new0(CGroupBlockIODeviceWeight, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }
                                        LIST_APPEND(device_weights, c->blockio_device_weights, a);
                                }

                                a->weight = weight;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                while (c->blockio_device_weights)
                                        cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);

                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        fputs("BlockIODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->blockio_device_weights)
                                fprintf(f, "BlockIODeviceWeight=%s %" PRIu64 "\n", a->path, a->weight);

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;

        } else if (streq(name, "DevicePolicy")) {
                const char *policy;
                CGroupDevicePolicy p;

                r = sd_bus_message_read(message, "s", &policy);
                if (r < 0)
                        return r;

                p = cgroup_device_policy_from_string(policy);
                if (p < 0)
                        return p;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->device_policy = p;
                        unit_invalidate_cgroup(u, CGROUP_MASK_DEVICES);
                        unit_write_settingf(u, flags, name, "DevicePolicy=%s", policy);
                }

                return 1;

        } else if (streq(name, "DeviceAllow")) {
                const char *path, *rwm;
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(ss)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(ss)", &path, &rwm)) > 0) {
                        CGroupDevicePermissions p;

                        if (!valid_device_allow_pattern(path) || strpbrk(path, WHITESPACE))
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "DeviceAllow= requires device node or pattern");

                        if (isempty(rwm))
                                p = _CGROUP_DEVICE_PERMISSIONS_ALL;
                        else {
                                p = cgroup_device_permissions_from_string(rwm);
                                if (p < 0)
                                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "DeviceAllow= requires combination of rwm flags");
                        }

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                r = cgroup_context_add_or_update_device_allow(c, path, p);
                                if (r < 0)
                                        return r;
                        }

                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                while (c->device_allow)
                                        cgroup_context_free_device_allow(c, c->device_allow);

                        unit_invalidate_cgroup(u, CGROUP_MASK_DEVICES);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        fputs("DeviceAllow=\n", f);
                        LIST_FOREACH(device_allow, a, c->device_allow)
                                fprintf(f, "DeviceAllow=%s %s\n", a->path, cgroup_device_permissions_to_string(a->permissions));

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;

        } else if (streq(name, "IPAccounting")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->ip_accounting = b;

                        unit_invalidate_cgroup_bpf(u);
                        unit_write_settingf(u, flags, name, "IPAccounting=%s", yes_no(b));
                }

                return 1;

        } else if (STR_IN_SET(name, "IPAddressAllow", "IPAddressDeny")) {
                _cleanup_set_free_ Set *new_prefixes = NULL;
                size_t n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(iayu)");
                if (r < 0)
                        return r;

                for (;;) {
                        const void *ap;
                        int32_t family;
                        uint32_t prefixlen;
                        size_t an;

                        r = sd_bus_message_enter_container(message, 'r', "iayu");
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = sd_bus_message_read(message, "i", &family);
                        if (r < 0)
                                return r;

                        if (!IN_SET(family, AF_INET, AF_INET6))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s= expects IPv4 or IPv6 addresses only.", name);

                        r = sd_bus_message_read_array(message, 'y', &ap, &an);
                        if (r < 0)
                                return r;

                        if (an != FAMILY_ADDRESS_SIZE(family))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "IP address has wrong size for family (%s, expected %zu, got %zu)",
                                                               af_to_name(family), FAMILY_ADDRESS_SIZE(family), an);

                        r = sd_bus_message_read(message, "u", &prefixlen);
                        if (r < 0)
                                return r;

                        if (prefixlen > FAMILY_ADDRESS_SIZE(family)*8)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Prefix length %" PRIu32 " too large for address family %s.", prefixlen, af_to_name(family));

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                struct in_addr_prefix prefix = {
                                        .family = family,
                                        .prefixlen = prefixlen,
                                };

                                memcpy(&prefix.address, ap, an);

                                r = in_addr_prefix_add(&new_prefixes, &prefix);
                                if (r < 0)
                                        return r;
                        }

                        r = sd_bus_message_exit_container(message);
                        if (r < 0)
                                return r;

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        Set **prefixes;
                        bool *reduced;
                        FILE *f;

                        unit_invalidate_cgroup_bpf(u);

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        prefixes = streq(name, "IPAddressAllow") ? &c->ip_address_allow : &c->ip_address_deny;
                        reduced = streq(name, "IPAddressAllow") ? &c->ip_address_allow_reduced : &c->ip_address_deny_reduced;

                        fputs(name, f);
                        fputs("=\n", f);

                        if (n == 0) {
                                *reduced = true;
                                *prefixes = set_free(*prefixes);
                        } else {
                                *reduced = false;

                                r = in_addr_prefixes_merge(prefixes, new_prefixes);
                                if (r < 0)
                                        return r;

                                const struct in_addr_prefix *p;
                                SET_FOREACH(p, *prefixes)
                                        fprintf(f, "%s=%s\n", name,
                                                IN_ADDR_PREFIX_TO_STRING(p->family, &p->address, p->prefixlen));
                        }

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;
        }

        if (STR_IN_SET(name, "ManagedOOMSwap", "ManagedOOMMemoryPressure")) {
                ManagedOOMMode *cgroup_mode = streq(name, "ManagedOOMSwap") ? &c->moom_swap : &c->moom_mem_pressure;
                ManagedOOMMode m;
                const char *mode;

                if (!UNIT_VTABLE(u)->can_set_managed_oom)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot set %s for this unit type", name);

                r = sd_bus_message_read(message, "s", &mode);
                if (r < 0)
                        return r;

                m = managed_oom_mode_from_string(mode);
                if (m < 0)
                        return -EINVAL;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        *cgroup_mode = m;
                        unit_write_settingf(u, flags, name, "%s=%s", name, mode);
                }

                (void) manager_varlink_send_managed_oom_update(u);
                return 1;
        }

        if (streq(name, "ManagedOOMMemoryPressureLimit")) {
                uint32_t v;

                if (!UNIT_VTABLE(u)->can_set_managed_oom)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot set %s for this unit type", name);

                r = sd_bus_message_read(message, "u", &v);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->moom_mem_pressure_limit = v;
                        unit_write_settingf(u, flags, name,
                                            "ManagedOOMMemoryPressureLimit=" PERMYRIAD_AS_PERCENT_FORMAT_STR,
                                            PERMYRIAD_AS_PERCENT_FORMAT_VAL(UINT32_SCALE_TO_PERMYRIAD(v)));
                }

                if (c->moom_mem_pressure == MANAGED_OOM_KILL)
                        (void) manager_varlink_send_managed_oom_update(u);

                return 1;
        }

        if (streq(name, "ManagedOOMMemoryPressureDurationUSec")) {
                uint64_t t;

                if (!UNIT_VTABLE(u)->can_set_managed_oom)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot set %s for this unit type", name);

                r = sd_bus_message_read(message, "t", &t);
                if (r < 0)
                        return r;

                if (t < 1 * USEC_PER_SEC)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s= must be at least 1s, got %s", name,
                                                 FORMAT_TIMESPAN(t, USEC_PER_SEC));

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->memory_pressure_threshold_usec = t;
                        if (c->memory_pressure_threshold_usec == USEC_INFINITY)
                                unit_write_setting(u, flags, name, "ManagedOOMMemoryPressureDurationSec=");
                        else
                                unit_write_settingf(u, flags, name,
                                                    "ManagedOOMMemoryPressureDurationSec=%s",
                                                    FORMAT_TIMESPAN(c->memory_pressure_threshold_usec, 1));
                }

                if (c->moom_mem_pressure == MANAGED_OOM_KILL)
                        (void) manager_varlink_send_managed_oom_update(u);

                return 1;
        }

        if (streq(name, "ManagedOOMPreference")) {
                ManagedOOMPreference p;
                const char *pref;

                r = sd_bus_message_read(message, "s", &pref);
                if (r < 0)
                        return r;

                p = managed_oom_preference_from_string(pref);
                if (p < 0)
                        return p;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->moom_preference = p;
                        unit_write_settingf(u, flags, name, "ManagedOOMPreference=%s", pref);
                }

                return 1;
        }
        if (STR_IN_SET(name, "SocketBindAllow", "SocketBindDeny")) {
                CGroupSocketBindItem **list;
                uint16_t nr_ports, port_min;
                size_t n = 0;
                int32_t family, ip_protocol;

                list = streq(name, "SocketBindAllow") ? &c->socket_bind_allow : &c->socket_bind_deny;

                r = sd_bus_message_enter_container(message, 'a', "(iiqq)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(iiqq)", &family, &ip_protocol, &nr_ports, &port_min)) > 0) {

                        if (!IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s= expects INET or INET6 family, if specified.", name);

                        if (!IN_SET(ip_protocol, 0, IPPROTO_TCP, IPPROTO_UDP))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s= expects TCP or UDP protocol, if specified.", name);

                        if (port_min + (uint32_t) nr_ports > (1 << 16))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s= expects maximum port value lesser than 65536.", name);

                        if (port_min == 0 && nr_ports != 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "%s= expects port range starting with positive value.", name);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                _cleanup_free_ CGroupSocketBindItem *item = NULL;

                                item = new(CGroupSocketBindItem, 1);
                                if (!item)
                                        return log_oom();

                                *item = (CGroupSocketBindItem) {
                                        .address_family = family,
                                        .ip_protocol = ip_protocol,
                                        .nr_ports = nr_ports,
                                        .port_min = port_min
                                };

                                LIST_PREPEND(socket_bind_items, *list, TAKE_PTR(item));
                        }
                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_(memstream_done) MemStream m = {};
                        _cleanup_free_ char *buf = NULL;
                        FILE *f;

                        if (n == 0)
                                cgroup_context_remove_socket_bind(list);
                        else {
                                if ((u->manager->cgroup_supported & CGROUP_MASK_BPF_SOCKET_BIND) == 0)
                                        log_full(LOG_DEBUG,
                                                 "Unit %s configures source compiled BPF programs "
                                                 "but the local system does not support that.\n"
                                                 "Starting this unit will fail!", u->id);
                        }

                        f = memstream_init(&m);
                        if (!f)
                                return -ENOMEM;

                        if (n == 0)
                                fprintf(f, "%s=\n", name);
                        else
                                LIST_FOREACH(socket_bind_items, item, *list) {
                                        fprintf(f, "%s=", name);
                                        cgroup_context_dump_socket_bind_item(item, f);
                                        fputc('\n', f);
                                }

                        r = memstream_finalize(&m, &buf, NULL);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;
        }
        if (streq(name, "RestrictNetworkInterfaces")) {
                int is_allow_list;
                _cleanup_strv_free_ char **l = NULL;

                r = sd_bus_message_enter_container(message, 'r', "bas");
                if (r < 0)
                        return r;

                r = sd_bus_message_read(message, "b", &is_allow_list);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_strv(message, &l);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *joined = NULL;

                        if (strv_isempty(l)) {
                                c->restrict_network_interfaces_is_allow_list = false;
                                c->restrict_network_interfaces = set_free_free(c->restrict_network_interfaces);

                                unit_write_settingf(u, flags, name, "%s=", name);
                                return 1;
                        }

                        if (set_isempty(c->restrict_network_interfaces))
                                c->restrict_network_interfaces_is_allow_list = is_allow_list;

                        STRV_FOREACH(s, l) {
                                if (!ifname_valid_full(*s, IFNAME_VALID_ALTERNATIVE)) {
                                        log_full(LOG_WARNING, "Invalid interface name, ignoring: %s", *s);
                                        continue;
                                }
                                if (c->restrict_network_interfaces_is_allow_list != (bool) is_allow_list)
                                        free(set_remove(c->restrict_network_interfaces, *s));
                                else {
                                        r = set_put_strdup(&c->restrict_network_interfaces, *s);
                                        if (r < 0)
                                                return log_oom();
                                }
                        }

                        joined = strv_join(l, " ");
                        if (!joined)
                                return -ENOMEM;

                        unit_write_settingf(u, flags, name, "%s=%s%s", name, is_allow_list ? "" : "~", joined);
                }

                return 1;
        }

        if (streq(name, "NFTSet")) {
                int source, nfproto;
                const char *table, *set;
                bool empty = true;

                r = sd_bus_message_enter_container(message, 'a', "(iiss)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(iiss)", &source, &nfproto, &table, &set)) > 0) {
                        const char *source_name, *nfproto_name;

                        if (!IN_SET(source, NFT_SET_SOURCE_CGROUP, NFT_SET_SOURCE_USER, NFT_SET_SOURCE_GROUP))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid source %d.", source);

                        source_name = nft_set_source_to_string(source);
                        assert(source_name);

                        nfproto_name = nfproto_to_string(nfproto);
                        if (!nfproto_name)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid protocol %d.", nfproto);

                        if (!nft_identifier_valid(table)) {
                                _cleanup_free_ char *esc = NULL;

                                esc = cescape(table);
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid NFT table name %s.", strna(esc));
                        }

                        if (!nft_identifier_valid(set)) {
                                _cleanup_free_ char *esc = NULL;

                                esc = cescape(set);
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid NFT set name %s.", strna(esc));
                        }

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                r = nft_set_add(&c->nft_set_context, source, nfproto, table, set);
                                if (r < 0)
                                        return r;

                                unit_write_settingf(
                                                u, flags|UNIT_ESCAPE_SPECIFIERS, name,
                                                "%s=%s:%s:%s:%s",
                                                name,
                                                source_name,
                                                nfproto_name,
                                                table,
                                                set);
                        }

                        empty = false;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (empty && !UNIT_WRITE_FLAGS_NOOP(flags)) {
                        nft_set_context_clear(&c->nft_set_context);
                        unit_write_settingf(u, flags, name, "%s=", name);
                }

                return 1;
        }

        /* must be last */
        if (streq(name, "DisableControllers") || (u->transient && u->load_state == UNIT_STUB))
                return bus_cgroup_set_transient_property(u, c, name, message, flags, error);

        return 0;
}
