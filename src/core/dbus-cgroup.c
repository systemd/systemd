/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>

#include "af-list.h"
#include "alloc-util.h"
#include "bpf-firewall.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "cgroup.h"
#include "dbus-cgroup.h"
#include "dbus-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "limits-util.h"
#include "path-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_cgroup_device_policy, cgroup_device_policy, CGroupDevicePolicy);

static int property_get_cgroup_mask(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupMask *mask = userdata;
        CGroupController ctrl;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        for (ctrl = 0; ctrl < _CGROUP_CONTROLLER_MAX; ctrl++) {
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

        CGroupContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        if (!c->delegate)
                return sd_bus_message_append(reply, "as", 0);

        return property_get_cgroup_mask(bus, path, interface, property, reply, &c->delegate_controllers, error);
}

static int property_get_io_device_weight(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        CGroupContext *c = userdata;
        CGroupIODeviceWeight *w;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

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

        CGroupContext *c = userdata;
        CGroupIODeviceLimit *l;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

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

        CGroupContext *c = userdata;
        CGroupIODeviceLatency *l;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

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

        CGroupContext *c = userdata;
        CGroupBlockIODeviceWeight *w;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

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

        CGroupContext *c = userdata;
        CGroupBlockIODeviceBandwidth *b;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

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

        CGroupContext *c = userdata;
        CGroupDeviceAllow *a;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        LIST_FOREACH(device_allow, a, c->device_allow) {
                unsigned k = 0;
                char rwm[4];

                if (a->r)
                        rwm[k++] = 'r';
                if (a->w)
                        rwm[k++] = 'w';
                if (a->m)
                        rwm[k++] = 'm';

                rwm[k] = 0;

                r = sd_bus_message_append(reply, "(ss)", a->path, rwm);
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

        IPAddressAccessItem** items = userdata, *i;
        int r;

        r = sd_bus_message_open_container(reply, 'a', "(iayu)");
        if (r < 0)
                return r;

        LIST_FOREACH(items, i, *items) {

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

const sd_bus_vtable bus_cgroup_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Delegate", "b", bus_property_get_bool, offsetof(CGroupContext, delegate), 0),
        SD_BUS_PROPERTY("DelegateControllers", "as", property_get_delegate_controllers, 0, 0),
        SD_BUS_PROPERTY("CPUAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, cpu_accounting), 0),
        SD_BUS_PROPERTY("CPUWeight", "t", NULL, offsetof(CGroupContext, cpu_weight), 0),
        SD_BUS_PROPERTY("StartupCPUWeight", "t", NULL, offsetof(CGroupContext, startup_cpu_weight), 0),
        SD_BUS_PROPERTY("CPUShares", "t", NULL, offsetof(CGroupContext, cpu_shares), 0),
        SD_BUS_PROPERTY("StartupCPUShares", "t", NULL, offsetof(CGroupContext, startup_cpu_shares), 0),
        SD_BUS_PROPERTY("CPUQuotaPerSecUSec", "t", bus_property_get_usec, offsetof(CGroupContext, cpu_quota_per_sec_usec), 0),
        SD_BUS_PROPERTY("CPUQuotaPeriodUSec", "t", bus_property_get_usec, offsetof(CGroupContext, cpu_quota_period_usec), 0),
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
        SD_BUS_PROPERTY("DefaultMemoryMin", "t", NULL, offsetof(CGroupContext, default_memory_min), 0),
        SD_BUS_PROPERTY("MemoryMin", "t", NULL, offsetof(CGroupContext, memory_min), 0),
        SD_BUS_PROPERTY("MemoryLow", "t", NULL, offsetof(CGroupContext, memory_low), 0),
        SD_BUS_PROPERTY("MemoryHigh", "t", NULL, offsetof(CGroupContext, memory_high), 0),
        SD_BUS_PROPERTY("MemoryMax", "t", NULL, offsetof(CGroupContext, memory_max), 0),
        SD_BUS_PROPERTY("MemorySwapMax", "t", NULL, offsetof(CGroupContext, memory_swap_max), 0),
        SD_BUS_PROPERTY("MemoryLimit", "t", NULL, offsetof(CGroupContext, memory_limit), 0),
        SD_BUS_PROPERTY("DevicePolicy", "s", property_get_cgroup_device_policy, offsetof(CGroupContext, device_policy), 0),
        SD_BUS_PROPERTY("DeviceAllow", "a(ss)", property_get_device_allow, 0, 0),
        SD_BUS_PROPERTY("TasksAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, tasks_accounting), 0),
        SD_BUS_PROPERTY("TasksMax", "t", NULL, offsetof(CGroupContext, tasks_max), 0),
        SD_BUS_PROPERTY("IPAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, ip_accounting), 0),
        SD_BUS_PROPERTY("IPAddressAllow", "a(iayu)", property_get_ip_address_access, offsetof(CGroupContext, ip_address_allow), 0),
        SD_BUS_PROPERTY("IPAddressDeny", "a(iayu)", property_get_ip_address_access, offsetof(CGroupContext, ip_address_deny), 0),
        SD_BUS_PROPERTY("IPIngressFilterPath", "as", NULL, offsetof(CGroupContext, ip_filters_ingress), 0),
        SD_BUS_PROPERTY("IPEgressFilterPath", "as", NULL, offsetof(CGroupContext, ip_filters_egress), 0),
        SD_BUS_PROPERTY("DisableControllers", "as", property_get_cgroup_mask, offsetof(CGroupContext, disable_controllers), 0),
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
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Delegation not available for unit type");

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->delegate = b;
                        c->delegate_controllers = b ? _CGROUP_MASK_ALL : 0;

                        unit_write_settingf(u, flags, name, "Delegate=%s", yes_no(b));
                }

                return 1;

        } else if (STR_IN_SET(name, "DelegateControllers", "DisableControllers")) {
                CGroupMask mask = 0;

                if (streq(name, "DelegateControllers") && !UNIT_VTABLE(u)->can_delegate)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Delegation not available for unit type");

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
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        char **entry;
                        size_t size = 0;

                        if (n == 0)
                                *filters = strv_free(*filters);

                        unit_invalidate_cgroup_bpf(u);
                        f = open_memstream_unlocked(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs(name, f);
                        fputs("=\n", f);

                        STRV_FOREACH(entry, *filters)
                                fprintf(f, "%s=%s\n", name, *entry);

                        r = fflush_and_check(f);
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
                                                 "Transient unit %s configures an IP firewall with BPF, but the local system does not support BPF/cgroup firewalling with mulitiple filters.\n"
                                                 "Starting this unit will fail! (This warning is only shown for the first started transient unit using IP firewalling.)", u->id);
                                        warned = true;
                                }
                        }
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
                        unit_invalidate_cgroup(u, (mask));              \
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
                        unit_invalidate_cgroup(u, (mask));              \
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
                        const char *e;                                  \
                                                                        \
                        *p = v;                                         \
                        unit_invalidate_cgroup(u, (mask));              \
                                                                        \
                        /* Chop off suffix */                           \
                        assert_se(e = endswith(name, "Scale"));         \
                        name = strndupa(name, e - name);                \
                                                                        \
                        unit_write_settingf(u, flags, name, "%s=%" PRIu32 "%%", name, \
                                            (uint32_t) (DIV_ROUND_UP((uint64_t) raw * 100U, (uint64_t) UINT32_MAX))); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
BUS_DEFINE_SET_CGROUP_WEIGHT(cpu_weight, CGROUP_MASK_CPU, CGROUP_WEIGHT_IS_OK, CGROUP_WEIGHT_INVALID);
BUS_DEFINE_SET_CGROUP_WEIGHT(cpu_shares, CGROUP_MASK_CPU, CGROUP_CPU_SHARES_IS_OK, CGROUP_CPU_SHARES_INVALID);
BUS_DEFINE_SET_CGROUP_WEIGHT(io_weight, CGROUP_MASK_IO, CGROUP_WEIGHT_IS_OK, CGROUP_WEIGHT_INVALID);
BUS_DEFINE_SET_CGROUP_WEIGHT(blockio_weight, CGROUP_MASK_BLKIO, CGROUP_BLKIO_WEIGHT_IS_OK, CGROUP_BLKIO_WEIGHT_INVALID);
BUS_DEFINE_SET_CGROUP_LIMIT(memory, CGROUP_MASK_MEMORY, physical_memory_scale, 1);
BUS_DEFINE_SET_CGROUP_LIMIT(memory_protection, CGROUP_MASK_MEMORY, physical_memory_scale, 0);
BUS_DEFINE_SET_CGROUP_LIMIT(swap, CGROUP_MASK_MEMORY, physical_memory_scale, 0);
BUS_DEFINE_SET_CGROUP_LIMIT(tasks_max, CGROUP_MASK_PIDS, system_tasks_max_scale, 1);
#pragma GCC diagnostic pop

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

        if (streq(name, "MemoryMin"))
                return bus_cgroup_set_memory_protection(u, name, &c->memory_min, message, flags, error);

        if (streq(name, "MemoryLow"))
                return bus_cgroup_set_memory_protection(u, name, &c->memory_low, message, flags, error);

        if (streq(name, "DefaultMemoryMin"))
                return bus_cgroup_set_memory_protection(u, name, &c->default_memory_min, message, flags, error);

        if (streq(name, "DefaultMemoryLow"))
                return bus_cgroup_set_memory_protection(u, name, &c->default_memory_low, message, flags, error);

        if (streq(name, "MemoryHigh"))
                return bus_cgroup_set_memory(u, name, &c->memory_high, message, flags, error);

        if (streq(name, "MemorySwapMax"))
                return bus_cgroup_set_swap(u, name, &c->memory_swap_max, message, flags, error);

        if (streq(name, "MemoryMax"))
                return bus_cgroup_set_memory(u, name, &c->memory_max, message, flags, error);

        if (streq(name, "MemoryLimit"))
                return bus_cgroup_set_memory(u, name, &c->memory_limit, message, flags, error);

        if (streq(name, "MemoryMinScale"))
                return bus_cgroup_set_memory_protection_scale(u, name, &c->memory_min, message, flags, error);

        if (streq(name, "MemoryLowScale"))
                return bus_cgroup_set_memory_protection_scale(u, name, &c->memory_low, message, flags, error);

        if (streq(name, "DefaultMemoryMinScale"))
                return bus_cgroup_set_memory_protection_scale(u, name, &c->default_memory_min, message, flags, error);

        if (streq(name, "DefaultMemoryLowScale"))
                return bus_cgroup_set_memory_protection_scale(u, name, &c->default_memory_low, message, flags, error);

        if (streq(name, "MemoryHighScale"))
                return bus_cgroup_set_memory_scale(u, name, &c->memory_high, message, flags, error);

        if (streq(name, "MemorySwapMaxScale"))
                return bus_cgroup_set_swap_scale(u, name, &c->memory_swap_max, message, flags, error);

        if (streq(name, "MemoryMaxScale"))
                return bus_cgroup_set_memory_scale(u, name, &c->memory_max, message, flags, error);

        if (streq(name, "MemoryLimitScale"))
                return bus_cgroup_set_memory_scale(u, name, &c->memory_limit, message, flags, error);

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
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "CPUQuotaPerSecUSec= value out of range");

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->cpu_quota_per_sec_usec = u64;
                        u->warned_clamping_cpu_quota_period = false;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

                        if (c->cpu_quota_per_sec_usec == USEC_INFINITY)
                                unit_write_setting(u, flags, "CPUQuota", "CPUQuota=");
                        else
                                /* config_parse_cpu_quota() requires an integer, so truncating division is used on
                                 * purpose here. */
                                unit_write_settingf(u, flags, "CPUQuota",
                                                    "CPUQuota=%0.f%%",
                                                    (double) (c->cpu_quota_per_sec_usec / 10000));
                }

                return 1;

        } else if (streq(name, "CPUQuotaPeriodUSec")) {
                uint64_t u64;

                r = sd_bus_message_read(message, "t", &u64);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        c->cpu_quota_period_usec = u64;
                        u->warned_clamping_cpu_quota_period = false;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);
                        if (c->cpu_quota_period_usec == USEC_INFINITY)
                                unit_write_setting(u, flags, "CPUQuotaPeriodSec", "CPUQuotaPeriodSec=");
                        else {
                                char v[FORMAT_TIMESPAN_MAX];
                                unit_write_settingf(u, flags, "CPUQuotaPeriodSec",
                                                    "CPUQuotaPeriodSec=%s",
                                                    format_timespan(v, sizeof(v), c->cpu_quota_period_usec, 1));
                        }
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
                                CGroupIODeviceLimit *a = NULL, *b;

                                LIST_FOREACH(device_limits, b, c->io_device_limits) {
                                        if (path_equal(path, b->path)) {
                                                a = b;
                                                break;
                                        }
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

                                        LIST_PREPEND(device_limits, c->io_device_limits, a);
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
                        CGroupIODeviceLimit *a;
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        size_t size = 0;

                        if (n == 0) {
                                LIST_FOREACH(device_limits, a, c->io_device_limits)
                                        a->limits[iol_type] = cgroup_io_limit_defaults[iol_type];
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = open_memstream_unlocked(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fprintf(f, "%s=\n", name);
                        LIST_FOREACH(device_limits, a, c->io_device_limits)
                                        if (a->limits[iol_type] != cgroup_io_limit_defaults[iol_type])
                                                fprintf(f, "%s=%s %" PRIu64 "\n", name, a->path, a->limits[iol_type]);

                        r = fflush_and_check(f);
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
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "IODeviceWeight= value out of range");

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupIODeviceWeight *a = NULL, *b;

                                LIST_FOREACH(device_weights, b, c->io_device_weights) {
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                break;
                                        }
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
                                        LIST_PREPEND(device_weights, c->io_device_weights, a);
                                }

                                a->weight = weight;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupIODeviceWeight *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->io_device_weights)
                                        cgroup_context_free_io_device_weight(c, c->io_device_weights);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = open_memstream_unlocked(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("IODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->io_device_weights)
                                fprintf(f, "IODeviceWeight=%s %" PRIu64 "\n", a->path, a->weight);

                        r = fflush_and_check(f);
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
                                CGroupIODeviceLatency *a = NULL, *b;

                                LIST_FOREACH(device_latencies, b, c->io_device_latencies) {
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                break;
                                        }
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
                                        LIST_PREPEND(device_latencies, c->io_device_latencies, a);
                                }

                                a->target_usec = target;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        char ts[FORMAT_TIMESPAN_MAX];
                        CGroupIODeviceLatency *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->io_device_latencies)
                                        cgroup_context_free_io_device_latency(c, c->io_device_latencies);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = open_memstream_unlocked(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("IODeviceLatencyTargetSec=\n", f);
                        LIST_FOREACH(device_latencies, a, c->io_device_latencies)
                                fprintf(f, "IODeviceLatencyTargetSec=%s %s\n",
                                        a->path, format_timespan(ts, sizeof(ts), a->target_usec, 1));

                        r = fflush_and_check(f);
                        if (r < 0)
                                return r;
                        unit_write_setting(u, flags, name, buf);
                }

                return 1;

        } else if (STR_IN_SET(name, "BlockIOReadBandwidth", "BlockIOWriteBandwidth")) {
                const char *path;
                bool read = true;
                unsigned n = 0;
                uint64_t u64;

                if (streq(name, "BlockIOWriteBandwidth"))
                        read = false;

                r = sd_bus_message_enter_container(message, 'a', "(st)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(st)", &path, &u64)) > 0) {

                        if (!path_is_normalized(path))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path '%s' specified in %s= is not normalized.", name, path);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupBlockIODeviceBandwidth *a = NULL, *b;

                                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                                        if (path_equal(path, b->path)) {
                                                a = b;
                                                break;
                                        }
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

                                        LIST_PREPEND(device_bandwidths, c->blockio_device_bandwidths, a);
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
                        CGroupBlockIODeviceBandwidth *a;
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        size_t size = 0;

                        if (n == 0) {
                                LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths) {
                                        if (read)
                                                a->rbps = CGROUP_LIMIT_MAX;
                                        else
                                                a->wbps = CGROUP_LIMIT_MAX;
                                }
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        f = open_memstream_unlocked(&buf, &size);
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

                        r = fflush_and_check(f);
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
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "BlockIODeviceWeight= out of range");

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupBlockIODeviceWeight *a = NULL, *b;

                                LIST_FOREACH(device_weights, b, c->blockio_device_weights) {
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                break;
                                        }
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
                                        LIST_PREPEND(device_weights, c->blockio_device_weights, a);
                                }

                                a->weight = weight;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupBlockIODeviceWeight *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->blockio_device_weights)
                                        cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        f = open_memstream_unlocked(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("BlockIODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->blockio_device_weights)
                                fprintf(f, "BlockIODeviceWeight=%s %" PRIu64 "\n", a->path, a->weight);

                        r = fflush_and_check(f);
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
                        return -EINVAL;

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

                        if (!valid_device_allow_pattern(path) || strpbrk(path, WHITESPACE))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "DeviceAllow= requires device node or pattern");

                        if (isempty(rwm))
                                rwm = "rwm";
                        else if (!in_charset(rwm, "rwm"))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "DeviceAllow= requires combination of rwm flags");

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                CGroupDeviceAllow *a = NULL, *b;

                                LIST_FOREACH(device_allow, b, c->device_allow) {
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                break;
                                        }
                                }

                                if (!a) {
                                        a = new0(CGroupDeviceAllow, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }

                                        LIST_PREPEND(device_allow, c->device_allow, a);
                                }

                                a->r = !!strchr(rwm, 'r');
                                a->w = !!strchr(rwm, 'w');
                                a->m = !!strchr(rwm, 'm');
                        }

                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupDeviceAllow *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->device_allow)
                                        cgroup_context_free_device_allow(c, c->device_allow);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_DEVICES);

                        f = open_memstream_unlocked(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("DeviceAllow=\n", f);
                        LIST_FOREACH(device_allow, a, c->device_allow)
                                fprintf(f, "DeviceAllow=%s %s%s%s\n", a->path, a->r ? "r" : "", a->w ? "w" : "", a->m ? "m" : "");

                        r = fflush_and_check(f);
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
                IPAddressAccessItem **list;
                size_t n = 0;

                list = streq(name, "IPAddressAllow") ? &c->ip_address_allow : &c->ip_address_deny;

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
                                IPAddressAccessItem *item;

                                item = new0(IPAddressAccessItem, 1);
                                if (!item)
                                        return -ENOMEM;

                                item->family = family;
                                item->prefixlen = prefixlen;
                                memcpy(&item->address, ap, an);

                                LIST_PREPEND(items, *list, item);
                        }

                        r = sd_bus_message_exit_container(message);
                        if (r < 0)
                                return r;

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                *list = ip_address_access_reduce(*list);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        IPAddressAccessItem *item;
                        size_t size = 0;

                        if (n == 0)
                                *list = ip_address_access_free_all(*list);

                        unit_invalidate_cgroup_bpf(u);
                        f = open_memstream_unlocked(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs(name, f);
                        fputs("=\n", f);

                        LIST_FOREACH(items, item, *list) {
                                char buffer[CONST_MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

                                errno = 0;
                                if (!inet_ntop(item->family, &item->address, buffer, sizeof(buffer)))
                                        return errno_or_else(EINVAL);

                                fprintf(f, "%s=%s/%u\n", name, buffer, item->prefixlen);
                        }

                        r = fflush_and_check(f);
                        if (r < 0)
                                return r;

                        unit_write_setting(u, flags, name, buf);
                }

                return 1;
        }

        if (streq(name, "DisableControllers") || (u->transient && u->load_state == UNIT_STUB))
                return bus_cgroup_set_transient_property(u, c, name, message, flags, error);

        return 0;
}
