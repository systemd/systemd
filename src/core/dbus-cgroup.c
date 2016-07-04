/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "cgroup.h"
#include "dbus-cgroup.h"
#include "fd-util.h"
#include "fileio.h"
#include "path-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_cgroup_device_policy, cgroup_device_policy, CGroupDevicePolicy);

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

const sd_bus_vtable bus_cgroup_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Delegate", "b", bus_property_get_bool, offsetof(CGroupContext, delegate), 0),
        SD_BUS_PROPERTY("CPUAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, cpu_accounting), 0),
        SD_BUS_PROPERTY("CPUWeight", "t", NULL, offsetof(CGroupContext, cpu_weight), 0),
        SD_BUS_PROPERTY("StartupCPUWeight", "t", NULL, offsetof(CGroupContext, startup_cpu_weight), 0),
        SD_BUS_PROPERTY("CPUShares", "t", NULL, offsetof(CGroupContext, cpu_shares), 0),
        SD_BUS_PROPERTY("StartupCPUShares", "t", NULL, offsetof(CGroupContext, startup_cpu_shares), 0),
        SD_BUS_PROPERTY("CPUQuotaPerSecUSec", "t", bus_property_get_usec, offsetof(CGroupContext, cpu_quota_per_sec_usec), 0),
        SD_BUS_PROPERTY("IOAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, io_accounting), 0),
        SD_BUS_PROPERTY("IOWeight", "t", NULL, offsetof(CGroupContext, io_weight), 0),
        SD_BUS_PROPERTY("StartupIOWeight", "t", NULL, offsetof(CGroupContext, startup_io_weight), 0),
        SD_BUS_PROPERTY("IODeviceWeight", "a(st)", property_get_io_device_weight, 0, 0),
        SD_BUS_PROPERTY("IOReadBandwidthMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("IOWriteBandwidthMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("IOReadIOPSMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("IOWriteIOPSMax", "a(st)", property_get_io_device_limits, 0, 0),
        SD_BUS_PROPERTY("BlockIOAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, blockio_accounting), 0),
        SD_BUS_PROPERTY("BlockIOWeight", "t", NULL, offsetof(CGroupContext, blockio_weight), 0),
        SD_BUS_PROPERTY("StartupBlockIOWeight", "t", NULL, offsetof(CGroupContext, startup_blockio_weight), 0),
        SD_BUS_PROPERTY("BlockIODeviceWeight", "a(st)", property_get_blockio_device_weight, 0, 0),
        SD_BUS_PROPERTY("BlockIOReadBandwidth", "a(st)", property_get_blockio_device_bandwidths, 0, 0),
        SD_BUS_PROPERTY("BlockIOWriteBandwidth", "a(st)", property_get_blockio_device_bandwidths, 0, 0),
        SD_BUS_PROPERTY("MemoryAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, memory_accounting), 0),
        SD_BUS_PROPERTY("MemoryLow", "t", NULL, offsetof(CGroupContext, memory_low), 0),
        SD_BUS_PROPERTY("MemoryHigh", "t", NULL, offsetof(CGroupContext, memory_high), 0),
        SD_BUS_PROPERTY("MemoryMax", "t", NULL, offsetof(CGroupContext, memory_max), 0),
        SD_BUS_PROPERTY("MemorySwapMax", "t", NULL, offsetof(CGroupContext, memory_swap_max), 0),
        SD_BUS_PROPERTY("MemoryLimit", "t", NULL, offsetof(CGroupContext, memory_limit), 0),
        SD_BUS_PROPERTY("DevicePolicy", "s", property_get_cgroup_device_policy, offsetof(CGroupContext, device_policy), 0),
        SD_BUS_PROPERTY("DeviceAllow", "a(ss)", property_get_device_allow, 0, 0),
        SD_BUS_PROPERTY("TasksAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, tasks_accounting), 0),
        SD_BUS_PROPERTY("TasksMax", "t", NULL, offsetof(CGroupContext, tasks_max), 0),
        SD_BUS_VTABLE_END
};

static int bus_cgroup_set_transient_property(
                Unit *u,
                CGroupContext *c,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        int r;

        assert(u);
        assert(c);
        assert(name);
        assert(message);

        if (streq(name, "Delegate")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->delegate = b;
                        unit_write_drop_in_private(u, mode, name, b ? "Delegate=yes" : "Delegate=no");
                }

                return 1;
        }

        return 0;
}

int bus_cgroup_set_property(
                Unit *u,
                CGroupContext *c,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        CGroupIOLimitType iol_type;
        int r;

        assert(u);
        assert(c);
        assert(name);
        assert(message);

        if (streq(name, "CPUAccounting")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->cpu_accounting = b;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPUACCT|CGROUP_MASK_CPU);
                        unit_write_drop_in_private(u, mode, name, b ? "CPUAccounting=yes" : "CPUAccounting=no");
                }

                return 1;

        } else if (streq(name, "CPUWeight")) {
                uint64_t weight;

                r = sd_bus_message_read(message, "t", &weight);
                if (r < 0)
                        return r;

                if (!CGROUP_WEIGHT_IS_OK(weight))
                        return sd_bus_error_set_errnof(error, EINVAL, "CPUWeight value out of range");

                if (mode != UNIT_CHECK) {
                        c->cpu_weight = weight;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

                        if (weight == CGROUP_WEIGHT_INVALID)
                                unit_write_drop_in_private(u, mode, name, "CPUWeight=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "CPUWeight=%" PRIu64, weight);
                }

                return 1;

        } else if (streq(name, "StartupCPUWeight")) {
                uint64_t weight;

                r = sd_bus_message_read(message, "t", &weight);
                if (r < 0)
                        return r;

                if (!CGROUP_WEIGHT_IS_OK(weight))
                        return sd_bus_error_set_errnof(error, EINVAL, "StartupCPUWeight value out of range");

                if (mode != UNIT_CHECK) {
                        c->startup_cpu_weight = weight;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

                        if (weight == CGROUP_CPU_SHARES_INVALID)
                                unit_write_drop_in_private(u, mode, name, "StartupCPUWeight=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "StartupCPUWeight=%" PRIu64, weight);
                }

                return 1;

        } else if (streq(name, "CPUShares")) {
                uint64_t shares;

                r = sd_bus_message_read(message, "t", &shares);
                if (r < 0)
                        return r;

                if (!CGROUP_CPU_SHARES_IS_OK(shares))
                        return sd_bus_error_set_errnof(error, EINVAL, "CPUShares value out of range");

                if (mode != UNIT_CHECK) {
                        c->cpu_shares = shares;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

                        if (shares == CGROUP_CPU_SHARES_INVALID)
                                unit_write_drop_in_private(u, mode, name, "CPUShares=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "CPUShares=%" PRIu64, shares);
                }

                return 1;

        } else if (streq(name, "StartupCPUShares")) {
                uint64_t shares;

                r = sd_bus_message_read(message, "t", &shares);
                if (r < 0)
                        return r;

                if (!CGROUP_CPU_SHARES_IS_OK(shares))
                        return sd_bus_error_set_errnof(error, EINVAL, "StartupCPUShares value out of range");

                if (mode != UNIT_CHECK) {
                        c->startup_cpu_shares = shares;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);

                        if (shares == CGROUP_CPU_SHARES_INVALID)
                                unit_write_drop_in_private(u, mode, name, "StartupCPUShares=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "StartupCPUShares=%" PRIu64, shares);
                }

                return 1;

        } else if (streq(name, "CPUQuotaPerSecUSec")) {
                uint64_t u64;

                r = sd_bus_message_read(message, "t", &u64);
                if (r < 0)
                        return r;

                if (u64 <= 0)
                        return sd_bus_error_set_errnof(error, EINVAL, "CPUQuotaPerSecUSec value out of range");

                if (mode != UNIT_CHECK) {
                        c->cpu_quota_per_sec_usec = u64;
                        unit_invalidate_cgroup(u, CGROUP_MASK_CPU);
                        unit_write_drop_in_private_format(u, mode, "CPUQuota", "CPUQuota=%0.f%%", (double) (c->cpu_quota_per_sec_usec / 10000));
                }

                return 1;

        } else if (streq(name, "IOAccounting")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->io_accounting = b;
                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);
                        unit_write_drop_in_private(u, mode, name, b ? "IOAccounting=yes" : "IOAccounting=no");
                }

                return 1;

        } else if (streq(name, "IOWeight")) {
                uint64_t weight;

                r = sd_bus_message_read(message, "t", &weight);
                if (r < 0)
                        return r;

                if (!CGROUP_WEIGHT_IS_OK(weight))
                        return sd_bus_error_set_errnof(error, EINVAL, "IOWeight value out of range");

                if (mode != UNIT_CHECK) {
                        c->io_weight = weight;
                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        if (weight == CGROUP_WEIGHT_INVALID)
                                unit_write_drop_in_private(u, mode, name, "IOWeight=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "IOWeight=%" PRIu64, weight);
                }

                return 1;

        } else if (streq(name, "StartupIOWeight")) {
                uint64_t weight;

                r = sd_bus_message_read(message, "t", &weight);
                if (r < 0)
                        return r;

                if (CGROUP_WEIGHT_IS_OK(weight))
                        return sd_bus_error_set_errnof(error, EINVAL, "StartupIOWeight value out of range");

                if (mode != UNIT_CHECK) {
                        c->startup_io_weight = weight;
                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        if (weight == CGROUP_WEIGHT_INVALID)
                                unit_write_drop_in_private(u, mode, name, "StartupIOWeight=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "StartupIOWeight=%" PRIu64, weight);
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

                        if (mode != UNIT_CHECK) {
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

                if (mode != UNIT_CHECK) {
                        CGroupIODeviceLimit *a;
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        size_t size = 0;

                        if (n == 0) {
                                LIST_FOREACH(device_limits, a, c->io_device_limits)
                                        a->limits[iol_type] = cgroup_io_limit_defaults[iol_type];
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fprintf(f, "%s=\n", name);
                        LIST_FOREACH(device_limits, a, c->io_device_limits)
                                        if (a->limits[iol_type] != cgroup_io_limit_defaults[iol_type])
                                                fprintf(f, "%s=%s %" PRIu64 "\n", name, a->path, a->limits[iol_type]);

                        r = fflush_and_check(f);
                        if (r < 0)
                                return r;
                        unit_write_drop_in_private(u, mode, name, buf);
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

                        if (!CGROUP_WEIGHT_IS_OK(weight) || weight == CGROUP_WEIGHT_INVALID)
                                return sd_bus_error_set_errnof(error, EINVAL, "IODeviceWeight out of range");

                        if (mode != UNIT_CHECK) {
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
                                        LIST_PREPEND(device_weights,c->io_device_weights, a);
                                }

                                a->weight = weight;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupIODeviceWeight *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->io_device_weights)
                                        cgroup_context_free_io_device_weight(c, c->io_device_weights);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_IO);

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("IODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->io_device_weights)
                                fprintf(f, "IODeviceWeight=%s %" PRIu64 "\n", a->path, a->weight);

                        r = fflush_and_check(f);
                        if (r < 0)
                                return r;
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;

        } else if (streq(name, "BlockIOAccounting")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->blockio_accounting = b;
                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);
                        unit_write_drop_in_private(u, mode, name, b ? "BlockIOAccounting=yes" : "BlockIOAccounting=no");
                }

                return 1;

        } else if (streq(name, "BlockIOWeight")) {
                uint64_t weight;

                r = sd_bus_message_read(message, "t", &weight);
                if (r < 0)
                        return r;

                if (!CGROUP_BLKIO_WEIGHT_IS_OK(weight))
                        return sd_bus_error_set_errnof(error, EINVAL, "BlockIOWeight value out of range");

                if (mode != UNIT_CHECK) {
                        c->blockio_weight = weight;
                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        if (weight == CGROUP_BLKIO_WEIGHT_INVALID)
                                unit_write_drop_in_private(u, mode, name, "BlockIOWeight=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "BlockIOWeight=%" PRIu64, weight);
                }

                return 1;

        } else if (streq(name, "StartupBlockIOWeight")) {
                uint64_t weight;

                r = sd_bus_message_read(message, "t", &weight);
                if (r < 0)
                        return r;

                if (!CGROUP_BLKIO_WEIGHT_IS_OK(weight))
                        return sd_bus_error_set_errnof(error, EINVAL, "StartupBlockIOWeight value out of range");

                if (mode != UNIT_CHECK) {
                        c->startup_blockio_weight = weight;
                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        if (weight == CGROUP_BLKIO_WEIGHT_INVALID)
                                unit_write_drop_in_private(u, mode, name, "StartupBlockIOWeight=");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "StartupBlockIOWeight=%" PRIu64, weight);
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

                        if (mode != UNIT_CHECK) {
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

                if (mode != UNIT_CHECK) {
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

                        f = open_memstream(&buf, &size);
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
                        unit_write_drop_in_private(u, mode, name, buf);
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

                        if (!CGROUP_BLKIO_WEIGHT_IS_OK(weight) || weight == CGROUP_BLKIO_WEIGHT_INVALID)
                                return sd_bus_error_set_errnof(error, EINVAL, "BlockIODeviceWeight out of range");

                        if (mode != UNIT_CHECK) {
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
                                        LIST_PREPEND(device_weights,c->blockio_device_weights, a);
                                }

                                a->weight = weight;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupBlockIODeviceWeight *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->blockio_device_weights)
                                        cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("BlockIODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->blockio_device_weights)
                                fprintf(f, "BlockIODeviceWeight=%s %" PRIu64 "\n", a->path, a->weight);

                        r = fflush_and_check(f);
                        if (r < 0)
                                return r;
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;

        } else if (streq(name, "MemoryAccounting")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->memory_accounting = b;
                        unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);
                        unit_write_drop_in_private(u, mode, name, b ? "MemoryAccounting=yes" : "MemoryAccounting=no");
                }

                return 1;

        } else if (STR_IN_SET(name, "MemoryLow", "MemoryHigh", "MemoryMax", "MemorySwapMax")) {
                uint64_t v;

                r = sd_bus_message_read(message, "t", &v);
                if (r < 0)
                        return r;
                if (v <= 0)
                        return sd_bus_error_set_errnof(error, EINVAL, "%s= is too small", name);

                if (mode != UNIT_CHECK) {
                        if (streq(name, "MemoryLow"))
                                c->memory_low = v;
                        else if (streq(name, "MemoryHigh"))
                                c->memory_high = v;
                        else if (streq(name, "MemorySwapMax"))
                                c->memory_swap_max = v;
                        else
                                c->memory_max = v;

                        unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);

                        if (v == CGROUP_LIMIT_MAX)
                                unit_write_drop_in_private_format(u, mode, name, "%s=infinity", name);
                        else
                                unit_write_drop_in_private_format(u, mode, name, "%s=%" PRIu64, name, v);
                }

                return 1;

        } else if (STR_IN_SET(name, "MemoryLowScale", "MemoryHighScale", "MemoryMaxScale")) {
                uint32_t raw;
                uint64_t v;

                r = sd_bus_message_read(message, "u", &raw);
                if (r < 0)
                        return r;

                v = physical_memory_scale(raw, UINT32_MAX);
                if (v <= 0 || v == UINT64_MAX)
                        return sd_bus_error_set_errnof(error, EINVAL, "%s= is out of range", name);

                if (mode != UNIT_CHECK) {
                        const char *e;

                        /* Chop off suffix */
                        assert_se(e = endswith(name, "Scale"));
                        name = strndupa(name, e - name);

                        if (streq(name, "MemoryLow"))
                                c->memory_low = v;
                        else if (streq(name, "MemoryHigh"))
                                c->memory_high = v;
                        else
                                c->memory_max = v;

                        unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);
                        unit_write_drop_in_private_format(u, mode, name, "%s=%" PRIu32 "%%", name,
                                                          (uint32_t) (DIV_ROUND_UP((uint64_t) raw * 100U, (uint64_t) UINT32_MAX)));
                }

                return 1;

        } else if (streq(name, "MemoryLimit")) {
                uint64_t limit;

                r = sd_bus_message_read(message, "t", &limit);
                if (r < 0)
                        return r;
                if (limit <= 0)
                        return sd_bus_error_set_errnof(error, EINVAL, "%s= is too small", name);

                if (mode != UNIT_CHECK) {
                        c->memory_limit = limit;
                        unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);

                        if (limit == (uint64_t) -1)
                                unit_write_drop_in_private(u, mode, name, "MemoryLimit=infinity");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "MemoryLimit=%" PRIu64, limit);
                }

                return 1;

        } else if (streq(name, "MemoryLimitScale")) {
                uint64_t limit;
                uint32_t raw;

                r = sd_bus_message_read(message, "u", &raw);
                if (r < 0)
                        return r;

                limit = physical_memory_scale(raw, UINT32_MAX);
                if (limit <= 0 || limit == UINT64_MAX)
                        return sd_bus_error_set_errnof(error, EINVAL, "%s= is out of range", name);

                if (mode != UNIT_CHECK) {
                        c->memory_limit = limit;
                        unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);
                        unit_write_drop_in_private_format(u, mode, "MemoryLimit", "MemoryLimit=%" PRIu32 "%%",
                                                          (uint32_t) (DIV_ROUND_UP((uint64_t) raw * 100U, (uint64_t) UINT32_MAX)));
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

                if (mode != UNIT_CHECK) {
                        c->device_policy = p;
                        unit_invalidate_cgroup(u, CGROUP_MASK_DEVICES);
                        unit_write_drop_in_private_format(u, mode, name, "DevicePolicy=%s", policy);
                }

                return 1;

        } else if (streq(name, "DeviceAllow")) {
                const char *path, *rwm;
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "(ss)");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "(ss)", &path, &rwm)) > 0) {

                        if ((!startswith(path, "/dev/") &&
                             !startswith(path, "/run/systemd/inaccessible/") &&
                             !startswith(path, "block-") &&
                             !startswith(path, "char-")) ||
                            strpbrk(path, WHITESPACE))
                            return sd_bus_error_set_errnof(error, EINVAL, "DeviceAllow= requires device node");

                        if (isempty(rwm))
                                rwm = "rwm";

                        if (!in_charset(rwm, "rwm"))
                                return sd_bus_error_set_errnof(error, EINVAL, "DeviceAllow= requires combination of rwm flags");

                        if (mode != UNIT_CHECK) {
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

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupDeviceAllow *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->device_allow)
                                        cgroup_context_free_device_allow(c, c->device_allow);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_DEVICES);

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("DeviceAllow=\n", f);
                        LIST_FOREACH(device_allow, a, c->device_allow)
                                fprintf(f, "DeviceAllow=%s %s%s%s\n", a->path, a->r ? "r" : "", a->w ? "w" : "", a->m ? "m" : "");

                        r = fflush_and_check(f);
                        if (r < 0)
                                return r;
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;

        } else if (streq(name, "TasksAccounting")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->tasks_accounting = b;
                        unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);
                        unit_write_drop_in_private(u, mode, name, b ? "TasksAccounting=yes" : "TasksAccounting=no");
                }

                return 1;

        } else if (streq(name, "TasksMax")) {
                uint64_t limit;

                r = sd_bus_message_read(message, "t", &limit);
                if (r < 0)
                        return r;
                if (limit <= 0)
                        return sd_bus_error_set_errnof(error, EINVAL, "%s= is too small", name);

                if (mode != UNIT_CHECK) {
                        c->tasks_max = limit;
                        unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);

                        if (limit == (uint64_t) -1)
                                unit_write_drop_in_private(u, mode, name, "TasksMax=infinity");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "TasksMax=%" PRIu64, limit);
                }

                return 1;
        } else if (streq(name, "TasksMaxScale")) {
                uint64_t limit;
                uint32_t raw;

                r = sd_bus_message_read(message, "u", &raw);
                if (r < 0)
                        return r;

                limit = system_tasks_max_scale(raw, UINT32_MAX);
                if (limit <= 0 || limit >= UINT64_MAX)
                        return sd_bus_error_set_errnof(error, EINVAL, "%s= is out of range", name);

                if (mode != UNIT_CHECK) {
                        c->tasks_max = limit;
                        unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);
                        unit_write_drop_in_private_format(u, mode, name, "TasksMax=%" PRIu32 "%%",
                                                          (uint32_t) (DIV_ROUND_UP((uint64_t) raw * 100U, (uint64_t) UINT32_MAX)));
                }

                return 1;
        }

        if (u->transient && u->load_state == UNIT_STUB) {
                r = bus_cgroup_set_transient_property(u, c, name, message, mode, error);
                if (r != 0)
                        return r;

        }

        return 0;
}
