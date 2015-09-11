/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "bus-util.h"
#include "path-util.h"
#include "cgroup-util.h"
#include "cgroup.h"
#include "dbus-cgroup.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_cgroup_device_policy, cgroup_device_policy, CGroupDevicePolicy);

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

                if (streq(property, "BlockIOReadBandwidth") != b->read)
                        continue;

                r = sd_bus_message_append(reply, "(st)", b->path, b->bandwidth);
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
        SD_BUS_PROPERTY("CPUShares", "t", NULL, offsetof(CGroupContext, cpu_shares), 0),
        SD_BUS_PROPERTY("StartupCPUShares", "t", NULL, offsetof(CGroupContext, startup_cpu_shares), 0),
        SD_BUS_PROPERTY("CPUQuotaPerSecUSec", "t", bus_property_get_usec, offsetof(CGroupContext, cpu_quota_per_sec_usec), 0),
        SD_BUS_PROPERTY("BlockIOAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, blockio_accounting), 0),
        SD_BUS_PROPERTY("BlockIOWeight", "t", NULL, offsetof(CGroupContext, blockio_weight), 0),
        SD_BUS_PROPERTY("StartupBlockIOWeight", "t", NULL, offsetof(CGroupContext, startup_blockio_weight), 0),
        SD_BUS_PROPERTY("BlockIODeviceWeight", "a(st)", property_get_blockio_device_weight, 0, 0),
        SD_BUS_PROPERTY("BlockIOReadBandwidth", "a(st)", property_get_blockio_device_bandwidths, 0, 0),
        SD_BUS_PROPERTY("BlockIOWriteBandwidth", "a(st)", property_get_blockio_device_bandwidths, 0, 0),
        SD_BUS_PROPERTY("MemoryAccounting", "b", bus_property_get_bool, offsetof(CGroupContext, memory_accounting), 0),
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

                if (CGROUP_BLKIO_WEIGHT_IS_OK(weight))
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

        } else if (streq(name, "BlockIOReadBandwidth") || streq(name, "BlockIOWriteBandwidth")) {
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
                                        if (path_equal(path, b->path) && read == b->read) {
                                                a = b;
                                                break;
                                        }
                                }

                                if (!a) {
                                        a = new0(CGroupBlockIODeviceBandwidth, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->read = read;
                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }

                                        LIST_PREPEND(device_bandwidths, c->blockio_device_bandwidths, a);
                                }

                                a->bandwidth = u64;
                        }

                        n++;
                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        CGroupBlockIODeviceBandwidth *a, *next;
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        size_t size = 0;

                        if (n == 0) {
                                LIST_FOREACH_SAFE(device_bandwidths, a, next, c->blockio_device_bandwidths)
                                        if (a->read == read)
                                                cgroup_context_free_blockio_device_bandwidth(c, a);
                        }

                        unit_invalidate_cgroup(u, CGROUP_MASK_BLKIO);

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        if (read) {
                                fputs("BlockIOReadBandwidth=\n", f);
                                LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths)
                                        if (a->read)
                                                fprintf(f, "BlockIOReadBandwidth=%s %" PRIu64 "\n", a->path, a->bandwidth);
                        } else {
                                fputs("BlockIOWriteBandwidth=\n", f);
                                LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths)
                                        if (!a->read)
                                                fprintf(f, "BlockIOWriteBandwidth=%s %" PRIu64 "\n", a->path, a->bandwidth);
                        }

                        fflush(f);
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

                        fflush(f);
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

        } else if (streq(name, "MemoryLimit")) {
                uint64_t limit;

                r = sd_bus_message_read(message, "t", &limit);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->memory_limit = limit;
                        unit_invalidate_cgroup(u, CGROUP_MASK_MEMORY);

                        if (limit == (uint64_t) -1)
                                unit_write_drop_in_private(u, mode, name, "MemoryLimit=infinity");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "MemoryLimit=%" PRIu64, limit);
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
                        char *buf;

                        c->device_policy = p;
                        unit_invalidate_cgroup(u, CGROUP_MASK_DEVICES);

                        buf = strjoina("DevicePolicy=", policy);
                        unit_write_drop_in_private(u, mode, name, buf);
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

                        fflush(f);
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

                if (mode != UNIT_CHECK) {
                        c->tasks_max = limit;
                        unit_invalidate_cgroup(u, CGROUP_MASK_PIDS);

                        if (limit == (uint64_t) -1)
                                unit_write_drop_in_private(u, mode, name, "TasksMax=infinity");
                        else
                                unit_write_drop_in_private_format(u, mode, name, "TasksMax=%" PRIu64, limit);
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
