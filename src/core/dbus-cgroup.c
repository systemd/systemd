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

#include <dbus/dbus.h>

#include "dbus-cgroup.h"

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_cgroup_append_device_policy, cgroup_device_policy, CGroupDevicePolicy);

static int bus_cgroup_append_device_weights(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub, sub2;
        CGroupContext *c = data;
        CGroupBlockIODeviceWeight *w;

        assert(i);
        assert(property);
        assert(c);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(st)", &sub))
                return -ENOMEM;

        LIST_FOREACH(device_weights, w, c->blockio_device_weights) {

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &w->path) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT64, &w->weight) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_cgroup_append_device_bandwidths(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub, sub2;
        CGroupContext *c = data;
        CGroupBlockIODeviceBandwidth *b;

        assert(i);
        assert(property);
        assert(c);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(st)", &sub))
                return -ENOMEM;

        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {

                if (streq(property, "BlockIOReadBandwidth") != b->read)
                        continue;

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &b->path) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT64, &b->bandwidth) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_cgroup_append_device_allow(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub, sub2;
        CGroupContext *c = data;
        CGroupDeviceAllow *a;

        assert(i);
        assert(property);
        assert(c);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(ss)", &sub))
                return -ENOMEM;

        LIST_FOREACH(device_allow, a, c->device_allow) {
                const char *rwm;
                char buf[4];
                unsigned k = 0;

                if (a->r)
                        buf[k++] = 'r';
                if (a->w)
                        buf[k++] = 'w';
                if (a->m)
                        buf[k++] = 'm';

                buf[k] = 0;
                rwm = buf;

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &a->path) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &rwm) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

const BusProperty bus_cgroup_context_properties[] = {
        { "CPUAccounting",           bus_property_append_bool,            "b",     offsetof(CGroupContext, cpu_accounting)     },
        { "CPUShares",               bus_property_append_ul,              "t",     offsetof(CGroupContext, cpu_shares)         },
        { "BlockIOAccounting",       bus_property_append_bool,            "b",     offsetof(CGroupContext, blockio_accounting) },
        { "BlockIOWeight",           bus_property_append_ul,              "t",     offsetof(CGroupContext, blockio_weight)     },
        { "BlockIODeviceWeight",     bus_cgroup_append_device_weights,    "a(st)", 0                                           },
        { "BlockIOReadBandwidth",    bus_cgroup_append_device_bandwidths, "a(st)", 0                                           },
        { "BlockIOWriteBandwidth",   bus_cgroup_append_device_bandwidths, "a(st)", 0                                           },
        { "MemoryAccounting",        bus_property_append_bool,            "b",     offsetof(CGroupContext, memory_accounting)  },
        { "MemoryLimit",             bus_property_append_uint64,          "t",     offsetof(CGroupContext, memory_limit)       },
        { "MemorySoftLimit",         bus_property_append_uint64,          "t",     offsetof(CGroupContext, memory_soft_limit)  },
        { "DevicePolicy",            bus_cgroup_append_device_policy,     "s",     offsetof(CGroupContext, device_policy)      },
        { "DeviceAllow",             bus_cgroup_append_device_allow,      "a(ss)", 0                                           },
        {}
};
