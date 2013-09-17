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

#include "path-util.h"
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
        { "DevicePolicy",            bus_cgroup_append_device_policy,     "s",     offsetof(CGroupContext, device_policy)      },
        { "DeviceAllow",             bus_cgroup_append_device_allow,      "a(ss)", 0                                           },
        {}
};

int bus_cgroup_set_property(
                Unit *u,
                CGroupContext *c,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        assert(name);
        assert(u);
        assert(c);
        assert(i);

        if (streq(name, "CPUAccounting")) {

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_BOOLEAN)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        dbus_bool_t b;
                        dbus_message_iter_get_basic(i, &b);

                        c->cpu_accounting = b;
                        unit_write_drop_in_private(u, mode, name, b ? "CPUAccounting=yes" : "CPUAccounting=no");
                }

                return 1;

        } else if (streq(name, "CPUShares")) {
                uint64_t u64;
                unsigned long ul;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_UINT64)
                        return -EINVAL;

                dbus_message_iter_get_basic(i, &u64);
                ul = (unsigned long) u64;

                if (u64 <= 0 || u64 != (uint64_t) ul)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        c->cpu_shares = ul;
                        unit_write_drop_in_private_format(u, mode, name, "CPUShares=%lu", ul);
                }

                return 1;

        } else if (streq(name, "BlockIOAccounting")) {

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_BOOLEAN)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        dbus_bool_t b;
                        dbus_message_iter_get_basic(i, &b);

                        c->blockio_accounting = b;
                        unit_write_drop_in_private(u, mode, name, b ? "BlockIOAccounting=yes" : "BlockIOAccounting=no");
                }

                return 1;

        } else if (streq(name, "BlockIOWeight")) {
                uint64_t u64;
                unsigned long ul;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_UINT64)
                        return -EINVAL;

                dbus_message_iter_get_basic(i, &u64);
                ul = (unsigned long) u64;

                if (u64 < 10 || u64 > 1000)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        c->blockio_weight = ul;
                        unit_write_drop_in_private_format(u, mode, name, "BlockIOWeight=%lu", ul);
                }

                return 1;

        } else if (streq(name, "BlockIOReadBandwidth") || streq(name, "BlockIOWriteBandwidth")) {
                DBusMessageIter sub;
                unsigned n = 0;
                bool read = true;

                if (streq(name, "BlockIOWriteBandwidth"))
                        read = false;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(i) != DBUS_TYPE_STRUCT)
                         return -EINVAL;

                dbus_message_iter_recurse(i, &sub);
                while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                        DBusMessageIter sub2;
                        const char *path;
                        uint64_t u64;
                        CGroupBlockIODeviceBandwidth *a;

                        dbus_message_iter_recurse(&sub, &sub2);
                        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &u64, false) < 0)
                                return -EINVAL;

                        if (mode != UNIT_CHECK) {
                                CGroupBlockIODeviceBandwidth *b;
                                bool exist = false;

                                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                                        if (path_equal(path, b->path) && read == b->read) {
                                                a = b;
                                                exist = true;
                                                break;
                                        }
                                }

                                if (!exist) {
                                        a = new0(CGroupBlockIODeviceBandwidth, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->read = read;
                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }
                                }

                                a->bandwidth = u64;

                                if (!exist)
                                        LIST_PREPEND(CGroupBlockIODeviceBandwidth, device_bandwidths,
                                                     c->blockio_device_bandwidths, a);
                        }

                        n++;
                        dbus_message_iter_next(&sub);
                }

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupBlockIODeviceBandwidth *a;
                        CGroupBlockIODeviceBandwidth *next;
                        size_t size = 0;

                        if (n == 0) {
                                LIST_FOREACH_SAFE(device_bandwidths, a, next, c->blockio_device_bandwidths)
                                        if (a->read == read)
                                                cgroup_context_free_blockio_device_bandwidth(c, a);
                        }

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
                DBusMessageIter sub;
                unsigned n = 0;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(i) != DBUS_TYPE_STRUCT)
                        return -EINVAL;

                dbus_message_iter_recurse(i, &sub);
                while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                        DBusMessageIter sub2;
                        const char *path;
                        uint64_t u64;
                        unsigned long ul;
                        CGroupBlockIODeviceWeight *a;

                        dbus_message_iter_recurse(&sub, &sub2);

                        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &u64, false) < 0)
                                return -EINVAL;

                        ul = (unsigned long) u64;
                        if (ul < 10 || ul > 1000)
                                return -EINVAL;

                        if (mode != UNIT_CHECK) {
                                CGroupBlockIODeviceWeight *b;
                                bool exist = false;

                                LIST_FOREACH(device_weights, b, c->blockio_device_weights) {
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                exist = true;
                                                break;
                                        }
                                }

                                if (!exist) {
                                        a = new0(CGroupBlockIODeviceWeight, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }
                                }

                                a->weight = ul;

                                if (!exist)
                                        LIST_PREPEND(CGroupBlockIODeviceWeight, device_weights,
                                                     c->blockio_device_weights, a);
                        }

                        n++;
                        dbus_message_iter_next(&sub);
                }

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupBlockIODeviceWeight *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->blockio_device_weights)
                                        cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);
                        }

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("BlockIODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->blockio_device_weights)
                                fprintf(f, "BlockIODeviceWeight=%s %lu\n", a->path, a->weight);

                        fflush(f);
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;

        } else if (streq(name, "MemoryAccounting")) {

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_BOOLEAN)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        dbus_bool_t b;
                        dbus_message_iter_get_basic(i, &b);

                        c->memory_accounting = b;
                        unit_write_drop_in_private(u, mode, name, b ? "MemoryAccounting=yes" : "MemoryAccounting=no");
                }

                return 1;

        } else if (streq(name, "MemoryLimit")) {

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_UINT64)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        uint64_t limit;
                        dbus_message_iter_get_basic(i, &limit);

                        c->memory_limit = limit;
                        unit_write_drop_in_private_format(u, mode, name, "%s=%" PRIu64, name, limit);
                }

                return 1;

        } else if (streq(name, "DevicePolicy")) {
                const char *policy;
                CGroupDevicePolicy p;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_STRING)
                        return -EINVAL;

                dbus_message_iter_get_basic(i, &policy);
                p = cgroup_device_policy_from_string(policy);
                if (p < 0)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        char *buf;

                        c->device_policy = p;

                        buf = strappenda("DevicePolicy=", policy);
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;

        } else if (streq(name, "DeviceAllow")) {
                DBusMessageIter sub;
                unsigned n = 0;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(i) != DBUS_TYPE_STRUCT)
                        return -EINVAL;

                dbus_message_iter_recurse(i, &sub);
                while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                        DBusMessageIter sub2;
                        const char *path, *rwm;
                        CGroupDeviceAllow *a;

                        dbus_message_iter_recurse(&sub, &sub2);

                        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &rwm, false) < 0)
                                return -EINVAL;

                        if (!path_startswith(path, "/dev")) {
                                dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "DeviceAllow= requires device node");
                                return -EINVAL;
                        }

                        if (isempty(rwm))
                                rwm = "rwm";

                        if (!in_charset(rwm, "rwm")) {
                                dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "DeviceAllow= requires combination of rwm flags");
                                return -EINVAL;
                        }

                        if (mode != UNIT_CHECK) {
                                CGroupDeviceAllow *b;
                                bool exist = false;

                                LIST_FOREACH(device_allow, b, c->device_allow) {
                                        if (path_equal(b->path, path)) {
                                                a = b;
                                                exist = true;
                                                break;
                                        }
                                }

                                if (!exist) {
                                        a = new0(CGroupDeviceAllow, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }
                                }

                                a->r = !!strchr(rwm, 'r');
                                a->w = !!strchr(rwm, 'w');
                                a->m = !!strchr(rwm, 'm');

                                if (!exist)
                                        LIST_PREPEND(CGroupDeviceAllow, device_allow, c->device_allow, a);
                        }

                        n++;
                        dbus_message_iter_next(&sub);
                }

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupDeviceAllow *a;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->device_allow)
                                        cgroup_context_free_device_allow(c, c->device_allow);
                        }

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
        }

        return 0;
}
