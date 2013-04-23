/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>

#include "dbus-unit.h"
#include "dbus-path.h"
#include "dbus-execute.h"
#include "dbus-common.h"
#include "selinux-access.h"

#define BUS_PATH_INTERFACE                                              \
        " <interface name=\"org.freedesktop.systemd1.Path\">\n"         \
        "  <property name=\"Unit\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Paths\" type=\"a(ss)\" access=\"read\"/>\n" \
        "  <property name=\"MakeDirectory\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"DirectoryMode\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"Result\" type=\"s\" access=\"read\"/>\n"    \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_PATH_INTERFACE                                              \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Path\0"

const char bus_path_interface[] _introspect_("Path") = BUS_PATH_INTERFACE;

const char bus_path_invalidating_properties[] =
        "Result\0";

static int bus_path_append_paths(DBusMessageIter *i, const char *property, void *data) {
        Path *p = data;
        DBusMessageIter sub, sub2;
        PathSpec *k;

        assert(i);
        assert(property);
        assert(p);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(ss)", &sub))
                return -ENOMEM;

        LIST_FOREACH(spec, k, p->specs) {
                const char *t = path_type_to_string(k->type);

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &t) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &k->path) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_path_append_unit(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data, *trigger;
        const char *t;

        assert(i);
        assert(property);
        assert(u);

        trigger = UNIT_TRIGGER(u);
        t = trigger ? trigger->id : "";

        return dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t) ? 0 : -ENOMEM;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_path_append_path_result, path_result, PathResult);

static const BusProperty bus_path_properties[] = {
        { "Unit",          bus_path_append_unit,      "s", 0 },
        { "Paths",         bus_path_append_paths, "a(ss)", 0 },
        { "MakeDirectory", bus_property_append_bool,  "b", offsetof(Path, make_directory) },
        { "DirectoryMode", bus_property_append_mode,  "u", offsetof(Path, directory_mode) },
        { "Result",        bus_path_append_path_result, "s", offsetof(Path, result) },
        { NULL, }
};

DBusHandlerResult bus_path_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Path *p = PATH(u);
        const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit", bus_unit_properties, u },
                { "org.freedesktop.systemd1.Path", bus_path_properties, p },
                { NULL, }
        };

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
}
