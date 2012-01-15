/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>

#include "dbus-unit.h"
#include "dbus-path.h"
#include "dbus-execute.h"
#include "dbus-common.h"

#define BUS_PATH_INTERFACE                                              \
        " <interface name=\"org.freedesktop.systemd1.Path\">\n"         \
        "  <property name=\"Unit\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Paths\" type=\"a(ss)\" access=\"read\"/>\n" \
        "  <property name=\"MakeDirectory\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"DirectoryMode\" type=\"u\" access=\"read\"/>\n" \
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
        Unit *u = data;
        Path *p = PATH(u);
        const char *t;

        assert(i);
        assert(property);
        assert(u);

        t = UNIT_DEREF(p->unit) ? UNIT_DEREF(p->unit)->id : "";

        return dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t) ? 0 : -ENOMEM;
}

DBusHandlerResult bus_path_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Path *p = PATH(u);
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Path", "Unit",          bus_path_append_unit,     "s",     u                   },
                { "org.freedesktop.systemd1.Path", "Paths",         bus_path_append_paths,    "a(ss)", u                   },
                { "org.freedesktop.systemd1.Path", "MakeDirectory", bus_property_append_bool, "b",     &p->make_directory  },
                { "org.freedesktop.systemd1.Path", "DirectoryMode", bus_property_append_mode, "u",     &p->directory_mode  },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, properties);
}
