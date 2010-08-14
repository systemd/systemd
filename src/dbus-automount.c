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

#include "dbus-unit.h"
#include "dbus-automount.h"

#define BUS_AUTOMOUNT_INTERFACE                                      \
        " <interface name=\"org.freedesktop.systemd1.Automount\">\n" \
        "  <property name=\"Where\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"DirectoryMode\" type=\"u\" access=\"read\"/>\n" \
        " </interface>\n"

#define INTROSPECTION                                                \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                    \
        "<node>\n"                                                   \
        BUS_UNIT_INTERFACE                                           \
        BUS_AUTOMOUNT_INTERFACE                                      \
        BUS_PROPERTIES_INTERFACE                                     \
        BUS_INTROSPECTABLE_INTERFACE                                 \
        "</node>\n"

const char bus_automount_interface[] = BUS_AUTOMOUNT_INTERFACE;

DBusHandlerResult bus_automount_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Automount", "Where", bus_property_append_string,       "s", u->automount.where           },
                { "org.freedesktop.systemd1.Automount", "DirectoryMode", bus_property_append_mode, "u", &u->automount.directory_mode },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, c, message, INTROSPECTION, properties);
}
