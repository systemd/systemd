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
#include "dbus-automount.h"
#include "dbus-common.h"
#include "selinux-access.h"

#define BUS_AUTOMOUNT_INTERFACE                                      \
        " <interface name=\"org.freedesktop.systemd1.Automount\">\n" \
        "  <property name=\"Where\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"DirectoryMode\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"Result\" type=\"s\" access=\"read\"/>\n"    \
        " </interface>\n"

#define INTROSPECTION                                                \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                    \
        "<node>\n"                                                   \
        BUS_UNIT_INTERFACE                                           \
        BUS_AUTOMOUNT_INTERFACE                                      \
        BUS_PROPERTIES_INTERFACE                                     \
        BUS_PEER_INTERFACE                                           \
        BUS_INTROSPECTABLE_INTERFACE                                 \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Automount\0"

const char bus_automount_interface[] _introspect_("Automount") = BUS_AUTOMOUNT_INTERFACE;

const char bus_automount_invalidating_properties[] =
        "Result\0";

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_automount_append_automount_result, automount_result, AutomountResult);

static const BusProperty bus_automount_properties[] = {
        { "Where",         bus_property_append_string, "s", offsetof(Automount, where),    true },
        { "DirectoryMode", bus_property_append_mode,   "u", offsetof(Automount, directory_mode) },
        { "Result",        bus_automount_append_automount_result, "s", offsetof(Automount, result) },
        { NULL, }
};

DBusHandlerResult bus_automount_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Automount *am = AUTOMOUNT(u);
        const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit",      bus_unit_properties,      u  },
                { "org.freedesktop.systemd1.Automount", bus_automount_properties, am },
                { NULL, }
        };

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
}
