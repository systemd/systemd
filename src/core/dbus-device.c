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

#include "dbus-unit.h"
#include "dbus-device.h"
#include "dbus-common.h"
#include "selinux-access.h"

#define BUS_DEVICE_INTERFACE                                            \
        " <interface name=\"org.freedesktop.systemd1.Device\">\n"       \
        "  <property name=\"SysFSPath\" type=\"s\" access=\"read\"/>\n" \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_DEVICE_INTERFACE                                            \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_UNIT_INTERFACES_LIST                     \
        "org.freedesktop.systemd1.Device\0"

const char bus_device_interface[] _introspect_("Device") = BUS_DEVICE_INTERFACE;

const char bus_device_invalidating_properties[] =
        "SysFSPath\0";

static const BusProperty bus_device_properties[] = {
        { "SysFSPath", bus_property_append_string, "s", offsetof(Device, sysfs), true },
        { NULL, }
};


DBusHandlerResult bus_device_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        Device *d = DEVICE(u);
        const BusBoundProperties bps[] = {
                { "org.freedesktop.systemd1.Unit",   bus_unit_properties,   u },
                { "org.freedesktop.systemd1.Device", bus_device_properties, d },
                { NULL, }
        };

        SELINUX_UNIT_ACCESS_CHECK(u, c, message, "status");

        return bus_default_message_handler(c, message, INTROSPECTION, INTERFACES_LIST, bps);
}
