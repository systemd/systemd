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
#include "dbus-snapshot.h"

#define BUS_SNAPSHOT_INTERFACE                                          \
        " <interface name=\"org.freedesktop.systemd1.Snapshot\">\n"     \
        "  <method name=\"Remove\"/>\n"                                 \
        "  <property name=\"Cleanup\" type=\"b\" access=\"read\"/>\n"   \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_SNAPSHOT_INTERFACE                                          \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

const char bus_snapshot_interface[] = BUS_SNAPSHOT_INTERFACE;

DBusHandlerResult bus_snapshot_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Snapshot", "Cleanup", bus_property_append_bool, "b", &u->snapshot.cleanup },
                { NULL, NULL, NULL, NULL, NULL }
        };

        DBusMessage *reply = NULL;
        DBusError error;

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Snapshot", "Remove")) {

                snapshot_remove(SNAPSHOT(u));

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else
                return bus_default_message_handler(u->meta.manager, c, message, INTROSPECTION, properties);

        if (reply) {
                if (!dbus_connection_send(c, reply, NULL))
                        goto oom;

                dbus_message_unref(reply);
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}
