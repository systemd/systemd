/*-*- Mode: C; c-basic-offset: 8 -*-*/

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
#include "dbus-timer.h"
#include "dbus-execute.h"

#define BUS_TIMER_INTERFACE                                             \
        " <interface name=\"org.freedesktop.systemd1.Timer\">\n"        \
        "  <property name=\"Unit\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Timers\" type=\"a(stt)\" access=\"read\"/>\n" \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_UNIT_INTERFACE                                              \
        BUS_TIMER_INTERFACE                                             \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

const char bus_timer_interface[] = BUS_TIMER_INTERFACE;

static int bus_timer_append_timers(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Timer *p = data;
        DBusMessageIter sub, sub2;
        TimerValue *k;

        assert(m);
        assert(i);
        assert(property);
        assert(p);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(stt)", &sub))
                return -ENOMEM;

        LIST_FOREACH(value, k, p->values) {
                const char *t = timer_base_to_string(k->base);

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &t) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT64, &k->value) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT64, &k->next_elapse) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

DBusHandlerResult bus_timer_message_handler(Unit *u, DBusConnection *c, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Timer", "Unit",       bus_property_append_string, "s",      u->timer.unit->meta.id },
                { "org.freedesktop.systemd1.Timer", "Timers",     bus_timer_append_timers,    "a(stt)", u                      },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, c, message, INTROSPECTION, properties);
}
