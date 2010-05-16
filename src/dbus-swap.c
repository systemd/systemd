/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2010 Maarten Lankhorst

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
#include "dbus-swap.h"

static const char introspection[] =
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
        "<node>"
        BUS_UNIT_INTERFACE
        BUS_PROPERTIES_INTERFACE
        " <interface name=\"org.freedesktop.systemd1.Swap\">"
        "  <property name=\"What\" type=\"s\" access=\"read\"/>"
        "  <property name=\"Priority\" type=\"i\" access=\"read\"/>"
        " </interface>"
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

static int bus_swap_append_priority(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Swap *s = data;
        dbus_int32_t j;

        assert(m);
        assert(i);
        assert(property);
        assert(s);

        if (s->from_proc_swaps)
                j = s->parameters_proc_swaps.priority;
        else if (s->from_fragment)
                j = s->parameters_fragment.priority;
        else if (s->from_etc_fstab)
                j = s->parameters_etc_fstab.priority;
        else
                j = -1;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_INT32, &j))
                return -ENOMEM;

        return 0;
}

DBusHandlerResult bus_swap_message_handler(Unit *u, DBusMessage *message) {
        const BusProperty properties[] = {
                BUS_UNIT_PROPERTIES,
                { "org.freedesktop.systemd1.Swap", "What",     bus_property_append_string, "s", u->swap.what },
                { "org.freedesktop.systemd1.Swap", "Priority", bus_swap_append_priority,   "i", u            },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, message, introspection, properties);
}
