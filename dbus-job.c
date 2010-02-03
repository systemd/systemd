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

#include "dbus.h"
#include "log.h"

static const char introspection[] =
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
        "<node>"
        " <interface name=\"org.freedesktop.systemd1.Job\">"
        "  <method name=\"Cancel\"/>"
        "  <property name=\"Id\" type=\"u\" access=\"read\"/>"
        "  <property name=\"Unit\" type=\"(so)\" access=\"read\"/>"
        "  <property name=\"JobType\" type=\"s\" access=\"read\"/>"
        "  <property name=\"State\" type=\"s\" access=\"read\"/>"
        " </interface>"
        BUS_PROPERTIES_INTERFACE
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

static int bus_job_append_state(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Job *j = data;
        const char *state;

        assert(m);
        assert(i);
        assert(property);
        assert(j);

        state = job_state_to_string(j->state);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int bus_job_append_type(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Job *j = data;
        const char *type;

        assert(m);
        assert(i);
        assert(property);
        assert(j);

        type = job_type_to_string(j->type);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &type))
                return -ENOMEM;

        return 0;
}

static int bus_job_append_unit(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Job *j = data;
        DBusMessageIter sub;
        char *p;
        const char *id;

        assert(m);
        assert(i);
        assert(property);
        assert(j);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub))
                return -ENOMEM;

        if (!(p = unit_dbus_path(j->unit)))
                return -ENOMEM;

        id = unit_id(j->unit);

        if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &id) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &p)) {
                free(p);
                return -ENOMEM;
        }

        free(p);

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static DBusHandlerResult bus_job_message_dispatch(Job *j, DBusMessage *message) {
        const BusProperty properties[] = {
                { "org.freedesktop.systemd1.Job", "Id",      bus_property_append_uint32, "u",    &j->id },
                { "org.freedesktop.systemd1.Job", "State",   bus_job_append_state,       "s",    j      },
                { "org.freedesktop.systemd1.Job", "JobType", bus_job_append_type,        "s",    j      },
                { "org.freedesktop.systemd1.Job", "Unit",    bus_job_append_unit,        "(so)", j      },
                { NULL, NULL, NULL, NULL, NULL }
        };

        DBusMessage *reply = NULL;
        Manager *m = j->manager;

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Job", "Cancel")) {
                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                job_free(j);

        } else
                return bus_default_message_handler(j->manager, message, introspection, properties);

        if (reply) {
                if (!dbus_connection_send(m->bus, reply, NULL))
                        goto oom;

                dbus_message_unref(reply);
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

DBusHandlerResult bus_job_message_handler(DBusConnection  *connection, DBusMessage  *message, void *data) {
        Manager *m = data;
        Job *j;
        int r;

        assert(connection);
        assert(message);
        assert(m);

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if ((r = manager_get_job_from_dbus_path(m, dbus_message_get_path(message), &j)) < 0) {

                if (r == -ENOMEM)
                        return DBUS_HANDLER_RESULT_NEED_MEMORY;

                if (r == -ENOENT)
                        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

                return bus_send_error_reply(m, message, NULL, r);
        }

        return bus_job_message_dispatch(j, message);
}

const DBusObjectPathVTable bus_job_vtable = {
        .message_function = bus_job_message_handler
};
