/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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
#include <string.h>

#include "machined.h"
#include "machine.h"
#include "dbus-common.h"

#define BUS_MACHINE_INTERFACE \
        " <interface name=\"org.freedesktop.machine1.Machine\">\n"        \
        "  <method name=\"Terminate\"/>\n"                              \
        "  <method name=\"Kill\">\n"                                    \
        "   <arg name=\"who\" type=\"s\"/>\n"                           \
        "   <arg name=\"signal\" type=\"s\"/>\n"                        \
        "  </method>\n"                                                 \
        "  <property name=\"Name\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Id\" type=\"ay\" access=\"read\"/>\n"        \
        "  <property name=\"Timestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"TimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"Service\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"Scope\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"Leader\" type=\"u\" access=\"read\"/>\n"    \
        "  <property name=\"Class\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"State\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"RootDirectory\" type=\"s\" access=\"read\"/>\n" \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_MACHINE_INTERFACE                                           \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_GENERIC_INTERFACES_LIST                  \
        "org.freedesktop.machine1.Machine\0"

static int bus_machine_append_id(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub;
        Machine *m = data;
        dbus_bool_t b;
        void *p;

        assert(i);
        assert(property);
        assert(m);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "y", &sub))
                return -ENOMEM;

        p = &m->id;
        b = dbus_message_iter_append_fixed_array(&sub, DBUS_TYPE_BYTE, &p, 16);
        if (!b)
                return -ENOMEM;

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_machine_append_state(DBusMessageIter *i, const char *property, void *data) {
        Machine *m = data;
        const char *state;

        assert(i);
        assert(property);
        assert(m);

        state = machine_state_to_string(machine_get_state(m));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int get_machine_for_path(Manager *m, const char *path, Machine **_machine) {
        _cleanup_free_ char *e = NULL;
        Machine *machine;

        assert(m);
        assert(path);
        assert(_machine);

        if (!startswith(path, "/org/freedesktop/machine1/machine/"))
                return -EINVAL;

        e = bus_path_unescape(path + 34);
        if (!e)
                return -ENOMEM;

        machine = hashmap_get(m->machines, e);
        if (!machine)
                return -ENOENT;

        *_machine = machine;
        return 0;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_machine_append_class, machine_class, MachineClass);

static const BusProperty bus_machine_machine_properties[] = {
        { "Name",                   bus_property_append_string,        "s", offsetof(Machine, name),               true },
        { "Id",                     bus_machine_append_id,            "ay", 0 },
        { "Timestamp",              bus_property_append_usec,          "t", offsetof(Machine, timestamp.realtime)  },
        { "TimestampMonotonic",     bus_property_append_usec,          "t", offsetof(Machine, timestamp.monotonic) },
        { "Service",                bus_property_append_string,        "s", offsetof(Machine, service),            true },
        { "Scope",                  bus_property_append_string,        "s", offsetof(Machine, scope),              true },
        { "Leader",                 bus_property_append_pid,           "u", offsetof(Machine, leader)              },
        { "Class",                  bus_machine_append_class,          "s", offsetof(Machine, class)               },
        { "State",                  bus_machine_append_state,          "s", 0                                      },
        { "RootDirectory",          bus_property_append_string,        "s", offsetof(Machine, root_directory),     true },
        { NULL, }
};

static DBusHandlerResult machine_message_dispatch(
                Machine *m,
                DBusConnection *connection,
                DBusMessage *message) {

        DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;

        assert(m);
        assert(connection);
        assert(message);

        if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Machine", "Terminate")) {

                r = machine_stop(m);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Machine", "Kill")) {
                const char *swho;
                int32_t signo;
                KillWho who;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &swho,
                                    DBUS_TYPE_INT32, &signo,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (isempty(swho))
                        who = KILL_ALL;
                else {
                        who = kill_who_from_string(swho);
                        if (who < 0)
                                return bus_send_error_reply(connection, message, &error, -EINVAL);
                }

                if (signo <= 0 || signo >= _NSIG)
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                r = machine_kill(m, who, signo);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else {
                const BusBoundProperties bps[] = {
                        { "org.freedesktop.machine1.Machine", bus_machine_machine_properties, m },
                        { NULL, }
                };

                return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, bps);
        }

        if (reply) {
                if (!bus_maybe_send_reply(connection, message, reply))
                        goto oom;
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult machine_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *manager = userdata;
        Machine *m;
        int r;

        r = get_machine_for_path(manager, dbus_message_get_path(message), &m);
        if (r < 0) {

                if (r == -ENOMEM)
                        return DBUS_HANDLER_RESULT_NEED_MEMORY;

                if (r == -ENOENT) {
                        DBusError e;

                        dbus_error_init(&e);
                        dbus_set_error_const(&e, DBUS_ERROR_UNKNOWN_OBJECT, "Unknown machine");
                        return bus_send_error_reply(connection, message, &e, r);
                }

                return bus_send_error_reply(connection, message, NULL, r);
        }

        return machine_message_dispatch(m, connection, message);
}

const DBusObjectPathVTable bus_machine_vtable = {
        .message_function = machine_message_handler
};

char *machine_bus_path(Machine *m) {
        _cleanup_free_ char *e = NULL;

        assert(m);

        e = bus_path_escape(m->name);
        if (!e)
                return NULL;

        return strappend("/org/freedesktop/machine1/machine/", e);
}

int machine_send_signal(Machine *m, bool new_machine) {
        _cleanup_dbus_message_unref_ DBusMessage *msg = NULL;
        _cleanup_free_ char *p = NULL;

        assert(m);

        msg = dbus_message_new_signal("/org/freedesktop/machine1",
                                    "org.freedesktop.machine1.Manager",
                                    new_machine ? "MachineNew" : "MachineRemoved");

        if (!m)
                return -ENOMEM;

        p = machine_bus_path(m);
        if (!p)
                return -ENOMEM;

        if (!dbus_message_append_args(
                            msg,
                            DBUS_TYPE_STRING, &m->name,
                            DBUS_TYPE_OBJECT_PATH, &p,
                            DBUS_TYPE_INVALID))
                return -ENOMEM;

        if (!dbus_connection_send(m->manager->bus, msg, NULL))
                return -ENOMEM;

        return 0;
}

int machine_send_changed(Machine *m, const char *properties) {
        _cleanup_dbus_message_unref_ DBusMessage *msg = NULL;
        _cleanup_free_ char *p = NULL;

        assert(m);

        if (!m->started)
                return 0;

        p = machine_bus_path(m);
        if (!p)
                return -ENOMEM;

        msg = bus_properties_changed_new(p, "org.freedesktop.machine1.Machine", properties);
        if (!msg)
                return -ENOMEM;

        if (!dbus_connection_send(m->manager->bus, msg, NULL))
                return -ENOMEM;

        return 0;
}

int machine_send_create_reply(Machine *m, DBusError *error) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;

        assert(m);

        if (!m->create_message)
                return 0;

        if (error) {
                DBusError buffer;

                dbus_error_init(&buffer);

                if (!error || !dbus_error_is_set(error)) {
                        dbus_set_error_const(&buffer, DBUS_ERROR_INVALID_ARGS, "Invalid Arguments");
                        error = &buffer;
                }

                reply = dbus_message_new_error(m->create_message, error->name, error->message);
                dbus_error_free(&buffer);

                if (!reply)
                        return log_oom();
        } else {
                _cleanup_free_ char *p = NULL;

                p = machine_bus_path(m);
                if (!p)
                        return log_oom();

                reply = dbus_message_new_method_return(m->create_message);
                if (!reply)
                        return log_oom();

                if (!dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &p, DBUS_TYPE_INVALID))
                        return log_oom();
        }

        /* Update the machine state file before we notify the client
         * about the result. */
        machine_save(m);

        if (!dbus_connection_send(m->manager->bus, reply, NULL))
                return log_oom();

        dbus_message_unref(m->create_message);
        m->create_message = NULL;

        return 0;
}
