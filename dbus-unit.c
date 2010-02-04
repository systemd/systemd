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
        " <interface name=\"org.freedesktop.systemd1.Unit\">"
        "  <method name=\"Start\">"
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"
        "  </method>"
        "  <method name=\"Stop\">"
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"
        "  </method>"
        "  <method name=\"Restart\">"
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"
        "  </method>"
        "  <method name=\"Reload\">"
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"
        "  </method>"
        "  <signal name=\"Changed\"/>"
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>"
        "  <property name=\"Description\" type=\"s\" access=\"read\"/>"
        "  <property name=\"LoadState\" type=\"s\" access=\"read\"/>"
        "  <property name=\"ActiveState\" type=\"s\" access=\"read\"/>"
        "  <property name=\"LoadPath\" type=\"s\" access=\"read\"/>"
        "  <property name=\"ActiveEnterTimestamp\" type=\"t\" access=\"read\"/>"
        "  <property name=\"ActiveExitTimestamp\" type=\"t\" access=\"read\"/>"
        "  <property name=\"CanReload\" type=\"b\" access=\"read\"/>"
        "  <property name=\"CanStart\" type=\"b\" access=\"read\"/>"
        "  <property name=\"Job\" type=\"(uo)\" access=\"read\"/>"
        " </interface>"
        BUS_PROPERTIES_INTERFACE
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

static int bus_unit_append_id(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *id;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        id = unit_id(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &id))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_description(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *d;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        d = unit_description(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_load_state(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        state = unit_load_state_to_string(u->meta.load_state);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_active_state(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        state = unit_active_state_to_string(unit_active_state(u));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_can_reload(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        dbus_bool_t b;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        b = unit_can_reload(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_can_start(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        dbus_bool_t b;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        b = unit_can_start(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_job(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        DBusMessageIter sub;
        char *p;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub))
                return -ENOMEM;

        if (u->meta.job) {

                if (!(p = job_dbus_path(u->meta.job)))
                        return -ENOMEM;

                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &u->meta.job->id) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &p)) {
                        free(p);
                        return -ENOMEM;
                }
        } else {
                uint32_t id = 0;

                /* No job, so let's fill in some placeholder
                 * data. Since we need to fill in a valid path we
                 * simple point to ourselves. */

                if (!(p = unit_dbus_path(u)))
                        return -ENOMEM;

                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &id) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &p)) {
                        free(p);
                        return -ENOMEM;
                }
        }

        free(p);

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static DBusHandlerResult bus_unit_message_dispatch(Unit *u, DBusMessage *message) {

        const BusProperty properties[] = {
                { "org.freedesktop.systemd1.Unit", "Id",                   bus_unit_append_id,           "s",    u                               },
                { "org.freedesktop.systemd1.Unit", "Description",          bus_unit_append_description,  "s",    u                               },
                { "org.freedesktop.systemd1.Unit", "LoadState",            bus_unit_append_load_state,   "s",    u                               },
                { "org.freedesktop.systemd1.Unit", "ActiveState",          bus_unit_append_active_state, "s",    u                               },
                { "org.freedesktop.systemd1.Unit", "LoadPath",             bus_property_append_string,   "s",    u->meta.load_path               },
                { "org.freedesktop.systemd1.Unit", "ActiveEnterTimestamp", bus_property_append_uint64,   "t",    &u->meta.active_enter_timestamp },
                { "org.freedesktop.systemd1.Unit", "ActiveExitTimestamp",  bus_property_append_uint64,   "t",    &u->meta.active_exit_timestamp  },
                { "org.freedesktop.systemd1.Unit", "CanReload",            bus_unit_append_can_reload,   "b",    u                               },
                { "org.freedesktop.systemd1.Unit", "CanStart",             bus_unit_append_can_start,    "b",    u                               },
                { "org.freedesktop.systemd1.Unit", "Job",                  bus_unit_append_job,          "(uo)", u                               },
                { NULL, NULL, NULL, NULL, NULL }
        };

        DBusMessage *reply = NULL;
        Manager *m = u->meta.manager;
        DBusError error;
        JobType job_type = _JOB_TYPE_INVALID;

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Start"))
                job_type = JOB_START;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Stop"))
                job_type = JOB_STOP;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Reload"))
                job_type = JOB_RELOAD;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Restart"))
                job_type = JOB_RESTART;
        else
                return bus_default_message_handler(u->meta.manager, message, introspection, properties);

        if (job_type != _JOB_TYPE_INVALID) {
                const char *smode;
                JobMode mode;
                Job *j;
                int r;
                char *path;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &smode,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, message, &error, -EINVAL);

                if ((mode = job_mode_from_string(smode)) == _JOB_MODE_INVALID)
                        return bus_send_error_reply(m, message, NULL, -EINVAL);

                if ((r = manager_add_job(m, job_type, u, mode, true, &j)) < 0)
                        return bus_send_error_reply(m, message, NULL, r);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = job_dbus_path(j)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;
        }

        if (reply) {
                if (!dbus_connection_send(m->bus, reply, NULL))
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

static DBusHandlerResult bus_unit_message_handler(DBusConnection  *connection, DBusMessage  *message, void *data) {
        Manager *m = data;
        Unit *u;
        int r;

        assert(connection);
        assert(message);
        assert(m);

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if ((r = manager_get_unit_from_dbus_path(m, dbus_message_get_path(message), &u)) < 0) {

                if (r == -ENOMEM)
                        return DBUS_HANDLER_RESULT_NEED_MEMORY;

                if (r == -ENOENT)
                        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

                return bus_send_error_reply(m, message, NULL, r);
        }

        return bus_unit_message_dispatch(u, message);
}

const DBusObjectPathVTable bus_unit_vtable = {
        .message_function = bus_unit_message_handler
};

void bus_unit_send_change_signal(Unit *u) {
        char *p = NULL;
        DBusMessage *m = NULL;

        assert(u);
        assert(u->meta.in_dbus_queue);

        LIST_REMOVE(Meta, dbus_queue, u->meta.manager->dbus_unit_queue, &u->meta);
        u->meta.in_dbus_queue = false;

        if (set_isempty(u->meta.manager->subscribed))
                return;

        if (!(p = unit_dbus_path(u)))
                goto oom;

        if (u->meta.sent_dbus_new_signal) {
                /* Send a change signal */

                if (!(m = dbus_message_new_signal(p, "org.freedesktop.systemd1.Unit", "Changed")))
                        goto oom;
        } else {
                const char *id;
                /* Send a new signal */

                if (!(m = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1", "UnitNew")))
                        goto oom;

                id = unit_id(u);
                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &id,
                                              DBUS_TYPE_OBJECT_PATH, &p,
                                              DBUS_TYPE_INVALID))
                        goto oom;
        }

        if (!dbus_connection_send(u->meta.manager->bus, m, NULL))
                goto oom;

        free(p);
        dbus_message_unref(m);

        u->meta.sent_dbus_new_signal = true;

        return;

oom:
        free(p);

        if (m)
                dbus_message_unref(m);

        log_error("Failed to allocate unit change/new signal.");
}

void bus_unit_send_removed_signal(Unit *u) {
        char *p = NULL;
        DBusMessage *m = NULL;
        const char *id;

        assert(u);

        if (set_isempty(u->meta.manager->subscribed) || !u->meta.sent_dbus_new_signal)
                return;

        if (!(p = unit_dbus_path(u)))
                goto oom;

        if (!(m = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1", "UnitRemoved")))
                goto oom;

        id = unit_id(u);
        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &id,
                                      DBUS_TYPE_OBJECT_PATH, &p,
                                      DBUS_TYPE_INVALID))
                goto oom;

        if (!dbus_connection_send(u->meta.manager->bus, m, NULL))
                goto oom;

        free(p);
        dbus_message_unref(m);

        return;

oom:
        free(p);

        if (m)
                dbus_message_unref(m);

        log_error("Failed to allocate unit remove signal.");
}
