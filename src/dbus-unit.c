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
#include "dbus-unit.h"

const char bus_unit_interface[] = BUS_UNIT_INTERFACE;

int bus_unit_append_names(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        char *t;
        Iterator j;
        DBusMessageIter sub;
        Unit *u = data;

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "s", &sub))
                return -ENOMEM;

        SET_FOREACH(t, u->meta.names, j)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &t))
                        return -ENOMEM;

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

int bus_unit_append_dependencies(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u;
        Iterator j;
        DBusMessageIter sub;
        Set *s = data;

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "s", &sub))
                return -ENOMEM;

        SET_FOREACH(u, s, j)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &u->meta.id))
                        return -ENOMEM;

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

int bus_unit_append_description(Manager *m, DBusMessageIter *i, const char *property, void *data) {
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

DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_unit_append_load_state, unit_load_state, UnitLoadState);

int bus_unit_append_active_state(Manager *m, DBusMessageIter *i, const char *property, void *data) {
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

int bus_unit_append_sub_state(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        state = unit_sub_state_to_string(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

int bus_unit_append_can_start(Manager *m, DBusMessageIter *i, const char *property, void *data) {
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

int bus_unit_append_can_reload(Manager *m, DBusMessageIter *i, const char *property, void *data) {
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

int bus_unit_append_job(Manager *m, DBusMessageIter *i, const char *property, void *data) {
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

int bus_unit_append_default_cgroup(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        char *t;
        CGroupBonding *cgb;
        bool success;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        if ((cgb = unit_get_default_cgroup(u))) {
                if (!(t = cgroup_bonding_to_string(cgb)))
                        return -ENOMEM;
        } else
                t = (char*) "";

        success = dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t);

        if (cgb)
                free(t);

        return success ? 0 : -ENOMEM;
}

int bus_unit_append_cgroups(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        CGroupBonding *cgb;
        DBusMessageIter sub;

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "s", &sub))
                return -ENOMEM;

        LIST_FOREACH(by_unit, cgb, u->meta.cgroup_bondings) {
                char *t;
                bool success;

                if (!(t = cgroup_bonding_to_string(cgb)))
                        return -ENOMEM;

                success = dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &t);
                free(t);

                if (!success)
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_unit_append_kill_mode, kill_mode, KillMode);

static DBusHandlerResult bus_unit_message_dispatch(Unit *u, DBusConnection *connection, DBusMessage *message) {
        DBusMessage *reply = NULL;
        Manager *m = u->meta.manager;
        DBusError error;
        JobType job_type = _JOB_TYPE_INVALID;
        char *path = NULL;

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Start"))
                job_type = JOB_START;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Stop"))
                job_type = JOB_STOP;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Reload"))
                job_type = JOB_RELOAD;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Restart"))
                job_type = JOB_RESTART;
        else if (UNIT_VTABLE(u)->bus_message_handler)
                return UNIT_VTABLE(u)->bus_message_handler(u, connection, message);
        else
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

        if (job_type != _JOB_TYPE_INVALID) {
                const char *smode;
                JobMode mode;
                Job *j;
                int r;

                if (job_type == JOB_START && u->meta.only_by_dependency)
                        return bus_send_error_reply(m, connection, message, NULL, -EPERM);

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &smode,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, connection, message, &error, -EINVAL);

                if ((mode = job_mode_from_string(smode)) == _JOB_MODE_INVALID)
                        return bus_send_error_reply(m, connection, message, NULL, -EINVAL);

                if ((r = manager_add_job(m, job_type, u, mode, true, &j)) < 0)
                        return bus_send_error_reply(m, connection, message, NULL, r);

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

        free(path);

        if (reply) {
                if (!dbus_connection_send(connection, reply, NULL))
                        goto oom;

                dbus_message_unref(reply);
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        free(path);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult bus_unit_message_handler(DBusConnection *connection, DBusMessage  *message, void *data) {
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

                return bus_send_error_reply(m, connection, message, NULL, r);
        }

        return bus_unit_message_dispatch(u, connection, message);
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

        if (!bus_has_subscriber(u->meta.manager)) {
                u->meta.sent_dbus_new_signal = true;
                return;
        }

        if (!(p = unit_dbus_path(u)))
                goto oom;

        if (u->meta.sent_dbus_new_signal) {
                /* Send a change signal */

                if (!(m = dbus_message_new_signal(p, "org.freedesktop.systemd1.Unit", "Changed")))
                        goto oom;
        } else {
                /* Send a new signal */

                if (!(m = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "UnitNew")))
                        goto oom;

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &u->meta.id,
                                              DBUS_TYPE_OBJECT_PATH, &p,
                                              DBUS_TYPE_INVALID))
                        goto oom;
        }

        if (bus_broadcast(u->meta.manager, m) < 0)
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

        assert(u);

        if (!bus_has_subscriber(u->meta.manager))
                return;

        if (!u->meta.sent_dbus_new_signal)
                bus_unit_send_change_signal(u);

        if (!(p = unit_dbus_path(u)))
                goto oom;

        if (!(m = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "UnitRemoved")))
                goto oom;

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &u->meta.id,
                                      DBUS_TYPE_OBJECT_PATH, &p,
                                      DBUS_TYPE_INVALID))
                goto oom;

        if (bus_broadcast(u->meta.manager, m) < 0)
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
