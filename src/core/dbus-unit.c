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

#include "dbus.h"
#include "log.h"
#include "dbus-unit.h"
#include "bus-errors.h"
#include "dbus-common.h"
#include "selinux-access.h"
#include "cgroup-util.h"
#include "strv.h"
#include "path-util.h"
#include "fileio.h"

const char bus_unit_interface[] _introspect_("Unit") = BUS_UNIT_INTERFACE;

#define INVALIDATING_PROPERTIES                 \
        "LoadState\0"                           \
        "ActiveState\0"                         \
        "SubState\0"                            \
        "InactiveExitTimestamp\0"               \
        "ActiveEnterTimestamp\0"                \
        "ActiveExitTimestamp\0"                 \
        "InactiveEnterTimestamp\0"              \
        "Job\0"                                 \
        "NeedDaemonReload\0"

static int bus_unit_append_names(DBusMessageIter *i, const char *property, void *data) {
        char *t;
        Iterator j;
        DBusMessageIter sub;
        Unit *u = data;

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "s", &sub))
                return -ENOMEM;

        SET_FOREACH(t, u->names, j)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &t))
                        return -ENOMEM;

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_following(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data, *f;
        const char *d;

        assert(i);
        assert(property);
        assert(u);

        f = unit_following(u);
        d = f ? f->id : "";

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_slice(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *d;

        assert(i);
        assert(property);
        assert(u);

        d = strempty(unit_slice_name(u));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_dependencies(DBusMessageIter *i, const char *property, void *data) {
        Unit *u;
        Iterator j;
        DBusMessageIter sub;
        Set *s = data;

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "s", &sub))
                return -ENOMEM;

        SET_FOREACH(u, s, j)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &u->id))
                        return -ENOMEM;

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_description(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *d;

        assert(i);
        assert(property);
        assert(u);

        d = unit_description(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_unit_append_load_state, unit_load_state, UnitLoadState);

static int bus_unit_append_active_state(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(i);
        assert(property);
        assert(u);

        state = unit_active_state_to_string(unit_active_state(u));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_sub_state(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(i);
        assert(property);
        assert(u);

        state = unit_sub_state_to_string(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_file_state(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(i);
        assert(property);
        assert(u);

        state = strempty(unit_file_state_to_string(unit_get_unit_file_state(u)));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_can_start(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(u);

        b = unit_can_start(u) &&
                !u->refuse_manual_start;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_can_stop(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(u);

        /* On the lower levels we assume that every unit we can start
         * we can also stop */

        b = unit_can_start(u) &&
                !u->refuse_manual_stop;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_can_reload(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(u);

        b = unit_can_reload(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_can_isolate(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(u);

        b = unit_can_isolate(u) &&
                !u->refuse_manual_start;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_job(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        DBusMessageIter sub;
        _cleanup_free_ char *p = NULL;

        assert(i);
        assert(property);
        assert(u);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub))
                return -ENOMEM;

        if (u->job) {

                p = job_dbus_path(u->job);
                if (!p)
                        return -ENOMEM;

                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &u->job->id) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &p))
                        return -ENOMEM;
        } else {
                uint32_t id = 0;

                /* No job, so let's fill in some placeholder
                 * data. Since we need to fill in a valid path we
                 * simple point to ourselves. */

                p = unit_dbus_path(u);
                if (!p)
                        return -ENOMEM;

                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &id) ||
                    !dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &p))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_need_daemon_reload(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        dbus_bool_t b;

        assert(i);
        assert(property);
        assert(u);

        b = unit_need_daemon_reload(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &b))
                return -ENOMEM;

        return 0;
}

static int bus_property_append_condition(DBusMessageIter *i, const char *property, void *data) {
        Condition **cp = data;
        Condition *c;
        const char *name, *param;
        dbus_bool_t trigger, negate;
        dbus_int32_t state;
        DBusMessageIter sub;

        assert(i);
        assert(property);
        assert(cp);

        c = *cp;
        assert(c);

        name = condition_type_to_string(c->type);
        param = c->parameter;
        trigger = c->trigger;
        negate = c->negate;
        state = c->state;

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &name) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_BOOLEAN, &trigger) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_BOOLEAN, &negate) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &param) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &state) ||
            !dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_property_append_condition_list(DBusMessageIter *i, const char *property, void *data) {
        Condition **first = data, *c;
        DBusMessageIter sub;

        assert(i);
        assert(data);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "(sbbsi)", &sub))
                return -ENOMEM;

        LIST_FOREACH(conditions, c, *first)
                bus_property_append_condition(&sub, property, &c);

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_load_error(DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *name, *message;
        DBusMessageIter sub;

        assert(i);
        assert(property);
        assert(u);

        if (u->load_error != 0) {
                name = bus_errno_to_dbus(u->load_error);
                message = strempty(strerror(-u->load_error));
        } else
                name = message = "";

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_STRUCT, NULL, &sub) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &name) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &message) ||
            !dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

static DBusHandlerResult bus_unit_message_dispatch(Unit *u, DBusConnection *connection, DBusMessage *message) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusError error;
        JobType job_type = _JOB_TYPE_INVALID;
        bool reload_if_possible = false;
        int r;

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Start"))
                job_type = JOB_START;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Stop"))
                job_type = JOB_STOP;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Reload"))
                job_type = JOB_RELOAD;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Restart"))
                job_type = JOB_RESTART;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "TryRestart"))
                job_type = JOB_TRY_RESTART;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "ReloadOrRestart")) {
                reload_if_possible = true;
                job_type = JOB_RESTART;
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "ReloadOrTryRestart")) {
                reload_if_possible = true;
                job_type = JOB_TRY_RESTART;
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "Kill")) {
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

                SELINUX_UNIT_ACCESS_CHECK(u, connection, message, "stop");

                r = unit_kill(u, who, signo, &error);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "ResetFailed")) {

                SELINUX_UNIT_ACCESS_CHECK(u, connection, message, "reload");

                unit_reset_failed(u);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Unit", "SetProperties")) {
                DBusMessageIter iter;
                dbus_bool_t runtime;

                if (!dbus_message_iter_init(message, &iter))
                        goto oom;

                if (bus_iter_get_basic_and_next(&iter, DBUS_TYPE_BOOLEAN, &runtime, true) < 0)
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                SELINUX_UNIT_ACCESS_CHECK(u, connection, message, "start");

                r = bus_unit_set_properties(u, &iter, runtime ? UNIT_RUNTIME : UNIT_PERSISTENT, true, &error);
                if (r < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (UNIT_VTABLE(u)->bus_message_handler)
                return UNIT_VTABLE(u)->bus_message_handler(u, connection, message);
        else
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

        if (job_type != _JOB_TYPE_INVALID) {
                const char *smode;
                JobMode mode;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &smode,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                mode = job_mode_from_string(smode);
                if (mode < 0) {
                        dbus_set_error(&error, BUS_ERROR_INVALID_JOB_MODE, "Job mode %s is invalid.", smode);
                        return bus_send_error_reply(connection, message, &error, -EINVAL);
                }

                return bus_unit_queue_job(connection, message, u, job_type, mode, reload_if_possible);
        }

        if (reply)
                if (!bus_maybe_send_reply(connection, message, reply))
                        goto oom;

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult bus_unit_message_handler(DBusConnection *connection, DBusMessage  *message, void *data) {
        Manager *m = data;
        Unit *u;
        int r;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusError error;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        if (streq(dbus_message_get_path(message), "/org/freedesktop/systemd1/unit")) {
                /* Be nice to gdbus and return introspection data for our mid-level paths */

                SELINUX_ACCESS_CHECK(connection, message, "status");

                if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                        char *introspection = NULL;
                        FILE *f;
                        Iterator i;
                        const char *k;
                        size_t size;

                        reply = dbus_message_new_method_return(message);
                        if (!reply)
                                goto oom;

                        /* We roll our own introspection code here, instead of
                         * relying on bus_default_message_handler() because we
                         * need to generate our introspection string
                         * dynamically. */

                        f = open_memstream(&introspection, &size);
                        if (!f)
                                goto oom;

                        fputs(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
                              "<node>\n", f);

                        fputs(BUS_INTROSPECTABLE_INTERFACE, f);
                        fputs(BUS_PEER_INTERFACE, f);

                        HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                                char *p;

                                if (k != u->id)
                                        continue;

                                p = bus_path_escape(k);
                                if (!p) {
                                        fclose(f);
                                        free(introspection);
                                        goto oom;
                                }

                                fprintf(f, "<node name=\"%s\"/>", p);
                                free(p);
                        }

                        fputs("</node>\n", f);

                        if (ferror(f)) {
                                fclose(f);
                                free(introspection);
                                goto oom;
                        }

                        fclose(f);

                        if (!introspection)
                                goto oom;

                        if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection, DBUS_TYPE_INVALID)) {
                                free(introspection);
                                goto oom;
                        }

                        free(introspection);

                        if (!bus_maybe_send_reply(connection, message, reply))
                                goto oom;

                        return DBUS_HANDLER_RESULT_HANDLED;
                }

                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

        r = manager_load_unit_from_dbus_path(m, dbus_message_get_path(message), &error, &u);
        if (r == -ENOMEM)
                goto oom;
        if (r < 0)
                return bus_send_error_reply(connection, message, &error, r);

        return bus_unit_message_dispatch(u, connection, message);

oom:
        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

const DBusObjectPathVTable bus_unit_vtable = {
        .message_function = bus_unit_message_handler
};

void bus_unit_send_change_signal(Unit *u) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(u);

        if (u->in_dbus_queue) {
                LIST_REMOVE(Unit, dbus_queue, u->manager->dbus_unit_queue, u);
                u->in_dbus_queue = false;
        }

        if (!u->id)
                return;

        if (!bus_has_subscriber(u->manager)) {
                u->sent_dbus_new_signal = true;
                return;
        }

        p = unit_dbus_path(u);
        if (!p) {
                log_oom();
                return;
        }

        if (u->sent_dbus_new_signal) {
                /* Send a properties changed signal. First for the
                 * specific type, then for the generic unit. The
                 * clients may rely on this order to get atomic
                 * behavior if needed. */

                if (UNIT_VTABLE(u)->bus_invalidating_properties) {

                        m = bus_properties_changed_new(p,
                                                       UNIT_VTABLE(u)->bus_interface,
                                                       UNIT_VTABLE(u)->bus_invalidating_properties);
                        if (!m) {
                                log_oom();
                                return;
                        }

                        r = bus_broadcast(u->manager, m);
                        if (r < 0) {
                                log_error("Failed to broadcast change message: %s", strerror(-r));
                                return;
                        }

                        dbus_message_unref(m);
                }

                m = bus_properties_changed_new(p, "org.freedesktop.systemd1.Unit",
                                               INVALIDATING_PROPERTIES);
                if (!m) {
                        log_oom();
                        return;
                }

        } else {
                /* Send a new signal */

                m = dbus_message_new_signal("/org/freedesktop/systemd1",
                                            "org.freedesktop.systemd1.Manager",
                                            "UnitNew");
                if (!m) {
                        log_oom();
                        return;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &u->id,
                                              DBUS_TYPE_OBJECT_PATH, &p,
                                              DBUS_TYPE_INVALID)) {
                        log_oom();
                        return;
                }
        }

        r = bus_broadcast(u->manager, m);
        if (r < 0) {
                log_error("Failed to broadcast UnitNew/PropertiesChanged message.");
                return;
        }

        u->sent_dbus_new_signal = true;
}

void bus_unit_send_removed_signal(Unit *u) {
        _cleanup_free_ char *p = NULL;
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;

        assert(u);

        if (!bus_has_subscriber(u->manager))
                return;

        if (!u->sent_dbus_new_signal)
                bus_unit_send_change_signal(u);

        if (!u->id)
                return;

        p = unit_dbus_path(u);
        if (!p)
                goto oom;

        m = dbus_message_new_signal("/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "UnitRemoved");
        if (!m)
                goto oom;

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &u->id,
                                      DBUS_TYPE_OBJECT_PATH, &p,
                                      DBUS_TYPE_INVALID))
                goto oom;

        if (bus_broadcast(u->manager, m) < 0)
                goto oom;

        return;

oom:
        log_oom();
}

DBusHandlerResult bus_unit_queue_job(
                DBusConnection *connection,
                DBusMessage *message,
                Unit *u,
                JobType type,
                JobMode mode,
                bool reload_if_possible) {

        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ char *path = NULL;
        Job *j;
        JobBusClient *cl;
        DBusError error;
        int r;

        assert(connection);
        assert(message);
        assert(u);
        assert(type >= 0 && type < _JOB_TYPE_MAX);
        assert(mode >= 0 && mode < _JOB_MODE_MAX);

        dbus_error_init(&error);

        if (reload_if_possible && unit_can_reload(u)) {
                if (type == JOB_RESTART)
                        type = JOB_RELOAD_OR_START;
                else if (type == JOB_TRY_RESTART)
                        type = JOB_RELOAD;
        }

        SELINUX_UNIT_ACCESS_CHECK(u, connection, message,
                                  (type == JOB_START || type == JOB_RESTART || type == JOB_TRY_RESTART) ? "start" :
                                  type == JOB_STOP ? "stop" : "reload");

        if (type == JOB_STOP && (u->load_state == UNIT_NOT_FOUND || u->load_state == UNIT_ERROR) && unit_active_state(u) == UNIT_INACTIVE) {
                dbus_set_error(&error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", u->id);
                return bus_send_error_reply(connection, message, &error, -EPERM);
        }

        if ((type == JOB_START && u->refuse_manual_start) ||
            (type == JOB_STOP && u->refuse_manual_stop) ||
            ((type == JOB_RESTART || type == JOB_TRY_RESTART) && (u->refuse_manual_start || u->refuse_manual_stop))) {
                dbus_set_error(&error, BUS_ERROR_ONLY_BY_DEPENDENCY,
                               "Operation refused, unit %s may be requested by dependency only.", u->id);
                return bus_send_error_reply(connection, message, &error, -EPERM);
        }

        r = manager_add_job(u->manager, type, u, mode, true, &error, &j);
        if (r < 0)
                return bus_send_error_reply(connection, message, &error, r);

        cl = job_bus_client_new(connection, bus_message_get_sender_with_fallback(message));
        if (!cl)
                goto oom;

        LIST_PREPEND(JobBusClient, client, j->bus_client_list, cl);

        reply = dbus_message_new_method_return(message);
        if (!reply)
                goto oom;

        path = job_dbus_path(j);
        if (!path)
                goto oom;

        if (!dbus_message_append_args(
                            reply,
                            DBUS_TYPE_OBJECT_PATH, &path,
                            DBUS_TYPE_INVALID))
                goto oom;

        if (!bus_maybe_send_reply(connection, message, reply))
                goto oom;

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static int bus_unit_set_transient_property(
                Unit *u,
                const char *name,
                DBusMessageIter *i,
                UnitSetPropertiesMode mode,
                DBusError *error) {

        int r;

        assert(u);
        assert(name);
        assert(i);

        if (streq(name, "Description")) {
                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_STRING)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        const char *description;

                        dbus_message_iter_get_basic(i, &description);

                        r = unit_set_description(u, description);
                        if (r < 0)
                                return r;

                        unit_write_drop_in_format(u, mode, name, "[Unit]\nDescription=%s\n", description);
                }

                return 1;

        } else if (streq(name, "Slice") && unit_get_cgroup_context(u)) {
                const char *s;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_STRING)
                        return -EINVAL;

                dbus_message_iter_get_basic(i, &s);

                if (isempty(s)) {
                        if (mode != UNIT_CHECK) {
                                unit_ref_unset(&u->slice);
                                unit_remove_drop_in(u, mode, name);
                        }
                } else {
                        Unit *slice;

                        r = manager_load_unit(u->manager, s, NULL, error, &slice);
                        if (r < 0)
                                return r;

                        if (slice->type != UNIT_SLICE)
                                return -EINVAL;

                        if (mode != UNIT_CHECK) {
                                unit_ref_set(&u->slice, slice);
                                unit_write_drop_in_private_format(u, mode, name, "Slice=%s\n", s);
                        }
                }

                return 1;

        } else if (streq(name, "Requires") ||
                   streq(name, "RequiresOverridable") ||
                   streq(name, "Requisite") ||
                   streq(name, "RequisiteOverridable") ||
                   streq(name, "Wants") ||
                   streq(name, "BindsTo") ||
                   streq(name, "Conflicts") ||
                   streq(name, "Before") ||
                   streq(name, "After") ||
                   streq(name, "OnFailure") ||
                   streq(name, "PropagatesReloadTo") ||
                   streq(name, "ReloadPropagatedFrom") ||
                   streq(name, "PartOf")) {

                UnitDependency d;
                DBusMessageIter sub;

                d = unit_dependency_from_string(name);
                if (d < 0)
                        return -EINVAL;

                if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(i) != DBUS_TYPE_STRING)
                        return -EINVAL;

                dbus_message_iter_recurse(i, &sub);
                while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING) {
                        const char *other;

                        dbus_message_iter_get_basic(&sub, &other);

                        if (!unit_name_is_valid(other, false))
                                return -EINVAL;

                        if (mode != UNIT_CHECK) {
                                _cleanup_free_ char *label = NULL;

                                r = unit_add_dependency_by_name(u, d, other, NULL, true);
                                if (r < 0)
                                        return r;

                                label = strjoin(name, "-", other, NULL);
                                if (!label)
                                        return -ENOMEM;

                                unit_write_drop_in_format(u, mode, label, "[Unit]\n%s=%s\n", name, other);
                        }

                        dbus_message_iter_next(&sub);
                }

                return 1;
        }

        return 0;
}

int bus_unit_set_properties(
                Unit *u,
                DBusMessageIter *iter,
                UnitSetPropertiesMode mode,
                bool commit,
                DBusError *error) {

        bool for_real = false;
        DBusMessageIter sub;
        unsigned n = 0;
        int r;

        assert(u);
        assert(iter);

        if (u->transient)
                mode &= UNIT_RUNTIME;

        /* We iterate through the array twice. First run we just check
         * if all passed data is valid, second run actually applies
         * it. This is to implement transaction-like behaviour without
         * actually providing full transactions. */

        if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(iter) != DBUS_TYPE_STRUCT)
                return -EINVAL;

        dbus_message_iter_recurse(iter, &sub);
        for (;;) {
                DBusMessageIter sub2, sub3;
                const char *name;

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_INVALID) {

                        if (for_real || mode == UNIT_CHECK)
                                break;

                        /* Reached EOF. Let's try again, and this time for realz... */
                        dbus_message_iter_recurse(iter, &sub);
                        for_real = true;
                        continue;
                }

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT)
                        return -EINVAL;

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0 ||
                    dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT)
                        return -EINVAL;

                if (!UNIT_VTABLE(u)->bus_set_property) {
                        dbus_set_error(error, DBUS_ERROR_PROPERTY_READ_ONLY, "Objects of this type do not support setting properties.");
                        return -ENOENT;
                }

                dbus_message_iter_recurse(&sub2, &sub3);
                r = UNIT_VTABLE(u)->bus_set_property(u, name, &sub3, for_real ? mode : UNIT_CHECK, error);
                if (r == 0 && u->transient && u->load_state == UNIT_STUB)
                        r = bus_unit_set_transient_property(u, name, &sub3, for_real ? mode : UNIT_CHECK, error);
                if (r < 0)
                        return r;
                if (r == 0) {
                        dbus_set_error(error, DBUS_ERROR_PROPERTY_READ_ONLY, "Cannot set property %s, or unknown property.", name);
                        return -ENOENT;
                }

                dbus_message_iter_next(&sub);

                n += for_real;
        }

        if (commit && n > 0 && UNIT_VTABLE(u)->bus_commit_properties)
                UNIT_VTABLE(u)->bus_commit_properties(u);

        return n;
}

const BusProperty bus_unit_properties[] = {
        { "Id",                              bus_property_append_string,                "s", offsetof(Unit, id),                                         true },
        { "Names",                           bus_unit_append_names,                    "as", 0                                                                },
        { "Following",                       bus_unit_append_following,                 "s", 0                                                                },
        { "Requires",                        bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_REQUIRES]),                true },
        { "RequiresOverridable",             bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_REQUIRES_OVERRIDABLE]),    true },
        { "Requisite",                       bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_REQUISITE]),               true },
        { "RequisiteOverridable",            bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_REQUISITE_OVERRIDABLE]),   true },
        { "Wants",                           bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_WANTS]),                   true },
        { "BindsTo",                         bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_BINDS_TO]),                true },
        { "PartOf",                          bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_PART_OF]),                 true },
        { "RequiredBy",                      bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_REQUIRED_BY]),             true },
        { "RequiredByOverridable",           bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_REQUIRED_BY_OVERRIDABLE]), true },
        { "WantedBy",                        bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_WANTED_BY]),               true },
        { "BoundBy",                         bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_BOUND_BY]),                true },
        { "ConsistsOf",                      bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_CONSISTS_OF]),             true },
        { "Conflicts",                       bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_CONFLICTS]),               true },
        { "ConflictedBy",                    bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_CONFLICTED_BY]),           true },
        { "Before",                          bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_BEFORE]),                  true },
        { "After",                           bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_AFTER]),                   true },
        { "OnFailure",                       bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_ON_FAILURE]),              true },
        { "Triggers",                        bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_TRIGGERS]),                true },
        { "TriggeredBy",                     bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_TRIGGERED_BY]),            true },
        { "PropagatesReloadTo",              bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_PROPAGATES_RELOAD_TO]),    true },
        { "ReloadPropagatedFrom",            bus_unit_append_dependencies,             "as", offsetof(Unit, dependencies[UNIT_RELOAD_PROPAGATED_FROM]),  true },
        { "RequiresMountsFor",               bus_property_append_strv,                 "as", offsetof(Unit, requires_mounts_for),                        true },
        { "Documentation",                   bus_property_append_strv,                 "as", offsetof(Unit, documentation),                              true },
        { "Description",                     bus_unit_append_description,               "s", 0                                                                },
        { "LoadState",                       bus_unit_append_load_state,                "s", offsetof(Unit, load_state)                                       },
        { "ActiveState",                     bus_unit_append_active_state,              "s", 0                                                                },
        { "SubState",                        bus_unit_append_sub_state,                 "s", 0                                                                },
        { "FragmentPath",                    bus_property_append_string,                "s", offsetof(Unit, fragment_path),                              true },
        { "SourcePath",                      bus_property_append_string,                "s", offsetof(Unit, source_path),                                true },
        { "DropInPaths",                     bus_property_append_strv,                 "as", offsetof(Unit, dropin_paths),                               true },
        { "UnitFileState",                   bus_unit_append_file_state,                "s", 0                                                                },
        { "InactiveExitTimestamp",           bus_property_append_usec,                  "t", offsetof(Unit, inactive_exit_timestamp.realtime)                 },
        { "InactiveExitTimestampMonotonic",  bus_property_append_usec,                  "t", offsetof(Unit, inactive_exit_timestamp.monotonic)                },
        { "ActiveEnterTimestamp",            bus_property_append_usec,                  "t", offsetof(Unit, active_enter_timestamp.realtime)                  },
        { "ActiveEnterTimestampMonotonic",   bus_property_append_usec,                  "t", offsetof(Unit, active_enter_timestamp.monotonic)                 },
        { "ActiveExitTimestamp",             bus_property_append_usec,                  "t", offsetof(Unit, active_exit_timestamp.realtime)                   },
        { "ActiveExitTimestampMonotonic",    bus_property_append_usec,                  "t", offsetof(Unit, active_exit_timestamp.monotonic)                  },
        { "InactiveEnterTimestamp",          bus_property_append_usec,                  "t", offsetof(Unit, inactive_enter_timestamp.realtime)                },
        { "InactiveEnterTimestampMonotonic", bus_property_append_usec,                  "t", offsetof(Unit, inactive_enter_timestamp.monotonic)               },
        { "CanStart",                        bus_unit_append_can_start,                 "b", 0                                                                },
        { "CanStop",                         bus_unit_append_can_stop,                  "b", 0                                                                },
        { "CanReload",                       bus_unit_append_can_reload,                "b", 0                                                                },
        { "CanIsolate",                      bus_unit_append_can_isolate,               "b", 0                                                                },
        { "Job",                             bus_unit_append_job,                    "(uo)", 0                                                                },
        { "StopWhenUnneeded",                bus_property_append_bool,                  "b", offsetof(Unit, stop_when_unneeded)                               },
        { "RefuseManualStart",               bus_property_append_bool,                  "b", offsetof(Unit, refuse_manual_start)                              },
        { "RefuseManualStop",                bus_property_append_bool,                  "b", offsetof(Unit, refuse_manual_stop)                               },
        { "AllowIsolate",                    bus_property_append_bool,                  "b", offsetof(Unit, allow_isolate)                                    },
        { "DefaultDependencies",             bus_property_append_bool,                  "b", offsetof(Unit, default_dependencies)                             },
        { "OnFailureIsolate",                bus_property_append_bool,                  "b", offsetof(Unit, on_failure_isolate)                               },
        { "IgnoreOnIsolate",                 bus_property_append_bool,                  "b", offsetof(Unit, ignore_on_isolate)                                },
        { "IgnoreOnSnapshot",                bus_property_append_bool,                  "b", offsetof(Unit, ignore_on_snapshot)                               },
        { "NeedDaemonReload",                bus_unit_append_need_daemon_reload,        "b", 0                                                                },
        { "JobTimeoutUSec",                  bus_property_append_usec,                  "t", offsetof(Unit, job_timeout)                                      },
        { "ConditionTimestamp",              bus_property_append_usec,                  "t", offsetof(Unit, condition_timestamp.realtime)                     },
        { "ConditionTimestampMonotonic",     bus_property_append_usec,                  "t", offsetof(Unit, condition_timestamp.monotonic)                    },
        { "ConditionResult",                 bus_property_append_bool,                  "b", offsetof(Unit, condition_result)                                 },
        { "Conditions",                      bus_property_append_condition_list, "a(sbbsi)", offsetof(Unit, conditions)                                       },
        { "LoadError",                       bus_unit_append_load_error,             "(ss)", 0                                                                },
        { "Transient",                       bus_property_append_bool,                  "b", offsetof(Unit, transient)                                        },
        {}
};

const BusProperty bus_unit_cgroup_properties[] = {
        { "Slice",                bus_unit_append_slice,              "s", 0 },
        { "ControlGroup",         bus_property_append_string,         "s", offsetof(Unit, cgroup_path),                                true },
        {}
};
