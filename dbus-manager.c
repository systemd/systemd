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
#include "dbus-manager.h"

#define INTROSPECTION_BEGIN                                             \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>"                                                        \
        " <interface name=\"org.freedesktop.systemd1.Manager\">"        \
        "  <method name=\"GetUnit\">"                                   \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>"           \
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>"          \
        "  </method>"                                                   \
        "  <method name=\"LoadUnit\">"                                  \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>"           \
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>"          \
        "  </method>"                                                   \
        "  <method name=\"GetJob\">"                                    \
        "   <arg name=\"id\" type=\"u\" direction=\"in\"/>"             \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"           \
        "  </method>"                                                   \
        "  <method name=\"ClearJobs\"/>"                                \
        "  <method name=\"ListUnits\">"                                 \
        "   <arg name=\"units\" type=\"a(sssssouso)\" direction=\"out\"/>" \
        "  </method>"                                                   \
        "  <method name=\"ListJobs\">"                                  \
        "   <arg name=\"jobs\" type=\"a(usssoo)\" direction=\"out\"/>"  \
        "  </method>"                                                   \
        "  <method name=\"Subscribe\"/>"                                \
        "  <method name=\"Unsubscribe\"/>"                              \
        "  <method name=\"Dump\"/>"                                     \
        "  <method name=\"CreateSnapshot\">"                            \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>"           \
        "   <arg nane=\"cleanup\" type=\"b\" direction=\"in\"/>"        \
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>"          \
        "  </method>"                                                   \
        "  <signal name=\"UnitNew\">"                                   \
        "   <arg name=\"id\" type=\"s\"/>"                              \
        "   <arg name=\"unit\" type=\"o\"/>"                            \
        "  </signal>"                                                   \
        "  <signal name=\"UnitRemoved\">"                               \
        "   <arg name=\"id\" type=\"s\"/>"                              \
        "   <arg name=\"unit\" type=\"o\"/>"                            \
        "  </signal>"                                                   \
        "  <signal name=\"JobNew\">"                                    \
        "   <arg name=\"id\" type=\"u\"/>"                              \
        "   <arg name=\"job\" type=\"o\"/>"                             \
        "  </signal>"                                                   \
        "  <signal name=\"JobRemoved\">"                                \
        "   <arg name=\"id\" type=\"u\"/>"                              \
        "   <arg name=\"job\" type=\"o\"/>"                             \
        "  </signal>"                                                   \
        "  <property name=\"Version\" type=\"s\" access=\"read\"/>"     \
        "  <property name=\"RunningAs\" type=\"s\" access=\"read\"/>"   \
        "  <property name=\"BootTimestamp\" type=\"t\" access=\"read\"/>" \
        "  <property name=\"LogLevel\" type=\"s\" access=\"readwrite\"/>" \
        "  <property name=\"LogTarget\" type=\"s\" access=\"readwrite\"/>" \
        " </interface>"                                                 \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE

#define INTROSPECTION_END                                               \
        "</node>"

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_manager_append_running_as, manager_running_as, ManagerRunningAs);

static int bus_manager_append_log_target(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        const char *t;

        assert(m);
        assert(i);
        assert(property);

        t = log_target_to_string(log_get_target());

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t))
                return -ENOMEM;

        return 0;
}

static int bus_manager_append_log_level(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        const char *t;

        assert(m);
        assert(i);
        assert(property);

        t = log_level_to_string(log_get_max_level());

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t))
                return -ENOMEM;

        return 0;
}

static DBusHandlerResult bus_manager_message_handler(DBusConnection  *connection, DBusMessage *message, void *data) {
        Manager *m = data;

        const BusProperty properties[] = {
                { "org.freedesktop.systemd1.Manager", "Version",       bus_property_append_string,    "s", PACKAGE_STRING     },
                { "org.freedesktop.systemd1.Manager", "RunningAs",     bus_manager_append_running_as, "s", &m->running_as     },
                { "org.freedesktop.systemd1.Manager", "BootTimestamp", bus_property_append_uint64,    "t", &m->boot_timestamp },
                { "org.freedesktop.systemd1.Manager", "LogLevel",      bus_manager_append_log_level,  "s", NULL               },
                { "org.freedesktop.systemd1.Manager", "LogTarget",     bus_manager_append_log_target, "s", NULL               },
                { NULL, NULL, NULL, NULL, NULL }
        };

        int r;
        DBusError error;
        DBusMessage *reply = NULL;
        char * path = NULL;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "GetUnit")) {
                const char *name;
                Unit *u;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, message, &error, -EINVAL);

                if (!(u = manager_get_unit(m, name)))
                        return bus_send_error_reply(m, message, NULL, -ENOENT);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = unit_dbus_path(u)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "LoadUnit")) {
                const char *name;
                Unit *u;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, message, &error, -EINVAL);

                if ((r = manager_load_unit(m, name, NULL, &u)) < 0)
                        return bus_send_error_reply(m, message, NULL, r);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = unit_dbus_path(u)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1", "GetJob")) {
                uint32_t id;
                Job *j;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &id,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, message, &error, -EINVAL);

                if (!(j = manager_get_job(m, id)))
                        return bus_send_error_reply(m, message, NULL, -ENOENT);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = job_dbus_path(j)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ClearJobs")) {

                manager_clear_jobs(m);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ListUnits")) {
                DBusMessageIter iter, sub;
                Iterator i;
                Unit *u;
                const char *k;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sssssouso)", &sub))
                        goto oom;

                HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                        char *u_path, *j_path;
                        const char *description, *load_state, *active_state, *sub_state, *job_type;
                        DBusMessageIter sub2;
                        uint32_t job_id;

                        if (k != u->meta.id)
                                continue;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        description = unit_description(u);
                        load_state = unit_load_state_to_string(u->meta.load_state);
                        active_state = unit_active_state_to_string(unit_active_state(u));
                        sub_state = unit_sub_state_to_string(u);

                        if (!(u_path = unit_dbus_path(u)))
                                goto oom;

                        if (u->meta.job) {
                                job_id = (uint32_t) u->meta.job->id;

                                if (!(j_path = job_dbus_path(u->meta.job))) {
                                        free(u_path);
                                        goto oom;
                                }

                                job_type = job_type_to_string(u->meta.job->type);
                        } else {
                                job_id = 0;
                                j_path = u_path;
                                job_type = "";
                        }

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &u->meta.id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &description) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &load_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &active_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &sub_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &u_path) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &job_id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &job_type) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &j_path)) {
                                free(u_path);
                                if (u->meta.job)
                                        free(j_path);
                                goto oom;
                        }

                        free(u_path);
                        if (u->meta.job)
                                free(j_path);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ListJobs")) {
                DBusMessageIter iter, sub;
                Iterator i;
                Job *j;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(usssoo)", &sub))
                        goto oom;

                HASHMAP_FOREACH(j, m->jobs, i) {
                        char *u_path, *j_path;
                        const char *state, *type;
                        uint32_t id;
                        DBusMessageIter sub2;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        id = (uint32_t) j->id;
                        state = job_state_to_string(j->state);
                        type = job_type_to_string(j->type);

                        if (!(j_path = job_dbus_path(j)))
                                goto oom;

                        if (!(u_path = unit_dbus_path(j->unit))) {
                                free(j_path);
                                goto oom;
                        }

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &j->unit->meta.id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &type) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &j_path) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &u_path)) {
                                free(j_path);
                                free(u_path);
                                goto oom;
                        }

                        free(j_path);
                        free(u_path);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Subscribe")) {
                char *client;

                if (!(client = strdup(dbus_message_get_sender(message))))
                        goto oom;

                r = set_put(m->subscribed, client);

                if (r < 0)
                        return bus_send_error_reply(m, message, NULL, r);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Unsubscribe")) {
                char *client;

                if (!(client = set_remove(m->subscribed, (char*) dbus_message_get_sender(message))))
                        return bus_send_error_reply(m, message, NULL, -ENOENT);

                free(client);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Dump")) {
                FILE *f;
                char *dump = NULL;
                size_t size;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(f = open_memstream(&dump, &size)))
                        goto oom;

                manager_dump_units(m, f, NULL);
                manager_dump_jobs(m, f, NULL);

                if (ferror(f)) {
                        fclose(f);
                        free(dump);
                        goto oom;
                }

                fclose(f);

                if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &dump, DBUS_TYPE_INVALID)) {
                        free(dump);
                        goto oom;
                }

                free(dump);
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "CreateSnapshot")) {
                const char *name;
                dbus_bool_t cleanup;
                Snapshot *s;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_BOOLEAN, &cleanup,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, message, &error, -EINVAL);

                if (name && name[0] == 0)
                        name = NULL;

                if ((r = snapshot_create(m, name, cleanup, &s)) < 0)
                        return bus_send_error_reply(m, message, NULL, r);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = unit_dbus_path(UNIT(s))))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                char *introspection = NULL;
                FILE *f;
                Iterator i;
                Unit *u;
                Job *j;
                const char *k;
                size_t size;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                /* We roll our own introspection code here, instead of
                 * relying on bus_default_message_handler() because we
                 * need to generate our introspection string
                 * dynamically. */

                if (!(f = open_memstream(&introspection, &size)))
                        goto oom;

                fputs(INTROSPECTION_BEGIN, f);

                HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                        char *p;

                        if (k != u->meta.id)
                                continue;

                        if (!(p = bus_path_escape(k))) {
                                fclose(f);
                                free(introspection);
                                goto oom;
                        }

                        fprintf(f, "<node name=\"unit/%s\"/>", p);
                        free(p);
                }

                HASHMAP_FOREACH(j, m->jobs, i)
                        fprintf(f, "<node name=\"job/%lu\"/>", (unsigned long) j->id);

                fputs(INTROSPECTION_END, f);

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

        } else
                return bus_default_message_handler(m, message, NULL, properties);

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

const DBusObjectPathVTable bus_manager_vtable = {
        .message_function = bus_manager_message_handler
};
