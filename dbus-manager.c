/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "dbus.h"
#include "log.h"

#define INTROSPECTION_BEGIN                                             \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>"                                                        \
        " <interface name=\"org.freedesktop.systemd1\">"                \
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
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>"          \
        "  </method>"                                                   \
        "  <method name=\"ClearJobs\"/>"                                \
        "  <method name=\"ListUnits\">"                                 \
        "   <arg name=\"units\" type=\"a(ssssouso)\" direction=\"out\"/>" \
        "  </method>"                                                   \
        "  <method name=\"ListJobs\">"                                  \
        "   <arg name=\"jobs\" type=\"a(usssoo)\" direction=\"out\"/>"  \
        "  </method>"                                                   \
        " </interface>"                                                 \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE

#define INTROSPECTION_END                                               \
        "</node>"

DBusHandlerResult bus_manager_message_handler(DBusConnection  *connection, DBusMessage *message, void *data) {
        int r;
        Manager *m = data;
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

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1", "GetUnit")) {
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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1", "LoadUnit")) {
                const char *name;
                Unit *u;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, message, &error, -EINVAL);

                if ((r = manager_load_unit(m, name, &u)) < 0)
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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1",  "GetJob")) {
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

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1",  "ClearJobs")) {

                manager_clear_jobs(m);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1",  "ListUnits")) {
                DBusMessageIter iter, sub;
                Iterator i;
                Unit *u;
                const char *k;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssssouso)", &sub))
                        goto oom;

                HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                        char *unit_path, *job_path;
                        const char *id, *description, *load_state, *active_state, *job_type;
                        DBusMessageIter sub2;
                        uint32_t job_id;

                        id = unit_id(u);
                        if (k != id)
                                continue;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        description = unit_description(u);
                        load_state = unit_load_state_to_string(u->meta.load_state);
                        active_state = unit_active_state_to_string(unit_active_state(u));

                        if (!(unit_path = unit_dbus_path(u)))
                                goto oom;

                        if (u->meta.job) {
                                job_id = (uint32_t) u->meta.job->id;

                                if (!(job_path = job_dbus_path(u->meta.job))) {
                                        free(unit_path);
                                        goto oom;
                                }

                                job_type = job_type_to_string(u->meta.job->state);
                        } else {
                                job_id = 0;
                                job_path = unit_path;
                                job_type = "";
                        }

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &description) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &load_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &active_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &unit_path) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &job_id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &job_type) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &job_path)) {
                                free(unit_path);
                                if (u->meta.job)
                                        free(job_path);
                                goto oom;
                        }

                        free(unit_path);
                        if (u->meta.job)
                                free(job_path);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1",  "ListJobs")) {
                DBusMessageIter iter, sub;
                Iterator i;
                Job *j;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(usssoo)", &sub))
                        goto oom;

                HASHMAP_FOREACH(j, m->jobs, i) {
                        char *unit_path, *job_path;
                        const char *unit, *state, *type;
                        uint32_t id;
                        DBusMessageIter sub2;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        id = (uint32_t) j->id;
                        unit = unit_id(j->unit);
                        state = job_state_to_string(j->state);
                        type = job_type_to_string(j->state);

                        if (!(job_path = job_dbus_path(j)))
                                goto oom;

                        if (!(unit_path = unit_dbus_path(j->unit))) {
                                free(job_path);
                                goto oom;
                        }

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &unit) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &type) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &job_path) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &unit_path)) {
                                free(job_path);
                                free(unit_path);
                                goto oom;
                        }

                        free(job_path);
                        free(unit_path);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
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

                        if (k != unit_id(u))
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
                return bus_default_message_handler(m, message, NULL, NULL);

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
