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
#include <unistd.h>
#include <pwd.h>

#include <systemd/sd-id128.h>
#include <systemd/sd-messages.h>

#include "machined.h"
#include "dbus-common.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "special.h"
#include "sleep-config.h"
#include "fileio-label.h"
#include "label.h"
#include "utf8.h"
#include "unit-name.h"
#include "bus-errors.h"
#include "virt.h"
#include "cgroup-util.h"

#define BUS_MANAGER_INTERFACE                                           \
        " <interface name=\"org.freedesktop.machine1.Manager\">\n"      \
        "  <method name=\"GetMachine\">\n"                              \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"machine\" type=\"o\" direction=\"out\"/>\n"     \
        "  </method>\n"                                                 \
        "  <method name=\"GetMachineByPID\">\n"                         \
        "   <arg name=\"pid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"machine\" type=\"o\" direction=\"out\"/>\n"     \
        "  </method>\n"                                                 \
        "  <method name=\"ListMachines\">\n"                            \
        "   <arg name=\"machines\" type=\"a(ssso)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"CreateMachine\">\n"                           \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"id\" type=\"ay\" direction=\"in\"/>\n"          \
        "   <arg name=\"service\" type=\"s\" direction=\"in\"/>\n"      \
        "   <arg name=\"class\" type=\"s\" direction=\"in\"/>\n"        \
        "   <arg name=\"leader\" type=\"u\" direction=\"in\"/>\n"       \
        "   <arg name=\"root_directory\" type=\"s\" direction=\"in\"/>\n" \
        "   <arg name=\"scope_properties\" type=\"a(sv)\" direction=\"in\"/>\n" \
        "   <arg name=\"path\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"KillMachine\">\n"                             \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"who\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"signal\" type=\"s\" direction=\"in\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"TerminateMachine\">\n"                        \
        "   <arg name=\"id\" type=\"s\" direction=\"in\"/>\n"           \
        "  </method>\n"                                                 \
        "  <signal name=\"MachineNew\">\n"                              \
        "   <arg name=\"machine\" type=\"s\"/>\n"                       \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"MachineRemoved\">\n"                          \
        "   <arg name=\"machine\" type=\"s\"/>\n"                       \
        "   <arg name=\"path\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        " </interface>\n"

#define INTROSPECTION_BEGIN                                             \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_MANAGER_INTERFACE                                           \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE

#define INTROSPECTION_END                                               \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_GENERIC_INTERFACES_LIST                  \
        "org.freedesktop.machine1.Manager\0"

static bool valid_machine_name(const char *p) {
        size_t l;

        if (!filename_is_safe(p))
                return false;

        if (!ascii_is_valid(p))
                return false;

        l = strlen(p);

        if (l < 1 || l> 64)
                return false;

        return true;
}

static int bus_manager_create_machine(Manager *manager, DBusMessage *message) {

        const char *name, *service, *class, *root_directory;
        DBusMessageIter iter, sub;
        MachineClass c;
        uint32_t leader;
        sd_id128_t id;
        Machine *m;
        int n, r;
        void *v;

        assert(manager);
        assert(message);

        if (!dbus_message_iter_init(message, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &name);

        if (!valid_machine_name(name) ||
            !dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE)
                return -EINVAL;

        dbus_message_iter_recurse(&iter, &sub);
        dbus_message_iter_get_fixed_array(&sub, &v, &n);

        if (n == 0)
                id = SD_ID128_NULL;
        else if (n == 16)
                memcpy(&id, v, n);
        else
                return -EINVAL;

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &service);

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &class);

        if (isempty(class))
                c = _MACHINE_CLASS_INVALID;
        else {
                c = machine_class_from_string(class);
                if (c < 0)
                        return -EINVAL;
        }

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &leader);
        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                return -EINVAL;

        dbus_message_iter_get_basic(&iter, &root_directory);

        if (!(isempty(root_directory) || path_is_absolute(root_directory)))
                return -EINVAL;

        if (!dbus_message_iter_next(&iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)
                return -EINVAL;

        dbus_message_iter_recurse(&iter, &sub);

        if (hashmap_get(manager->machines, name))
                return -EEXIST;

        if (leader <= 0) {
                leader = bus_get_unix_process_id(manager->bus, dbus_message_get_sender(message), NULL);
                if (leader == 0)
                        return -EINVAL;
        }

        r = manager_add_machine(manager, name, &m);
        if (r < 0)
                goto fail;

        m->leader = leader;
        m->class = c;
        m->id = id;

        if (!isempty(service)) {
                m->service = strdup(service);
                if (!m->service) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (!isempty(root_directory)) {
                m->root_directory = strdup(root_directory);
                if (!m->root_directory) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        r = machine_start(m, &sub);
        if (r < 0)
                goto fail;

        m->create_message = dbus_message_ref(message);

        return 0;

fail:
        if (m)
                machine_add_to_gc_queue(m);

        return r;
}

static DBusHandlerResult manager_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;

        DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Manager", "GetMachine")) {
                Machine *machine;
                const char *name;
                char *p;
                bool b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                machine = hashmap_get(m->machines, name);
                if (!machine)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                p = machine_bus_path(machine);
                if (!p)
                        goto oom;

                b = dbus_message_append_args(
                                reply,
                                DBUS_TYPE_OBJECT_PATH, &p,
                                DBUS_TYPE_INVALID);
                free(p);

                if (!b)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Manager", "GetMachineByPID")) {
                uint32_t pid;
                char *p;
                Machine *machine;
                bool b;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &pid,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                r = manager_get_machine_by_pid(m, pid, &machine);
                if (r <= 0)
                        return bus_send_error_reply(connection, message, NULL, r < 0 ? r : -ENOENT);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                p = machine_bus_path(machine);
                if (!p)
                        goto oom;

                b = dbus_message_append_args(
                                reply,
                                DBUS_TYPE_OBJECT_PATH, &p,
                                DBUS_TYPE_INVALID);
                free(p);

                if (!b)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Manager", "ListMachines")) {
                Machine *machine;
                Iterator i;
                DBusMessageIter iter, sub;

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssso)", &sub))
                        goto oom;

                HASHMAP_FOREACH(machine, m->machines, i) {
                        _cleanup_free_ char *p = NULL;
                        DBusMessageIter sub2;
                        const char *class;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        p = machine_bus_path(machine);
                        if (!p)
                                goto oom;

                        class = strempty(machine_class_to_string(machine->class));

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &machine->name) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &class) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &machine->service) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &p)) {
                                free(p);
                                goto oom;
                        }

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Manager", "CreateMachine")) {

                r = bus_manager_create_machine(m, message);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Manager", "KillMachine")) {
                const char *swho;
                int32_t signo;
                KillWho who;
                const char *name;
                Machine *machine;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
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

                machine = hashmap_get(m->machines, name);
                if (!machine)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = machine_kill(machine, who, signo);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.machine1.Manager", "TerminateMachine")) {
                const char *name;
                Machine *machine;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                machine = hashmap_get(m->machines, name);
                if (!machine)
                        return bus_send_error_reply(connection, message, &error, -ENOENT);

                r = machine_stop(machine);
                if (r < 0)
                        return bus_send_error_reply(connection, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                char *introspection = NULL;
                FILE *f;
                Iterator i;
                Machine *machine;
                size_t size;
                char *p;

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

                fputs(INTROSPECTION_BEGIN, f);

                HASHMAP_FOREACH(machine, m->machines, i) {
                        p = bus_path_escape(machine->name);

                        if (p) {
                                fprintf(f, "<node name=\"machine/%s\"/>", p);
                                free(p);
                        }
                }

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
                return bus_default_message_handler(connection, message, NULL, INTERFACES_LIST, NULL);

        if (reply) {
                if (!bus_maybe_send_reply(connection, message, reply))
                        goto oom;
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

const DBusObjectPathVTable bus_manager_vtable = {
        .message_function = manager_message_handler
};

DBusHandlerResult bus_message_filter(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        Manager *m = userdata;
        DBusError error;

        assert(m);
        assert(connection);
        assert(message);

        dbus_error_init(&error);

        log_debug("Got message: %s %s %s", strna(dbus_message_get_sender(message)), strna(dbus_message_get_interface(message)), strna(dbus_message_get_member(message)));

        if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "JobRemoved")) {
                const char *path, *result, *unit;
                Machine *mm;
                uint32_t id;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_UINT32, &id,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_STRING, &unit,
                                           DBUS_TYPE_STRING, &result,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse JobRemoved message: %s", bus_error_message(&error));
                        goto finish;
                }

                mm = hashmap_get(m->machine_units, unit);
                if (mm) {
                        if (streq_ptr(path, mm->scope_job)) {
                                free(mm->scope_job);
                                mm->scope_job = NULL;

                                if (mm->started) {
                                        if (streq(result, "done"))
                                                machine_send_create_reply(mm, NULL);
                                        else {
                                                dbus_set_error(&error, BUS_ERROR_JOB_FAILED, "Start job for unit %s failed with '%s'", unit, result);
                                                machine_send_create_reply(mm, &error);
                                        }
                                } else
                                        machine_save(mm);
                        }

                        machine_add_to_gc_queue(mm);
                }

        } else if (dbus_message_is_signal(message, "org.freedesktop.DBus.Properties", "PropertiesChanged")) {

                _cleanup_free_ char *unit = NULL;
                const char *path;

                path = dbus_message_get_path(message);
                if (!path)
                        goto finish;

                unit_name_from_dbus_path(path, &unit);
                if (unit) {
                        Machine *mm;

                        mm = hashmap_get(m->machine_units, unit);
                        if (mm)
                                machine_add_to_gc_queue(mm);
                }

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "UnitRemoved")) {
                const char *path, *unit;
                Machine *mm;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &unit,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse UnitRemoved message: %s", bus_error_message(&error));
                        goto finish;
                }

                mm = hashmap_get(m->machine_units, unit);
                if (mm)
                        machine_add_to_gc_queue(mm);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "Reloading")) {
                dbus_bool_t b;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_BOOLEAN, &b,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse Reloading message: %s", bus_error_message(&error));
                        goto finish;
                }

                /* systemd finished reloading, let's recheck all our machines */
                if (!b) {
                        Machine *mm;
                        Iterator i;

                        log_debug("System manager has been reloaded, rechecking machines...");

                        HASHMAP_FOREACH(mm, m->machines, i)
                                machine_add_to_gc_queue(mm);
                }
        }

finish:
        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int copy_many_fields(DBusMessageIter *dest, DBusMessageIter *src);

static int copy_one_field(DBusMessageIter *dest, DBusMessageIter *src) {
        int type, r;

        type = dbus_message_iter_get_arg_type(src);

        switch (type) {

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter dest_sub, src_sub;

                dbus_message_iter_recurse(src, &src_sub);

                if (!dbus_message_iter_open_container(dest, DBUS_TYPE_STRUCT, NULL, &dest_sub))
                        return log_oom();

                r = copy_many_fields(&dest_sub, &src_sub);
                if (r < 0)
                        return r;

                if (!dbus_message_iter_close_container(dest, &dest_sub))
                        return log_oom();

                return 0;
        }

        case DBUS_TYPE_ARRAY: {
                DBusMessageIter dest_sub, src_sub;

                dbus_message_iter_recurse(src, &src_sub);

                if (!dbus_message_iter_open_container(dest, DBUS_TYPE_ARRAY, dbus_message_iter_get_signature(&src_sub), &dest_sub))
                        return log_oom();

                r = copy_many_fields(&dest_sub, &src_sub);
                if (r < 0)
                        return r;

                if (!dbus_message_iter_close_container(dest, &dest_sub))
                        return log_oom();

                return 0;
        }

        case DBUS_TYPE_VARIANT: {
                DBusMessageIter dest_sub, src_sub;

                dbus_message_iter_recurse(src, &src_sub);

                if (!dbus_message_iter_open_container(dest, DBUS_TYPE_VARIANT, dbus_message_iter_get_signature(&src_sub), &dest_sub))
                        return log_oom();

                r = copy_one_field(&dest_sub, &src_sub);
                if (r < 0)
                        return r;

                if (!dbus_message_iter_close_container(dest, &dest_sub))
                        return log_oom();

                return 0;
        }

        case DBUS_TYPE_STRING:
        case DBUS_TYPE_OBJECT_PATH:
        case DBUS_TYPE_BYTE:
        case DBUS_TYPE_BOOLEAN:
        case DBUS_TYPE_UINT16:
        case DBUS_TYPE_INT16:
        case DBUS_TYPE_UINT32:
        case DBUS_TYPE_INT32:
        case DBUS_TYPE_UINT64:
        case DBUS_TYPE_INT64:
        case DBUS_TYPE_DOUBLE:
        case DBUS_TYPE_SIGNATURE: {
                const void *p;

                dbus_message_iter_get_basic(src, &p);
                dbus_message_iter_append_basic(dest, type, &p);
                return 0;
        }

        default:
                return -EINVAL;
        }
}

static int copy_many_fields(DBusMessageIter *dest, DBusMessageIter *src) {
        int r;

        assert(dest);
        assert(src);

        while (dbus_message_iter_get_arg_type(src) != DBUS_TYPE_INVALID) {

                r = copy_one_field(dest, src);
                if (r < 0)
                        return r;

                dbus_message_iter_next(src);
        }

        return 0;
}

int manager_start_scope(
                Manager *manager,
                const char *scope,
                pid_t pid,
                const char *slice,
                const char *description,
                DBusMessageIter *more_properties,
                DBusError *error,
                char **job) {

        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        DBusMessageIter iter, sub, sub2, sub3, sub4;
        const char *timeout_stop_property = "TimeoutStopUSec";
        const char *pids_property = "PIDs";
        uint64_t timeout = 500 * USEC_PER_MSEC;
        const char *fail = "fail";
        uint32_t u;
        int r;

        assert(manager);
        assert(scope);
        assert(pid > 1);

        if (!slice)
                slice = "";

        m = dbus_message_new_method_call(
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (!m)
                return log_oom();

        dbus_message_iter_init_append(m, &iter);

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &scope) ||
            !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &fail) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sv)", &sub))
                return log_oom();

        if (!isempty(slice)) {
                const char *slice_property = "Slice";

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &slice_property) ||
                    !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "s", &sub3) ||
                    !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &slice) ||
                    !dbus_message_iter_close_container(&sub2, &sub3) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();
        }

        if (!isempty(description)) {
                const char *description_property = "Description";

                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &description_property) ||
                    !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "s", &sub3) ||
                    !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_STRING, &description) ||
                    !dbus_message_iter_close_container(&sub2, &sub3) ||
                    !dbus_message_iter_close_container(&sub, &sub2))
                        return log_oom();
        }

        /* cgroup empty notification is not available in containers
         * currently. To make this less problematic, let's shorten the
         * stop timeout for sessions, so that we don't wait
         * forever. */

        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &timeout_stop_property) ||
            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "t", &sub3) ||
            !dbus_message_iter_append_basic(&sub3, DBUS_TYPE_UINT64, &timeout) ||
            !dbus_message_iter_close_container(&sub2, &sub3) ||
            !dbus_message_iter_close_container(&sub, &sub2))
                return log_oom();

        u = pid;
        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2) ||
            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &pids_property) ||
            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, "au", &sub3) ||
            !dbus_message_iter_open_container(&sub3, DBUS_TYPE_ARRAY, "u", &sub4) ||
            !dbus_message_iter_append_basic(&sub4, DBUS_TYPE_UINT32, &u) ||
            !dbus_message_iter_close_container(&sub3, &sub4) ||
            !dbus_message_iter_close_container(&sub2, &sub3) ||
            !dbus_message_iter_close_container(&sub, &sub2))
                return log_oom();

        if (more_properties) {
                r = copy_many_fields(&sub, more_properties);
                if (r < 0)
                        return r;
        }

        if (!dbus_message_iter_close_container(&iter, &sub))
                return log_oom();

        reply = dbus_connection_send_with_reply_and_block(manager->bus, m, -1, error);
        if (!reply)
                return -EIO;

        if (job) {
                const char *j;
                char *copy;

                if (!dbus_message_get_args(reply, error, DBUS_TYPE_OBJECT_PATH, &j, DBUS_TYPE_INVALID))
                        return -EIO;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 0;
}

int manager_stop_unit(Manager *manager, const char *unit, DBusError *error, char **job) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *fail = "fail";
        int r;

        assert(manager);
        assert(unit);

        r = bus_method_call_with_reply(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StopUnit",
                        &reply,
                        error,
                        DBUS_TYPE_STRING, &unit,
                        DBUS_TYPE_STRING, &fail,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                if (dbus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT) ||
                    dbus_error_has_name(error, BUS_ERROR_LOAD_FAILED)) {

                        if (job)
                                *job = NULL;

                        dbus_error_free(error);
                        return 0;
                }

                log_error("Failed to stop unit %s: %s", unit, bus_error(error, r));
                return r;
        }

        if (job) {
                const char *j;
                char *copy;

                if (!dbus_message_get_args(reply, error,
                                           DBUS_TYPE_OBJECT_PATH, &j,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_kill_unit(Manager *manager, const char *unit, KillWho who, int signo, DBusError *error) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *w;
        int r;

        assert(manager);
        assert(unit);

        w = who == KILL_LEADER ? "process" : "cgroup";
        assert_cc(sizeof(signo) == sizeof(int32_t));

        r = bus_method_call_with_reply(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "KillUnit",
                        &reply,
                        error,
                        DBUS_TYPE_STRING, &unit,
                        DBUS_TYPE_STRING, &w,
                        DBUS_TYPE_INT32, &signo,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                log_error("Failed to stop unit %s: %s", unit, bus_error(error, r));
                return r;
        }

        return 0;
}

int manager_unit_is_active(Manager *manager, const char *unit) {

        const char *interface = "org.freedesktop.systemd1.Unit";
        const char *property = "ActiveState";
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ char *path = NULL;
        DBusMessageIter iter, sub;
        const char *state;
        DBusError error;
        int r;

        assert(manager);
        assert(unit);

        dbus_error_init(&error);

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return -ENOMEM;

        r = bus_method_call_with_reply(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &reply,
                        &error,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_STRING, &property,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                if (dbus_error_has_name(&error, DBUS_ERROR_NO_REPLY) ||
                    dbus_error_has_name(&error, DBUS_ERROR_DISCONNECTED)) {
                        dbus_error_free(&error);
                        return true;
                }

                if (dbus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT) ||
                    dbus_error_has_name(&error, BUS_ERROR_LOAD_FAILED)) {
                        dbus_error_free(&error);
                        return false;
                }

                log_error("Failed to query ActiveState: %s", bus_error(&error, r));
                dbus_error_free(&error);
                return r;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply.");
                return -EINVAL;
        }

        dbus_message_iter_recurse(&iter, &sub);
        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                log_error("Failed to parse reply.");
                return -EINVAL;
        }

        dbus_message_iter_get_basic(&sub, &state);

        return !streq(state, "inactive") && !streq(state, "failed");
}

int manager_add_machine(Manager *m, const char *name, Machine **_machine) {
        Machine *machine;

        assert(m);
        assert(name);

        machine = hashmap_get(m->machines, name);
        if (machine) {
                if (_machine)
                        *_machine = machine;

                return 0;
        }

        machine = machine_new(m, name);
        if (!machine)
                return -ENOMEM;

        if (_machine)
                *_machine = machine;

        return 0;
}

int manager_get_machine_by_pid(Manager *m, pid_t pid, Machine **machine) {
        _cleanup_free_ char *unit = NULL;
        Machine *mm;
        int r;

        assert(m);
        assert(pid >= 1);
        assert(machine);

        r = cg_pid_get_unit(pid, &unit);
        if (r < 0)
                return r;

        mm = hashmap_get(m->machine_units, unit);
        if (!mm)
                return 0;

        *machine = mm;
        return 1;
}
