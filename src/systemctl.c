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

#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "set.h"

static const char *arg_type = NULL;
static bool arg_all = false;
static bool arg_replace = false;
static bool arg_session = false;
static bool arg_block = false;

static int bus_iter_get_basic_and_next(DBusMessageIter *iter, int type, void *data, bool next) {

        if (dbus_message_iter_get_arg_type(iter) != type)
                return -EIO;

        dbus_message_iter_get_basic(iter, data);

        if (!dbus_message_iter_next(iter) != !next)
                return -EIO;

        return 0;
}

static int columns(void) {
        static int parsed_columns = 0;
        const char *e;

        if (parsed_columns > 0)
                return parsed_columns;

        if ((e = getenv("COLUMNS")))
                parsed_columns = atoi(e);

        if (parsed_columns <= 0) {
                struct winsize ws;
                zero(ws);

                if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0)
                        parsed_columns = ws.ws_col;
        }

        if (parsed_columns <= 0)
                parsed_columns = 80;

        return parsed_columns;
}

static int list_units(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "ListUnits"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        printf("%-45s %-6s %-12s %-12s %-15s %s\n", "UNIT", "LOAD", "ACTIVE", "SUB", "JOB", "DESCRIPTION");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *id, *description, *load_state, *active_state, *sub_state, *unit_state, *job_type, *job_path, *dot;
                uint32_t job_id;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &description, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &load_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &active_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &sub_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &unit_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &job_id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &job_type, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &job_path, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if ((!arg_type || ((dot = strrchr(id, '.')) &&
                                   streq(dot+1, arg_type))) &&
                    (arg_all || !streq(active_state, "inactive"))) {

                        int a = 0, b = 0;

                        printf("%-45s %-6s %-12s %-12s%n", id, load_state, active_state, sub_state, &a);

                        if (job_id != 0)
                                printf(" %-15s%n", job_type, &b);
                        else
                                b = 1 + 15;

                        if (a + b + 2 < columns()) {
                                if (job_id == 0)
                                        printf("                ");

                                printf("%.*s", columns() - a - b - 2, description);
                        }

                        fputs("\n", stdout);
                        k++;
                }

                dbus_message_iter_next(&sub);
        }

        if (arg_all)
                printf("\n%u units listed.\n", k);
        else
                printf("\n%u live units listed. Pass --all to see dead units, too.\n", k);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int list_jobs(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "ListJobs"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        printf("%4s %-45s %-17s %-7s\n", "JOB", "UNIT", "TYPE", "STATE");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name, *type, *state, *job_path, *unit_path;
                uint32_t id;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &job_path, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &unit_path, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                printf("%4u %-45s %-17s %-7s\n", id, name, type, state);
                k++;

                dbus_message_iter_next(&sub);
        }

        printf("\n%u jobs listed.\n", k);
        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int load_unit(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        unsigned i;

        dbus_error_init(&error);

        for (i = 1; i < n; i++) {

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "LoadUnit"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &args[i],
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", error.message);
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                dbus_message_unref(reply);

                m = reply = NULL;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int cancel_job(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        unsigned i;

        dbus_error_init(&error);

        for (i = 1; i < n; i++) {
                unsigned id;
                const char *path;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "GetJob"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = safe_atou(args[i], &id)) < 0) {
                        log_error("Failed to parse job id: %s", strerror(-r));
                        goto finish;
                }

                assert_cc(sizeof(uint32_t) == sizeof(id));
                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_UINT32, &id,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", error.message);
                        r = -EIO;
                        goto finish;
                }

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", error.message);
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      path,
                                      "org.freedesktop.systemd1.Job",
                                      "Cancel"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                dbus_message_unref(reply);
                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", error.message);
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                dbus_message_unref(reply);
                m = reply = NULL;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static DBusHandlerResult wait_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        DBusError error;
        Set *s = data;

        assert(connection);
        assert(message);
        assert(s);

        dbus_error_init(&error);

        /* log_debug("Got D-Bus request: %s.%s() on %s", */
        /*           dbus_message_get_interface(message), */
        /*           dbus_message_get_member(message), */
        /*           dbus_message_get_path(message)); */

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! D-Bus connection terminated.");
                dbus_connection_close(connection);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "JobRemoved")) {
                uint32_t id;
                const char *path;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_UINT32, &id,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse message: %s", error.message);
                else {
                        char *p;

                        if ((p = set_remove(s, (char*) path)))
                                free(p);
                }
        }

        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int wait_for_jobs(DBusConnection *bus, Set *s) {
        DBusError error;
        DBusMessage *m = NULL, *reply = NULL;
        int r;

        assert(bus);
        assert(s);

        dbus_error_init(&error);

        dbus_bus_add_match(bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Manager',"
                           "member='JobRemoved',"
                           "path='/org/freedesktop/systemd1'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_connection_add_filter(bus, wait_filter, s, NULL)) {
                log_error("Failed to add filter.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "Subscribe"))) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        while (!set_isempty(s) &&
               dbus_connection_read_write_dispatch(bus, -1))
                ;

        r = 0;

finish:
        /* This is slightly dirty, since we don't undo the filter or the matches. */

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int start_unit(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        unsigned i;
        const char *method, *mode;
        char *p = NULL;
        Set *s = NULL;

        dbus_error_init(&error);

        method =
                streq(args[0], "start")  ? "StartUnit" :
                streq(args[0], "stop")   ? "StopUnit" :
                streq(args[0], "reload") ? "ReloadUnit" :
                                           "RestartUnit";

        mode = arg_replace ? "replace" : "fail";

        for (i = 1; i < n; i++) {

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      method))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &args[i],
                                              DBUS_TYPE_STRING, &mode,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", error.message);
                        r = -EIO;
                        goto finish;
                }

                if (arg_block) {
                        const char *path;

                        if (!dbus_message_get_args(reply, &error,
                                                   DBUS_TYPE_OBJECT_PATH, &path,
                                                   DBUS_TYPE_INVALID)) {
                                log_error("Failed to parse reply: %s", error.message);
                                r = -EIO;
                                goto finish;
                        }

                        if (!s)
                                if (!(s = set_new(string_hash_func, string_compare_func))) {
                                        log_error("Failed to allocate set.");
                                        r = -ENOMEM;
                                        goto finish;
                                }

                        if (!(p = strdup(path))) {
                                log_error("Failed to duplicate path.");
                                r = -ENOMEM;
                                goto finish;
                        }

                        if ((r = set_put(s, p)) < 0) {
                                log_error("Failed to add path to set.");
                                goto finish;
                        }
                        p = NULL;
                }

                dbus_message_unref(m);
                dbus_message_unref(reply);

                m = reply = NULL;
        }

        if (arg_block)
                r = wait_for_jobs(bus, s);
        else
                r = 0;

finish:
        free(p);

        if (s)
                set_free_free(s);

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int isolate_unit(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *mode = "isolate";
        char *p = NULL;
        Set *s = NULL;

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "StartUnit"))) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &args[1],
                                      DBUS_TYPE_STRING, &mode,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (arg_block) {
                const char *path;

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", error.message);
                        r = -EIO;
                        goto finish;
                }

                if (!(s = set_new(string_hash_func, string_compare_func))) {
                        log_error("Failed to allocate set.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(p = strdup(path))) {
                        log_error("Failed to duplicate path.");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = set_put(s, p)) < 0) {
                        log_error("Failed to add path to set.");
                        goto finish;
                }
                p = NULL;

                r = wait_for_jobs(bus, s);

        } else
                r = 0;

finish:
        free(p);

        if (s)
                set_free_free(s);

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static DBusHandlerResult monitor_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        DBusError error;
        DBusMessage *m = NULL, *reply = NULL;

        assert(connection);
        assert(message);

        dbus_error_init(&error);

        /* log_debug("Got D-Bus request: %s.%s() on %s", */
        /*           dbus_message_get_interface(message), */
        /*           dbus_message_get_member(message), */
        /*           dbus_message_get_path(message)); */

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! D-Bus connection terminated.");
                dbus_connection_close(connection);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "UnitNew") ||
                   dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "UnitRemoved")) {
                const char *id, *path;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &id,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse message: %s", error.message);
                else if (streq(dbus_message_get_member(message), "UnitNew"))
                        printf("Unit %s added.\n", id);
                else
                        printf("Unit %s removed.\n", id);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "JobNew") ||
                   dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "JobRemoved")) {
                uint32_t id;
                const char *path;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_UINT32, &id,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse message: %s", error.message);
                else if (streq(dbus_message_get_member(message), "JobNew"))
                        printf("Job %u added.\n", id);
                else
                        printf("Job %u removed.\n", id);


        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Unit", "Changed") ||
                   dbus_message_is_signal(message, "org.freedesktop.systemd1.Job", "Changed")) {

                const char *path, *interface, *property = "Id";
                DBusMessageIter iter, sub;

                path = dbus_message_get_path(message);
                interface = dbus_message_get_interface(message);

                if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "Get"))) {
                        log_error("Could not allocate message.");
                        goto oom;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &interface,
                                              DBUS_TYPE_STRING, &property,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(connection, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", error.message);
                        goto finish;
                }

                if (!dbus_message_iter_init(reply, &iter) ||
                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                        log_error("Failed to parse reply.");
                        goto finish;
                }

                dbus_message_iter_recurse(&iter, &sub);

                if (streq(interface, "org.freedesktop.systemd1.Unit")) {
                        const char *id;

                        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)  {
                                log_error("Failed to parse reply.");
                                goto finish;
                        }

                        dbus_message_iter_get_basic(&sub, &id);
                        printf("Unit %s changed.\n", id);
                } else {
                        uint32_t id;

                        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT32)  {
                                log_error("Failed to parse reply.");
                                goto finish;
                        }

                        dbus_message_iter_get_basic(&sub, &id);
                        printf("Job %u changed.\n", id);
                }
        }

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

oom:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static int monitor(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;

        dbus_error_init(&error);

        dbus_bus_add_match(bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Manager',"
                           "path='/org/freedesktop/systemd1'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match: %s", error.message);
                r = -EIO;
                goto finish;
        }

        dbus_bus_add_match(bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Unit',"
                           "member='Changed'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match: %s", error.message);
                r = -EIO;
                goto finish;
        }

        dbus_bus_add_match(bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Job',"
                           "member='Changed'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_connection_add_filter(bus, monitor_filter, NULL, NULL)) {
                log_error("Failed to add filter.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "Subscribe"))) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        while (dbus_connection_read_write_dispatch(bus, -1))
                ;

        r = 0;

finish:

        /* This is slightly dirty, since we don't undo the filter or the matches. */

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int dump(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *text;

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "Dump"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_STRING, &text,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", error.message);
                r = -EIO;
                goto finish;
        }

        fputs(text, stdout);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int snapshot(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *name = "", *path, *id;
        dbus_bool_t cleanup = FALSE;
        DBusMessageIter iter, sub;
        const char
                *interface = "org.freedesktop.systemd1.Unit",
                *property = "Id";

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "CreateSnapshot"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (n > 1)
                name = args[1];

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_BOOLEAN, &cleanup,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", error.message);
                r = -EIO;
                goto finish;
        }

        dbus_message_unref(m);
        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "Get"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        dbus_message_unref(reply);
        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_get_basic(&sub, &id);
        puts(id);
        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int clear_jobs(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *method;

        dbus_error_init(&error);

        method =
                streq(args[0], "clear-jobs")    ? "ClearJobs" :
                streq(args[0], "daemon-reload") ? "Reload" :
                streq(args[0], "daemon-reexec") ? "Reexecute" :
                                                  "Exit";

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              method))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int show_enviroment(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        DBusMessageIter iter, sub, sub2;
        int r;
        const char
                *interface = "org.freedesktop.systemd1.Manager",
                *property = "Environment";

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.DBus.Properties",
                              "Get"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&sub) != DBUS_TYPE_STRING)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&sub, &sub2);

        while (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_INVALID) {
                const char *text;

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_STRING) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_get_basic(&sub2, &text);
                printf("%s\n", text);

                dbus_message_iter_next(&sub2);
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int set_environment(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *method;
        DBusMessageIter iter, sub;
        unsigned i;

        dbus_error_init(&error);

        method = streq(args[0], "set-environment")
                ? "SetEnvironment"
                : "UnsetEnvironment";

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              method))) {

                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        dbus_message_iter_init_append(m, &iter);

        if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        for (i = 1; i < n; i++)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &args[i])) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

        if (!dbus_message_iter_close_container(&iter, &sub)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int help(void) {

        printf("%s [options]\n\n"
               "  -h --help      Show this help\n"
               "  -t --type=TYPE List only units of a particular type\n"
               "  -a --all       Show all units, including dead ones\n"
               "     --replace   When installing a new job, replace existing conflicting ones\n"
               "     --system    Connect to system bus\n"
               "     --session   Connect to session bus\n"
               "     --block     Wait until operation finished\n\n"
               "Commands:\n"
               "  list-units                      List units\n"
               "  list-jobs                       List jobs\n"
               "  clear-jobs                      Cancel all jobs\n"
               "  load [NAME...]                  Load one or more units\n"
               "  cancel [JOB...]                 Cancel one or more jobs\n"
               "  start [NAME...]                 Start one or more units\n"
               "  stop [NAME...]                  Stop one or more units\n"
               "  restart [NAME...]               Restart one or more units\n"
               "  reload [NAME...]                Reload one or more units\n"
               "  isolate [NAME]                  Start one unit and stop all others\n"
               "  monitor                         Monitor unit/job changes\n"
               "  dump                            Dump server status\n"
               "  snapshot [NAME]                 Create a snapshot\n"
               "  daemon-reload                   Reload daemon configuration\n"
               "  daemon-reexecute                Reexecute daemon\n"
               "  daemon-exit                     Ask the daemon to quit\n"
               "  show-environment                Dump environment\n"
               "  set-environment [NAME=VALUE...] Set one or more environment variables\n"
               "  unset-environment [NAME...]     Unset one or more environment variables\n",
               __progname);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_REPLACE = 0x100,
                ARG_SESSION,
                ARG_SYSTEM,
                ARG_BLOCK,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'         },
                { "type",      required_argument, NULL, 't'         },
                { "all",       no_argument,       NULL, 'a'         },
                { "replace",   no_argument,       NULL, ARG_REPLACE },
                { "session",   no_argument,       NULL, ARG_SESSION },
                { "system",    no_argument,       NULL, ARG_SYSTEM  },
                { "block",     no_argument,       NULL, ARG_BLOCK   }
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hta", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 't':
                        arg_type = optarg;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case ARG_REPLACE:
                        arg_replace = true;
                        break;

                case ARG_SESSION:
                        arg_session = true;
                        break;

                case ARG_SYSTEM:
                        arg_session = false;
                        break;

                case ARG_BLOCK:
                        arg_block = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

int main(int argc, char*argv[]) {


        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(DBusConnection *bus, char **args, unsigned n);
        } verbs[] = {
                { "list-units",        LESS,  1, list_units      },
                { "list-jobs",         EQUAL, 1, list_jobs       },
                { "clear-jobs",        EQUAL, 1, clear_jobs      },
                { "load",              MORE,  2, load_unit       },
                { "cancel",            MORE,  2, cancel_job      },
                { "start",             MORE,  2, start_unit      },
                { "stop",              MORE,  2, start_unit      },
                { "reload",            MORE,  2, start_unit      },
                { "restart",           MORE,  2, start_unit      },
                { "isolate",           EQUAL, 2, isolate_unit    },
                { "monitor",           EQUAL, 1, monitor         },
                { "dump",              EQUAL, 1, dump            },
                { "snapshot",          LESS,  2, snapshot        },
                { "daemon-reload",     EQUAL, 1, clear_jobs      },
                { "daemon-reexec",     EQUAL, 1, clear_jobs      },
                { "daemon-exit",       EQUAL, 1, clear_jobs      },
                { "show-environment",  EQUAL, 1, show_enviroment },
                { "set-environment",   MORE,  2, set_environment },
                { "unset-environment", MORE,  2, set_environment },
        };

        int r, retval = 1, left;
        unsigned i;
        DBusConnection *bus = NULL;
        DBusError error;

        dbus_error_init(&error);

        log_set_target(LOG_TARGET_CONSOLE);
        log_parse_environment();

        if ((r = parse_argv(argc, argv)) < 0)
                goto finish;
        else if (r == 0) {
                retval = 0;
                goto finish;
        }

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list-units" */
                i = 0;
        else {
                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        goto finish;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        goto finish;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        goto finish;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        goto finish;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        if (!(bus = dbus_bus_get(arg_session ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM, &error))) {
                log_error("Failed to get D-Bus connection: %s", error.message);
                goto finish;
        }

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        retval = verbs[i].dispatch(bus, argv + optind, left) < 0;

finish:

        if (bus)
                dbus_connection_unref(bus);

        dbus_shutdown();

        return retval;
}
