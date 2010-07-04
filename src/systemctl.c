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

#include <sys/reboot.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <dbus/dbus.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "set.h"
#include "utmp-wtmp.h"
#include "special.h"
#include "initreq.h"
#include "strv.h"

static const char *arg_type = NULL;
static const char *arg_property = NULL;
static bool arg_all = false;
static bool arg_replace = false;
static bool arg_session = false;
static bool arg_no_block = false;
static bool arg_immediate = false;
static bool arg_no_wtmp = false;
static bool arg_no_sync = false;
static bool arg_no_wall = false;
static bool arg_dry = false;
static bool arg_quiet = false;
static char **arg_wall = NULL;
enum action {
        ACTION_INVALID,
        ACTION_SYSTEMCTL,
        ACTION_HALT,
        ACTION_POWEROFF,
        ACTION_REBOOT,
        ACTION_RUNLEVEL2,
        ACTION_RUNLEVEL3,
        ACTION_RUNLEVEL4,
        ACTION_RUNLEVEL5,
        ACTION_RESCUE,
        ACTION_EMERGENCY,
        ACTION_DEFAULT,
        ACTION_RELOAD,
        ACTION_REEXEC,
        ACTION_RUNLEVEL,
        _ACTION_MAX
} arg_action = ACTION_SYSTEMCTL;

static bool error_is_no_service(DBusError *error) {

        assert(error);

        if (!dbus_error_is_set(error))
                return false;

        if (dbus_error_has_name(error, DBUS_ERROR_NAME_HAS_NO_OWNER))
                return true;

        if (dbus_error_has_name(error, DBUS_ERROR_SERVICE_UNKNOWN))
                return true;

        return startswith(error->name, "org.freedesktop.DBus.Error.Spawn.");
}

static int bus_iter_get_basic_and_next(DBusMessageIter *iter, int type, void *data, bool next) {

        assert(iter);
        assert(data);

        if (dbus_message_iter_get_arg_type(iter) != type)
                return -EIO;

        dbus_message_iter_get_basic(iter, data);

        if (!dbus_message_iter_next(iter) != !next)
                return -EIO;

        return 0;
}

static int bus_check_peercred(DBusConnection *c) {
        int fd;
        struct ucred ucred;
        socklen_t l;

        assert(c);

        assert_se(dbus_connection_get_unix_fd(c, &fd));

        l = sizeof(struct ucred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &l) < 0) {
                log_error("SO_PEERCRED failed: %m");
                return -errno;
        }

        if (l != sizeof(struct ucred)) {
                log_error("SO_PEERCRED returned wrong size.");
                return -E2BIG;
        }

        if (ucred.uid != 0)
                return -EPERM;

        return 1;
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

static void warn_wall(enum action action) {
        static const char *table[_ACTION_MAX] = {
                [ACTION_HALT]      = "The system is going down for system halt NOW!",
                [ACTION_REBOOT]    = "The system is going down for reboot NOW!",
                [ACTION_POWEROFF]  = "The system is going down for power-off NOW!",
                [ACTION_RESCUE]    = "The system is going down to rescue mode NOW!",
                [ACTION_EMERGENCY] = "The system is going down to emergency mode NOW!"
        };

        if (arg_no_wall)
                return;

        if (arg_wall) {
                char *p;

                if (!(p = strv_join(arg_wall, " "))) {
                        log_error("Failed to join strings.");
                        return;
                }

                if (*p) {
                        utmp_wall(p);
                        free(p);
                        return;
                }

                free(p);
        }

        if (!table[action])
                return;

        utmp_wall(table[action]);
}

static int list_units(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        dbus_error_init(&error);

        assert(bus);

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

        assert(bus);

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

        assert(bus);
        assert(args);

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

        assert(bus);
        assert(args);

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

typedef struct WaitData {
        Set *set;
        bool failed;
} WaitData;

static DBusHandlerResult wait_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        DBusError error;
        WaitData *d = data;

        assert(connection);
        assert(message);
        assert(d);

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
                dbus_bool_t success = true;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_UINT32, &id,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_BOOLEAN, &success,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse message: %s", error.message);
                else {
                        char *p;

                        if ((p = set_remove(d->set, (char*) path)))
                                free(p);

                        if (!success)
                                d->failed = true;
                }
        }

        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int enable_wait_for_jobs(DBusConnection *bus) {
        DBusError error;
        DBusMessage *m = NULL, *reply = NULL;
        int r;

        assert(bus);

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

        r = 0;

finish:
        /* This is slightly dirty, since we don't undo the match registrations. */

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int wait_for_jobs(DBusConnection *bus, Set *s) {
        int r;
        WaitData d;

        assert(bus);
        assert(s);

        zero(d);
        d.set = s;
        d.failed = false;

        if (!dbus_connection_add_filter(bus, wait_filter, &d, NULL)) {
                log_error("Failed to add filter.");
                r = -ENOMEM;
                goto finish;
        }

        while (!set_isempty(s) &&
               dbus_connection_read_write_dispatch(bus, -1))
                ;

        if (!arg_quiet && d.failed)
                log_error("Job failed, see logs for details.");

        r = d.failed ? -EIO : 0;

finish:
        /* This is slightly dirty, since we don't undo the filter registration. */

        return r;
}

static int start_unit_one(
                DBusConnection *bus,
                const char *method,
                const char *name,
                const char *mode,
                Set *s) {

        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;

        assert(bus);
        assert(method);
        assert(name);
        assert(mode);
        assert(arg_no_block || s);

        dbus_error_init(&error);

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
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_STRING, &mode,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {

                if (arg_action != ACTION_SYSTEMCTL && error_is_no_service(&error)) {
                        /* There's always a fallback possible for
                         * legacy actions. */
                        r = 0;
                        goto finish;
                }

                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if (!arg_no_block) {
                const char *path;
                char *p;

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", error.message);
                        r = -EIO;
                        goto finish;
                }

                if (!(p = strdup(path))) {
                        log_error("Failed to duplicate path.");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = set_put(s, p)) < 0) {
                        free(p);
                        log_error("Failed to add path to set.");
                        goto finish;
                }
        }

        r = 1;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static enum action verb_to_action(const char *verb) {
        if (streq(verb, "halt"))
                return ACTION_HALT;
        else if (streq(verb, "poweroff"))
                return ACTION_POWEROFF;
        else if (streq(verb, "reboot"))
                return ACTION_REBOOT;
        else if (streq(verb, "rescue"))
                return ACTION_RESCUE;
        else if (streq(verb, "emergency"))
                return ACTION_EMERGENCY;
        else if (streq(verb, "default"))
                return ACTION_DEFAULT;
        else
                return ACTION_INVALID;
}

static int start_unit(DBusConnection *bus, char **args, unsigned n) {

        static const char * const table[_ACTION_MAX] = {
                [ACTION_HALT] = SPECIAL_HALT_TARGET,
                [ACTION_POWEROFF] = SPECIAL_POWEROFF_TARGET,
                [ACTION_REBOOT] = SPECIAL_REBOOT_TARGET,
                [ACTION_RUNLEVEL2] = SPECIAL_RUNLEVEL2_TARGET,
                [ACTION_RUNLEVEL3] = SPECIAL_RUNLEVEL3_TARGET,
                [ACTION_RUNLEVEL4] = SPECIAL_RUNLEVEL4_TARGET,
                [ACTION_RUNLEVEL5] = SPECIAL_RUNLEVEL5_TARGET,
                [ACTION_RESCUE] = SPECIAL_RESCUE_TARGET,
                [ACTION_EMERGENCY] = SPECIAL_EMERGENCY_SERVICE,
                [ACTION_DEFAULT] = SPECIAL_DEFAULT_TARGET
        };

        int r;
        unsigned i;
        const char *method, *mode, *one_name;
        Set *s = NULL;

        assert(bus);

        if (arg_action == ACTION_SYSTEMCTL) {
                method =
                        streq(args[0], "stop")    ? "StopUnit" :
                        streq(args[0], "reload")  ? "ReloadUnit" :
                        streq(args[0], "restart") ? "RestartUnit" :
                                                    "StartUnit";

                mode =
                        (streq(args[0], "isolate") ||
                         streq(args[0], "rescue")  ||
                         streq(args[0], "emergency")) ? "isolate" :
                                          arg_replace ? "replace" :
                                                        "fail";

                one_name = table[verb_to_action(args[0])];

        } else {
                assert(arg_action < ELEMENTSOF(table));
                assert(table[arg_action]);

                method = "StartUnit";

                mode = (arg_action == ACTION_EMERGENCY ||
                        arg_action == ACTION_RESCUE) ? "isolate" : "replace";

                one_name = table[arg_action];
        }

        if (!arg_no_block) {
                if ((r = enable_wait_for_jobs(bus)) < 0) {
                        log_error("Could not watch jobs: %s", strerror(-r));
                        goto finish;
                }

                if (!(s = set_new(string_hash_func, string_compare_func))) {
                        log_error("Failed to allocate set.");
                        r = -ENOMEM;
                        goto finish;
                }
        }

        r = 0;

        if (one_name) {
                if ((r = start_unit_one(bus, method, one_name, mode, s)) <= 0)
                        goto finish;
        } else {
                for (i = 1; i < n; i++)
                        if ((r = start_unit_one(bus, method, args[i], mode, s)) < 0)
                                goto finish;
        }

        if (!arg_no_block)
                r = wait_for_jobs(bus, s);

finish:
        if (s)
                set_free_free(s);

        return r;
}

static int start_special(DBusConnection *bus, char **args, unsigned n) {
        assert(bus);
        assert(args);

        warn_wall(verb_to_action(args[0]));

        return start_unit(bus, args, n);
}

static int check_unit(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        const char
                *interface = "org.freedesktop.systemd1.Unit",
                *property = "ActiveState";
        int r = -EADDRNOTAVAIL;
        DBusError error;
        unsigned i;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        for (i = 1; i < n; i++) {
                const char *path = NULL;
                const char *state;
                DBusMessageIter iter, sub;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "GetUnit"))) {
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

                        /* Hmm, cannot figure out anything about this unit... */
                        if (!arg_quiet)
                                puts("unknown");

                        continue;
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
                        r = -ENOMEM;
                        goto finish;
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

                dbus_message_iter_get_basic(&sub, &state);

                if (!arg_quiet)
                        puts(state);

                if (streq(state, "active") || startswith(state, "reloading"))
                        r = 0;

                dbus_message_unref(m);
                dbus_message_unref(reply);
                m = reply = NULL;
        }

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int print_property(const char *name, DBusMessageIter *iter) {
        assert(name);
        assert(iter);

        if (arg_property && !streq(name, arg_property))
                return 0;

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;
                dbus_message_iter_get_basic(iter, &s);

                if (arg_all || s[0])
                        printf("%s=%s\n", name, s);

                return 0;
        }

        case DBUS_TYPE_BOOLEAN: {
                dbus_bool_t b;
                dbus_message_iter_get_basic(iter, &b);
                printf("%s=%s\n", name, yes_no(b));

                return 0;
        }

        case DBUS_TYPE_UINT64: {
                uint64_t u;
                dbus_message_iter_get_basic(iter, &u);

                /* Yes, heuristics! But we can change this check
                 * should it turn out to not be sufficient */

                if (strstr(name, "Timestamp")) {
                        char timestamp[FORMAT_TIMESTAMP_MAX], *t;

                        if ((t = format_timestamp(timestamp, sizeof(timestamp), u)) || arg_all)
                                printf("%s=%s\n", name, strempty(t));
                } else
                        printf("%s=%llu\n", name, (unsigned long long) u);

                return 0;
        }

        case DBUS_TYPE_UINT32: {
                uint32_t u;
                dbus_message_iter_get_basic(iter, &u);

                if (strstr(name, "UMask"))
                        printf("%s=%04o\n", name, u);
                else
                        printf("%s=%u\n", name, (unsigned) u);

                return 0;
        }

        case DBUS_TYPE_INT32: {
                int32_t i;
                dbus_message_iter_get_basic(iter, &i);

                printf("%s=%i\n", name, (int) i);
                return 0;
        }

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter sub;
                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_UINT32 && streq(name, "Job")) {
                        uint32_t u;

                        dbus_message_iter_get_basic(&sub, &u);

                        if (u)
                                printf("%s=%u\n", name, (unsigned) u);
                        else if (arg_all)
                                printf("%s=\n", name);

                        return 0;
                } else if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "Unit")) {
                        const char *s;

                        dbus_message_iter_get_basic(&sub, &s);

                        if (arg_all || s[0])
                                printf("%s=%s\n", name, s);

                        return 0;
                }

                break;
        }

        case DBUS_TYPE_ARRAY:

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRING) {
                        DBusMessageIter sub;
                        bool space = false;

                        dbus_message_iter_recurse(iter, &sub);

                        if (arg_all ||
                            dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                printf("%s=", name);

                                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                        const char *s;

                                        assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING);
                                        dbus_message_iter_get_basic(&sub, &s);
                                        printf("%s%s", space ? " " : "", s);

                                        space = true;
                                        dbus_message_iter_next(&sub);
                                }

                                puts("");
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Paths")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);

                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *type, *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, false) >= 0)
                                        printf("%s=%s\n", type, path);

                                dbus_message_iter_next(&sub);
                        }

                        return 0;
                }

                break;
        }

        if (arg_all)
                printf("%s=[unprintable]\n", name);

        return 0;
}

static int show_one(DBusConnection *bus, const char *path) {
        DBusMessage *m = NULL, *reply = NULL;
        const char *interface = "";
        int r;
        DBusError error;
        DBusMessageIter iter, sub, sub2, sub3;

        assert(bus);
        assert(path);

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "GetAll"))) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
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
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_DICT_ENTRY) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT)  {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub2, &sub3);

                if (print_property(name, &sub3) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_next(&sub);
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

static int show(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        int r;
        DBusError error;
        unsigned i;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        if (n <= 1) {
                /* If not argument is specified inspect the manager
                 * itself */

                r = show_one(bus, "/org/freedesktop/systemd1");
                goto finish;
        }

        for (i = 1; i < n; i++) {
                const char *path = NULL;
                uint32_t id;

                if (safe_atou32(args[i], &id) < 0) {

                        if (!(m = dbus_message_new_method_call(
                                              "org.freedesktop.systemd1",
                                              "/org/freedesktop/systemd1",
                                              "org.freedesktop.systemd1.Manager",
                                              "GetUnit"))) {
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

                } else {

                        if (!(m = dbus_message_new_method_call(
                                              "org.freedesktop.systemd1",
                                              "/org/freedesktop/systemd1",
                                              "org.freedesktop.systemd1.Manager",
                                              "GetJob"))) {
                                log_error("Could not allocate message.");
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (!dbus_message_append_args(m,
                                                      DBUS_TYPE_UINT32, &id,
                                                      DBUS_TYPE_INVALID)) {
                                log_error("Could not append arguments to message.");
                                r = -ENOMEM;
                                goto finish;
                        }
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

                if ((r = show_one(bus, path)) < 0)
                        goto finish;

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

        if (!arg_quiet)
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

static int delete_snapshot(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        int r;
        DBusError error;
        unsigned i;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        for (i = 1; i < n; i++) {
                const char *path = NULL;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "GetUnit"))) {
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
                                      "org.freedesktop.systemd1.Snapshot",
                                      "Remove"))) {
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

static int clear_jobs(DBusConnection *bus, char **args, unsigned n) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *method;

        dbus_error_init(&error);

        if (arg_action == ACTION_RELOAD)
                method = "Reload";
        else if (arg_action == ACTION_REEXEC)
                method = "Reexecute";
        else {
                assert(arg_action == ACTION_SYSTEMCTL);

                method =
                        streq(args[0], "clear-jobs")    ? "ClearJobs" :
                        streq(args[0], "daemon-reload") ? "Reload" :
                        streq(args[0], "daemon-reexec") ? "Reexecute" :
                                                          "Exit";
        }

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              method))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {

                if (arg_action != ACTION_SYSTEMCTL && error_is_no_service(&error)) {
                        /* There's always a fallback possible for
                         * legacy actions. */
                        r = 0;
                        goto finish;
                }

                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        r = 1;

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

static int systemctl_help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to the systemd manager.\n\n"
               "  -h --help          Show this help\n"
               "  -t --type=TYPE     List only units of a particular type\n"
               "  -p --property=NAME Show only property by this name\n"
               "  -a --all           Show all units/properties, including dead/empty ones\n"
               "     --replace       When installing a new job, replace existing conflicting ones\n"
               "     --system        Connect to system bus\n"
               "     --session       Connect to session bus\n"
               "  -q --quiet         Suppress output\n"
               "     --no-block      Do not wait until operation finished\n"
               "     --no-wall       Don't send wall message before halt/power-off/reboot\n\n"
               "Commands:\n"
               "  list-units                      List units\n"
               "  start [NAME...]                 Start one or more units\n"
               "  stop [NAME...]                  Stop one or more units\n"
               "  restart [NAME...]               Restart one or more units\n"
               "  reload [NAME...]                Reload one or more units\n"
               "  isolate [NAME]                  Start one unit and stop all others\n"
               "  check [NAME...]                 Check whether any of the passed units are active\n"
               "  show [NAME...|JOB...]           Show information about one or more units\n"
               "  load [NAME...]                  Load one or more units\n"
               "  list-jobs                       List jobs\n"
               "  cancel [JOB...]                 Cancel one or more jobs\n"
               "  clear-jobs                      Cancel all jobs\n"
               "  monitor                         Monitor unit/job changes\n"
               "  dump                            Dump server status\n"
               "  snapshot [NAME]                 Create a snapshot\n"
               "  delete [NAME...]                Remove one or more snapshots\n"
               "  daemon-reload                   Reload systemd manager configuration\n"
               "  daemon-reexec                   Reexecute systemd manager\n"
               "  daemon-exit                     Ask the systemd manager to quit\n"
               "  show-environment                Dump environment\n"
               "  set-environment [NAME=VALUE...] Set one or more environment variables\n"
               "  unset-environment [NAME...]     Unset one or more environment variables\n"
               "  halt                            Shut down and halt the system\n"
               "  poweroff                        Shut down and power-off the system\n"
               "  reboot                          Shut down and reboot the system\n"
               "  default                         Enter default mode\n"
               "  rescue                          Enter rescue mode\n"
               "  emergency                       Enter emergency mode\n",
               program_invocation_short_name);

        return 0;
}

static int halt_help(void) {

        printf("%s [OPTIONS...]\n\n"
               "%s the system.\n\n"
               "     --help      Show this help\n"
               "     --halt      Halt the machine\n"
               "  -p --poweroff  Switch off the machine\n"
               "     --reboot    Reboot the machine\n"
               "  -f --force     Force immediate halt/power-off/reboot\n"
               "  -w --wtmp-only Don't halt/power-off/reboot, just write wtmp record\n"
               "  -d --no-wtmp   Don't write wtmp record\n"
               "  -n --no-sync   Don't sync before halt/power-off/reboot\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n",
               program_invocation_short_name,
               arg_action == ACTION_REBOOT   ? "Reboot" :
               arg_action == ACTION_POWEROFF ? "Power off" :
                                               "Halt");

        return 0;
}

static int shutdown_help(void) {

        printf("%s [OPTIONS...] [now] [WALL...]\n\n"
               "Shut down the system.\n\n"
               "     --help      Show this help\n"
               "  -H --halt      Halt the machine\n"
               "  -P --poweroff  Power-off the machine\n"
               "  -r --reboot    Reboot the machine\n"
               "  -h             Equivalent to --poweroff, overriden by --halt\n"
               "  -k             Don't halt/power-off/reboot, just send warnings\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n",
               program_invocation_short_name);

        return 0;
}

static int telinit_help(void) {

        printf("%s [OPTIONS...] {COMMAND}\n\n"
               "Send control commands to the init daemon.\n\n"
               "     --help      Show this help\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n\n"
               "Commands:\n"
               "  0              Power-off the machine\n"
               "  6              Reboot the machine\n"
               "  2, 3, 4, 5     Start runlevelX.target unit\n"
               "  1, s, S        Enter rescue mode\n"
               "  q, Q           Reload init daemon configuration\n"
               "  u, U           Reexecute init daemon\n",
               program_invocation_short_name);

        return 0;
}

static int runlevel_help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Prints the previous and current runlevel of the init system.\n\n"
               "     --help      Show this help\n",
               program_invocation_short_name);

        return 0;
}

static int systemctl_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_REPLACE = 0x100,
                ARG_SESSION,
                ARG_SYSTEM,
                ARG_NO_BLOCK,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'          },
                { "type",      required_argument, NULL, 't'          },
                { "property",  required_argument, NULL, 'p'          },
                { "all",       no_argument,       NULL, 'a'          },
                { "replace",   no_argument,       NULL, ARG_REPLACE  },
                { "session",   no_argument,       NULL, ARG_SESSION  },
                { "system",    no_argument,       NULL, ARG_SYSTEM   },
                { "no-block",  no_argument,       NULL, ARG_NO_BLOCK },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL  },
                { "quiet",     no_argument,       NULL, 'q'          },
                { NULL,        0,                 NULL, 0            }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ht:p:aq", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        systemctl_help();
                        return 0;

                case 't':
                        arg_type = optarg;
                        break;

                case 'p':
                        arg_property = optarg;

                        /* If the user asked for a particular
                         * property, show it to him, even if it is
                         * empty. */
                        arg_all = true;
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

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 'q':
                        arg_quiet = true;
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

static int halt_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
                ARG_HALT,
                ARG_REBOOT,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "halt",      no_argument,       NULL, ARG_HALT    },
                { "poweroff",  no_argument,       NULL, 'p'         },
                { "reboot",    no_argument,       NULL, ARG_REBOOT  },
                { "force",     no_argument,       NULL, 'f'         },
                { "wtmp-only", no_argument,       NULL, 'w'         },
                { "no-wtmp",   no_argument,       NULL, 'd'         },
                { "no-sync",   no_argument,       NULL, 'n'         },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                { NULL,        0,                 NULL, 0           }
        };

        int c, runlevel;

        assert(argc >= 0);
        assert(argv);

        if (utmp_get_runlevel(&runlevel, NULL) >= 0)
                if (runlevel == '0' || runlevel == '6')
                        arg_immediate = true;

        while ((c = getopt_long(argc, argv, "pfwdnih", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        halt_help();
                        return 0;

                case ARG_HALT:
                        arg_action = ACTION_HALT;
                        break;

                case 'p':
                        arg_action = ACTION_POWEROFF;
                        break;

                case ARG_REBOOT:
                        arg_action = ACTION_REBOOT;
                        break;

                case 'f':
                        arg_immediate = true;
                        break;

                case 'w':
                        arg_dry = true;
                        break;

                case 'd':
                        arg_no_wtmp = true;
                        break;

                case 'n':
                        arg_no_sync = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 'i':
                case 'h':
                        /* Compatibility nops */
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        return 1;
}

static int shutdown_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "halt",      no_argument,       NULL, 'H'         },
                { "poweroff",  no_argument,       NULL, 'P'         },
                { "reboot",    no_argument,       NULL, 'r'         },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                { NULL,        0,                 NULL, 0           }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "HPrhkt:a", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        shutdown_help();
                        return 0;

                case 'H':
                        arg_action = ACTION_HALT;
                        break;

                case 'P':
                        arg_action = ACTION_POWEROFF;
                        break;

                case 'r':
                        arg_action = ACTION_REBOOT;
                        break;

                case 'h':
                        if (arg_action != ACTION_HALT)
                                arg_action = ACTION_POWEROFF;
                        break;

                case 'k':
                        arg_dry = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 't':
                case 'a':
                        /* Compatibility nops */
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (argc > optind && !streq(argv[optind], "now"))
                log_warning("First argument '%s' isn't 'now'. Ignoring.", argv[optind]);

        /* We ignore the time argument */
        if (argc > optind + 1)
                arg_wall = argv + optind + 1;

        optind = argc;

        return 1;
}

static int telinit_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                { NULL,        0,                 NULL, 0           }
        };

        static const struct {
                char from;
                enum action to;
        } table[] = {
                { '0', ACTION_POWEROFF },
                { '6', ACTION_REBOOT },
                { '1', ACTION_RESCUE },
                { '2', ACTION_RUNLEVEL2 },
                { '3', ACTION_RUNLEVEL3 },
                { '4', ACTION_RUNLEVEL4 },
                { '5', ACTION_RUNLEVEL5 },
                { 's', ACTION_RESCUE },
                { 'S', ACTION_RESCUE },
                { 'q', ACTION_RELOAD },
                { 'Q', ACTION_RELOAD },
                { 'u', ACTION_REEXEC },
                { 'U', ACTION_REEXEC }
        };

        unsigned i;
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        telinit_help();
                        return 0;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc) {
                telinit_help();
                return -EINVAL;
        }

        if (optind + 1 < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        if (strlen(argv[optind]) != 1) {
                log_error("Expected single character argument.");
                return -EINVAL;
        }

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (table[i].from == argv[optind][0])
                        break;

        if (i >= ELEMENTSOF(table)) {
                log_error("Unknown command %s.", argv[optind]);
                return -EINVAL;
        }

        arg_action = table[i].to;

        optind ++;

        return 1;
}

static int runlevel_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { NULL,        0,                 NULL, 0           }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        runlevel_help();
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        return 1;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        if (program_invocation_short_name) {

                if (strstr(program_invocation_short_name, "halt")) {
                        arg_action = ACTION_HALT;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "poweroff")) {
                        arg_action = ACTION_POWEROFF;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "reboot")) {
                        arg_action = ACTION_REBOOT;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "shutdown")) {
                        arg_action = ACTION_POWEROFF;
                        return shutdown_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "init")) {
                        arg_action = ACTION_INVALID;
                        return telinit_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "runlevel")) {
                        arg_action = ACTION_RUNLEVEL;
                        return runlevel_parse_argv(argc, argv);
                }
        }

        arg_action = ACTION_SYSTEMCTL;
        return systemctl_parse_argv(argc, argv);
}

static int action_to_runlevel(void) {

        static const char table[_ACTION_MAX] = {
                [ACTION_HALT] =      '0',
                [ACTION_POWEROFF] =  '0',
                [ACTION_REBOOT] =    '6',
                [ACTION_RUNLEVEL2] = '2',
                [ACTION_RUNLEVEL3] = '3',
                [ACTION_RUNLEVEL4] = '4',
                [ACTION_RUNLEVEL5] = '5',
                [ACTION_RESCUE] =    '1'
        };

        assert(arg_action < _ACTION_MAX);

        return table[arg_action];
}

static int talk_upstart(void) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int previous, rl, r;
        char
                env1_buf[] = "RUNLEVEL=X",
                env2_buf[] = "PREVLEVEL=X";
        char *env1 = env1_buf, *env2 = env2_buf;
        const char *emit = "runlevel";
        dbus_bool_t b_false = FALSE;
        DBusMessageIter iter, sub;
        DBusConnection *bus;

        dbus_error_init(&error);

        if (!(rl = action_to_runlevel()))
                return 0;

        if (utmp_get_runlevel(&previous, NULL) < 0)
                previous = 'N';

        if (!(bus = dbus_connection_open("unix:abstract=/com/ubuntu/upstart", &error))) {
                if (dbus_error_has_name(&error, DBUS_ERROR_NO_SERVER)) {
                        r = 0;
                        goto finish;
                }

                log_error("Failed to connect to Upstart bus: %s", error.message);
                r = -EIO;
                goto finish;
        }

        if ((r = bus_check_peercred(bus)) < 0) {
                log_error("Failed to verify owner of bus.");
                goto finish;
        }

        if (!(m = dbus_message_new_method_call(
                              "com.ubuntu.Upstart",
                              "/com/ubuntu/Upstart",
                              "com.ubuntu.Upstart0_6",
                              "EmitEvent"))) {

                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        dbus_message_iter_init_append(m, &iter);

        env1_buf[sizeof(env1_buf)-2] = rl;
        env2_buf[sizeof(env2_buf)-2] = previous;

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &emit) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &env1) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &env2) ||
            !dbus_message_iter_close_container(&iter, &sub) ||
            !dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &b_false)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {

                if (error_is_no_service(&error)) {
                        r = 0;
                        goto finish;
                }

                log_error("Failed to issue method call: %s", error.message);
                r = -EIO;
                goto finish;
        }

        r = 1;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        if (bus)
                dbus_connection_unref(bus);

        dbus_error_free(&error);

        return r;
}

static int talk_initctl(void) {
        struct init_request request;
        int r, fd;
        char rl;

        if (!(rl = action_to_runlevel()))
                return 0;

        zero(request);
        request.magic = INIT_MAGIC;
        request.sleeptime = 0;
        request.cmd = INIT_CMD_RUNLVL;
        request.runlevel = rl;

        if ((fd = open(INIT_FIFO, O_WRONLY|O_NDELAY|O_CLOEXEC|O_NOCTTY)) < 0) {

                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open "INIT_FIFO": %m");
                return -errno;
        }

        errno = 0;
        r = loop_write(fd, &request, sizeof(request), false) != sizeof(request);
        close_nointr_nofail(fd);

        if (r < 0) {
                log_error("Failed to write to "INIT_FIFO": %m");
                return errno ? -errno : -EIO;
        }

        return 1;
}

static int systemctl_main(DBusConnection *bus, int argc, char *argv[]) {

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
                { "isolate",           EQUAL, 2, start_unit      },
                { "check",             MORE,  2, check_unit      },
                { "show",              MORE,  1, show            },
                { "monitor",           EQUAL, 1, monitor         },
                { "dump",              EQUAL, 1, dump            },
                { "snapshot",          LESS,  2, snapshot        },
                { "delete",            MORE,  2, delete_snapshot },
                { "daemon-reload",     EQUAL, 1, clear_jobs      },
                { "daemon-reexec",     EQUAL, 1, clear_jobs      },
                { "daemon-exit",       EQUAL, 1, clear_jobs      },
                { "show-environment",  EQUAL, 1, show_enviroment },
                { "set-environment",   MORE,  2, set_environment },
                { "unset-environment", MORE,  2, set_environment },
                { "halt",              EQUAL, 1, start_special   },
                { "poweroff",          EQUAL, 1, start_special   },
                { "reboot",            EQUAL, 1, start_special   },
                { "default",           EQUAL, 1, start_special   },
                { "rescue",            EQUAL, 1, start_special   },
                { "emergency",         EQUAL, 1, start_special   },
        };

        int left;
        unsigned i;

        assert(bus);
        assert(argc >= 0);
        assert(argv);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list-units" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        systemctl_help();
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        return verbs[i].dispatch(bus, argv + optind, left);
}

static int reload_with_fallback(DBusConnection *bus) {
        int r;

        if (bus) {
                /* First, try systemd via D-Bus. */
                if ((r = clear_jobs(bus, NULL, 0)) > 0)
                        return 0;
        }

        /* Nothing else worked, so let's try signals */
        assert(arg_action == ACTION_RELOAD || arg_action == ACTION_REEXEC);

        if (kill(1, arg_action == ACTION_RELOAD ? SIGHUP : SIGTERM) < 0) {
                log_error("kill() failed: %m");
                return -errno;
        }

        return 0;
}

static int start_with_fallback(DBusConnection *bus) {
        int r;

        warn_wall(arg_action);

        if (bus) {
                /* First, try systemd via D-Bus. */
                if ((r = start_unit(bus, NULL, 0)) > 0)
                        return 0;

                /* Hmm, talking to systemd via D-Bus didn't work. Then
                 * let's try to talk to Upstart via D-Bus. */
                if ((r = talk_upstart()) > 0)
                        return 0;
        }

        /* Nothing else worked, so let's try
         * /dev/initctl */
        if ((r = talk_initctl()) != 0)
                return 0;

        log_error("Failed to talk to init daemon.");
        return -EIO;
}

static int halt_main(DBusConnection *bus) {
        int r;

        if (!arg_immediate)
                return start_with_fallback(bus);

        if (!arg_no_wtmp)
                if ((r = utmp_put_shutdown(0)) < 0)
                        log_warning("Failed to write utmp record: %s", strerror(-r));

        if (!arg_no_sync)
                sync();

        if (arg_dry)
                return 0;

        /* Make sure C-A-D is handled by the kernel from this
         * point on... */
        reboot(RB_ENABLE_CAD);

        switch (arg_action) {

        case ACTION_HALT:
                log_info("Halting");
                reboot(RB_HALT_SYSTEM);
                break;

        case ACTION_POWEROFF:
                log_info("Powering off");
                reboot(RB_POWER_OFF);
                break;

        case ACTION_REBOOT:
                log_info("Rebooting");
                reboot(RB_AUTOBOOT);
                break;

        default:
                assert_not_reached("Unknown halt action.");
        }

        /* We should never reach this. */
        return -ENOSYS;
}

static int runlevel_main(void) {
        int r, runlevel, previous;

        if ((r = utmp_get_runlevel(&runlevel, &previous)) < 0) {
                printf("unknown");
                return r;
        }

        printf("%c %c\n",
               previous <= 0 ? 'N' : previous,
               runlevel <= 0 ? 'N' : runlevel);

        return 0;
}

int main(int argc, char*argv[]) {
        int r, retval = 1;
        DBusConnection *bus = NULL;
        DBusError error;

        dbus_error_init(&error);

        log_parse_environment();

        if ((r = parse_argv(argc, argv)) < 0)
                goto finish;
        else if (r == 0) {
                retval = 0;
                goto finish;
        }

        /* /sbin/runlevel doesn't need to communicate via D-Bus, so
         * let's shortcut this */
        if (arg_action == ACTION_RUNLEVEL) {
                retval = runlevel_main() < 0;
                goto finish;
        }

        /* If we are root, then let's not go via the bus */
        if (geteuid() == 0 && !arg_session) {
                bus = dbus_connection_open("unix:abstract=/org/freedesktop/systemd1/private", &error);

                if (bus && bus_check_peercred(bus) < 0) {
                        log_error("Failed to verify owner of bus.");
                        goto finish;
                }
        } else
                bus = dbus_bus_get(arg_session ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM, &error);

        if (bus)
                dbus_connection_set_exit_on_disconnect(bus, FALSE);

        switch (arg_action) {

        case ACTION_SYSTEMCTL: {

                if (!bus) {
                        log_error("Failed to get D-Bus connection: %s", error.message);
                        goto finish;
                }

                retval = systemctl_main(bus, argc, argv) < 0;
                break;
        }

        case ACTION_HALT:
        case ACTION_POWEROFF:
        case ACTION_REBOOT:
                retval = halt_main(bus) < 0;
                break;

        case ACTION_RUNLEVEL2:
        case ACTION_RUNLEVEL3:
        case ACTION_RUNLEVEL4:
        case ACTION_RUNLEVEL5:
        case ACTION_RESCUE:
        case ACTION_EMERGENCY:
        case ACTION_DEFAULT:
                retval = start_with_fallback(bus) < 0;
                break;

        case ACTION_RELOAD:
        case ACTION_REEXEC:
                retval = reload_with_fallback(bus) < 0;
                break;

        case ACTION_INVALID:
        case ACTION_RUNLEVEL:
        default:
                assert_not_reached("Unknown action");
        }

finish:

        if (bus)
                dbus_connection_unref(bus);

        dbus_error_free(&error);

        dbus_shutdown();

        return retval;
}
