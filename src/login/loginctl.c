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

#include <dbus/dbus.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <pwd.h>
#include <locale.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "pager.h"
#include "dbus-common.h"
#include "build.h"
#include "strv.h"
#include "unit-name.h"
#include "sysfs-show.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "spawn-polkit-agent.h"

static char **arg_property = NULL;
static bool arg_all = false;
static bool arg_full = false;
static bool arg_no_pager = false;
static const char *arg_kill_who = NULL;
static int arg_signal = SIGTERM;
static enum transport {
        TRANSPORT_NORMAL,
        TRANSPORT_SSH,
        TRANSPORT_POLKIT
} arg_transport = TRANSPORT_NORMAL;
static bool arg_ask_password = true;
static char *arg_host = NULL;
static char *arg_user = NULL;

static void pager_open_if_enabled(void) {

        /* Cache result before we open the pager */
        if (arg_no_pager)
                return;

        pager_open(false);
}

static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        polkit_agent_open();
}

static int list_sessions(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        pager_open_if_enabled();

        r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListSessions",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%10s %10s %-16s %-16s\n", "SESSION", "UID", "USER", "SEAT");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *id, *user, *seat, *object;
                uint32_t uid;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &uid, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &user, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &seat, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &object, false) < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                printf("%10s %10u %-16s %-16s\n", id, (unsigned) uid, user, seat);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u sessions listed.\n", k);

        return 0;
}

static int list_users(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        pager_open_if_enabled();

        r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListUsers",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%10s %-16s\n", "UID", "USER");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *user, *object;
                uint32_t uid;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &uid, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &user, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &object, false) < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                printf("%10u %-16s\n", (unsigned) uid, user);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u users listed.\n", k);

        return 0;
}

static int list_seats(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        pager_open_if_enabled();

        r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListSeats",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%-16s\n", "SEAT");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *seat, *object;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &seat, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &object, false) < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                printf("%-16s\n", seat);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u seats listed.\n", k);

        return 0;
}

static int show_unit_cgroup(DBusConnection *bus, const char *interface, const char *unit, pid_t leader) {
        const char *property = "ControlGroup";
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        _cleanup_free_ char *path = NULL;
        DBusMessageIter iter, sub;
        const char *cgroup;
        DBusError error;
        int r, output_flags;
        unsigned c;

        assert(bus);
        assert(unit);

        if (arg_transport == TRANSPORT_SSH)
                return 0;

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = bus_method_call_with_reply(
                        bus,
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
                log_error("Failed to query ControlGroup: %s", bus_error(&error, r));
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

        dbus_message_iter_get_basic(&sub, &cgroup);

        if (isempty(cgroup))
                return 0;

        if (cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, cgroup, false) != 0 && leader <= 0)
                return 0;

        output_flags =
                arg_all * OUTPUT_SHOW_ALL |
                arg_full * OUTPUT_FULL_WIDTH;

        c = columns();
        if (c > 18)
                c -= 18;
        else
                c = 0;

        show_cgroup_and_extra(SYSTEMD_CGROUP_CONTROLLER, cgroup, "\t\t  ", c, false, &leader, leader > 0, output_flags);
        return 0;
}

typedef struct SessionStatusInfo {
        const char *id;
        uid_t uid;
        const char *name;
        usec_t timestamp;
        int vtnr;
        const char *seat;
        const char *tty;
        const char *display;
        bool remote;
        const char *remote_host;
        const char *remote_user;
        const char *service;
        pid_t leader;
        const char *type;
        const char *class;
        const char *state;
        const char *scope;
} SessionStatusInfo;

typedef struct UserStatusInfo {
        uid_t uid;
        const char *name;
        usec_t timestamp;
        const char *state;
        char **sessions;
        const char *display;
        const char *slice;
} UserStatusInfo;

typedef struct SeatStatusInfo {
        const char *id;
        const char *active_session;
        char **sessions;
} SeatStatusInfo;

static void print_session_status_info(DBusConnection *bus, SessionStatusInfo *i) {
        char since1[FORMAT_TIMESTAMP_RELATIVE_MAX], *s1;
        char since2[FORMAT_TIMESTAMP_MAX], *s2;
        assert(i);

        printf("%s - ", strna(i->id));

        if (i->name)
                printf("%s (%u)\n", i->name, (unsigned) i->uid);
        else
                printf("%u\n", (unsigned) i->uid);

        s1 = format_timestamp_relative(since1, sizeof(since1), i->timestamp);
        s2 = format_timestamp(since2, sizeof(since2), i->timestamp);

        if (s1)
                printf("\t   Since: %s; %s\n", s2, s1);
        else if (s2)
                printf("\t   Since: %s\n", s2);

        if (i->leader > 0) {
                _cleanup_free_ char *t = NULL;

                printf("\t  Leader: %u", (unsigned) i->leader);

                get_process_comm(i->leader, &t);
                if (t)
                        printf(" (%s)", t);

                printf("\n");
        }

        if (i->seat) {
                printf("\t    Seat: %s", i->seat);

                if (i->vtnr > 0)
                        printf("; vc%i", i->vtnr);

                printf("\n");
        }

        if (i->tty)
                printf("\t     TTY: %s\n", i->tty);
        else if (i->display)
                printf("\t Display: %s\n", i->display);

        if (i->remote_host && i->remote_user)
                printf("\t  Remote: %s@%s\n", i->remote_user, i->remote_host);
        else if (i->remote_host)
                printf("\t  Remote: %s\n", i->remote_host);
        else if (i->remote_user)
                printf("\t  Remote: user %s\n", i->remote_user);
        else if (i->remote)
                printf("\t  Remote: Yes\n");

        if (i->service) {
                printf("\t Service: %s", i->service);

                if (i->type)
                        printf("; type %s", i->type);

                if (i->class)
                        printf("; class %s", i->class);

                printf("\n");
        } else if (i->type) {
                printf("\t    Type: %s\n", i->type);

                if (i->class)
                        printf("; class %s", i->class);
        } else if (i->class)
                printf("\t   Class: %s\n", i->class);

        if (i->state)
                printf("\t   State: %s\n", i->state);

        if (i->scope) {
                printf("\t    Unit: %s\n", i->scope);
                show_unit_cgroup(bus, "org.freedesktop.systemd1.Scope", i->scope, i->leader);
        }
}

static void print_user_status_info(DBusConnection *bus, UserStatusInfo *i) {
        char since1[FORMAT_TIMESTAMP_RELATIVE_MAX], *s1;
        char since2[FORMAT_TIMESTAMP_MAX], *s2;
        assert(i);

        if (i->name)
                printf("%s (%u)\n", i->name, (unsigned) i->uid);
        else
                printf("%u\n", (unsigned) i->uid);

        s1 = format_timestamp_relative(since1, sizeof(since1), i->timestamp);
        s2 = format_timestamp(since2, sizeof(since2), i->timestamp);

        if (s1)
                printf("\t   Since: %s; %s\n", s2, s1);
        else if (s2)
                printf("\t   Since: %s\n", s2);

        if (!isempty(i->state))
                printf("\t   State: %s\n", i->state);


        if (!strv_isempty(i->sessions)) {
                char **l;
                printf("\tSessions:");

                STRV_FOREACH(l, i->sessions) {
                        if (streq_ptr(*l, i->display))
                                printf(" *%s", *l);
                        else
                                printf(" %s", *l);
                }

                printf("\n");
        }

        if (i->slice) {
                printf("\t    Unit: %s\n", i->slice);
                show_unit_cgroup(bus, "org.freedesktop.systemd1.Slice", i->slice, 0);
        }
}

static void print_seat_status_info(SeatStatusInfo *i) {
        assert(i);

        printf("%s\n", strna(i->id));

        if (!strv_isempty(i->sessions)) {
                char **l;
                printf("\tSessions:");

                STRV_FOREACH(l, i->sessions) {
                        if (streq_ptr(*l, i->active_session))
                                printf(" *%s", *l);
                        else
                                printf(" %s", *l);
                }

                printf("\n");
        }

        if (arg_transport != TRANSPORT_SSH) {
                unsigned c;

                c = columns();
                if (c > 21)
                        c -= 21;
                else
                        c = 0;

                printf("\t Devices:\n");

                show_sysfs(i->id, "\t\t  ", c);
        }
}

static int status_property_session(const char *name, DBusMessageIter *iter, SessionStatusInfo *i) {
        assert(name);
        assert(iter);
        assert(i);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);

                if (!isempty(s)) {
                        if (streq(name, "Id"))
                                i->id = s;
                        else if (streq(name, "Name"))
                                i->name = s;
                        else if (streq(name, "TTY"))
                                i->tty = s;
                        else if (streq(name, "Display"))
                                i->display = s;
                        else if (streq(name, "RemoteHost"))
                                i->remote_host = s;
                        else if (streq(name, "RemoteUser"))
                                i->remote_user = s;
                        else if (streq(name, "Service"))
                                i->service = s;
                        else if (streq(name, "Type"))
                                i->type = s;
                        else if (streq(name, "Class"))
                                i->class = s;
                        else if (streq(name, "Scope"))
                                i->scope = s;
                        else if (streq(name, "State"))
                                i->state = s;
                }
                break;
        }

        case DBUS_TYPE_UINT32: {
                uint32_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "VTNr"))
                        i->vtnr = (int) u;
                else if (streq(name, "Leader"))
                        i->leader = (pid_t) u;

                break;
        }

        case DBUS_TYPE_BOOLEAN: {
                dbus_bool_t b;

                dbus_message_iter_get_basic(iter, &b);

                if (streq(name, "Remote"))
                        i->remote = b;

                break;
        }

        case DBUS_TYPE_UINT64: {
                uint64_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "Timestamp"))
                        i->timestamp = (usec_t) u;

                break;
        }

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter sub;

                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_UINT32 && streq(name, "User")) {
                        uint32_t u;

                        dbus_message_iter_get_basic(&sub, &u);
                        i->uid = (uid_t) u;

                } else if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "Seat")) {
                        const char *s;

                        dbus_message_iter_get_basic(&sub, &s);

                        if (!isempty(s))
                                i->seat = s;
                }

                break;
        }
        }

        return 0;
}

static int status_property_user(const char *name, DBusMessageIter *iter, UserStatusInfo *i) {
        assert(name);
        assert(iter);
        assert(i);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);

                if (!isempty(s)) {
                        if (streq(name, "Name"))
                                i->name = s;
                        else if (streq(name, "Slice"))
                                i->slice = s;
                        else if (streq(name, "State"))
                                i->state = s;
                }
                break;
        }

        case DBUS_TYPE_UINT32: {
                uint32_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "UID"))
                        i->uid = (uid_t) u;

                break;
        }

        case DBUS_TYPE_UINT64: {
                uint64_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "Timestamp"))
                        i->timestamp = (usec_t) u;

                break;
        }

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter sub;

                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "Display")) {
                        const char *s;

                        dbus_message_iter_get_basic(&sub, &s);

                        if (!isempty(s))
                                i->display = s;
                }

                break;
        }

        case DBUS_TYPE_ARRAY: {

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Sessions")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *id;
                                const char *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &path, false) >= 0) {
                                        char **l;

                                        l = strv_append(i->sessions, id);
                                        if (!l)
                                                return -ENOMEM;

                                        strv_free(i->sessions);
                                        i->sessions = l;
                                }

                                dbus_message_iter_next(&sub);
                        }

                        return 0;
                }
        }
        }

        return 0;
}

static int status_property_seat(const char *name, DBusMessageIter *iter, SeatStatusInfo *i) {
        assert(name);
        assert(iter);
        assert(i);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);

                if (!isempty(s)) {
                        if (streq(name, "Id"))
                                i->id = s;
                }
                break;
        }

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter sub;

                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "ActiveSession")) {
                        const char *s;

                        dbus_message_iter_get_basic(&sub, &s);

                        if (!isempty(s))
                                i->active_session = s;
                }

                break;
        }

        case DBUS_TYPE_ARRAY: {

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Sessions")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *id;
                                const char *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &path, false) >= 0) {
                                        char **l;

                                        l = strv_append(i->sessions, id);
                                        if (!l)
                                                return -ENOMEM;

                                        strv_free(i->sessions);
                                        i->sessions = l;
                                }

                                dbus_message_iter_next(&sub);
                        }

                        return 0;
                }
        }
        }

        return 0;
}

static int print_property(const char *name, DBusMessageIter *iter) {
        assert(name);
        assert(iter);

        if (arg_property && !strv_find(arg_property, name))
                return 0;

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter sub;

                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING &&
                    (streq(name, "Display") || streq(name, "ActiveSession"))) {
                        const char *s;

                        dbus_message_iter_get_basic(&sub, &s);

                        if (arg_all || !isempty(s))
                                printf("%s=%s\n", name, s);
                        return 0;
                }
                break;
        }

        case DBUS_TYPE_ARRAY:

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Sessions")) {
                        DBusMessageIter sub, sub2;
                        bool found = false;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *id;
                                const char *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &path, false) >= 0) {
                                        if (found)
                                                printf(" %s", id);
                                        else {
                                                printf("%s=%s", name, id);
                                                found = true;
                                        }
                                }

                                dbus_message_iter_next(&sub);
                        }

                        if (!found && arg_all)
                                printf("%s=\n", name);
                        else if (found)
                                printf("\n");

                        return 0;
                }

                break;
        }

        if (generic_print_property(name, iter, arg_all) > 0)
                return 0;

        if (arg_all)
                printf("%s=[unprintable]\n", name);

        return 0;
}

static int show_one(const char *verb, DBusConnection *bus, const char *path, bool show_properties, bool *new_line) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *interface = "";
        int r;
        DBusMessageIter iter, sub, sub2, sub3;
        SessionStatusInfo session_info = {};
        UserStatusInfo user_info = {};
        SeatStatusInfo seat_info = {};

        assert(path);
        assert(new_line);

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.login1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                goto finish;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (*new_line)
                printf("\n");

        *new_line = true;

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

                if (show_properties)
                        r = print_property(name, &sub3);
                else if (strstr(verb, "session"))
                        r = status_property_session(name, &sub3, &session_info);
                else if (strstr(verb, "user"))
                        r = status_property_user(name, &sub3, &user_info);
                else
                        r = status_property_seat(name, &sub3, &seat_info);

                if (r < 0) {
                        log_error("Failed to parse reply.");
                        goto finish;
                }

                dbus_message_iter_next(&sub);
        }

        if (!show_properties) {
                if (strstr(verb, "session"))
                        print_session_status_info(bus, &session_info);
                else if (strstr(verb, "user"))
                        print_user_status_info(bus, &user_info);
                else
                        print_seat_status_info(&seat_info);
        }

        r = 0;

finish:
        strv_free(seat_info.sessions);
        strv_free(user_info.sessions);

        return r;
}

static int show(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r, ret = 0;
        DBusError error;
        unsigned i;
        bool show_properties, new_line = false;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        show_properties = !strstr(args[0], "status");

        pager_open_if_enabled();

        if (show_properties && n <= 1) {
                /* If not argument is specified inspect the manager
                 * itself */

                ret = show_one(args[0], bus, "/org/freedesktop/login1", show_properties, &new_line);
                goto finish;
        }

        for (i = 1; i < n; i++) {
                const char *path = NULL;

                if (strstr(args[0], "session")) {

                        ret = bus_method_call_with_reply (
                                        bus,
                                        "org.freedesktop.login1",
                                        "/org/freedesktop/login1",
                                        "org.freedesktop.login1.Manager",
                                        "GetSession",
                                        &reply,
                                        NULL,
                                        DBUS_TYPE_STRING, &args[i],
                                        DBUS_TYPE_INVALID);

                } else if (strstr(args[0], "user")) {
                        uid_t uid;
                        uint32_t u;

                        ret = get_user_creds((const char**) (args+i), &uid, NULL, NULL, NULL);
                        if (ret < 0) {
                                log_error("User %s unknown.", args[i]);
                                goto finish;
                        }

                        u = (uint32_t) uid;
                        ret = bus_method_call_with_reply(
                                        bus,
                                        "org.freedesktop.login1",
                                        "/org/freedesktop/login1",
                                        "org.freedesktop.login1.Manager",
                                        "GetUser",
                                        &reply,
                                        NULL,
                                        DBUS_TYPE_UINT32, &u,
                                        DBUS_TYPE_INVALID);

                } else {

                        ret = bus_method_call_with_reply(
                                        bus,
                                        "org.freedesktop.login1",
                                        "/org/freedesktop/login1",
                                        "org.freedesktop.login1.Manager",
                                        "GetSeat",
                                        &reply,
                                        NULL,
                                        DBUS_TYPE_STRING, &args[i],
                                        DBUS_TYPE_INVALID);

                }

                if (ret < 0)
                        goto finish;

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", bus_error_message(&error));
                        ret = -EIO;
                        goto finish;
                }

                r = show_one(args[0], bus, path, show_properties, &new_line);
                if (r != 0)
                        ret = r;
        }

finish:
        dbus_error_free(&error);

        return ret;
}

static int activate(DBusConnection *bus, char **args, unsigned n) {
        int ret = 0;
        unsigned i;

        assert(args);

        for (i = 1; i < n; i++) {

                ret = bus_method_call_with_reply (
                                bus,
                                "org.freedesktop.login1",
                                "/org/freedesktop/login1",
                                "org.freedesktop.login1.Manager",
                                streq(args[0], "lock-session")      ? "LockSession" :
                                streq(args[0], "unlock-session")    ? "UnlockSession" :
                                streq(args[0], "terminate-session") ? "TerminateSession" :
                                                                      "ActivateSession",
                                NULL,
                                NULL,
                                DBUS_TYPE_STRING, &args[i],
                                DBUS_TYPE_INVALID);
                if (ret)
                        goto finish;
        }

finish:
        return ret;
}

static int kill_session(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;

        assert(args);

        if (!arg_kill_who)
                arg_kill_who = "all";

        for (i = 1; i < n; i++) {
                int r;

                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "KillSession",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING, &args[i],
                        DBUS_TYPE_STRING, &arg_kill_who,
                        DBUS_TYPE_INT32, &arg_signal,
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int enable_linger(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;
        dbus_bool_t b, interactive = true;

        assert(args);

        polkit_agent_open_if_enabled();

        b = streq(args[0], "enable-linger");

        for (i = 1; i < n; i++) {
                uint32_t u;
                uid_t uid;
                int r;

                r = get_user_creds((const char**) (args+i), &uid, NULL, NULL, NULL);
                if (r < 0) {
                        log_error("Failed to resolve user %s: %s", args[i], strerror(-r));
                        return r;
                }

                u = (uint32_t) uid;
                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "SetUserLinger",
                        NULL,
                        NULL,
                        DBUS_TYPE_UINT32, &u,
                        DBUS_TYPE_BOOLEAN, &b,
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int terminate_user(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;

        assert(args);

        for (i = 1; i < n; i++) {
                uint32_t u;
                uid_t uid;
                int r;

                r = get_user_creds((const char**) (args+i), &uid, NULL, NULL, NULL);
                if (r < 0) {
                        log_error("Failed to look up user %s: %s", args[i], strerror(-r));
                        return r;
                }

                u = (uint32_t) uid;
                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "TerminateUser",
                        NULL,
                        NULL,
                        DBUS_TYPE_UINT32, &u,
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int kill_user(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;

        assert(args);

        if (!arg_kill_who)
                arg_kill_who = "all";

        for (i = 1; i < n; i++) {
                uid_t uid;
                uint32_t u;
                int r;

                r = get_user_creds((const char**) (args+i), &uid, NULL, NULL, NULL);
                if (r < 0) {
                        log_error("Failed to look up user %s: %s", args[i], strerror(-r));
                        return r;
                }

                u = (uint32_t) uid;
                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "KillUser",
                        NULL,
                        NULL,
                        DBUS_TYPE_UINT32, &u,
                        DBUS_TYPE_INT32, &arg_signal,
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int attach(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;
        dbus_bool_t interactive = true;

        assert(args);

        polkit_agent_open_if_enabled();

        for (i = 2; i < n; i++) {
                int r;

                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "AttachDevice",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING, &args[1],
                        DBUS_TYPE_STRING, &args[i],
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int flush_devices(DBusConnection *bus, char **args, unsigned n) {
        dbus_bool_t interactive = true;

        assert(args);

        polkit_agent_open_if_enabled();

        return bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "FlushDevices",
                        NULL,
                        NULL,
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
}

static int lock_sessions(DBusConnection *bus, char **args, unsigned n) {
        assert(args);

        polkit_agent_open_if_enabled();

        return bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        streq(args[0], "lock-sessions") ? "LockSessions" : "UnlockSessions",
                        NULL,
                        NULL,
                        DBUS_TYPE_INVALID);
}

static int terminate_seat(DBusConnection *bus, char **args, unsigned n) {
        unsigned i;

        assert(args);

        for (i = 1; i < n; i++) {
                int r;

                r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "TerminateSeat",
                        NULL,
                        NULL,
                        DBUS_TYPE_STRING, &args[i],
                        DBUS_TYPE_INVALID);
                if (r)
                        return r;
        }

        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to or query the login manager.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "  -p --property=NAME     Show only properties by this name\n"
               "  -a --all               Show all properties, including empty ones\n"
               "     --kill-who=WHO      Who to send signal to\n"
               "  -l --full              Do not ellipsize output\n"
               "  -s --signal=SIGNAL     Which signal to send\n"
               "     --no-ask-password   Don't prompt for password\n"
               "  -H --host=[USER@]HOST  Show information for remote host\n"
               "  -P --privileged        Acquire privileges before execution\n"
               "     --no-pager          Do not pipe output into a pager\n\n"
               "Commands:\n"
               "  list-sessions                   List sessions\n"
               "  session-status [ID...]          Show session status\n"
               "  show-session [ID...]            Show properties of one or more sessions\n"
               "  activate [ID]                   Activate a session\n"
               "  lock-session [ID...]            Screen lock one or more sessions\n"
               "  unlock-session [ID...]          Screen unlock one or more sessions\n"
               "  lock-sessions                   Screen lock all current sessions\n"
               "  unlock-sessions                 Screen unlock all current sessions\n"
               "  terminate-session [ID...]       Terminate one or more sessions\n"
               "  kill-session [ID...]            Send signal to processes of a session\n"
               "  list-users                      List users\n"
               "  user-status [USER...]           Show user status\n"
               "  show-user [USER...]             Show properties of one or more users\n"
               "  enable-linger [USER...]         Enable linger state of one or more users\n"
               "  disable-linger [USER...]        Disable linger state of one or more users\n"
               "  terminate-user [USER...]        Terminate all sessions of one or more users\n"
               "  kill-user [USER...]             Send signal to processes of a user\n"
               "  list-seats                      List seats\n"
               "  seat-status [NAME...]           Show seat status\n"
               "  show-seat [NAME...]             Show properties of one or more seats\n"
               "  attach [NAME] [DEVICE...]       Attach one or more devices to a seat\n"
               "  flush-devices                   Flush all device associations\n"
               "  terminate-seat [NAME...]        Terminate all sessions on one or more seats\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_KILL_WHO,
                ARG_NO_ASK_PASSWORD,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "property",        required_argument, NULL, 'p'                 },
                { "all",             no_argument,       NULL, 'a'                 },
                { "full",            no_argument,       NULL, 'l'                 },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "kill-who",        required_argument, NULL, ARG_KILL_WHO        },
                { "signal",          required_argument, NULL, 's'                 },
                { "host",            required_argument, NULL, 'H'                 },
                { "privileged",      no_argument,       NULL, 'P'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { NULL,              0,                 NULL, 0                   }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:als:H:P", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'p': {
                        char **l;

                        l = strv_append(arg_property, optarg);
                        if (!l)
                                return -ENOMEM;

                        strv_free(arg_property);
                        arg_property = l;

                        /* If the user asked for a particular
                         * property, show it to him, even if it is
                         * empty. */
                        arg_all = true;
                        break;
                }

                case 'a':
                        arg_all = true;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_KILL_WHO:
                        arg_kill_who = optarg;
                        break;

                case 's':
                        arg_signal = signal_from_string_try_harder(optarg);
                        if (arg_signal < 0) {
                                log_error("Failed to parse signal string %s.", optarg);
                                return -EINVAL;
                        }
                        break;

                case 'P':
                        arg_transport = TRANSPORT_POLKIT;
                        break;

                case 'H':
                        arg_transport = TRANSPORT_SSH;
                        parse_user_at_host(optarg, &arg_user, &arg_host);
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

static int loginctl_main(DBusConnection *bus, int argc, char *argv[], DBusError *error) {

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
                { "list-sessions",         LESS,   1, list_sessions     },
                { "session-status",        MORE,   2, show              },
                { "show-session",          MORE,   1, show              },
                { "activate",              EQUAL,  2, activate          },
                { "lock-session",          MORE,   2, activate          },
                { "unlock-session",        MORE,   2, activate          },
                { "lock-sessions",         EQUAL,  1, lock_sessions     },
                { "unlock-sessions",       EQUAL,  1, lock_sessions     },
                { "terminate-session",     MORE,   2, activate          },
                { "kill-session",          MORE,   2, kill_session      },
                { "list-users",            EQUAL,  1, list_users        },
                { "user-status",           MORE,   2, show              },
                { "show-user",             MORE,   1, show              },
                { "enable-linger",         MORE,   2, enable_linger     },
                { "disable-linger",        MORE,   2, enable_linger     },
                { "terminate-user",        MORE,   2, terminate_user    },
                { "kill-user",             MORE,   2, kill_user         },
                { "list-seats",            EQUAL,  1, list_seats        },
                { "seat-status",           MORE,   2, show              },
                { "show-seat",             MORE,   1, show              },
                { "attach",                MORE,   3, attach            },
                { "flush-devices",         EQUAL,  1, flush_devices     },
                { "terminate-seat",        MORE,   2, terminate_seat    },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);
        assert(error);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list-sessions" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        help();
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

        if (!bus) {
                log_error("Failed to get D-Bus connection: %s", error->message);
                return -EIO;
        }

        return verbs[i].dispatch(bus, argv + optind, left);
}

int main(int argc, char*argv[]) {
        int r, retval = EXIT_FAILURE;
        DBusConnection *bus = NULL;
        DBusError error;

        dbus_error_init(&error);

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        if (arg_transport == TRANSPORT_NORMAL)
                bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        else if (arg_transport == TRANSPORT_POLKIT)
                bus_connect_system_polkit(&bus, &error);
        else if (arg_transport == TRANSPORT_SSH)
                bus_connect_system_ssh(NULL, arg_host, &bus, &error);
        else
                assert_not_reached("Uh, invalid transport...");

        r = loginctl_main(bus, argc, argv, &error);
        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);
        dbus_shutdown();

        strv_free(arg_property);

        pager_close();

        return retval;
}
