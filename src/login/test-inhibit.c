/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <unistd.h>

#include <dbus/dbus.h>

#include "macro.h"
#include "util.h"
#include "dbus-common.h"

static int inhibit(DBusConnection *bus, const char *what) {
        DBusMessage *m, *reply;
        DBusError error;
        const char *who = "Test Tool", *reason = "Just because!", *mode = "block";
        int fd;

        dbus_error_init(&error);

        m = dbus_message_new_method_call(
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "Inhibit");
        assert(m);

        assert_se(dbus_message_append_args(m,
                                           DBUS_TYPE_STRING, &what,
                                           DBUS_TYPE_STRING, &who,
                                           DBUS_TYPE_STRING, &reason,
                                           DBUS_TYPE_STRING, &mode,
                                           DBUS_TYPE_INVALID));

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        assert(reply);

        assert(dbus_message_get_args(reply, &error,
                                     DBUS_TYPE_UNIX_FD, &fd,
                                     DBUS_TYPE_INVALID));

        dbus_message_unref(m);
        dbus_message_unref(reply);

        return fd;
}

static void print_inhibitors(DBusConnection *bus) {
        DBusMessage *m, *reply;
        DBusError error;
        unsigned n = 0;
        DBusMessageIter iter, sub, sub2;

        dbus_error_init(&error);

        m = dbus_message_new_method_call(
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListInhibitors");
        assert(m);

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        assert(reply);

        assert(dbus_message_iter_init(reply, &iter));
        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *what, *who, *why, *mode;
                dbus_uint32_t uid, pid;

                dbus_message_iter_recurse(&sub, &sub2);

                assert_se(bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &what, true) >= 0);
                assert_se(bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &who, true) >= 0);
                assert_se(bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &why, true) >= 0);
                assert_se(bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &mode, true) >= 0);
                assert_se(bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &uid, true) >= 0);
                assert_se(bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &pid, false) >= 0);

                printf("what=<%s> who=<%s> why=<%s> mode=<%s> uid=<%lu> pid=<%lu>\n",
                       what, who, why, mode, (unsigned long) uid, (unsigned long) pid);

                dbus_message_iter_next(&sub);

                n++;
        }

        printf("%u inhibitors\n", n);

        dbus_message_unref(m);
        dbus_message_unref(reply);
}

int main(int argc, char*argv[]) {
        DBusConnection *bus;
        int fd1, fd2;

        bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, NULL);
        assert(bus);

        print_inhibitors(bus);

        fd1 = inhibit(bus, "sleep");
        assert(fd1 >= 0);
        print_inhibitors(bus);

        fd2 = inhibit(bus, "idle:shutdown");
        assert(fd2 >= 0);
        print_inhibitors(bus);

        close_nointr_nofail(fd1);
        sleep(1);
        print_inhibitors(bus);

        close_nointr_nofail(fd2);
        sleep(1);
        print_inhibitors(bus);

        return 0;
}
