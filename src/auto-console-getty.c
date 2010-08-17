/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <string.h>
#include <stdlib.h>

#include <dbus/dbus.h>

#include "util.h"
#include "log.h"
#include "dbus-common.h"

static int spawn_getty(DBusConnection *bus, const char *console) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        const char *fail = "fail";
        char *name;
        int r = -EIO;

        dbus_error_init(&error);

        assert(bus);
        assert(console);

        /* FIXME: we probably should escape the tty name properly here */
        if (asprintf(&name, "getty@%s.service", console) < 0)
                return -ENOMEM;

        if (!(m = dbus_message_new_method_call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnit"))) {
                log_error("Could not allocate message.");
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_STRING, &fail,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not attach target and flag information to message.");
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to start unit: %s", error.message);
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        free(name);

        return r;
}

static int parse_proc_cmdline_word(const char *word, char **console) {
        assert(word);

        if (startswith(word, "console=")) {
                const char *k;
                size_t l;
                char *w = NULL;

                k = word + 8;
                l = strcspn(k, ",");

                if (l < 4 ||
                    !startswith(k, "tty") ||
                    k[3+strspn(k+3, "0123456789")] != 0) {

                        if (!(w = strndup(k, l)))
                                return -ENOMEM;

                }

                free(*console);
                *console = w;
        }

        return 0;
}

static int parse_proc_cmdline(char **console) {
        char *line;
        int r;
        char *w;
        size_t l;
        char *state;

        assert(console);

        if ((r = read_one_line_file("/tmp/cmdline", &line)) < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {
                char *word;

                if (!(word = strndup(w, l))) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = parse_proc_cmdline_word(word, console);
                free(word);

                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        free(line);
        return r;
}

int main(int argc, char *argv[]) {
        DBusError error;
        int r = 1;
        char *console = NULL;
        DBusConnection *bus = NULL;

        dbus_error_init(&error);

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return 1;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (bus_connect(DBUS_BUS_SYSTEM, &bus, NULL, &error) < 0) {
                log_error("Failed to get D-Bus connection: %s", error.message);
                goto finish;
        }

        if (parse_proc_cmdline(&console) < 0)
                goto finish;

        if (console)
                if (spawn_getty(bus, console) < 0)
                        goto finish;

        r = 0;

finish:
        free(console);

        if (bus) {
               dbus_connection_close(bus);
               dbus_connection_unref(bus);
        }

        dbus_error_free(&error);

        dbus_shutdown();

        return r;
}
