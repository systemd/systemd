/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <stdio.h>

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "strv.h"

static int start_transient_service(
                sd_bus *bus,
                const char *name,
                char **argv,
                sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        char **i;
        int r;

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit", &m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", name, "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", "ExecStart");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'v', "a(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'r', "sasb");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", argv[0]);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return r;

        STRV_FOREACH(i, argv) {
                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "b", false);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        return sd_bus_send_with_reply_and_block(bus, m, 0, error, &reply);
}

int main(int argc, char* argv[]) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *name = NULL;
        int r;

        log_parse_environment();
        log_open();

        if (argc < 2) {
                log_error("Missing command line.");
                r = -EINVAL;
                goto fail;
        }

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error("Failed to create new bus: %s", strerror(-r));
                goto fail;
        }

        if (asprintf(&name, "run-%lu.service", (unsigned long) getpid()) < 0) {
                r = log_oom();
                goto fail;
        }

        r = start_transient_service(bus, name, argv + 1, &error);
        if (r < 0) {
                log_error("Failed start transient service: %s", error.message);
                sd_bus_error_free(&error);
                goto fail;
        }

fail:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
