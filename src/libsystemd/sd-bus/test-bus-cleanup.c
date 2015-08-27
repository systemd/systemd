/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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
#include "bus-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "refcnt.h"

static void test_bus_new(void) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;

        assert_se(sd_bus_new(&bus) == 0);
        printf("after new: refcount %u\n", REFCNT_GET(bus->n_ref));
}

static int test_bus_open(void) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r == -ECONNREFUSED || r == -ENOENT)
                return r;

        assert_se(r >= 0);
        printf("after open: refcount %u\n", REFCNT_GET(bus->n_ref));

        return 0;
}

static void test_bus_new_method_call(void) {
        sd_bus *bus = NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

        assert_se(sd_bus_open_system(&bus) >= 0);

        assert_se(sd_bus_message_new_method_call(bus, &m, "a.service.name", "/an/object/path", "an.interface.name", "AMethodName") >= 0);

        printf("after message_new_method_call: refcount %u\n", REFCNT_GET(bus->n_ref));

        sd_bus_unref(bus);
        printf("after bus_unref: refcount %u\n", m->n_ref);
}

static void test_bus_new_signal(void) {
        sd_bus *bus = NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

        assert_se(sd_bus_open_system(&bus) >= 0);

        assert_se(sd_bus_message_new_signal(bus, &m, "/an/object/path", "an.interface.name", "Name") >= 0);

        printf("after message_new_signal: refcount %u\n", REFCNT_GET(bus->n_ref));

        sd_bus_unref(bus);
        printf("after bus_unref: refcount %u\n", m->n_ref);
}

int main(int argc, char **argv) {
        int r;

        log_parse_environment();
        log_open();

        test_bus_new();
        r = test_bus_open();
        if (r < 0) {
                log_info("Failed to connect to bus, skipping tests.");
                return EXIT_TEST_SKIP;
        }

        test_bus_new_method_call();
        test_bus_new_signal();

        return EXIT_SUCCESS;
}
