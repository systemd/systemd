/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "sd-bus.h"

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "refcnt.h"
#include "tests.h"

static bool use_system_bus = false;

static void test_bus_new(void) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;

        assert_se(sd_bus_new(&bus) == 0);
        printf("after new: refcount %u\n", REFCNT_GET(bus->n_ref));
}

static int test_bus_open(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_user(&bus);
        if (IN_SET(r, -ECONNREFUSED, -ENOENT)) {
                r = sd_bus_open_system(&bus);
                if (IN_SET(r, -ECONNREFUSED, -ENOENT))
                        return r;
                use_system_bus = true;
        }

        assert_se(r >= 0);
        printf("after open: refcount %u\n", REFCNT_GET(bus->n_ref));

        return 0;
}

static void test_bus_new_method_call(void) {
        sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        assert_se(use_system_bus ? sd_bus_open_system(&bus) >= 0 : sd_bus_open_user(&bus) >= 0);

        assert_se(sd_bus_message_new_method_call(bus, &m, "a.service.name", "/an/object/path", "an.interface.name", "AMethodName") >= 0);

        printf("after message_new_method_call: refcount %u\n", REFCNT_GET(bus->n_ref));

        sd_bus_flush_close_unref(bus);
        printf("after bus_flush_close_unref: refcount %u\n", m->n_ref);
}

static void test_bus_new_signal(void) {
        sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        assert_se(use_system_bus ? sd_bus_open_system(&bus) >= 0 : sd_bus_open_user(&bus) >= 0);

        assert_se(sd_bus_message_new_signal(bus, &m, "/an/object/path", "an.interface.name", "Name") >= 0);

        printf("after message_new_signal: refcount %u\n", REFCNT_GET(bus->n_ref));

        sd_bus_flush_close_unref(bus);
        printf("after bus_flush_close_unref: refcount %u\n", m->n_ref);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_bus_new();

        if (test_bus_open() < 0)
                return log_tests_skipped("Failed to connect to bus");

        test_bus_new_method_call();
        test_bus_new_signal();

        return EXIT_SUCCESS;
}
