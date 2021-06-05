/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "sd-bus.h"

#include "main-func.h"
#include "tests.h"

static int test_ref_unref(void) {
        sd_bus_message *m = NULL;
        sd_bus *bus = NULL;
        int r;

        /* This test will result in a memory leak in <= v240, but not on v241. Hence to be really useful it
         * should be run through a leak tracker such as valgrind. */

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_tests_skipped("Failed to connect to bus");

        /* Create a message and enqueue it (this shouldn't send it though as the connection setup is not complete yet) */
        assert_se(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/foo", "quux.quux", "waldo") >= 0);
        assert_se(sd_bus_send(bus, m, NULL) >= 0);

        /* Let's now unref the message first and the bus second. */
        m = sd_bus_message_unref(m);
        bus = sd_bus_unref(bus);

        /* We should have a memory leak now on <= v240. Let's do this again, but destroy in the opposite
         * order. On v240 that too should be a leak. */

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_tests_skipped("Failed to connect to bus");

        assert_se(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/foo", "quux.quux", "waldo") >= 0);
        assert_se(sd_bus_send(bus, m, NULL) >= 0);

        /* Let's now unref things in the opposite order */
        bus = sd_bus_unref(bus);
        m = sd_bus_message_unref(m);

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        test_setup_logging(LOG_INFO);

        r = test_ref_unref();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
