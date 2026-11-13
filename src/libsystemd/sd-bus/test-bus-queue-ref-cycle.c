/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "tests.h"

TEST(ref_unref) {
        sd_bus_message *m = NULL;
        sd_bus *bus = NULL;
        int r;

        /* This test will result in a memory leak in <= v240, but not on v241. Hence to be really useful it
         * should be run through a leak tracker such as valgrind. */

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to connect to bus");

        /* Create a message and enqueue it (this shouldn't send it though as the connection setup is not complete yet) */
        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/foo", "quux.quux", "waldo"));
        ASSERT_OK(sd_bus_send(bus, m, /* ret_cookie= */ NULL));

        /* Let's now unref the message first and the bus second. */
        m = sd_bus_message_unref(m);
        bus = sd_bus_unref(bus);

        /* We should have a memory leak now on <= v240. Let's do this again, but destroy in the opposite
         * order. On v240 that too should be a leak. */

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to connect to bus");

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/foo", "quux.quux", "waldo"));
        ASSERT_OK(sd_bus_send(bus, m, /* ret_cookie= */ NULL));

        /* Let's now unref things in the opposite order */
        bus = sd_bus_unref(bus);
        m = sd_bus_message_unref(m);
}

DEFINE_TEST_MAIN(LOG_INFO);
