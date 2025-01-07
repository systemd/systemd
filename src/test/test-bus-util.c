/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-util.h"
#include "log.h"
#include "tests.h"

static int callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        return 1;
}

static void destroy_callback(void *userdata) {
        int *n_called = userdata;

        (*n_called)++;
}

TEST(destroy_callback) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_slot *slot = NULL;
        sd_bus_destroy_t t;

        int r, n_called = 0;

        r = bus_open_system_watch_bind_with_description(&bus, "test-bus");
        if (r < 0)
                return (void) log_error_errno(r, "Failed to connect to bus: %m");

        ASSERT_OK_EQ(sd_bus_request_name_async(bus, &slot, "org.freedesktop.systemd.test-bus-util", 0, callback, &n_called),
                     1);

        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, NULL), 0);
        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, &t), 0);

        ASSERT_EQ(sd_bus_slot_set_destroy_callback(slot, destroy_callback), 0);
        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, NULL), 1);
        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, &t), 1);
        assert_se(t == destroy_callback);

        /* Force cleanup so we can look at n_called */
        ASSERT_EQ(n_called, 0);
        sd_bus_slot_unref(slot);
        ASSERT_EQ(n_called, 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
