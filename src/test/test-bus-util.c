/* SPDX-License-Identifier: LGPL-2.1+ */

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

static void test_destroy_callback(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_slot *slot = NULL;
        sd_bus_destroy_t t;

        int r, n_called = 0;

        log_info("/* %s */", __func__);

        r = bus_open_system_watch_bind_with_description(&bus, "test-bus");
        if (r < 0) {
                log_error_errno(r, "Failed to connect to bus: %m");
                return;
        }

        r = sd_bus_request_name_async(
                bus, &slot, "org.freedesktop.systemd.test-bus-util", 0, callback, &n_called);
        assert(r == 1);

        assert_se(sd_bus_slot_get_destroy_callback(slot, NULL) == 0);
        assert_se(sd_bus_slot_get_destroy_callback(slot, &t) == 0);

        assert_se(sd_bus_slot_set_destroy_callback(slot, destroy_callback) == 0);
        assert_se(sd_bus_slot_get_destroy_callback(slot, NULL) == 1);
        assert_se(sd_bus_slot_get_destroy_callback(slot, &t) == 1);
        assert_se(t == destroy_callback);

        /* Force cleanup so we can look at n_called */
        assert(n_called == 0);
        sd_bus_slot_unref(slot);
        assert(n_called == 1);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_destroy_callback();

        return 0;
}
