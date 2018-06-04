/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-util.h"
#include "log.h"

static void test_name_async(unsigned n_messages) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;
        unsigned i;

        log_info("/* %s (%u) */", __func__, n_messages);

        r = bus_open_system_watch_bind_with_description(&bus, "test-bus");
        if (r < 0) {
                log_error_errno(r, "Failed to connect to bus: %m");
                return;
        }

        r = bus_request_name_async_may_reload_dbus(bus, NULL, "org.freedesktop.systemd.test-bus-util", 0, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to request name: %m");
                return;
        }

        for (i = 0; i < n_messages; i++) {
                r = sd_bus_process(bus, NULL);
                log_debug("stage %u: sd_bus_process returned %d", i, r);
                if (r < 0) {
                        log_notice_errno(r, "Processing failed: %m");
                        return;
                }

                if (r > 0 && i + 1 < n_messages)
                        (void) sd_bus_wait(bus, USEC_PER_SEC / 3);
        }
}

int main(int argc, char **argv) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_name_async(0);
        test_name_async(20);

        return 0;
}
