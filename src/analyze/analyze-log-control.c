/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-log-control.h"
#include "verb-log-control.h"

int verb_log_control(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(IN_SET(argc, 1, 2));

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        r = verb_log_control_common(bus, "org.freedesktop.systemd1", argv[0], argc == 2 ? argv[1] : NULL);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}
