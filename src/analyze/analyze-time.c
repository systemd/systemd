/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-time.h"
#include "analyze-time-data.h"

int verb_time(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        r = pretty_boot_time(bus, &buf);
        if (r < 0)
                return r;

        puts(buf);
        return EXIT_SUCCESS;
}
