/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd-bus.h"

int main(int argc, char *argv[]) {
        if (argc != 2) {
                fprintf(stderr, "Usage: %s BUSNAME\n", argv[0]);
                return EXIT_FAILURE;
        }

        const char *name = argv[1];

        for (;;) {
                sd_bus *bus = NULL;
                int r;

                r = sd_bus_open_system(&bus);
                if (r >= 0)
                        r = sd_bus_request_name(bus, name, 0);
                if (r < 0) {
                        fprintf(stderr, "Failed to acquire %s: %s\n", name, strerror(-r));
                        sd_bus_flush_close_unref(bus);
                        sleep(1);
                        continue;
                }

                fprintf(stderr, "Acquired dbus name %s\n", name);

                for (;;) {
                        r = sd_bus_process(bus, NULL);
                        if (r > 0)
                                continue;
                        if (r == 0)
                                r = sd_bus_wait(bus, UINT64_MAX);
                        if (r < 0)
                                break;
                }

                fprintf(stderr, "Disconnected from bus, reconnecting\n");
                sd_bus_flush_close_unref(bus);

                /* must be shorter than the manager's grace period */
                sleep(1);
        }
}
