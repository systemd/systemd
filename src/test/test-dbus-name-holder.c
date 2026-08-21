/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "errno-util.h"
#include "time-util.h"

int main(int argc, char *argv[]) {
        if (argc < 3 || argc > 5) {
                fprintf(stderr, "Usage: %s BUSNAME READY_MARKER [RELEASE_MARKER] [NOTIFY_MARKER]\n", argv[0]);
                return EXIT_FAILURE;
        }

        const char *name = argv[1];
        const char *marker = argv[2];
        const char *release_marker = argc > 3 ? argv[3] : NULL;
        const char *notify_marker = argc > 4 ? argv[4] : NULL;

        for (;;) {
                sd_bus *bus = NULL;
                int r;

                r = sd_bus_open_system(&bus);
                if (r >= 0)
                        r = sd_bus_request_name(bus, name, 0);
                if (r < 0) {
                        fprintf(stderr, "Failed to acquire %s: %s\n", name, STRERROR(r));
                        sd_bus_flush_close_unref(bus);
                        sleep(1);
                        continue;
                }

                fprintf(stderr, "Acquired dbus name %s\n", name);

                for (;;) {
                        r = sd_bus_process(bus, NULL);
                        if (r < 0)
                                break;
                        if (r > 0)
                                continue;

                        if (release_marker && access(release_marker, F_OK) >= 0) {
                                r = sd_bus_release_name(bus, name);
                                if (r < 0) {
                                        fprintf(stderr, "Failed to release %s: %s\n", name, STRERROR(r));
                                        break;
                                }
                                fprintf(stderr, "Released dbus name %s\n", name);
                                release_marker = NULL; /* go back to blocking until we're killed */
                        }

                        r = sd_bus_wait(bus, release_marker ? 100 * USEC_PER_MSEC : UINT64_MAX);
                        if (r < 0)
                                break;
                }

                fprintf(stderr, "Disconnected from bus, reconnecting\n");
                sd_bus_flush_close_unref(bus);

                while (access(marker, F_OK) < 0) {
                        if (notify_marker && access(notify_marker, F_OK) >= 0) {
                                r = sd_notify(/* unset_environment= */ false, "RELOADING=1\nREADY=1");
                                if (r < 0) {
                                        fprintf(stderr, "Failed to send reload notification: %s\n", STRERROR(r));
                                        return EXIT_FAILURE;
                                }

                                fprintf(stderr, "Sent reload notification\n");
                                notify_marker = NULL;
                        }

                        usleep_safe(50 * USEC_PER_MSEC);
                }
        }
}
