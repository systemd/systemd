/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "log.h"
#include "main-func.h"
#include "time-util.h"

static int run(int argc, char *argv[]) {
        int r;

        if (argc < 3 || argc > 5)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Usage: %s BUSNAME READY_MARKER [RELEASE_MARKER] [NOTIFY_MARKER]",
                                       program_invocation_short_name);

        const char
                *name = argv[1],
                *marker = argv[2],
                *release_marker = argc > 3 ? argv[3] : NULL,
                *notify_marker = argc > 4 ? argv[4] : NULL;

        for (;;) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                r = sd_bus_open_system(&bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to open system bus: %m");

                r = sd_bus_request_name(bus, name, /* flags= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire dbus name '%s': %m", name);

                log_info("Acquired dbus name '%s'.", name);

                for (;;) {
                        r = sd_bus_process(bus, /* ret= */ NULL);
                        if (r < 0)
                                break;
                        if (r > 0)
                                continue;

                        if (release_marker && access(release_marker, F_OK) >= 0) {
                                r = sd_bus_release_name(bus, name);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to release dbus name '%s': %m", name);

                                log_info("Released dbus name '%s'.", name);
                                release_marker = NULL; /* go back to blocking until we're killed */
                        }

                        r = sd_bus_wait(bus, release_marker ? 100 * USEC_PER_MSEC : USEC_INFINITY);
                        if (r < 0)
                                break;
                }

                log_info("Disconnected from bus, reconnecting...");

                while (access(marker, F_OK) < 0) {
                        if (notify_marker && access(notify_marker, F_OK) >= 0) {
                                r = sd_notify(/* unset_environment= */ false, "RELOADING=1\nREADY=1");
                                if (r < 0)
                                        return log_error_errno(r, "Failed to send reload notification: %m");

                                log_info("Sent reload notification.");
                                notify_marker = NULL;
                        }

                        usleep_safe(50 * USEC_PER_MSEC);
                }
        }
}

DEFINE_MAIN_FUNCTION(run);
