/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-device.h"

#define handle_error_errno(error, msg)                          \
        ({                                                      \
                errno = abs(error);                             \
                perror(msg);                                    \
                EXIT_FAILURE;                                   \
        })

int main(int argc, char *argv[]) {
        __attribute__((__cleanup__(sd_device_enumerator_unrefp))) sd_device_enumerator *e = NULL;
        int r;

        /* This is a test for the constructor of libsystemd. If this invoked with
         * SYSTEMD_LOG_LEVEL=debug, then we can find the debugging logs like the following:
         *
         * $ SYSTEMD_LOG_LEVEL=debug ./test-sd-device-log
         * sd-device-enumerator: Scan all dirs
         * sd-device-enumerator: Scanning /sys/bus
         * sd-device-enumerator: Scanning /sys/class
         */

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                handle_error_errno(r, "Failed to create sd-device-enumerator");

        r = sd_device_enumerator_add_match_subsystem(e, "net", true);
        if (r < 0)
                handle_error_errno(r, "Failed to add subsystem filter");

        (void) sd_device_enumerator_get_device_first(e);

        return 0;
}
