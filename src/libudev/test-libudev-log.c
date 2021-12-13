/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "libudev.h"

#define handle_error_errno(error, msg)                          \
        ({                                                      \
                errno = abs(error);                             \
                perror(msg);                                    \
                EXIT_FAILURE;                                   \
        })

int main(int argc, char *argv[]) {
        struct udev_enumerate *e;
        int r;

        /* This is a test for the constructor of libudev. If this invoked with
         * SYSTEMD_LOG_LEVEL=debug, then we can find the debugging logs like the following:
         *
         * $ SYSTEMD_LOG_LEVEL=debug ./test-libudev-log
         * sd-device-enumerator: Scan all dirs
         * sd-device-enumerator: Scanning /sys/bus
         * sd-device-enumerator: Scanning /sys/class
         */

        e = udev_enumerate_new(NULL);
        if (!e)
                handle_error_errno(errno, "Failed to create udev-enumerate");

        r = udev_enumerate_add_match_subsystem(e, "net");
        if (r < 0) {
                udev_enumerate_unref(e);
                handle_error_errno(r, "Failed to add subsystem filter");
        }

        (void) udev_enumerate_scan_devices(e);
        udev_enumerate_unref(e);

        return 0;
}
