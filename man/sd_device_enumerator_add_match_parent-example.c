/* SPDX-License-Identifier: MIT-0 */

#include <stdbool.h>
#include <stdio.h>
#include <systemd/sd-device.h>

int main(void) {
    __attribute__((cleanup(sd_device_enumerator_unrefp))) sd_device_enumerator *enumerator = NULL;
    sd_device *device;
    int r;

    /* Create a new device enumerator */
    r = sd_device_enumerator_new(&enumerator);
    if (r < 0) {
        fprintf(stderr, "Failed to create device enumerator: %s\n", strerror(-r));
        return 1;
    }

    /* Include only devices from the "usb" subsystem */
    r = sd_device_enumerator_add_match_subsystem(enumerator, "usb", true);
    if (r < 0) {
        fprintf(stderr, "Failed to add subsystem match: %s\n", strerror(-r));
        return 1;
    }

    /*
     * Exclude devices where the "removable" sysattr is "0"
     * These are typically non-removable devices like built-in USB interfaces
     */
    r = sd_device_enumerator_add_match_sysattr(enumerator, "removable", "0", false);
    if (r < 0) {
        fprintf(stderr, "Failed to add sysattr match: %s\n", strerror(-r));
        return 1;
    }

    /* Begin enumerating matching devices */
    for (device = sd_device_enumerator_get_device_first(enumerator);
         device;
         device = sd_device_enumerator_get_device_next(enumerator)) {
        const char *syspath;

        /* Get syspath for the device */
        if (sd_device_get_syspath(device, &syspath) >= 0)
            printf("Removable USB device found: %s\n", syspath);
    }
    return 0;
}
