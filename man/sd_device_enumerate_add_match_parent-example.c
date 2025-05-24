#include <systemd/sd-device.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    sd_device_enumerator *enumerator = NULL;
    sd_device *device = NULL;
    int r;

    /* Create a new device enumerator */
    r = sd_device_enumerator_new(&enumerator);
    if (r < 0) {
        fprintf(stderr, "Failed to create device enumerator: %s\n", strerror(-r));
        return 1;
    }

    /* Include only devices from the "usb" subsystem */
    sd_device_enumerator_add_match_subsystem(enumerator, "usb", 1);

    /*
     * Exclude devices where the "removable" sysattr is "0"
     * These are typically non-removable devices like built-in USB interfaces
     */
    sd_device_enumerator_add_match_sysattr(enumerator, "removable", "0", 0);

    /* Begin enumerating matching devices */
    device = sd_device_enumerator_get_device_first(enumerator);
    while (device) {
        const char *syspath = NULL;
        const char *devname = NULL;

        /* Get syspath and devname for the device */
        if (sd_device_get_syspath(device, &syspath) >= 0 &&
            sd_device_get_devname(device, &devname) >= 0) {
            printf("Removable USB device found: %s (%s)\n", devname, syspath);
        }

        /* Unref current device and move to the next */
        sd_device_unref(device);
        device = sd_device_enumerator_get_device_next(enumerator);
    }

    /* Clean up enumerator */
    sd_device_enumerator_unref(enumerator);
    return 0;
}