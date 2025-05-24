/* SPDX-License-Identifier: MIT-0 */

#include <systemd/sd-device.h>
#include <stdio.h>

int main(void) {
    sd_device_enumerator *enumerator = NULL;
    int r = sd_device_enumerator_new(&enumerator);
    if (r < 0) {
        fprintf(stderr, "Failed to create enumerator: %d\n", r);
        return 1;
    }

    sd_device_enumerator_ref(enumerator);
    sd_device_enumerator_unref(enumerator);

    sd_device_enumerator_unref(enumerator);

    return 0;
}