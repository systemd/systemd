/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "acpi-fpdt.h"
#include "boot-timestamps.h"
#include "efi-loader.h"
#include "macro.h"
#include "time-util.h"
#include "virt.h"

int boot_timestamps(const dual_timestamp *n, dual_timestamp *firmware, dual_timestamp *loader) {
        usec_t x = 0, y = 0, a;
        int r;
        dual_timestamp _n;
        bool use_firmware = true;

        assert(firmware);
        assert(loader);

        if (!n) {
                dual_timestamp_get(&_n);
                n = &_n;
        }

        r = acpi_get_boot_usec(&x, &y);
        if (r < 0) {
                r = efi_loader_get_boot_usec(&x, &y);
                if (r < 0)
                        return r;

                /* If we are running in a VM, the init timestamp would
                 * be equivalent to the host uptime. */
                use_firmware = detect_vm() <= 0;
        }

        /* Let's convert this to timestamps where the firmware
         * began/loader began working. To make this more confusing:
         * since usec_t is unsigned and the kernel's monotonic clock
         * begins at kernel initialization we'll actually initialize
         * the monotonic timestamps here as negative of the actual
         * value. */

        if (use_firmware) {
                firmware->monotonic = y;
                a = n->monotonic + firmware->monotonic;
                firmware->realtime = n->realtime > a ? n->realtime - a : 0;
        } else
                firmware->monotonic = firmware->realtime = 0;

        loader->monotonic = y - x;
        a = n->monotonic + loader->monotonic;
        loader->realtime = n->realtime > a ? n->realtime - a : 0;

        return 0;
}
