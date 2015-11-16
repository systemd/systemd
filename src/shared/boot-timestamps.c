/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Kay Sievers

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "acpi-fpdt.h"
#include "boot-timestamps.h"
#include "efivars.h"

int boot_timestamps(const dual_timestamp *n, dual_timestamp *firmware, dual_timestamp *loader) {
        usec_t x = 0, y = 0, a;
        int r;
        dual_timestamp _n;

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
        }

        /* Let's convert this to timestamps where the firmware
         * began/loader began working. To make this more confusing:
         * since usec_t is unsigned and the kernel's monotonic clock
         * begins at kernel initialization we'll actually initialize
         * the monotonic timestamps here as negative of the actual
         * value. */

        firmware->monotonic = y;
        loader->monotonic = y - x;

        a = n->monotonic + firmware->monotonic;
        firmware->realtime = n->realtime > a ? n->realtime - a : 0;

        a = n->monotonic + loader->monotonic;
        loader->realtime = n->realtime > a ? n->realtime - a : 0;

        return 0;
}
