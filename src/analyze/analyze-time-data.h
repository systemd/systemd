/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sd-bus.h>

#include "time-util.h"

typedef struct BootTimes {
        usec_t firmware_time;
        usec_t loader_time;
        usec_t kernel_time;
        usec_t kernel_done_time;
        usec_t initrd_time;
        usec_t userspace_time;
        usec_t finish_time;
        usec_t security_start_time;
        usec_t security_finish_time;
        usec_t generators_start_time;
        usec_t generators_finish_time;
        usec_t unitsload_start_time;
        usec_t unitsload_finish_time;
        usec_t initrd_security_start_time;
        usec_t initrd_security_finish_time;
        usec_t initrd_generators_start_time;
        usec_t initrd_generators_finish_time;
        usec_t initrd_unitsload_start_time;
        usec_t initrd_unitsload_finish_time;

        /*
         * If we're analyzing the user instance, all timestamps will be offset by its own start-up timestamp,
         * which may be arbitrarily big.  With "plot", this causes arbitrarily wide output SVG files which
         * almost completely consist of empty space. Thus we cancel out this offset.
         *
         * This offset is subtracted from times above by acquire_boot_times(), but it still needs to be
         * subtracted from unit-specific timestamps (so it is stored here for reference).
         */
        usec_t reverse_offset;
} BootTimes;

typedef struct UnitTimes {
        bool has_data;
        char *name;
        usec_t activating;
        usec_t activated;
        usec_t deactivated;
        usec_t deactivating;
        usec_t time;
} UnitTimes;

int acquire_boot_times(sd_bus *bus, BootTimes **ret);
int pretty_boot_time(sd_bus *bus, char **ret);

UnitTimes* unit_times_free_array(UnitTimes *t);
DEFINE_TRIVIAL_CLEANUP_FUNC(UnitTimes*, unit_times_free_array);

int acquire_time_data(sd_bus *bus, UnitTimes **out);
