/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "acpi-fpdt.h"
#include "tests.h"

TEST(acpi_get_boot_usec) {
        int r;
        usec_t *loader_start_time;
        usec_t *loader_exit_time;
        struct timespec ts_start;
        struct timespec ts_exit;

        timespec_get(&ts_start, TIME_UTC);
        loader_start_time = (long unsigned int *) &ts_start.tv_nsec;

        usleep_safe(1);

        timespec_get(&ts_exit, TIME_UTC);
        loader_exit_time = (long unsigned int *) &ts_exit.tv_nsec;

        r = acpi_get_boot_usec(loader_start_time, loader_exit_time);
        if (r < 0)
                return (void) log_error_errno(r, "acpi_get_boot_usec function failed: %m");

        ASSERT_OK(r);
        /* This assertion fails when the if statement above is commented */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
