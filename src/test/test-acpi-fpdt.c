/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "acpi-fpdt.h"
#include "tests.h"

TEST(acpi_get_boot_usec) {
        int r;
        r =acpi_get_boot_usec((long unsigned int *) pid_get_start_time, (((long unsigned int *) pid_get_start_time) + 3));
        if (r < 0)
                ASSERT_ERROR(r, ENODATA);
        ASSERT_OK(r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
