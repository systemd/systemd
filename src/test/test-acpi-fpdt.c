/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "acpi-fpdt.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "tests.h"
#include "test-acpi-fpdt.h"

TEST(acpi_get_boot_usec) {
    struct timespec ts_start;
    timespec_get(&ts_start, TIME_UTC);
    ASSERT_OK(ts_start.tv_nsec);
    usec_t start_time = ts_start.tv_nsec;
    usec_t *ret_loader_start = &start_time;

    ASSERT_OK_ZERO(usleep_safe(1));
    struct timespec ts_end;
    timespec_get(&ts_end, TIME_UTC);
    ASSERT_OK(ts_end.tv_nsec);
    usec_t exit_time = ts_end.tv_nsec;
    usec_t *ret_loader_exit = &exit_time;
    log_info("ret_loader start time: %lu\n", *ret_loader_start);
    log_info("ret_loader exit time:  %lu\n", *ret_loader_exit);

    int r;
    r = acpi_get_boot_usec(ret_loader_start, ret_loader_exit);
    if (r == -ENODATA)
                ASSERT_OK(r);

    /*The assertion ASSERT_OK(-ENODATA) failed because it expected -ENODATA to succeed, but it is actually an error: No data available.*/
}

DEFINE_TEST_MAIN(LOG_DEBUG);
