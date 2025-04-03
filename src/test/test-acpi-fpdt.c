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

        int r = acpi_get_boot_usec_kernel_parsed(ret_loader_start, ret_loader_exit);
        if (r < 0)
                return (void) log_error_errno(r, "'/sys/firmware/acpi/fpdt/boot/' not found: %m");

        ASSERT_OK(r);
}

static int acpi_get_boot_usec_kernel_parsed(usec_t *ret_loader_start, usec_t *ret_loader_exit) {
        usec_t start, end;
        int r;

        r = read_timestamp_file("/sys/firmware/acpi/fpdt/boot/exitbootservice_end_ns", &end);
        if (r < 0)
                return r;

        if (end == 0)
                return -ENODATA;

        r = read_timestamp_file("/sys/firmware/acpi/fpdt/boot/bootloader_launch_ns", &start);
        if (r < 0)
                return r;

        if (start == 0 || end < start)
                return -EINVAL;
        if (end > NSEC_PER_HOUR)
                return -EINVAL;

        if (ret_loader_start)
                *ret_loader_start = start / 1000;
        if (ret_loader_exit)
                *ret_loader_exit = end / 1000;

        return 0;
}

DEFINE_TEST_MAIN(LOG_DEBUG);
