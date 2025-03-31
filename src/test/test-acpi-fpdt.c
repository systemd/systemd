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
#include "time-util.h"
#include "threads.h"
#include "tests.h"

struct acpi_table_header {
        char signature[4];
        uint32_t length;
        uint8_t revision;
        uint8_t checksum;
        char oem_id[6];
        char oem_table_id[8];
        uint32_t oem_revision;
        char asl_compiler_id[4];
        uint32_t asl_compiler_revision;
} _packed_;

enum {
        ACPI_FPDT_TYPE_BOOT =   0,
        ACPI_FPDT_TYPE_S3PERF = 1,
};

struct acpi_fpdt_header {
        uint16_t type;
        uint8_t length;
        uint8_t revision;
        uint8_t reserved[4];
        uint64_t ptr;
} _packed_;

struct acpi_fpdt_boot_header {
        char signature[4];
        uint32_t length;
} _packed_;

enum {
        ACPI_FPDT_S3PERF_RESUME_REC =   0,
        ACPI_FPDT_S3PERF_SUSPEND_REC =  1,
        ACPI_FPDT_BOOT_REC =            2,
};

struct acpi_fpdt_boot {
        uint16_t type;
        uint8_t length;
        uint8_t revision;
        uint8_t reserved[4];
        uint64_t reset_end;
        uint64_t load_start;
        uint64_t startup_start;
        uint64_t exit_services_entry;
        uint64_t exit_services_exit;
} _packed;

static int acpi_get_boot_usec_kernel_parsed(usec_t *ret_loader_start, usec_t *ret_loader_exit);

TEST(acpi_get_boot_usec) {
        _cleanup_free_ char *buf = NULL;
        struct acpi_table_header *tbl;
        size_t l;
        int r;
        _cleanup_close_ int fd = -EBADF;
        struct timespec ts_start;
        timespec_get(&ts_start, TIME_UTC);
        usec_t start_time = (long unsigned int) ts_start.tv_nsec;
        usec_t *ret_loader_start = &start_time;

        ASSERT_OK_ZERO(usleep_safe(1));
        struct timespec ts_end;
        timespec_get(&ts_end, TIME_UTC);
        usec_t exit_time = (long unsigned int) ts_end.tv_nsec;
        usec_t *ret_loader_exit = &exit_time;

        log_info("ret_loader start time: %lu\n", *ret_loader_start);
        log_info("ret_loader exit time:  %lu\n", *ret_loader_exit);

        r = acpi_get_boot_usec_kernel_parsed(ret_loader_start, ret_loader_exit);
        if (r == -ENODATA || r == -EINVAL || r < 0)
                return (void) log_error_errno(r, "'/sys/firmware/acpi/fpdt/boot/' not found: %m");

        ASSERT_OK(r);

        r = read_full_virtual_file("/sys/firmware/acpi/tables/FPDT", &buf, &l);
        if (r < 0)
                return (void) log_error_errno(r, "'/sys/firmware/acpi/tables/FPDT' not found: %m");

        ASSERT_OK(r);

        tbl = (struct acpi_table_header *)buf;
        log_info("l value: %lu\n", l);
        log_info("tbl->length: %x\n", tbl->length);
        log_info("buf: %s\n", buf);

        ASSERT_OK(l == tbl->length);
        ASSERT_GE(l, (sizeof(struct acpi_table_header) + sizeof(struct acpi_fpdt_header)));
        ASSERT_OK(memcmp(tbl->signature, "FPDT", 4) == 0);
}
DEFINE_TEST_MAIN(LOG_DEBUG);


static int acpi_get_boot_usec_kernel_parsed(usec_t *ret_loader_start, usec_t *ret_loader_exit) {
        usec_t start, end;
        int r;

        r = read_timestamp_file("/sys/firmware/acpi/fpdt/boot/exitbootservice_end_ns", &end);
        if (r < 0)
                return r;

        if (end == 0)
                /* Non-UEFI compatible boot. */
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
