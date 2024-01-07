/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "acpi-fpdt.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "time-util.h"

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

/* /dev/mem is deprecated on many systems, try using /sys/firmware/acpi/fpdt parsing instead.
 * This code requires kernel version 5.12 on x86 based machines or 6.2 for arm64 */
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

int acpi_get_boot_usec(usec_t *ret_loader_start, usec_t *ret_loader_exit) {
        _cleanup_free_ void *buf = NULL;
        uint8_t *buf_base;
        struct acpi_table_header *tbl;
        size_t l;
        ssize_t ll;
        struct acpi_fpdt_header *rec;
        int r;
        uint64_t ptr = 0;
        _cleanup_close_ int fd = -EBADF;
        struct acpi_fpdt_boot_header hbrec;
        struct acpi_fpdt_boot brec;

        r = acpi_get_boot_usec_kernel_parsed(ret_loader_start, ret_loader_exit);
        if (r != -ENOENT) /* fallback to /dev/mem hack only if kernel doesn't support the new sysfs files */
                return r;

        r = read_full_virtual_file("/sys/firmware/acpi/tables/FPDT", &buf, &l);
        if (r < 0)
                return r;

        if (l < sizeof(struct acpi_table_header) + sizeof(struct acpi_fpdt_header))
                return -EINVAL;

        tbl = (struct acpi_table_header *)buf;
        if (l != tbl->length)
                return -EINVAL;

        if (memcmp(tbl->signature, "FPDT", 4) != 0)
                return -EINVAL;

        /* find Firmware Basic Boot Performance Pointer Record */
        buf_base = buf;
        for (rec = (struct acpi_fpdt_header *)(buf_base + sizeof(struct acpi_table_header));
             (char *)rec + offsetof(struct acpi_fpdt_header, revision) <= buf_base + l;
             rec = (struct acpi_fpdt_header *)((char *)rec + rec->length)) {
                if (rec->length <= 0)
                        break;
                if (rec->type != ACPI_FPDT_TYPE_BOOT)
                        continue;
                if (rec->length != sizeof(struct acpi_fpdt_header))
                        continue;

                ptr = rec->ptr;
                break;
        }

        if (ptr == 0)
                return -ENODATA;

        /* read Firmware Basic Boot Performance Data Record */
        fd = open("/dev/mem", O_CLOEXEC|O_RDONLY);
        if (fd < 0)
                return -errno;

        ll = pread(fd, &hbrec, sizeof(struct acpi_fpdt_boot_header), ptr);
        if (ll < 0)
                return -errno;
        if ((size_t) ll != sizeof(struct acpi_fpdt_boot_header))
                return -EINVAL;

        if (memcmp(hbrec.signature, "FBPT", 4) != 0)
                return -EINVAL;

        if (hbrec.length < sizeof(struct acpi_fpdt_boot_header) + sizeof(struct acpi_fpdt_boot))
                return -EINVAL;

        ll = pread(fd, &brec, sizeof(struct acpi_fpdt_boot), ptr + sizeof(struct acpi_fpdt_boot_header));
        if (ll < 0)
                return -errno;
        if ((size_t) ll != sizeof(struct acpi_fpdt_boot))
                return -EINVAL;

        if (brec.length != sizeof(struct acpi_fpdt_boot))
                return -EINVAL;

        if (brec.type != ACPI_FPDT_BOOT_REC)
                return -EINVAL;

        if (brec.exit_services_exit == 0)
                /* Non-UEFI compatible boot. */
                return -ENODATA;

        if (brec.startup_start == 0 || brec.exit_services_exit < brec.startup_start)
                return -EINVAL;
        if (brec.exit_services_exit > NSEC_PER_HOUR)
                return -EINVAL;

        if (ret_loader_start)
                *ret_loader_start = brec.startup_start / 1000;
        if (ret_loader_exit)
                *ret_loader_exit = brec.exit_services_exit / 1000;

        return 0;
}
