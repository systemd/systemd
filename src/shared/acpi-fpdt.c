/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

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

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "acpi-fpdt.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "time-util.h"
#include "util.h"

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
};

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
};

struct acpi_fpdt_boot_header {
        char signature[4];
        uint32_t length;
};

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
};

int acpi_get_boot_usec(usec_t *loader_start, usec_t *loader_exit) {
        _cleanup_free_ char *buf = NULL;
        struct acpi_table_header *tbl;
        size_t l = 0;
        struct acpi_fpdt_header *rec;
        int r;
        uint64_t ptr = 0;
        _cleanup_close_ int fd = -1;
        struct acpi_fpdt_boot_header hbrec;
        struct acpi_fpdt_boot brec;

        r = read_full_file("/sys/firmware/acpi/tables/FPDT", &buf, &l);
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
        for (rec = (struct acpi_fpdt_header *)(buf + sizeof(struct acpi_table_header));
             (char *)rec < buf + l;
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
                return -EINVAL;

        /* read Firmware Basic Boot Performance Data Record */
        fd = open("/dev/mem", O_CLOEXEC|O_RDONLY);
        if (fd < 0)
                return -errno;

        l = pread(fd, &hbrec, sizeof(struct acpi_fpdt_boot_header), ptr);
        if (l != sizeof(struct acpi_fpdt_boot_header))
                return -EINVAL;

        if (memcmp(hbrec.signature, "FBPT", 4) != 0)
                return -EINVAL;

        if (hbrec.length < sizeof(struct acpi_fpdt_boot_header) + sizeof(struct acpi_fpdt_boot))
                return -EINVAL;

        l = pread(fd, &brec, sizeof(struct acpi_fpdt_boot), ptr + sizeof(struct acpi_fpdt_boot_header));
        if (l != sizeof(struct acpi_fpdt_boot))
                return -EINVAL;

        if (brec.length != sizeof(struct acpi_fpdt_boot))
                return -EINVAL;

        if (brec.type != ACPI_FPDT_BOOT_REC)
                return -EINVAL;

        if (brec.startup_start == 0 || brec.exit_services_exit < brec.startup_start)
                return -EINVAL;
        if (brec.exit_services_exit > NSEC_PER_HOUR)
                return -EINVAL;

        if (loader_start)
                *loader_start = brec.startup_start / 1000;
        if (loader_exit)
                *loader_exit = brec.exit_services_exit / 1000;

        return 0;
}
