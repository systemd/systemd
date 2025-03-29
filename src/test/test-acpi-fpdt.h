/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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
