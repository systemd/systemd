/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* See linux Documentation/arm64/booting.txt */
struct arm64_kernel_header {
        UINT32 code0;		/* Executable code */
        UINT32 code1;		/* Executable code */
        UINT64 text_offset;     /* Image load offset, little endian */
        UINT64 image_size;	/* Effective Image size, little endian */
        UINT64 flags;		/* kernel flags, little endian */
        UINT64 res2;		/* reserved */
        UINT64 res3;		/* reserved */
        UINT64 res4;		/* reserved */
        UINT32 magic;		/* Magic number, little endian, "ARM\x64" */
        UINT32 hdr_offset;	/* Offset of PE/COFF header */
} __attribute__((packed));

/* PE image format structures, see
 * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 */

struct pe32_data_directory {
        UINT32 rva;
        UINT32 size;
}  __attribute__((packed));

struct pe64_optional_header {
        UINT16 magic;
        UINT8 major_linker_version;
        UINT8 minor_linker_version;
        UINT32 code_size;
        UINT32 initialized_data_size;
        UINT32 uninitialized_data_size;
        UINT32 entry_point_addr;
        UINT32 code_base;

        UINT64 image_base;

        UINT32 section_alignment;
        UINT32 file_alignment;
        UINT16 major_os_version;
        UINT16 minor_os_version;
        UINT16 major_image_version;
        UINT16 minor_image_version;
        UINT16 major_subsystem_version;
        UINT16 minor_subsystem_version;
        UINT32 win32_version_value;
        UINT32 image_size;
        UINT32 headers_size;
        UINT32 checksum;
        UINT16 subsystem;
        UINT16 dll_characteristics;

        UINT64 stack_reserve_size;
        UINT64 stack_commit_size;
        UINT64 heap_reserve_size;
        UINT64 heap_commit_size;

        UINT32 loader_flags;
        UINT32 num_rva_and_sizes;

        /* Data directories.  */
        struct pe32_data_directory export_table;
        struct pe32_data_directory import_table;
        struct pe32_data_directory resource_table;
        struct pe32_data_directory exception_table;
        struct pe32_data_directory certificate_table;
        struct pe32_data_directory base_relocation_table;
        struct pe32_data_directory debug;
        struct pe32_data_directory architecture;
        struct pe32_data_directory global_ptr;
        struct pe32_data_directory tls_table;
        struct pe32_data_directory load_config_table;
        struct pe32_data_directory bound_import;
        struct pe32_data_directory iat;
        struct pe32_data_directory delay_import_descriptor;
        struct pe32_data_directory clr_runtime_header;
        struct pe32_data_directory reserved;
} __attribute__((packed));

struct pe32_coff_header {
        UINT16 machine;
        UINT16 num_sections;
        UINT32 time_date_stamp;
        UINT32 symbol_table_ptr;
        UINT32 num_symbols;
        UINT16 optional_header_size;
        UINT16 characteristics;
} __attribute__((packed));

struct arm64_linux_pe_header {
        UINT32 magic;
        struct pe32_coff_header coff;
        struct pe64_optional_header opt;
} __attribute__((packed));
