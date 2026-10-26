/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

/* SetupHeader and BootParams follow the x86 boot protocol from https://docs.kernel.org/arch/x86/boot.html.
 * All fields are little-endian. */

#define SETUP_MAGIC 0x53726448u /* "HdrS" */

typedef struct {
        uint8_t  setup_sects;
        uint16_t root_flags;
        uint32_t syssize;
        uint16_t ram_size;
        uint16_t vid_mode;
        uint16_t root_dev;
        uint16_t boot_flag;
        uint8_t  jump; /* We split the 2-byte jump field from the spec in two for convenience. */
        uint8_t  setup_size;
        uint32_t header;
        uint16_t version;
        uint32_t realmode_swtch;
        uint16_t start_sys_seg;
        uint16_t kernel_version;
        uint8_t  type_of_loader;
        uint8_t  loadflags;
        uint16_t setup_move_size;
        uint32_t code32_start;
        uint32_t ramdisk_image;
        uint32_t ramdisk_size;
        uint32_t bootsect_kludge;
        uint16_t heap_end_ptr;
        uint8_t  ext_loader_ver;
        uint8_t  ext_loader_type;
        uint32_t cmd_line_ptr;
        uint32_t initrd_addr_max;
        uint32_t kernel_alignment;
        uint8_t  relocatable_kernel;
        uint8_t  min_alignment;
        uint16_t xloadflags;
        uint32_t cmdline_size;
        uint32_t hardware_subarch;
        uint64_t hardware_subarch_data;
        uint32_t payload_offset;
        uint32_t payload_length;
        uint64_t setup_data;
        uint64_t pref_address;
        uint32_t init_size;
        uint32_t handover_offset;
} _packed_ SetupHeader;

/* We really only care about a few fields, but we still have to provide a full page otherwise. */
typedef struct {
        uint8_t pad[192];
        uint32_t ext_ramdisk_image;
        uint32_t ext_ramdisk_size;
        uint32_t ext_cmd_line_ptr;
        uint8_t pad2[293];
        SetupHeader hdr;
        uint8_t pad3[3480];
} _packed_ BootParams;
assert_cc(offsetof(BootParams, ext_ramdisk_image) == 0x0C0);
assert_cc(offsetof(BootParams, hdr) == 0x1F1);
assert_cc(offsetof(BootParams, hdr.header) == 0x202);
assert_cc(offsetof(BootParams, hdr.kernel_version) == 0x20E);
assert_cc(sizeof(BootParams) == 4096);
