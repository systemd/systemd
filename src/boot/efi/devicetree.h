/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

struct devicetree_state {
        EFI_PHYSICAL_ADDRESS addr;
        size_t pages;
        void *orig;
};

enum {
        FDT_BEGIN_NODE = 1,
        FDT_END_NODE   = 2,
        FDT_PROP       = 3,
        FDT_NOP        = 4,
        FDT_END        = 9,
};

struct fdt_header {
        uint32_t Magic;
        uint32_t TotalSize;
        uint32_t OffDTStruct;
        uint32_t OffDTStrings;
        uint32_t OffMemRsvMap;
        uint32_t Version;
        uint32_t LastCompVersion;
        uint32_t BootCPUIDPhys;
        uint32_t SizeDTStrings;
        uint32_t SizeDTStruct;
};

EFI_STATUS devicetree_match(const void *dtb_buffer, size_t dtb_length);
EFI_STATUS devicetree_install(struct devicetree_state *state, EFI_FILE *root_dir, char16_t *name);
EFI_STATUS devicetree_install_from_memory(
                struct devicetree_state *state, const void *dtb_buffer, size_t dtb_length);
void devicetree_cleanup(struct devicetree_state *state);
