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

typedef struct FdtHeader {
        uint32_t magic;
        uint32_t total_size;
        uint32_t off_dt_struct;
        uint32_t off_dt_strings;
        uint32_t off_mem_rsv_map;
        uint32_t version;
        uint32_t last_comp_version;
        uint32_t boot_cpuid_phys;
        uint32_t size_dt_strings;
        uint32_t size_dt_struct;
} FdtHeader;

bool firmware_devicetree_exists(void);
EFI_STATUS devicetree_match(const void *uki_dtb, size_t uki_dtb_length);
EFI_STATUS devicetree_match_by_compatible(const void *uki_dtb, size_t uki_dtb_length, const char *compat);
EFI_STATUS devicetree_install(struct devicetree_state *state, EFI_FILE *root_dir, char16_t *name);
EFI_STATUS devicetree_install_from_memory(
                struct devicetree_state *state, const void *dtb_buffer, size_t dtb_length);
void devicetree_cleanup(struct devicetree_state *state);
