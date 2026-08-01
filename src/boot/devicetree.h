/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

struct devicetree_state {
        EFI_PHYSICAL_ADDRESS addr;
        size_t pages;
        void *orig;
};

bool firmware_devicetree_exists(void);
EFI_STATUS devicetree_match(const void *uki_dtb, size_t uki_dtb_length);
EFI_STATUS devicetree_match_by_compatible(const void *uki_dtb, size_t uki_dtb_length, const char *compat);
EFI_STATUS devicetree_load(struct devicetree_state *state, EFI_FILE *root_dir, char16_t *name);
EFI_STATUS devicetree_install(struct devicetree_state *state);
EFI_STATUS devicetree_install_from_memory(
                struct devicetree_state *state, const void *dtb_buffer, size_t dtb_length);
void devicetree_cleanup(struct devicetree_state *state);
