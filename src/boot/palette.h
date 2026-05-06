/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "proto/simple-text-io.h"
#include "string-table-fundamental.h"

DECLARE_STRING_TABLE_LOOKUP(efi_color, EfiColor);

typedef enum {
        EFI_PALETTE_COLORS_TEXT,
        EFI_PALETTE_COLORS_CURSOR,
        _EFI_PALETTE_COLORS_MAX,
} EfiPaletteColors;

typedef size_t EfiPalette[_EFI_PALETTE_COLORS_MAX];

typedef enum {
        EFI_PALETTE_NORMAL,
        /* boot loader palette for entries and selected entries */
        EFI_PALETTE_ENTRY,
        /* boot loader color for option line edit and cursor */
        EFI_PALETTE_EDIT,
        _EFI_PALETTE_TYPE_MAX,
        _EFI_PALETTE_TYPE_INVALID = -EINVAL,
} EfiPaletteType;

DECLARE_STRING_TABLE_LOOKUP(efi_palette_type, EfiPaletteType);

typedef EfiPalette EfiPalettes[_EFI_PALETTE_TYPE_MAX];

void init_palettes(EfiPalettes *palettes);

void parse_palette(EfiPaletteType type, char *value, EfiPalette *ret_palette);
