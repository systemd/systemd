/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "proto/simple-text-io.h"
#include "string-table-fundamental.h"

#define EFI_PALETTE(palettes, type) ((palettes)[(EFI_PALETTE_##type)])
#define EFI_PALETTE_COLOR(palettes, type, color) (EFI_PALETTE(palettes, type)[(EFI_PALETTE_COLORS_##color)])

DECLARE_STRING_TABLE_LOOKUP(efi_color, EfiColor);

typedef enum {
        EFI_PALETTE_COLORS_TEXT,
        EFI_PALETTE_COLORS_CURSOR,
        _EFI_PALETTE_COLORS_MAX,
} EfiPaletteColors;

typedef EfiColor EfiPalette[_EFI_PALETTE_COLORS_MAX];

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

void init_palettes(EfiPalettes palettes);

void empty_palette(EfiPalette palette);

EfiColor parse_palette_color(const char *fg_string, const char *bg_string);

void set_palette(EfiPaletteType palette_type, EfiPalette dest, const EfiPalette src);
