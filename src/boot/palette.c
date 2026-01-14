/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi.h"
#include "palette.h"
#include "proto/simple-text-io.h"
#include "string-table-fundamental.h"
#include "efi-string-table.h"

static const char *efi_color_table[_EFI_COLOR_MAX] = {
        [EFI_BLACK]        = "black",
        [EFI_BLUE]         = "blue",
        [EFI_GREEN]        = "green",
        [EFI_CYAN]         = "cyan",
        [EFI_RED]          = "red",
        [EFI_MAGENTA]      = "magenta",
        [EFI_BROWN]        = "brown",
        [EFI_LIGHTGRAY]    = "lightgray",
        [EFI_DARKGRAY]     = "darkgray",
        [EFI_LIGHTBLUE]    = "lightblue",
        [EFI_LIGHTGREEN]   = "lightgreen",
        [EFI_LIGHTCYAN]    = "lightcyan",
        [EFI_LIGHTRED]     = "lightred",
        [EFI_LIGHTMAGENTA] = "lightmagenta",
        [EFI_YELLOW]       = "yellow",
        [EFI_WHITE]        = "white",
};

DEFINE_STRING_TABLE_LOOKUP(efi_color, EfiColor);

static const char *efi_palette_type_table[_EFI_PALETTE_TYPE_MAX] = {
        [EFI_PALETTE_NORMAL]        = "normal",
        [EFI_PALETTE_ENTRY]         = "entry",
        [EFI_PALETTE_EDIT]          = "edit",
};

DEFINE_STRING_TABLE_LOOKUP(efi_palette_type, EfiPaletteType);

static const EfiPalettes efi_palettes_default = {
        [EFI_PALETTE_NORMAL]        = {
                [EFI_PALETTE_COLORS_TEXT] = COLOR_NORMAL,
                [EFI_PALETTE_COLORS_CURSOR] = EFI_TEXT_ATTR_SWAP(COLOR_NORMAL),
        },
        [EFI_PALETTE_ENTRY]         = {
                [EFI_PALETTE_COLORS_TEXT] = COLOR_ENTRY,
                [EFI_PALETTE_COLORS_CURSOR] = COLOR_HIGHLIGHT,
        },
        [EFI_PALETTE_EDIT]          = {
                [EFI_PALETTE_COLORS_TEXT] = COLOR_EDIT,
                [EFI_PALETTE_COLORS_CURSOR] = EFI_TEXT_ATTR_SWAP(COLOR_EDIT),
        },
};

void init_palettes(EfiPalettes palettes) {
        memcpy(palettes, efi_palettes_default, sizeof (EfiPalettes));
}

void empty_palette(EfiPalette palette) {
        for (EfiPaletteColors i = 0; i < _EFI_PALETTE_COLORS_MAX; i++)
                palette[i] = _EFI_COLOR_INVALID;
}

EfiColor parse_palette_color(const char *fg_string, const char *bg_string) {
        EfiColor fg_color, bg_color;

        assert(fg_string);
        assert(bg_string);

        fg_color = efi_color_from_string(fg_string);
        bg_color = efi_color_from_string(bg_string);

        if (fg_color < 0 || bg_color < 0 || bg_color & EFI_BRIGHT)
                return _EFI_COLOR_INVALID;

        return EFI_TEXT_ATTR(fg_color, bg_color);
}

static EfiColor get_palette_color_default(EfiPaletteType palette_type, EfiPaletteColors palette_colors, const EfiPalette src) {
        assert(palette_type >= 0 && palette_type < _EFI_PALETTE_TYPE_MAX);
        assert(palette_colors >= 0 && palette_colors < _EFI_PALETTE_COLORS_MAX);
        assert(src);

        if (palette_colors == EFI_PALETTE_COLORS_CURSOR && src != NULL && src[EFI_PALETTE_COLORS_TEXT] >= 0)
                return EFI_TEXT_ATTR_SWAP(src[EFI_PALETTE_COLORS_TEXT]);

        return efi_palettes_default[palette_type][palette_colors];
}

void set_palette(EfiPaletteType palette_type, EfiPalette dest, const EfiPalette src) {
        assert(palette_type >= 0 && palette_type < _EFI_PALETTE_TYPE_MAX);
        assert(dest);
        assert(src);

        for (EfiPaletteColors i = 0; i < _EFI_PALETTE_COLORS_MAX; i++) {
                if (src[i] < 0)
                        dest[i] = get_palette_color_default(palette_type, i, src);
                else
                        dest[i] = src[i];
        }
}
