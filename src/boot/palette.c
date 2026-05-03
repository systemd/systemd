/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi.h"
#include "palette.h"
#include "proto/simple-text-io.h"
#include "string-table-fundamental.h"
#include "efi-log.h"
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

void init_palettes(EfiPalettes *palettes) {
        memcpy(palettes, &efi_palettes_default, sizeof (EfiPalettes));
}

void parse_palette(EfiPaletteType type, char *value, EfiPalette *ret_palette) {
        size_t pos = 0;

        assert(type >= 0 && type < _EFI_PALETTE_TYPE_MAX);
        assert(value);
        assert(ret_palette);
        assert(EFI_PALETTE_COLORS_CURSOR > EFI_PALETTE_COLORS_TEXT);

        for (EfiPaletteColors i = 0; i < _EFI_PALETTE_COLORS_MAX; i++) {
                const char *fg_string = parse_array(value, ",", &pos);
                const char *bg_string = parse_array(value, ",", &pos);
                EfiColor fg_color = efi_color_from_string(fg_string);
                EfiColor bg_color = efi_color_from_string(bg_string);

                if (fg_string != NULL && (fg_color < -1 || bg_string == NULL))
                        /* parsing error if the foreground color is an invalid color or if the background color was not set */
                        log_warning("Error parsing 'efi-palette-%s' config option, ignoring index %zu: %s",
                                efi_palette_type_to_string(type), (size_t)(i * 2 + 1), fg_string);
                else if (bg_string != NULL && (bg_color < -1 || bg_color & EFI_BRIGHT))
                        /* parsing error if the background color is an invalid color or a bright color */
                        log_warning("Error parsing 'efi-palette-%s' config option, ignoring index %zu: %s",
                                efi_palette_type_to_string(type), (size_t)(i * 2 + 1), bg_string);
                else if (fg_string != NULL && bg_string != NULL) {
                        /* set parsed value if both colors are set and valid */
                        *ret_palette[i] = EFI_TEXT_ATTR(fg_color, bg_color);
                        continue;
                }
                /* set default value if both colors are not set or if a parsing error occured */
                if (i == EFI_PALETTE_COLORS_CURSOR)
                        *ret_palette[EFI_PALETTE_COLORS_CURSOR] = EFI_TEXT_ATTR_SWAP(*ret_palette[EFI_PALETTE_COLORS_TEXT]);
                else
                        *ret_palette[i] = efi_palettes_default[type][i];
        }
}
