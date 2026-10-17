/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "palette.h"
#include "tests.h"

#define ASSERT_COLOR_EQ(expr1, expr2) ASSERT_EQ((EfiColor)(expr1), (EfiColor)(expr2))

TEST(init_palettes) {
        EfiPalettes palettes;

        init_palettes(palettes);

        ASSERT_COLOR_EQ(EFI_PALETTE_COLOR(palettes, NORMAL, TEXT), EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK));
        ASSERT_COLOR_EQ(EFI_PALETTE_COLOR(palettes, NORMAL, CURSOR), EFI_TEXT_ATTR(EFI_BLACK, EFI_LIGHTGRAY));
        ASSERT_COLOR_EQ(EFI_PALETTE_COLOR(palettes, ENTRY, TEXT), EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK));
        ASSERT_COLOR_EQ(EFI_PALETTE_COLOR(palettes, ENTRY, CURSOR), EFI_TEXT_ATTR(EFI_BLACK, EFI_LIGHTGRAY));
        ASSERT_COLOR_EQ(EFI_PALETTE_COLOR(palettes, EDIT, TEXT), EFI_TEXT_ATTR(EFI_BLACK, EFI_LIGHTGRAY));
        ASSERT_COLOR_EQ(EFI_PALETTE_COLOR(palettes, EDIT, CURSOR), EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK));
}

TEST(empty_palette) {
        EfiPalette palette;

        empty_palette(palette);
        ASSERT_COLOR_EQ(palette[EFI_PALETTE_COLORS_TEXT], _EFI_COLOR_INVALID);
        ASSERT_COLOR_EQ(palette[EFI_PALETTE_COLORS_CURSOR], _EFI_COLOR_INVALID);
}

TEST(parse_palette_color) {
        ASSERT_COLOR_EQ(parse_palette_color("white", "black"), EFI_TEXT_ATTR(EFI_WHITE, EFI_BLACK));
        ASSERT_COLOR_EQ(parse_palette_color("yellow", "blue"), EFI_TEXT_ATTR(EFI_YELLOW, EFI_BLUE));
        ASSERT_COLOR_EQ(parse_palette_color("lightmagenta", "green"), EFI_TEXT_ATTR(EFI_LIGHTMAGENTA, EFI_GREEN));
        ASSERT_COLOR_EQ(parse_palette_color("lightred", "cyan"), EFI_TEXT_ATTR(EFI_LIGHTRED, EFI_CYAN));
        ASSERT_COLOR_EQ(parse_palette_color("lightcyan", "red"), EFI_TEXT_ATTR(EFI_LIGHTCYAN, EFI_RED));
        ASSERT_COLOR_EQ(parse_palette_color("lightgreen", "magenta"), EFI_TEXT_ATTR(EFI_LIGHTGREEN, EFI_MAGENTA));
        ASSERT_COLOR_EQ(parse_palette_color("lightblue", "brown"), EFI_TEXT_ATTR(EFI_LIGHTBLUE, EFI_BROWN));
        ASSERT_COLOR_EQ(parse_palette_color("darkgray", "lightgray"), EFI_TEXT_ATTR(EFI_DARKGRAY, EFI_LIGHTGRAY));
        /* case-sensitive */
        ASSERT_COLOR_EQ(parse_palette_color("YELLOW", "BLUE"), _EFI_COLOR_INVALID);
        /* invalid foreground color */
        ASSERT_COLOR_EQ(parse_palette_color("_yellow", "blue"), _EFI_COLOR_INVALID);
        /* invalid background color */
        ASSERT_COLOR_EQ(parse_palette_color("yellow", "_blue"), _EFI_COLOR_INVALID);
        /* invalid background color (light colors are not allowed) */
        ASSERT_COLOR_EQ(parse_palette_color("blue", "lightred"), _EFI_COLOR_INVALID);
        ASSERT_COLOR_EQ(parse_palette_color("blue", "darkgray"), _EFI_COLOR_INVALID);
        /* empty values */
        ASSERT_COLOR_EQ(parse_palette_color("", ""), _EFI_COLOR_INVALID);
        ASSERT_COLOR_EQ(parse_palette_color("", "blue"), _EFI_COLOR_INVALID);
        ASSERT_COLOR_EQ(parse_palette_color("yellow", ""), _EFI_COLOR_INVALID);
}

TEST(set_palette) {
        EfiPalette dest, src;

        /* setting both colors, sets both colors */
        empty_palette(dest);
        empty_palette(src);
        src[EFI_PALETTE_COLORS_TEXT] = EFI_TEXT_ATTR(EFI_YELLOW, EFI_BLUE);
        src[EFI_PALETTE_COLORS_CURSOR] = EFI_TEXT_ATTR(EFI_WHITE, EFI_GREEN);
        set_palette(EFI_PALETTE_EDIT, dest, src);
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_TEXT], EFI_TEXT_ATTR(EFI_YELLOW, EFI_BLUE));
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_CURSOR], EFI_TEXT_ATTR(EFI_WHITE, EFI_GREEN));

        /* cursor colors will be set to swapped text colors */
        empty_palette(dest);
        empty_palette(src);
        src[EFI_PALETTE_COLORS_TEXT] = EFI_TEXT_ATTR(EFI_YELLOW, EFI_BLUE);
        set_palette(EFI_PALETTE_EDIT, dest, src);
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_TEXT], EFI_TEXT_ATTR(EFI_YELLOW, EFI_BLUE));
        /* note that the yellow becomes brown here, since yellow is not a valid background color */
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_CURSOR], EFI_TEXT_ATTR(EFI_BLUE, EFI_BROWN));

        /* text colors will be set to deault colors */
        empty_palette(dest);
        empty_palette(src);
        src[EFI_PALETTE_COLORS_CURSOR] = EFI_TEXT_ATTR(EFI_WHITE, EFI_GREEN);
        set_palette(EFI_PALETTE_EDIT, dest, src);
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_TEXT], EFI_TEXT_ATTR(EFI_BLACK, EFI_LIGHTGRAY));
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_CURSOR], EFI_TEXT_ATTR(EFI_WHITE, EFI_GREEN));

        /* setting invalid colors, sets default colors */
        empty_palette(dest);
        empty_palette(src);
        set_palette(EFI_PALETTE_NORMAL, dest, src);
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_TEXT], EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK));
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_CURSOR], EFI_TEXT_ATTR(EFI_BLACK, EFI_LIGHTGRAY));
        empty_palette(dest);
        empty_palette(src);
        set_palette(EFI_PALETTE_ENTRY, dest, src);
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_TEXT], EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK));
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_CURSOR], EFI_TEXT_ATTR(EFI_BLACK, EFI_LIGHTGRAY));
        empty_palette(dest);
        empty_palette(src);
        set_palette(EFI_PALETTE_EDIT, dest, src);
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_TEXT], EFI_TEXT_ATTR(EFI_BLACK, EFI_LIGHTGRAY));
        ASSERT_COLOR_EQ(dest[EFI_PALETTE_COLORS_CURSOR], EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK));
}

DEFINE_TEST_MAIN(LOG_INFO);
