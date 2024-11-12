/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-util.h"
#include "glyph-util.h"
#include "locale-util.h"
#include "strv.h"

bool emoji_enabled(void) {
        static int cached_emoji_enabled = -1;

        if (cached_emoji_enabled < 0) {
                int val = getenv_bool("SYSTEMD_EMOJI");
                if (val >= 0)
                        return (cached_emoji_enabled = val);

                const char *term = getenv("TERM");
                if (!term || STR_IN_SET(term, "dumb", "linux"))
                        return (cached_emoji_enabled = false);

                cached_emoji_enabled = is_locale_utf8();
        }

        return cached_emoji_enabled;
}

const char* special_glyph_full(SpecialGlyph code, bool force_utf) {

        /* A list of a number of interesting unicode glyphs we can use to decorate our output. It's probably wise to be
         * conservative here, and primarily stick to the glyphs defined in the eurlatgr font, so that display still
         * works reasonably well on the Linux console. For details see:
         *
         * http://git.altlinux.org/people/legion/packages/kbd.git?p=kbd.git;a=blob;f=data/consolefonts/README.eurlatgr
         */

        static const char* const draw_table[2][_SPECIAL_GLYPH_MAX] = {
                /* ASCII fallback */
                [false] = {
                        [SPECIAL_GLYPH_TREE_VERTICAL]           = "| ",
                        [SPECIAL_GLYPH_TREE_BRANCH]             = "|-",
                        [SPECIAL_GLYPH_TREE_RIGHT]              = "`-",
                        [SPECIAL_GLYPH_TREE_SPACE]              = "  ",
                        [SPECIAL_GLYPH_TREE_TOP]                = ",-",
                        [SPECIAL_GLYPH_VERTICAL_DOTTED]         = ":",
                        [SPECIAL_GLYPH_HORIZONTAL_DOTTED]       = "-",
                        [SPECIAL_GLYPH_HORIZONTAL_FAT]          = "=",
                        [SPECIAL_GLYPH_TRIANGULAR_BULLET]       = ">",
                        [SPECIAL_GLYPH_BLACK_CIRCLE]            = "*",
                        [SPECIAL_GLYPH_WHITE_CIRCLE]            = "*",
                        [SPECIAL_GLYPH_MULTIPLICATION_SIGN]     = "x",
                        [SPECIAL_GLYPH_CIRCLE_ARROW]            = "*",
                        [SPECIAL_GLYPH_BULLET]                  = "*",
                        [SPECIAL_GLYPH_MU]                      = "u",
                        [SPECIAL_GLYPH_CHECK_MARK]              = "+",
                        [SPECIAL_GLYPH_CROSS_MARK]              = "-",
                        [SPECIAL_GLYPH_LIGHT_SHADE]             = "-",
                        [SPECIAL_GLYPH_DARK_SHADE]              = "X",
                        [SPECIAL_GLYPH_FULL_BLOCK]              = "#",
                        [SPECIAL_GLYPH_SIGMA]                   = "S",
                        [SPECIAL_GLYPH_ARROW_UP]                = "^",
                        [SPECIAL_GLYPH_ARROW_DOWN]              = "v",
                        [SPECIAL_GLYPH_ARROW_LEFT]              = "<-",
                        [SPECIAL_GLYPH_ARROW_RIGHT]             = "->",
                        [SPECIAL_GLYPH_ELLIPSIS]                = "...",
                        [SPECIAL_GLYPH_EXTERNAL_LINK]           = "[LNK]",
                        [SPECIAL_GLYPH_ECSTATIC_SMILEY]         = ":-]",
                        [SPECIAL_GLYPH_HAPPY_SMILEY]            = ":-}",
                        [SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY]   = ":-)",
                        [SPECIAL_GLYPH_NEUTRAL_SMILEY]          = ":-|",
                        [SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY] = ":-(",
                        [SPECIAL_GLYPH_UNHAPPY_SMILEY]          = ":-{",
                        [SPECIAL_GLYPH_DEPRESSED_SMILEY]        = ":-[",
                        [SPECIAL_GLYPH_LOCK_AND_KEY]            = "o-,",
                        [SPECIAL_GLYPH_TOUCH]                   = "O=",    /* Yeah, not very convincing, can you do it better? */
                        [SPECIAL_GLYPH_RECYCLING]               = "~",
                        [SPECIAL_GLYPH_DOWNLOAD]                = "\\",
                        [SPECIAL_GLYPH_SPARKLES]                = "*",
                        [SPECIAL_GLYPH_LOW_BATTERY]             = "!",
                        [SPECIAL_GLYPH_WARNING_SIGN]            = "!",
                        [SPECIAL_GLYPH_RED_CIRCLE]              = "o",
                        [SPECIAL_GLYPH_YELLOW_CIRCLE]           = "o",
                        [SPECIAL_GLYPH_BLUE_CIRCLE]             = "o",
                        [SPECIAL_GLYPH_GREEN_CIRCLE]            = "o",
                        [SPECIAL_GLYPH_SUPERHERO]               = "S",
                        [SPECIAL_GLYPH_IDCARD]                  = "@",
                },

                /* UTF-8 */
                [true] = {
                        /* The following are multiple glyphs in both ASCII and in UNICODE */
                        [SPECIAL_GLYPH_TREE_VERTICAL]           = u8"│ ",
                        [SPECIAL_GLYPH_TREE_BRANCH]             = u8"├─",
                        [SPECIAL_GLYPH_TREE_RIGHT]              = u8"└─",
                        [SPECIAL_GLYPH_TREE_SPACE]              = u8"  ",
                        [SPECIAL_GLYPH_TREE_TOP]                = u8"┌─",

                        /* Single glyphs in both cases */
                        [SPECIAL_GLYPH_VERTICAL_DOTTED]         = u8"┆",
                        [SPECIAL_GLYPH_HORIZONTAL_DOTTED]       = u8"┄",
                        [SPECIAL_GLYPH_HORIZONTAL_FAT]          = u8"━",
                        [SPECIAL_GLYPH_TRIANGULAR_BULLET]       = u8"‣",
                        [SPECIAL_GLYPH_BLACK_CIRCLE]            = u8"●",
                        [SPECIAL_GLYPH_WHITE_CIRCLE]            = u8"○",
                        [SPECIAL_GLYPH_MULTIPLICATION_SIGN]     = u8"×",
                        [SPECIAL_GLYPH_CIRCLE_ARROW]            = u8"↻",
                        [SPECIAL_GLYPH_BULLET]                  = u8"•",
                        [SPECIAL_GLYPH_MU]                      = u8"μ",       /* actually called: GREEK SMALL LETTER MU */
                        [SPECIAL_GLYPH_CHECK_MARK]              = u8"✓",
                        [SPECIAL_GLYPH_CROSS_MARK]              = u8"✗",        /* actually called: BALLOT X */
                        [SPECIAL_GLYPH_LIGHT_SHADE]             = u8"░",
                        [SPECIAL_GLYPH_DARK_SHADE]              = u8"▒",
                        [SPECIAL_GLYPH_FULL_BLOCK]              = u8"█",
                        [SPECIAL_GLYPH_SIGMA]                   = u8"Σ",
                        [SPECIAL_GLYPH_ARROW_UP]                = u8"↑",       /* actually called: UPWARDS ARROW */
                        [SPECIAL_GLYPH_ARROW_DOWN]              = u8"↓",       /* actually called: DOWNWARDS ARROW */

                        /* Single glyph in Unicode, two in ASCII */
                        [SPECIAL_GLYPH_ARROW_LEFT]              = u8"←",       /* actually called: LEFTWARDS ARROW */
                        [SPECIAL_GLYPH_ARROW_RIGHT]             = u8"→",       /* actually called: RIGHTWARDS ARROW */

                        /* Single glyph in Unicode, three in ASCII */
                        [SPECIAL_GLYPH_ELLIPSIS]                = u8"…",       /* actually called: HORIZONTAL ELLIPSIS */

                        /* Three glyphs in Unicode, five in ASCII */
                        [SPECIAL_GLYPH_EXTERNAL_LINK]           = u8"[🡕]",      /* actually called: NORTH EAST SANS-SERIF ARROW, enclosed in [] */

                        /* These smileys are a single glyph in Unicode, and three in ASCII */
                        [SPECIAL_GLYPH_ECSTATIC_SMILEY]         = u8"😇",       /* actually called: SMILING FACE WITH HALO */
                        [SPECIAL_GLYPH_HAPPY_SMILEY]            = u8"😀",       /* actually called: GRINNING FACE */
                        [SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY]   = u8"🙂",       /* actually called: SLIGHTLY SMILING FACE */
                        [SPECIAL_GLYPH_NEUTRAL_SMILEY]          = u8"😐",       /* actually called: NEUTRAL FACE */
                        [SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY] = u8"🙁",       /* actually called: SLIGHTLY FROWNING FACE */
                        [SPECIAL_GLYPH_UNHAPPY_SMILEY]          = u8"😨",       /* actually called: FEARFUL FACE */
                        [SPECIAL_GLYPH_DEPRESSED_SMILEY]        = u8"🤢",       /* actually called: NAUSEATED FACE */

                        /* This emoji is a single character cell glyph in Unicode, and three in ASCII */
                        [SPECIAL_GLYPH_LOCK_AND_KEY]            = u8"🔐",       /* actually called: CLOSED LOCK WITH KEY */

                        /* This emoji is a single character cell glyph in Unicode, and two in ASCII */
                        [SPECIAL_GLYPH_TOUCH]                   = u8"👆",       /* actually called: BACKHAND INDEX POINTING UP */

                        /* These four emojis are single character cell glyphs in Unicode and also in ASCII. */
                        [SPECIAL_GLYPH_RECYCLING]               = u8"♻️",        /* actually called: UNIVERSAL RECYCLNG SYMBOL */
                        [SPECIAL_GLYPH_DOWNLOAD]                = u8"⤵️",        /* actually called: RIGHT ARROW CURVING DOWN */
                        [SPECIAL_GLYPH_SPARKLES]                = u8"✨",
                        [SPECIAL_GLYPH_LOW_BATTERY]             = u8"🪫",
                        [SPECIAL_GLYPH_WARNING_SIGN]            = u8"⚠️",
                        [SPECIAL_GLYPH_COMPUTER_DISK]           = u8"💽",
                        [SPECIAL_GLYPH_WORLD]                   = u8"🌍",

                        [SPECIAL_GLYPH_RED_CIRCLE]              = u8"🔴",
                        [SPECIAL_GLYPH_YELLOW_CIRCLE]           = u8"🟡",
                        [SPECIAL_GLYPH_BLUE_CIRCLE]             = u8"🔵",
                        [SPECIAL_GLYPH_GREEN_CIRCLE]            = u8"🟢",
                        [SPECIAL_GLYPH_SUPERHERO]               = u8"🦸",
                        [SPECIAL_GLYPH_IDCARD]                  = u8"🪪",
                },
        };

        if (code < 0)
                return NULL;

        assert(code < _SPECIAL_GLYPH_MAX);
        return draw_table[force_utf || (code >= _SPECIAL_GLYPH_FIRST_EMOJI ? emoji_enabled() : is_locale_utf8())][code];
}
