/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-util.h"
#include "glyph-util.h"
#include "locale-util.h"
#include "strv.h"

bool emoji_enabled(void) {
        static int cached_emoji_enabled = -1;

        if (cached_emoji_enabled < 0) {
                int val;

                val = getenv_bool("SYSTEMD_EMOJI");
                if (val < 0)
                        cached_emoji_enabled =
                                is_locale_utf8() &&
                                !STRPTR_IN_SET(getenv("TERM"), "dumb", "linux");
                else
                        cached_emoji_enabled = val;
        }

        return cached_emoji_enabled;
}

const char *special_glyph(SpecialGlyph code) {

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
                        [SPECIAL_GLYPH_SIGMA]                   = "S",
                        [SPECIAL_GLYPH_ARROW]                   = "->",
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
                },

                /* UTF-8 */
                [true] = {
                        /* The following are multiple glyphs in both ASCII and in UNICODE */
                        [SPECIAL_GLYPH_TREE_VERTICAL]           = "\342\224\202 ",            /* │  */
                        [SPECIAL_GLYPH_TREE_BRANCH]             = "\342\224\234\342\224\200", /* ├─ */
                        [SPECIAL_GLYPH_TREE_RIGHT]              = "\342\224\224\342\224\200", /* └─ */
                        [SPECIAL_GLYPH_TREE_SPACE]              = "  ",                       /*    */

                        /* Single glyphs in both cases */
                        [SPECIAL_GLYPH_TRIANGULAR_BULLET]       = "\342\200\243",             /* ‣ */
                        [SPECIAL_GLYPH_BLACK_CIRCLE]            = "\342\227\217",             /* ● */
                        [SPECIAL_GLYPH_WHITE_CIRCLE]            = "\u25CB",                   /* ○ */
                        [SPECIAL_GLYPH_MULTIPLICATION_SIGN]     = "\u00D7",                   /* × */
                        [SPECIAL_GLYPH_CIRCLE_ARROW]            = "\u21BB",                   /* ↻ */
                        [SPECIAL_GLYPH_BULLET]                  = "\342\200\242",             /* • */
                        [SPECIAL_GLYPH_MU]                      = "\316\274",                 /* μ (actually called: GREEK SMALL LETTER MU) */
                        [SPECIAL_GLYPH_CHECK_MARK]              = "\342\234\223",             /* ✓ */
                        [SPECIAL_GLYPH_CROSS_MARK]              = "\342\234\227",             /* ✗ (actually called: BALLOT X) */
                        [SPECIAL_GLYPH_LIGHT_SHADE]             = "\342\226\221",             /* ░ */
                        [SPECIAL_GLYPH_DARK_SHADE]              = "\342\226\223",             /* ▒ */
                        [SPECIAL_GLYPH_SIGMA]                   = "\316\243",                 /* Σ */

                        /* Single glyph in Unicode, two in ASCII */
                        [SPECIAL_GLYPH_ARROW]                   = "\342\206\222",             /* → (actually called: RIGHTWARDS ARROW) */

                        /* Single glyph in Unicode, three in ASCII */
                        [SPECIAL_GLYPH_ELLIPSIS]                = "\342\200\246",             /* … (actually called: HORIZONTAL ELLIPSIS) */

                        /* Three glyphs in Unicode, five in ASCII */
                        [SPECIAL_GLYPH_EXTERNAL_LINK]           = "[\360\237\241\225]",       /* 🡕 (actually called: NORTH EAST SANS-SERIF ARROW, enclosed in []) */

                        /* These smileys are a single glyph in Unicode, and three in ASCII */
                        [SPECIAL_GLYPH_ECSTATIC_SMILEY]         = "\360\237\230\207",         /* 😇 (actually called: SMILING FACE WITH HALO) */
                        [SPECIAL_GLYPH_HAPPY_SMILEY]            = "\360\237\230\200",         /* 😀 (actually called: GRINNING FACE) */
                        [SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY]   = "\360\237\231\202",         /* 🙂 (actually called: SLIGHTLY SMILING FACE) */
                        [SPECIAL_GLYPH_NEUTRAL_SMILEY]          = "\360\237\230\220",         /* 😐 (actually called: NEUTRAL FACE) */
                        [SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY] = "\360\237\231\201",         /* 🙁 (actually called: SLIGHTLY FROWNING FACE) */
                        [SPECIAL_GLYPH_UNHAPPY_SMILEY]          = "\360\237\230\250",         /* 😨 (actually called: FEARFUL FACE) */
                        [SPECIAL_GLYPH_DEPRESSED_SMILEY]        = "\360\237\244\242",         /* 🤢 (actually called: NAUSEATED FACE) */

                        /* This emoji is a single character cell glyph in Unicode, and three in ASCII */
                        [SPECIAL_GLYPH_LOCK_AND_KEY]            = "\360\237\224\220",         /* 🔐 (actually called: CLOSED LOCK WITH KEY) */

                        /* This emoji is a single character cell glyph in Unicode, and two in ASCII */
                        [SPECIAL_GLYPH_TOUCH]                   = "\360\237\221\206",         /* 👆 (actually called: BACKHAND INDEX POINTING UP) */

                        /* These three emojis are single character cell glyphs in Unicode and also in ASCII. */
                        [SPECIAL_GLYPH_RECYCLING]               = "\u267B\uFE0F ",            /* ♻️  (actually called: UNIVERSAL RECYCLNG SYMBOL) */
                        [SPECIAL_GLYPH_DOWNLOAD]                = "\u2935\uFE0F ",            /* ⤵️  (actually called: RIGHT ARROW CURVING DOWN) */
                        [SPECIAL_GLYPH_SPARKLES]                = "\u2728",                   /* ✨ */
                },
        };

        if (code < 0)
                return NULL;

        assert(code < _SPECIAL_GLYPH_MAX);
        return draw_table[code >= _SPECIAL_GLYPH_FIRST_EMOJI ? emoji_enabled() : is_locale_utf8()][code];
}
