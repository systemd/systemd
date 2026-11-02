/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gunicode.h"
#include "tests.h"
#include "utf8.h"

TEST(unichar_iswide) {
        char32_t c;
        int r;

        /* FIXME: the cats are wide, but we get this wrong */
        for (const char *narrow = "abX_…ąęµ!" "😼😿🙀😸😻"; *narrow; narrow += r) {
                r = utf8_encoded_to_unichar(narrow, &c);
                bool w = unichar_iswide(c);
                ASSERT_OK_POSITIVE(r);
                ASSERT_FALSE(w);
        }

        for (const char *wide = "🐱／￥"; *wide; wide += r) {
                r = utf8_encoded_to_unichar(wide, &c);
                bool w = unichar_iswide(c);
                ASSERT_OK_POSITIVE(r);
                ASSERT_TRUE(w);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
