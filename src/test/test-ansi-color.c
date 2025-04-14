/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ansi-color.h"
#include "tests.h"

TEST(validate_ansi_color) {
        const char* ansi_color = "\x1B[0;1;32m";

        ASSERT_TRUE(validate_ansi_color(ansi_color));
        ASSERT_FALSE(validate_ansi_color("\x1B[0"));
        ASSERT_TRUE(validate_ansi_color(ansi_highlight_yellow()));
        ASSERT_TRUE(validate_ansi_color("\033[0;1;32m"));
        ASSERT_FALSE(validate_ansi_color("\031[0;1;32m"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
