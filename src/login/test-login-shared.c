/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "login-util.h"
#include "tests.h"

TEST(session_id_valid) {
        ASSERT_TRUE(session_id_valid("c1"));
        ASSERT_TRUE(session_id_valid("1234"));

        ASSERT_FALSE(session_id_valid("1-2"));
        ASSERT_FALSE(session_id_valid(""));
        ASSERT_FALSE(session_id_valid("\tid"));
}

DEFINE_TEST_MAIN(LOG_INFO);
