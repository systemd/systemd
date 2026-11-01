/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "login-util.h"
#include "tests.h"

TEST(session_id_valid) {
        /* Invalid Session ID */
        ASSERT_FALSE(session_id_valid(""));
        ASSERT_FALSE(session_id_valid(/* id= */ NULL));
        ASSERT_FALSE(session_id_valid("abc-123"));
        ASSERT_FALSE(session_id_valid("abc_123"));
        ASSERT_FALSE(session_id_valid("abc123*"));

        /* Valid Session ID */
        ASSERT_TRUE(session_id_valid("abc123"));
        ASSERT_TRUE(session_id_valid("AbCdEfG123456"));
        ASSERT_TRUE(session_id_valid("1234567890"));
        ASSERT_TRUE(session_id_valid("ABCDEFGHI"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
