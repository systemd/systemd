/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "login-util.h"
#include "tests.h"

TEST(session_id_valid) {
        /* Invalid Session ID */
        assert_se(!session_id_valid(""));
        assert_se(!session_id_valid(NULL));
        assert_se(!session_id_valid("abc-123"));
        assert_se(!session_id_valid("abc_123"));
        assert_se(!session_id_valid("abc123*"));

        /* Valid Session ID */
        assert_se(session_id_valid("abc123"));
        assert_se(session_id_valid("AbCdEfG123456"));
        assert_se(session_id_valid("1234567890"));
        assert_se(session_id_valid("ABCDEFGHI"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
