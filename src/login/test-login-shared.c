/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "login-util.h"
#include "macro.h"

static void test_session_id_valid(void) {
        assert_se(session_id_valid("c1"));
        assert_se(session_id_valid("1234"));

        assert_se(!session_id_valid("1-2"));
        assert_se(!session_id_valid(""));
        assert_se(!session_id_valid("\tid"));
}

int main(int argc, char* argv[]) {
        log_parse_environment();
        log_open();

        test_session_id_valid();

        return 0;
}
