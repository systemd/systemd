/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "strv.h"
#include "tests.h"

TEST(ask_password) {
        int r;
        _cleanup_strv_free_ char **ret = NULL;

        r = ask_password_tty(-1, "hello?", "da key", 0, ASK_PASSWORD_CONSOLE_COLOR, NULL, &ret);
        if (r == -ECANCELED)
                assert_se(ret == NULL);
        else {
                assert_se(r >= 0);
                assert_se(strv_length(ret) == 1);
                log_info("Got \"%s\"", *ret);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
