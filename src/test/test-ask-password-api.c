/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "strv.h"
#include "tests.h"

TEST(ask_password) {
        _cleanup_strv_free_ char **ret = NULL;
        int r;

        static const AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = "hello?",
                .keyring = "da key",
                .until = USEC_INFINITY,
                .hup_fd = -EBADF,
        };

        r = ask_password_tty(&req, /* flags= */ ASK_PASSWORD_CONSOLE_COLOR, &ret);
        if (r == -ECANCELED)
                ASSERT_NULL(ret);
        else {
                ASSERT_OK(r);
                assert_se(strv_length(ret) == 1);
                log_info("Got \"%s\"", *ret);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
