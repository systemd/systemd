/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "strv.h"
#include "tests.h"

static void test_ask_password(void) {
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

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_ask_password();
        return EXIT_SUCCESS;
}
