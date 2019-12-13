/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "ask-password-api.h"
#include "log.h"
#include "strv.h"

static void ask_password(void) {
        int r;
        _cleanup_strv_free_ char **ret = NULL;

        r = ask_password_tty(-1, "hello?", "da key", 0, 0, NULL, &ret);
        assert(r >= 0);
        assert(strv_length(ret) == 1);

        log_info("Got %s", *ret);
}

int main(int argc, char **argv) {
        log_parse_environment();

        ask_password();
        return EXIT_SUCCESS;
}
