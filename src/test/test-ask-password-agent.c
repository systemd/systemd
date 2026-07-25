/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "tests.h"

TEST(request_valid) {
        AskPasswordRequest req = {
                .message = "Password for /dev/disk/by-label/über?",
                .icon = "drive-harddisk",
                .id = "cryptsetup:/dev/disk\\by-label/'data'[*]",
                .tty_fd = -EBADF,
                .hup_fd = -EBADF,
        };

        ASSERT_TRUE(ask_password_agent_request_is_valid(&req));

        req.message = "";
        ASSERT_TRUE(ask_password_agent_request_is_valid(&req));

        req.message = "first line\nSocket=/tmp/injected";
        ASSERT_FALSE(ask_password_agent_request_is_valid(&req));

        req.message = "Password:";
        req.icon = "drive\rIcon";
        ASSERT_FALSE(ask_password_agent_request_is_valid(&req));

        req.icon = "drive-harddisk";
        req.id = "cryptsetup:\x01/dev/sda";
        ASSERT_FALSE(ask_password_agent_request_is_valid(&req));

        req.id = "cryptsetup:\xff/dev/sda";
        ASSERT_FALSE(ask_password_agent_request_is_valid(&req));
}

DEFINE_TEST_MAIN(LOG_INFO);
