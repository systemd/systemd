/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ssh-util.h"
#include "tests.h"

static void test_one(const char *dump, int expected, const char *expected_value) {
        _cleanup_free_ char *v = NULL;

        assert_se(sshd_config_dump_get_authorized_keys_file(dump, &v) == expected);
        ASSERT_STREQ(v, expected_value);
}

TEST(sshd_config_dump_get_authorized_keys_file) {
        test_one("", 0, NULL);
        test_one("loglevel INFO\n", 0, NULL);

        /* Prefix of the key we are looking for, but not the key itself */
        test_one("authorizedkeyscommand none\n"
                 "authorizedkeyscommanduser none\n", 0, NULL);

        test_one("authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n",
                 1, ".ssh/authorized_keys .ssh/authorized_keys2");

        /* Surrounded by other settings, and with the value indented */
        test_one("authorizedkeyscommand none\n"
                 "authorizedkeysfile   .ssh/authorized_keys.d/ignition .ssh/authorized_keys\n"
                 "loglevel INFO\n",
                 1, ".ssh/authorized_keys.d/ignition .ssh/authorized_keys");

        /* Last line without terminating newline */
        test_one("loglevel INFO\n"
                 "authorizedkeysfile /etc/ssh/keys/%u/authorized_keys",
                 1, "/etc/ssh/keys/%u/authorized_keys");

        /* Turned off entirely */
        test_one("authorizedkeysfile none\n", 1, "");

        /* Key without any value */
        test_one("authorizedkeysfile\n", 0, NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
