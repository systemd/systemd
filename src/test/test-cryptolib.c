/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "openssl-util.h"
#include "tests.h"

TEST(string_hashsum) {
        _cleanup_free_ char *out1 = NULL, *out2 = NULL, *out3 = NULL, *out4 = NULL;

        ASSERT_OK(string_hashsum("asdf", 4, "SHA224", &out1));
        /* echo -n 'asdf' | sha224sum - */
        ASSERT_STREQ(out1, "7872a74bcbf298a1e77d507cd95d4f8d96131cbbd4cdfc571e776c8a");

        ASSERT_OK(string_hashsum("asdf", 4, "SHA256", &out2));
        /* echo -n 'asdf' | sha256sum - */
        ASSERT_STREQ(out2, "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b");

        ASSERT_OK(string_hashsum("", 0, "SHA224", &out3));
        /* echo -n '' | sha224sum - */
        ASSERT_STREQ(out3, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

        ASSERT_OK(string_hashsum("", 0, "SHA256", &out4));
        /* echo -n '' | sha256sum - */
        ASSERT_STREQ(out4, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

DEFINE_TEST_MAIN(LOG_INFO);
