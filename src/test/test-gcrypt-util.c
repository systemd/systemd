/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "gcrypt-util.h"
#include "macro.h"
#include "string-util.h"

static void test_string_hashsum(void) {
        _cleanup_free_ char *out1 = NULL, *out2 = NULL, *out3 = NULL, *out4 = NULL;

        assert_se(string_hashsum("asdf", 4, GCRY_MD_SHA224, &out1) == 0);
        /* echo -n 'asdf' | sha224sum - */
        assert_se(streq(out1, "7872a74bcbf298a1e77d507cd95d4f8d96131cbbd4cdfc571e776c8a"));

        assert_se(string_hashsum("asdf", 4, GCRY_MD_SHA256, &out2) == 0);
        /* echo -n 'asdf' | sha256sum - */
        assert_se(streq(out2, "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"));

        assert_se(string_hashsum("", 0, GCRY_MD_SHA224, &out3) == 0);
        /* echo -n '' | sha224sum - */
        assert_se(streq(out3, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"));

        assert_se(string_hashsum("", 0, GCRY_MD_SHA256, &out4) == 0);
        /* echo -n '' | sha256sum - */
        assert_se(streq(out4, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

int main(int argc, char **argv) {
        test_string_hashsum();

        return 0;
}
