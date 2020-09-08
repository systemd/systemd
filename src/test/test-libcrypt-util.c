/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_CRYPT_H
#  include <crypt.h>
#else
#  include <unistd.h>
#endif

#include "strv.h"
#include "tests.h"
#include "libcrypt-util.h"

static void test_hash_password_full(void) {
        log_info("/* %s */", __func__);

        _cleanup_free_ void *cd_data = NULL;
        const char *i;
        int cd_size = 0;

        log_info("sizeof(struct crypt_data): %zu bytes", sizeof(struct crypt_data));

        for (unsigned c = 0; c < 2; c++)
                FOREACH_STRING(i, "abc123", "h⸿sło") {
                        _cleanup_free_ char *hashed;

                        if (c == 0)
                                assert_se(hash_password_full(i, &cd_data, &cd_size, &hashed) == 0);
                        else
                                assert_se(hash_password_full(i, NULL, NULL, &hashed) == 0);
                        log_debug("\"%s\" → \"%s\"", i, hashed);
                        log_info("crypt_r[a] buffer size: %i bytes", cd_size);

                        assert_se(test_password_one(hashed, i) == true);
                        assert_se(test_password_one(i, hashed) <= 0); /* We get an error for non-utf8 */
                        assert_se(test_password_one(hashed, "foobar") == false);
                        assert_se(test_password_many(STRV_MAKE(hashed), i) == true);
                        assert_se(test_password_many(STRV_MAKE(hashed), "foobar") == false);
                        assert_se(test_password_many(STRV_MAKE(hashed, hashed, hashed), "foobar") == false);
                        assert_se(test_password_many(STRV_MAKE("$y$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH",
                                                               hashed,
                                                               "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                     i) == true);
                        assert_se(test_password_many(STRV_MAKE("$y$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH",
                                                               hashed,
                                                               "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                     "") == false);
                }
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_hash_password_full();

        return 0;
}
