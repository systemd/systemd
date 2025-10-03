/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <crypt.h>

#include "libcrypt-util.h"
#include "strv.h"
#include "tests.h"

TEST(crypt_preferred_method) {
        log_info("crypt_preferred_method: %s", crypt_preferred_method());
}

TEST(make_salt) {
        for (int i = 0; i < 10; i++) {
                _cleanup_free_ char *t;

                ASSERT_OK(make_salt(&t));
                log_info("%s", t);
        }
}

TEST(hash_password) {
        /* As a warm-up exercise, check if we can hash passwords. */
        FOREACH_STRING(hash,
                       "ew3bU1.hoKk4o",
                       "$1$gc5rWpTB$wK1aul1PyBn9AX1z93stk1",
                       "$2b$12$BlqcGkB/7BFvNMXKGxDea.5/8D6FTny.cbNcHW/tqcrcyo6ZJd8u2",
                       "$5$lGhDrcrao9zb5oIK$05KlOVG3ocknx/ThreqXE/gk.XzFFBMTksc4t2CPDUD",
                       "$6$c7wB/3GiRk0VHf7e$zXJ7hN0aLZapE.iO4mn/oHu6.prsXTUG/5k1AxpgR85ELolyAcaIGRgzfwJs3isTChMDBjnthZyaMCfCNxo9I.",
#ifdef __GLIBC__
                       /* musl does not support yescrypt yet. */
                       "$y$j9T$$9cKOWsAm4m97WiYk61lPPibZpy3oaGPIbsL4koRe/XD",
#endif
                       NULL)
                ASSERT_OK_POSITIVE(test_password_one(hash, "ppp"));

        _cleanup_free_ void *cd_data = NULL;
        int cd_size = 0;

        log_info("sizeof(struct crypt_data): %zu bytes", sizeof(struct crypt_data));

        for (unsigned c = 0; c < 2; c++)
                FOREACH_STRING(i, "abc123", "h⸿sło") {
                        _cleanup_free_ char *hashed;

                        if (c == 0)
                                ASSERT_OK(hash_password_full(i, &cd_data, &cd_size, &hashed));
                        else
                                ASSERT_OK(hash_password_full(i, NULL, NULL, &hashed));
                        log_debug("\"%s\" → \"%s\"", i, hashed);
                        log_info("crypt_r[a] buffer size: %i bytes", cd_size);

                        ASSERT_OK_POSITIVE(test_password_one(hashed, i));
                        ASSERT_LE(test_password_one(i, hashed), 0); /* We get an error for non-utf8 */
                        ASSERT_OK_ZERO(test_password_one(hashed, "foobar"));
                        ASSERT_OK_POSITIVE(test_password_many(STRV_MAKE(hashed), i));
                        ASSERT_OK_ZERO(test_password_many(STRV_MAKE(hashed), "foobar"));
                        ASSERT_OK_ZERO(test_password_many(STRV_MAKE(hashed, hashed, hashed), "foobar"));
                        ASSERT_OK_POSITIVE(test_password_many(STRV_MAKE("$y$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH",
                                                                        hashed,
                                                                        "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                              i));
                        ASSERT_OK_POSITIVE(test_password_many(STRV_MAKE("$W$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH", /* no such method exists... */
                                                                        hashed,
                                                                        "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                              i));
                        ASSERT_OK_ZERO(test_password_many(STRV_MAKE("$y$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH",
                                                                    hashed,
                                                                    "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                          ""));
                        ASSERT_OK_ZERO(test_password_many(STRV_MAKE("$W$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH", /* no such method exists... */
                                                                    hashed,
                                                                    "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                          ""));
                }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
