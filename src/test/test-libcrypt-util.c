/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <crypt.h>

#include "libcrypt-util.h"
#include "strv.h"
#include "tests.h"

static void test_crypt_preferred_method(void) {
        log_info("/* %s */", __func__);

        log_info("crypt_preferred_method: %s", crypt_preferred_method());
}

static void test_make_salt(void) {
        log_info("/* %s */", __func__);

        for (int i = 0; i < 10; i++) {
                _cleanup_free_ char *t;

                assert_se(make_salt(&t) == 0);
                log_info("%s", t);
        }
}

static void test_hash_password(void) {
        log_info("/* %s */", __func__);

        /* As a warm-up exercise, check if we can hash passwords. */

        FOREACH_STRING(hash,
                       "ew3bU1.hoKk4o",
                       "$1$gc5rWpTB$wK1aul1PyBn9AX1z93stk1",
                       "$2b$12$BlqcGkB/7BFvNMXKGxDea.5/8D6FTny.cbNcHW/tqcrcyo6ZJd8u2",
                       "$5$lGhDrcrao9zb5oIK$05KlOVG3ocknx/ThreqXE/gk.XzFFBMTksc4t2CPDUD",
                       "$6$c7wB/3GiRk0VHf7e$zXJ7hN0aLZapE.iO4mn/oHu6.prsXTUG/5k1AxpgR85ELolyAcaIGRgzfwJs3isTChMDBjnthZyaMCfCNxo9I.",
                       "$y$j9T$$9cKOWsAm4m97WiYk61lPPibZpy3oaGPIbsL4koRe/XD") {
                int b;

                b = test_password_one(hash, "ppp");
                log_info("%s: %s", hash, yes_no(b));
                assert_se(b);
        }
}

static void test_hash_password_full(void) {
        log_info("/* %s */", __func__);

        _cleanup_free_ void *cd_data = NULL;
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
                        assert_se(test_password_many(STRV_MAKE("$W$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH", /* no such method exists... */
                                                               hashed,
                                                               "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                     i) == true);
                        assert_se(test_password_many(STRV_MAKE("$y$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH",
                                                               hashed,
                                                               "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                     "") == false);
                        assert_se(test_password_many(STRV_MAKE("$W$j9T$dlCXwkX0GC5L6B8Gf.4PN/$VCyEH", /* no such method exists... */
                                                               hashed,
                                                               "$y$j9T$SAayASazWZIQeJd9AS02m/$"),
                                                     "") == false);
                }
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_crypt_preferred_method();
        test_make_salt();
        test_hash_password();
        test_hash_password_full();

        return 0;
}
