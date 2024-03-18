/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "random-util.h"
#include "recovery-key.h"
#include "memory-util.h"
#include "tests.h"

TEST(make_recovery_key) {
        _cleanup_(erase_and_freep) char *recovery_key = NULL;
        size_t length;
        const int num_test = 10;
        char *generated_keys[num_test];
        int r;

        /* Check for succesful recovery-key creation */
        r = make_recovery_key(&recovery_key);

        assert_se(r == 0);
        assert_se(recovery_key != NULL);
        /* Check that length of formatted key is 72 with 64 modhex characters*/
        length = strlen(recovery_key);

        assert_se(length == RECOVERY_KEY_MODHEX_FORMATTED_LENGTH - 1);
        /* Check modhex characters in formatted key with dashes */
        for(size_t i = 0; i < length; i++) {

                assert_se((recovery_key[i] >= 'a' && recovery_key[i] <= 'v') || recovery_key[i] == '-');
                if (i % 9 == 8)
                        /* confirm '-' is after every 8 characters */
                        assert_se(recovery_key[i] == '-');
        }

        /* Repeat tests to determine randomness */
        for (int test = 0; test < num_test; ++test) {
                r = make_recovery_key(&generated_keys[test]);

                assert_se(r == 0);
                length = strlen(generated_keys[test]);

                assert_se(length == RECOVERY_KEY_MODHEX_FORMATTED_LENGTH - 1);

                for (size_t i = 0; i < length; i++) {

                        assert_se((generated_keys[test][i] >= 'a' && generated_keys[test][i] <= 'v')
                                || generated_keys[test][i] == '-');

                        if (i % 9 == 8)
                                assert_se(generated_keys[test][i] == '-');
                }
                /* check for uniqueness of each generated recovery key*/
                for (int prev = 0; prev < test; ++prev) {

                        assert_se(!streq(generated_keys[test], generated_keys[prev]));
                }

        }
        for (int i = 0; i < num_test; i++) {
                free(generated_keys[i]);
        }
}

TEST(decode_modhex_char) {

        assert_se(decode_modhex_char('c') == 0);
        assert_se(decode_modhex_char('C') == 0);
        assert_se(decode_modhex_char('b') == 1);
        assert_se(decode_modhex_char('B') == 1);
        assert_se(decode_modhex_char('d') == 2);
        assert_se(decode_modhex_char('D') == 2);
        assert_se(decode_modhex_char('e') == 3);
        assert_se(decode_modhex_char('E') == 3);
        assert_se(decode_modhex_char('f') == 4);
        assert_se(decode_modhex_char('F') == 4);
        assert_se(decode_modhex_char('g') == 5);
        assert_se(decode_modhex_char('G') == 5);
        assert_se(decode_modhex_char('h') == 6);
        assert_se(decode_modhex_char('H') == 6);
        assert_se(decode_modhex_char('i') == 7);
        assert_se(decode_modhex_char('I') == 7);
        assert_se(decode_modhex_char('j') == 8);
        assert_se(decode_modhex_char('J') == 8);
        assert_se(decode_modhex_char('k') == 9);
        assert_se(decode_modhex_char('K') == 9);
        assert_se(decode_modhex_char('l') == 10);
        assert_se(decode_modhex_char('L') == 10);
        assert_se(decode_modhex_char('n') == 11);
        assert_se(decode_modhex_char('N') == 11);
        assert_se(decode_modhex_char('r') == 12);
        assert_se(decode_modhex_char('R') == 12);
        assert_se(decode_modhex_char('t') == 13);
        assert_se(decode_modhex_char('T') == 13);
        assert_se(decode_modhex_char('u') == 14);
        assert_se(decode_modhex_char('U') == 14);
        assert_se(decode_modhex_char('v') == 15);
        assert_se(decode_modhex_char('V') == 15);
        assert_se(decode_modhex_char('a') == -EINVAL);
        assert_se(decode_modhex_char('A') == -EINVAL);
        assert_se(decode_modhex_char('x') == -EINVAL);
        assert_se(decode_modhex_char('.') == -EINVAL);
        assert_se(decode_modhex_char('/') == -EINVAL);
        assert_se(decode_modhex_char('O') == -EINVAL);
        assert_se(decode_modhex_char('\0') == -EINVAL);
        assert_se(decode_modhex_char('J') == 8);

}

TEST(normalize_recovery_key) {
        char *normalized_key = NULL;
        int r;

        /* Case 1: Normalization without dashes */
        r = normalize_recovery_key("cdefghijcdefghijcdefghijcdefghijcdefghijcdefghijcdefghijcdefghij",
                        &normalized_key);

        assert(r == 0);
        assert(streq(normalized_key, "cdefghij-cdefghij-cdefghij-cdefghij-cdefghij-cdefghij-cdefghij-cdefghij"));
        free(normalized_key);

        /* Case2: Normalization with dashes */
        r = normalize_recovery_key("cdefVhij-cDefghij-cdefkhij-cdufghij-cdefgdij-cidefIhj-cdefNijR-cdVfguij",
                        &normalized_key);

        assert_se(r == 0);
        assert_se(streq(normalized_key, "cdefvhij-cdefghij-cdefkhij-cdufghij-cdefgdij-cidefihj-cdefnijr-cdvfguij"));
        free(normalized_key);

        /* Case3: Invaled password length*/
        r = normalize_recovery_key("1234-5678-90AB-CDEF-1234-5678-90AB-CDEF", &normalized_key);

        assert(r == -EINVAL);

        /* Case 4: Invalid password format(missing dash)*/
        r = normalize_recovery_key("cdefghij-cdefghij-cdefghij-cdefghij-cdefghij-cdefghij-cdefghijcdefghij",
                        &normalized_key);

        assert_se(r == -EINVAL);

        /*Case 5: Normalization of Upper cases password without dashes*/
        r = normalize_recovery_key("BFGHICEHHIUVLKJIHFHEDlntruvcdefjiTUVKLNIJVTUTKJIHDFBCBGHIJHHFDBC",
                        &normalized_key);

        assert(r == 0);
        assert_se(streq(normalized_key, "bfghiceh-hiuvlkji-hfhedlnt-ruvcdefj-ituvklni-jvtutkji-hdfbcbgh-ijhhfdbc"));
        free(normalized_key);

        /*Case 5: Minimun password length */
        r = normalize_recovery_key("", &normalized_key);
        assert_se(r == -EINVAL);

        /* Case 6: Invalid characters and numbers in password*/
        r = normalize_recovery_key("cde123hi-cdefgzij-cdefghij-cdefghij-cdefghij-cdefghij-cdefghijcdefghij",
                        &normalized_key);
        assert_se(r == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
