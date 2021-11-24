/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tpm2-util.h"
#include "tests.h"

static void test_tpm2_parse_pcrs_one(const char *s, uint32_t mask, int ret) {
        uint32_t m;

        assert_se(tpm2_parse_pcrs(s, &m) == ret);

        if (ret >= 0)
                assert_se(m == mask);
}

TEST(tpm2_parse_pcrs) {
        test_tpm2_parse_pcrs_one("", 0, 0);
        test_tpm2_parse_pcrs_one("0", 1, 0);
        test_tpm2_parse_pcrs_one("1", 2, 0);
        test_tpm2_parse_pcrs_one("0,1", 3, 0);
        test_tpm2_parse_pcrs_one("0+1", 3, 0);
        test_tpm2_parse_pcrs_one("0-1", 0, -EINVAL);
        test_tpm2_parse_pcrs_one("0,1,2", 7, 0);
        test_tpm2_parse_pcrs_one("0+1+2", 7, 0);
        test_tpm2_parse_pcrs_one("0+1,2", 7, 0);
        test_tpm2_parse_pcrs_one("0,1+2", 7, 0);
        test_tpm2_parse_pcrs_one("0,2", 5, 0);
        test_tpm2_parse_pcrs_one("0+2", 5, 0);
        test_tpm2_parse_pcrs_one("foo", 0, -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
