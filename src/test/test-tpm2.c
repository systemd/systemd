/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tpm2-util.h"
#include "tests.h"

static void test_tpm2_parse_pcrs(const char *s, uint32_t mask, int ret) {
        uint32_t m;

        assert_se(tpm2_parse_pcrs(s, &m) == ret);

        if (ret >= 0)
                assert_se(m == mask);
}

int main(int argc, char *argv[]) {

        test_setup_logging(LOG_DEBUG);

        test_tpm2_parse_pcrs("", 0, 0);
        test_tpm2_parse_pcrs("0", 1, 0);
        test_tpm2_parse_pcrs("1", 2, 0);
        test_tpm2_parse_pcrs("0,1", 3, 0);
        test_tpm2_parse_pcrs("0+1", 3, 0);
        test_tpm2_parse_pcrs("0-1", 0, -EINVAL);
        test_tpm2_parse_pcrs("0,1,2", 7, 0);
        test_tpm2_parse_pcrs("0+1+2", 7, 0);
        test_tpm2_parse_pcrs("0+1,2", 7, 0);
        test_tpm2_parse_pcrs("0,1+2", 7, 0);
        test_tpm2_parse_pcrs("0,2", 5, 0);
        test_tpm2_parse_pcrs("0+2", 5, 0);
        test_tpm2_parse_pcrs("foo", 0, -EINVAL);

        return 0;
}
