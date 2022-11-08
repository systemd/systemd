/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memory-util.h"
#include "tests.h"

TEST(eqzero) {
        const uint32_t zeros[] = {0, 0, 0};
        const uint32_t ones[] = {1, 1};
        const uint32_t mixed[] = {0, 1, 0, 0, 0};
        const uint8_t longer[] = {[55] = 255};

        assert_se(eqzero(zeros));
        assert_se(!eqzero(ones));
        assert_se(!eqzero(mixed));
        assert_se(!eqzero(longer));
}

DEFINE_TEST_MAIN(LOG_INFO);
