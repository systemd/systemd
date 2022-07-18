/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>

#include "math-util.h"
#include "tests.h"

TEST(iszero_safe) {
        assert_se( iszero_safe(0.0));
        assert_se( iszero_safe(-0.0));
        assert_se(!iszero_safe(DBL_MIN / 2));
}

TEST(fp_equal) {
        assert_se( fp_equal(3.0, 3));
        assert_se( fp_equal(DBL_MIN, DBL_MIN));
        assert_se( fp_equal(DBL_MIN / 10, DBL_MIN / 10));
        assert_se(!fp_equal(DBL_MIN / 10, DBL_MIN / 15));
        assert_se(!fp_equal(3.0, 3.0 + DBL_MIN / 2));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
