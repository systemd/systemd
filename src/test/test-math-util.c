/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>

#include "math-util.h"
#include "tests.h"

TEST(iszero_safe) {
        /* zeros */
        assert_se(iszero_safe(0.0));
        assert_se(iszero_safe(-0.0));
        assert_se(iszero_safe(0e0));
        assert_se(iszero_safe(-0e0));
        assert_se(iszero_safe(0e+0));
        assert_se(iszero_safe(0e-0));
        assert_se(iszero_safe(-0e-0));
        assert_se(iszero_safe(-0e000));
        assert_se(iszero_safe(0e000));

        /* non-zero normal values */
        assert_se(!iszero_safe(42.0));
        assert_se(!iszero_safe(M_PI));
        assert_se(!iszero_safe(DBL_MAX));
        assert_se(!iszero_safe(-DBL_MAX));
        assert_se(!iszero_safe(DBL_MIN));
        assert_se(!iszero_safe(-DBL_MIN));
        assert_se(!iszero_safe(1 / DBL_MAX));

        /* subnormal values */
        assert_se(!iszero_safe(DBL_MIN / 2));
        assert_se(!iszero_safe(-DBL_MIN / 42));
        assert_se(!iszero_safe(1 / DBL_MAX / 2));

        /* too small values which cannot be in subnormal form */
        assert_se( iszero_safe(DBL_MIN / DBL_MAX));
        assert_se( iszero_safe(DBL_MIN / -DBL_MAX));
        assert_se( iszero_safe(-DBL_MIN / DBL_MAX));
        assert_se( iszero_safe(-DBL_MIN / -DBL_MAX));

        /* NaN or infinity */
        assert_se(!iszero_safe(NAN));
        assert_se(!iszero_safe(INFINITY));
        assert_se(!iszero_safe(-INFINITY));
        assert_se(!iszero_safe(1 / NAN));

        /* inverse of infinity */
        assert_se( iszero_safe(1 / INFINITY));
        assert_se( iszero_safe(1 / -INFINITY));
        assert_se( iszero_safe(-1 / INFINITY));
        assert_se( iszero_safe(-1 / -INFINITY));
        assert_se( iszero_safe(42 / -INFINITY));
        assert_se( iszero_safe(-42 / -INFINITY));
        assert_se( iszero_safe(DBL_MIN / INFINITY));
        assert_se( iszero_safe(DBL_MIN / -INFINITY));
        assert_se( iszero_safe(DBL_MAX / INFINITY / 2));
        assert_se( iszero_safe(DBL_MAX / -INFINITY * DBL_MAX));

        /* infinity / infinity is NaN */
        assert_se(!iszero_safe(INFINITY / INFINITY));
        assert_se(!iszero_safe(INFINITY * 2 / INFINITY));
        assert_se(!iszero_safe(INFINITY / DBL_MAX / INFINITY));
}

TEST(fp_equal) {
        /* normal values */
        assert_se( fp_equal(0.0, -0e0));
        assert_se( fp_equal(3.0, 3));
        assert_se(!fp_equal(3.000001, 3));
        assert_se( fp_equal(M_PI, M_PI));
        assert_se(!fp_equal(M_PI, -M_PI));
        assert_se( fp_equal(DBL_MAX, DBL_MAX));
        assert_se(!fp_equal(DBL_MAX, -DBL_MAX));
        assert_se(!fp_equal(-DBL_MAX, DBL_MAX));
        assert_se( fp_equal(-DBL_MAX, -DBL_MAX));
        assert_se( fp_equal(DBL_MIN, DBL_MIN));
        assert_se(!fp_equal(DBL_MIN, -DBL_MIN));
        assert_se(!fp_equal(-DBL_MIN, DBL_MIN));
        assert_se( fp_equal(-DBL_MIN, -DBL_MIN));

        /* subnormal values */
        assert_se( fp_equal(DBL_MIN / 10, DBL_MIN / 10));
        assert_se(!fp_equal(DBL_MIN / 10, -DBL_MIN / 10));
        assert_se(!fp_equal(-DBL_MIN / 10, DBL_MIN / 10));
        assert_se( fp_equal(-DBL_MIN / 10, -DBL_MIN / 10));
        assert_se(!fp_equal(DBL_MIN / 10, DBL_MIN / 15));
        assert_se(!fp_equal(DBL_MIN / 10, DBL_MIN / 15));

        /* subnormal difference */
        assert_se(!fp_equal(DBL_MIN / 10, DBL_MIN + DBL_MIN / 10));
        assert_se( fp_equal(3.0, 3.0 + DBL_MIN / 2)); /* 3.0 + DBL_MIN / 2 is truncated to 3.0 */

        /* too small values */
        assert_se( fp_equal(DBL_MIN / DBL_MAX, -DBL_MIN / DBL_MAX));

        /* NaN or infinity */
        assert_se(!fp_equal(NAN, NAN));
        assert_se(!fp_equal(NAN, 0));
        assert_se(!fp_equal(NAN, INFINITY));
        assert_se(!fp_equal(INFINITY, INFINITY));
        assert_se(!fp_equal(INFINITY, -INFINITY));
        assert_se(!fp_equal(-INFINITY, INFINITY));
        assert_se(!fp_equal(-INFINITY, -INFINITY));

        /* inverse of infinity */
        assert_se( fp_equal(0, 1 / INFINITY));
        assert_se( fp_equal(42 / INFINITY, 1 / -INFINITY));
        assert_se(!fp_equal(42 / INFINITY, INFINITY / INFINITY));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
