/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "math-util.h"

double xfmod(double x, double y) {
        /* Cap the quotient at 2^53 — binary64's exact-integer range. Beyond that, x/y rounds to
         * a value whose product with y can differ from x by more than |y|, so the truncation
         * stops yielding a valid remainder. */
        assert(!iszero_safe(y));
        assert(ABS(x) / ABS(y) < (double) (INT64_C(1) << 53));
        return x - (double) (int64_t) (x / y) * y;
}

double xexp10i(int n) {
        /* Powers of 10 up to 10^22 are exact in IEEE-754 binary64. */
        static const double table[] = {
                1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,  1e8,  1e9,  1e10, 1e11,
                1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
        };
        bool negative = n < 0;
        /* Cast before negation so n == INT_MIN doesn't invoke signed-overflow UB. Unsigned negation
         * wraps to the magnitude we want. */
        unsigned k = negative ? -(unsigned) n : (unsigned) n;
        double r;

        if (k < ELEMENTSOF(table))
                r = table[k];
        else {
                /* 10^309 already overflows binary64 to +Inf; anything beyond just stays there. */
                k = MIN(k, 309u);
                r = table[ELEMENTSOF(table) - 1];
                for (unsigned i = ELEMENTSOF(table) - 1; i < k; i++)
                        r *= 10.0;
        }

        return negative ? 1.0 / r : r;
}
