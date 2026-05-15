/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "math-util.h"

bool iszero_safe(double x) {
        uint64_t bits;
        __builtin_memcpy(&bits, &x, sizeof(bits));
        return (bits & UINT64_C(0x7FFFFFFFFFFFFFFF)) == 0;
}

bool fp_equal(double x, double y) {
        return iszero_safe(x - y);
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

        /* 10^309 already overflows binary64 to +Inf; anything beyond just stays there. */
        k = MIN(k, 309u);
        double r = k < ELEMENTSOF(table) ? table[k] : table[ELEMENTSOF(table) - 1];
        for (unsigned i = ELEMENTSOF(table) - 1; i < k; i++)
                r *= 10.0;

        return negative ? 1.0 / r : r;
}

double double_nth_root(double a, unsigned n) {
        assert(a > 0);
        assert(!xisinf(a));
        assert(n >= 1);

        if (n == 1 || fp_equal(a, 1.0))
                return a;

        /* For a normal a = m · 2^e with m ∈ [1, 2), seed y ≈ 2^(e/n), within a factor of 2 of the
         * true root. For subnormals the biased exponent field is 0, so the line below yields
         * e = -1023 — one off from the "true" -1022 — but the seed is still within a factor of 2
         * and Newton recovers in one extra step. */
        uint64_t bits;
        __builtin_memcpy(&bits, &a, sizeof(bits));
        int e = (int) ((bits >> 52) & 0x7FF) - 1023;
        double y = xexp2i(e / (int) n);

        /* Newton: y_{k+1} = ((n−1)·y_k + a / y_k^(n−1)) / n. Quadratic convergence; capped as a
         * safety net since we don't otherwise prove termination.
         * See https://en.wikipedia.org/wiki/Nth_root_algorithm. */
        for (int k = 0; k < 50; k++) {
                double y_pow = 1.0;
                for (unsigned j = 1; j < n; j++)
                        y_pow *= y;
                double y_next = ((double) (n - 1) * y + a / y_pow) / (double) n;
                if (fp_equal(y, y_next))
                        break;
                y = y_next;
        }

        return y;
}
