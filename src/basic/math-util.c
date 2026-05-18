/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "math-util.h"

double xexp10i(int n) {
        /* Powers of 10 up to 10^22 are exact in IEEE-754 binary64. */
        static const double table[] = {
                1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,  1e8,  1e9,  1e10, 1e11,
                1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
        };
        bool negative = n < 0;

        /* Why not just __builtin_powi(10.0, n)? At runtime it resolves to libgcc's __powidf2, which
         * computes 10^n by repeatedly squaring: 10^16 → 10^32 → 10^64 → … . That's fast, but a double
         * can only store 10^k exactly for k ≤ 22 — beyond that, every squaring has to round to fit in
         * 53 mantissa bits, and the errors compound across squarings. By 10^308 (close to the largest
         * finite double) the answer is off by a few of the smallest possible double-steps. That sounds
         * tiny, but at the edge it's decisive: parsing DBL_MAX back from its JSON representation does
         * (mantissa × 10^308), and if 10^308 is even slightly too big the product overflows to +Inf and
         * the round-trip fails.
         *
         * So this does it the slower-but-safer way — a 23-entry table for 10^0..10^22 (all exact) plus
         * a multiply-by-10 loop for larger exponents. Each result beyond 10^22 picks up at most one
         * rounding instead of a whole chain. */

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
