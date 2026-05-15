/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

/* IEEE-754 specials exposed without dragging in <math.h>. Guarded so we coexist with TUs that
 * also include <math.h>. */
#ifndef NAN
#  define NAN __builtin_nan("")
#endif
#ifndef INFINITY
#  define INFINITY __builtin_inf()
#endif

/* True iff x is +0.0 or -0.0. Avoids -Wfloat-equal and any libm fallback fpclassify() might take
 * under -Os. */
bool iszero_safe(double x);

/* True iff x and y are equal as finite doubles. False if either is NaN, or if x and y are ±Inf
 * of opposite sign. Wraps xiszero(x - y) to side-step -Wfloat-equal. */
bool fp_equal(double x, double y);

/* True iff x is a NaN / ±Inf. The compiler builtins lower to inline bit checks at every -O level
 * and never call into libm. !! normalizes __builtin_isinf's -1-for-negative-Inf to a plain 0/1. */
#define xisnan(x) (!!__builtin_isnan(x))
#define xisinf(x) (!!__builtin_isinf(x))

/* √x via the compiler's hardware-sqrt builtin. With -fno-math-errno (set globally) this lowers to a
 * single instruction (sqrtsd/fsqrt) at every -O level, so we don't need to link libm for the cold
 * errno-setting path the plain sqrt() would otherwise pull in. */
#define xsqrt(x) __builtin_sqrt(x)

/* 2^n via __builtin_powi (lowers to libgcc's __powidf2, never libm). Exact across the whole
 * normal+subnormal range — squaring powers of 2 never rounds — and saturates to 0.0/+Inf outside,
 * including for INT_MIN/INT_MAX. */
#define xexp2i(n) __builtin_powi(2.0, (n))

/* 10^n. Exact for |n| ≤ 22; otherwise multiplies and may accumulate rounding error. Saturates to
 * 0.0 or +Inf outside binary64's exponent range; large |n| is capped internally so untrusted
 * inputs can't cause unbounded work. */
double xexp10i(int n);

/* a^(1/n) without libm. Newton's iteration on y^n − a, seeded from a magnitude-aware initial guess
 * derived from the IEEE-754 exponent of a so we converge in a handful of steps regardless of how
 * large a is. Requires a > 0 and n >= 1. */
double double_nth_root(double a, unsigned n);
