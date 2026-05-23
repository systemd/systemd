/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "../basic/math-util.h" /* IWYU pragma: export */

/* Helpers defined here cannot be used in libsystemd, as they cause
 * certain programs using ifuncs to crash on startup */

/* 10^n. Exact for |n| ≤ 22; otherwise multiplies and may accumulate rounding error. Saturates to
 * 0.0 or +Inf outside binary64's exponent range; large |n| is capped internally so untrusted
 * inputs can't cause unbounded work. */
double xexp10i(int n);
