/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <math.h>

#include "macro.h"

/* This also accept subnormal value, which is too small to be represented in normalized format. */
#define iszero_relaxed(x) IN_SET(fpclassify(x), FP_ZERO, FP_SUBNORMAL)

/* To avoid x == y and triggering compile warning -Wfloat-equal. */
#define fp_equal(x, y) iszero_relaxed(x - y)
