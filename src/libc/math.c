/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>

#include "libc-shim.h"

DEFINE_LIBC_PURE_SHIM(fmod, double,
                      double, x,
                      double, y)

DEFINE_LIBC_PURE_SHIM(exp10, double,
                      double, x)
