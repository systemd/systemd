/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <math.h>       /* IWYU pragma: export */

double fmod_shim(double x, double y);
double exp10_shim(double x);
#define fmod fmod_shim
#define exp10 exp10_shim
