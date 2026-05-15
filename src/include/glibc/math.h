/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <math.h>       /* IWYU pragma: export */

/* fmod was bumped to GLIBC_2.38 and exp10 to GLIBC_2.39, but the GLIBC_2.2.5 versions are still
 * exported and behaviorally adequate for our use. Pin every reference to the old version via
 * an assembler version stamp so we keep a direct link-time reference (libm stays in DT_NEEDED
 * naturally) without raising our minimum glibc requirement. */

__asm__(".symver fmod, fmod@GLIBC_2.2.5");
__asm__(".symver exp10, exp10@GLIBC_2.2.5");
