/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <features.h>
#include_next <math.h>       /* IWYU pragma: export */

/* fmod was bumped to GLIBC_2.38 and exp10 to GLIBC_2.39, but the GLIBC_2.2.5 versions are still
 * exported as compat symbols and behaviorally adequate for our use. Pin every reference to the old
 * version via an assembler version stamp so we keep a direct link-time reference (libm stays in
 * DT_NEEDED naturally) without raising our minimum glibc requirement. Only emit the pin when
 * building against a glibc new enough to have the bumped symbol — on older glibc the bare symbol
 * already resolves to the GLIBC_2.2.5 default, and the compat tag isn't a valid version request. */

#if __GLIBC_PREREQ(2, 38)
__asm__(".symver fmod, fmod@GLIBC_2.2.5");
#endif
#if __GLIBC_PREREQ(2, 39)
__asm__(".symver exp10, exp10@GLIBC_2.2.5");
#endif
