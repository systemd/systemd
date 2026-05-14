/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Force glibc's stdio.h to route sscanf/fscanf to the old __isoc99_* siblings (GLIBC_2.7) rather
 * than the newer __isoc23_* ones (GLIBC_2.38). The only behavioural difference is "0b" prefix
 * support in %i conversions, which we don't use. We include features.h first so the macro is set
 * to its normal value, then override it before stdio.h's body evaluates __GLIBC_USE(C23_STRTOL).
 *
 * The macro was named __GLIBC_USE_C2X_STRTOL on glibc 2.38–2.39 and renamed to the C23 spelling
 * in glibc 2.40; clear both so this override works across that range. */

#include <features.h>
#undef __GLIBC_USE_C2X_STRTOL
#define __GLIBC_USE_C2X_STRTOL 0
#undef __GLIBC_USE_C23_STRTOL
#define __GLIBC_USE_C23_STRTOL 0

#include_next <stdio.h>      /* IWYU pragma: export */
