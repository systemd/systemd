/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Force glibc's stdlib.h to leave strtol/strtoul/strtoll/strtoull as their original GLIBC_2.2.5
 * symbols rather than redirect to __isoc23_* (GLIBC_2.38). The only behavioural difference is
 * "0b" prefix support in base 0/2 parsing, which we don't use. */

#include <features.h>
#undef __GLIBC_USE_C23_STRTOL
#define __GLIBC_USE_C23_STRTOL 0

#include_next <stdlib.h>     /* IWYU pragma: export */
