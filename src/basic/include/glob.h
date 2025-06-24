/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <glob.h>

/* musl does not GLOB_ALTDIRFUNC */
#ifndef GLOB_ALTDIRFUNC
#define HAVE_GLOB_ALTDIRFUNC 0
#define GLOB_ALTDIRFUNC      (1 << 9)
#else
#define HAVE_GLOB_ALTDIRFUNC 1
assert_cc(GLOB_ALTDIRFUNC == (1 << 9));
#endif

/* musl does not GLOB_BRACE */
#ifndef GLOB_BRACE
#define HAVE_GLOB_BRACE 0
#define GLOB_BRACE      (1 << 10)
#else
#define HAVE_GLOB_BRACE 1
assert_cc(GLOB_BRACE == (1 << 10));
#endif
