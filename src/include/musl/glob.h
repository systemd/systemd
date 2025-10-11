/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <glob.h>

/* Here, we set 0 to GLOB_ALTDIRFUNC and GLOB_BRACE, rather than the values used by glibc,
 * to indicate that glob() does not support these flags. */

#ifndef GLOB_ALTDIRFUNC
#define GLOB_ALTDIRFUNC 0
#define gl_flags    __dummy1
#define gl_closedir __dummy2[0]
#define gl_readdir  __dummy2[1]
#define gl_opendir  __dummy2[2]
#define gl_lstat    __dummy2[3]
#define gl_stat     __dummy2[4]
#endif

#ifndef GLOB_BRACE
#define GLOB_BRACE 0
#endif
