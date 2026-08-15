/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <glob.h>

#ifndef GLOB_ALTDIRFUNC
#define GLOB_ALTDIRFUNC (1 << 9)
#define gl_flags    __dummy1
#define gl_closedir __dummy2[0]
#define gl_readdir  __dummy2[1]
#define gl_opendir  __dummy2[2]
#define gl_lstat    __dummy2[3]
#define gl_stat     __dummy2[4]
#endif

#ifndef GLOB_BRACE
#define GLOB_BRACE      (1 << 10)
#endif
