/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * When built with --coverage (gcov), we need to explicitly call __gcov_dump() in places where we use _exit(),
 * since _exit() skips at-exit hooks resulting in lost coverage. To make sure we don't miss any _exit() calls,
 * this header file is included explicitly on the compiler command line via the -include directive (only when
 * built with -Db_coverage=true)
 *
 * When built with -Dvalgrind=true and running on valgrind, we should call exit() in forked processes instead
 * of _exit(). Otherwise, cleanup functions for loaded libraries will never be called, and valgrind warns
 * many memory leaks in loaded libraries.
 * */

#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

extern void exit(int);
extern void _exit(int);
#if COVERAGE
extern void __gcov_dump(void);
#endif

static inline void _exit_wrapper(int status) {
#if HAVE_VALGRIND_VALGRIND_H
        if (RUNNING_ON_VALGRIND)
                exit(status);
#endif

#if COVERAGE
        __gcov_dump();
#endif
        _exit(status);
}
#define _exit(x) _exit_wrapper(x)
