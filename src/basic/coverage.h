/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* When built with --coverage (gcov) we need to explicitly call __gcov_dump()
 * in places where we use _exit(), since _exit() skips at-exit hooks resulting
 * in lost coverage.
 *
 * To make sure we don't miss any _exit() calls, this header file is included
 * explicitly on the compiler command line via the -include directive (only
 * when built with -Db_coverage=true)
 * */
extern void _exit(int);
extern void __gcov_dump(void);

static inline _Noreturn void _coverage__exit(int status) {
        __gcov_dump();
        _exit(status);
}
#define _exit(x) _coverage__exit(x)
