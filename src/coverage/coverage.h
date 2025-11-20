/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Use the coverage-related tweaks below only for C stuff as they're not really
 * C++ compatible, and the only thing that is built with a C++ compiler is
 * the lone test-bus-vtable-cc unit test.
 */
#ifndef __cplusplus

void __gcov_dump(void);
void __gcov_reset(void);

/* When built with --coverage (gcov) we need to explicitly call __gcov_dump()
 * in places where we use _exit(), since _exit() skips at-exit hooks resulting
 * in lost coverage.
 *
 * To make sure we don't miss any _exit() calls, this header file is included
 * explicitly on the compiler command line via the -include directive (only
 * when built with -Db_coverage=true)
 */
void _exit(int);

static inline _Noreturn void _coverage__exit(int status) {
        __gcov_dump();
        _exit(status);
}
#define _exit(x) _coverage__exit(x)

/* gcov provides wrappers for the exec*() calls but there's none for execveat()
 * and execvpe() which means we lose all coverage prior to such call. To mitigate
 * this, let's add simple wrappers in gcov's style[0] for these exec*() calls,
 * which dump and reset the coverage data as needed.
 *
 * [0] https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=libgcc/libgcov-interface.c;h=b2ee930864183b78c8826255183ca86e15e21ded;hb=HEAD
 */

int execveat(int, const char *, char * const [], char * const [], int);
int execvpe(const char *, char * const [], char * const []);

static inline int _coverage_execveat(
                        int dirfd,
                        const char *pathname,
                        char * const argv[],
                        char * const envp[],
                        int flags) {
        __gcov_dump();
        int r = execveat(dirfd, pathname, argv, envp, flags);
        __gcov_reset();

        return r;
}
#define execveat(d,p,a,e,f) _coverage_execveat(d, p, a, e, f)

static inline int _coverage_execvpe(
                        const char *file,
                        char * const argv[],
                        char * const envp[]) {
        __gcov_dump();
        int r = execvpe(file, argv, envp);
        __gcov_reset();

        return r;
}
#define execvpe(f,a,e) _coverage_execvpe(f, a, e)

#endif
