/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "format-util.h"
#include "macro.h"
#include "missing.h"
#include "time-util.h"

size_t page_size(void) _pure_;
#define PAGE_ALIGN(l) ALIGN_TO((l), page_size())

static inline const char* yes_no(bool b) {
        return b ? "yes" : "no";
}

static inline const char* true_false(bool b) {
        return b ? "true" : "false";
}

static inline const char* one_zero(bool b) {
        return b ? "1" : "0";
}

static inline const char* enable_disable(bool b) {
        return b ? "enable" : "disable";
}

bool plymouth_running(void);

bool display_is_local(const char *display) _pure_;

#define NULSTR_FOREACH(i, l)                                    \
        for ((i) = (l); (i) && *(i); (i) = strchr((i), 0)+1)

#define NULSTR_FOREACH_PAIR(i, j, l)                             \
        for ((i) = (l), (j) = strchr((i), 0)+1; (i) && *(i); (i) = strchr((j), 0)+1, (j) = *(i) ? strchr((i), 0)+1 : (i))

extern int saved_argc;
extern char **saved_argv;

bool kexec_loaded(void);

int prot_from_flags(int flags) _const_;

bool in_initrd(void);
void in_initrd_force(bool value);

void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 __compar_d_fn_t compar, void *arg);

#define typesafe_bsearch_r(k, b, n, func, userdata)                     \
        ({                                                              \
                const typeof(b[0]) *_k = k;                             \
                int (*_func_)(const typeof(b[0])*, const typeof(b[0])*, typeof(userdata)) = func; \
                xbsearch_r((const void*) _k, (b), (n), sizeof((b)[0]), (__compar_d_fn_t) _func_, userdata); \
        })

/**
 * Normal bsearch requires base to be nonnull. Here were require
 * that only if nmemb > 0.
 */
static inline void* bsearch_safe(const void *key, const void *base,
                                 size_t nmemb, size_t size, __compar_fn_t compar) {
        if (nmemb <= 0)
                return NULL;

        assert(base);
        return bsearch(key, base, nmemb, size, compar);
}

#define typesafe_bsearch(k, b, n, func)                                 \
        ({                                                              \
                const typeof(b[0]) *_k = k;                             \
                int (*_func_)(const typeof(b[0])*, const typeof(b[0])*) = func; \
                bsearch_safe((const void*) _k, (b), (n), sizeof((b)[0]), (__compar_fn_t) _func_); \
        })

/**
 * Normal qsort requires base to be nonnull. Here were require
 * that only if nmemb > 0.
 */
static inline void qsort_safe(void *base, size_t nmemb, size_t size, __compar_fn_t compar) {
        if (nmemb <= 1)
                return;

        assert(base);
        qsort(base, nmemb, size, compar);
}

/* A wrapper around the above, but that adds typesafety: the element size is automatically derived from the type and so
 * is the prototype for the comparison function */
#define typesafe_qsort(p, n, func)                                      \
        ({                                                              \
                int (*_func_)(const typeof(p[0])*, const typeof(p[0])*) = func; \
                qsort_safe((p), (n), sizeof((p)[0]), (__compar_fn_t) _func_); \
        })

static inline void qsort_r_safe(void *base, size_t nmemb, size_t size, __compar_d_fn_t compar, void *userdata) {
        if (nmemb <= 1)
                return;

        assert(base);
        qsort_r(base, nmemb, size, compar, userdata);
}

#define typesafe_qsort_r(p, n, func, userdata)                          \
        ({                                                              \
                int (*_func_)(const typeof(p[0])*, const typeof(p[0])*, typeof(userdata)) = func; \
                qsort_r_safe((p), (n), sizeof((p)[0]), (__compar_d_fn_t) _func_, userdata); \
        })

/* Normal memcpy requires src to be nonnull. We do nothing if n is 0. */
static inline void memcpy_safe(void *dst, const void *src, size_t n) {
        if (n == 0)
                return;
        assert(src);
        memcpy(dst, src, n);
}

/* Normal memcmp requires s1 and s2 to be nonnull. We do nothing if n is 0. */
static inline int memcmp_safe(const void *s1, const void *s2, size_t n) {
        if (n == 0)
                return 0;
        assert(s1);
        assert(s2);
        return memcmp(s1, s2, n);
}

int on_ac_power(void);

#define memzero(x,l)                                            \
        ({                                                      \
                size_t _l_ = (l);                               \
                void *_x_ = (x);                                \
                _l_ == 0 ? _x_ : memset(_x_, 0, _l_);           \
        })

#define zero(x) (memzero(&(x), sizeof(x)))

static inline void *mempset(void *s, int c, size_t n) {
        memset(s, c, n);
        return (uint8_t*)s + n;
}

static inline void _reset_errno_(int *saved_errno) {
        errno = *saved_errno;
}

#define PROTECT_ERRNO _cleanup_(_reset_errno_) __attribute__((unused)) int _saved_errno_ = errno

static inline int negative_errno(void) {
        /* This helper should be used to shut up gcc if you know 'errno' is
         * negative. Instead of "return -errno;", use "return negative_errno();"
         * It will suppress bogus gcc warnings in case it assumes 'errno' might
         * be 0 and thus the caller's error-handling might not be triggered. */
        assert_return(errno > 0, -EINVAL);
        return -errno;
}

static inline unsigned u64log2(uint64_t n) {
#if __SIZEOF_LONG_LONG__ == 8
        return (n > 1) ? (unsigned) __builtin_clzll(n) ^ 63U : 0;
#else
#error "Wut?"
#endif
}

static inline unsigned u32ctz(uint32_t n) {
#if __SIZEOF_INT__ == 4
        return __builtin_ctz(n);
#else
#error "Wut?"
#endif
}

static inline unsigned log2i(int x) {
        assert(x > 0);

        return __SIZEOF_INT__ * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u(unsigned x) {
        assert(x > 0);

        return sizeof(unsigned) * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u_round_up(unsigned x) {
        assert(x > 0);

        if (x == 1)
                return 0;

        return log2u(x - 1) + 1;
}

int container_get_leader(const char *machine, pid_t *pid);

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd);
int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd);

uint64_t physical_memory(void);
uint64_t physical_memory_scale(uint64_t v, uint64_t max);

uint64_t system_tasks_max(void);
uint64_t system_tasks_max_scale(uint64_t v, uint64_t max);

int version(void);

int str_verscmp(const char *s1, const char *s2);

void disable_coredumps(void);
