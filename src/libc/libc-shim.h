/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dlfcn.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Each parameter is passed as a flat (type, name) pair: type1, name1, type2, name2, ... The
 * _SHIM_DECL/_SHIM_NAME macros consume two args at a time and emit either "type name" pairs (for
 * the function declarator) or just the names (for forwarding). _SHIM_PAIRS counts the number of
 * pairs by indexing into a table that increments every two positions. */
#define _SHIM_CAT(a, b) _SHIM_CAT_(a, b)
#define _SHIM_CAT_(a, b) a##b

#define _SHIM_NTH(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define _SHIM_PAIRS(...) _SHIM_NTH(__VA_ARGS__, 8, 8, 7, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0)

#define _SHIM_DECL_1(t, n)      t n
#define _SHIM_DECL_2(t, n, ...) t n, _SHIM_DECL_1(__VA_ARGS__)
#define _SHIM_DECL_3(t, n, ...) t n, _SHIM_DECL_2(__VA_ARGS__)
#define _SHIM_DECL_4(t, n, ...) t n, _SHIM_DECL_3(__VA_ARGS__)
#define _SHIM_DECL_5(t, n, ...) t n, _SHIM_DECL_4(__VA_ARGS__)
#define _SHIM_DECL_6(t, n, ...) t n, _SHIM_DECL_5(__VA_ARGS__)
#define _SHIM_DECL_7(t, n, ...) t n, _SHIM_DECL_6(__VA_ARGS__)
#define _SHIM_DECL_8(t, n, ...) t n, _SHIM_DECL_7(__VA_ARGS__)
#define _SHIM_DECL(...) _SHIM_CAT(_SHIM_DECL_, _SHIM_PAIRS(__VA_ARGS__))(__VA_ARGS__)

#define _SHIM_NAME_1(t, n)      n
#define _SHIM_NAME_2(t, n, ...) n, _SHIM_NAME_1(__VA_ARGS__)
#define _SHIM_NAME_3(t, n, ...) n, _SHIM_NAME_2(__VA_ARGS__)
#define _SHIM_NAME_4(t, n, ...) n, _SHIM_NAME_3(__VA_ARGS__)
#define _SHIM_NAME_5(t, n, ...) n, _SHIM_NAME_4(__VA_ARGS__)
#define _SHIM_NAME_6(t, n, ...) n, _SHIM_NAME_5(__VA_ARGS__)
#define _SHIM_NAME_7(t, n, ...) n, _SHIM_NAME_6(__VA_ARGS__)
#define _SHIM_NAME_8(t, n, ...) n, _SHIM_NAME_7(__VA_ARGS__)
#define _SHIM_NAME(...) _SHIM_CAT(_SHIM_NAME_, _SHIM_PAIRS(__VA_ARGS__))(__VA_ARGS__)

/* The shim resolves the libc symbol via dlsym(RTLD_DEFAULT) on first call and caches the result.
 * The cache uses (void *) -1 as a sentinel for "not resolved yet" so NULL (libc doesn't provide
 * the symbol) is also cacheable. Racing threads may all perform the dlsym() but they all store the
 * same value, so no locking is needed; acquire/release ordering guarantees later loads observe a
 * consistent cached value.
 *
 * Each reference to `func` in the macro body is positioned as an operand of `#` or `##` so the
 * override headers (e.g. "#define openat2 openat2_shim") don't rewrite the token before pasting or
 * stringification. For the same reason the resolution logic isn't extracted into a helper macro —
 * passing `func` to a nested macro would expand it as a regular argument and re-trigger the
 * override.
 *
 * Defines a wrapper that calls the libc symbol if available at runtime, or falls back to the
 * corresponding direct syscall otherwise. Each parameter is passed as type, name pairs (flat). */
#define DEFINE_SYSCALL_SHIM(func, ret, ...)                                                          \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                static void *cache = (void *) -1;                                                    \
                void *p = __atomic_load_n(&cache, __ATOMIC_ACQUIRE);                                 \
                if (p == (void *) -1) {                                                              \
                        p = dlsym(RTLD_DEFAULT, #func);                                              \
                        __atomic_store_n(&cache, p, __ATOMIC_RELEASE);                               \
                }                                                                                    \
                typeof(&func##_shim) fn = (typeof(&func##_shim)) p;                                  \
                if (fn)                                                                              \
                        return fn(_SHIM_NAME(__VA_ARGS__));                                          \
                return syscall(__NR_##func, _SHIM_NAME(__VA_ARGS__));                                \
        }

/* Like DEFINE_SYSCALL_SHIM but for libc helpers that have no corresponding syscall and report errors
 * by returning the positive errno value directly (posix_spawn-family convention). If the libc symbol
 * is missing at runtime, ENOSYS is returned. */
#define DEFINE_LIBC_SHIM(func, ret, ...)                                                             \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                static void *cache = (void *) -1;                                                    \
                void *p = __atomic_load_n(&cache, __ATOMIC_ACQUIRE);                                 \
                if (p == (void *) -1) {                                                              \
                        p = dlsym(RTLD_DEFAULT, #func);                                              \
                        __atomic_store_n(&cache, p, __ATOMIC_RELEASE);                               \
                }                                                                                    \
                typeof(&func##_shim) fn = (typeof(&func##_shim)) p;                                  \
                if (fn)                                                                              \
                        return fn(_SHIM_NAME(__VA_ARGS__));                                          \
                return ENOSYS;                                                                       \
        }

/* Like DEFINE_LIBC_SHIM but for libc helpers that report errors via errno + -1 return value. If the
 * libc symbol is missing at runtime, errno is set to ENOSYS and -1 is returned. */
#define DEFINE_LIBC_ERRNO_SHIM(func, ret, ...)                                                       \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                static void *cache = (void *) -1;                                                    \
                void *p = __atomic_load_n(&cache, __ATOMIC_ACQUIRE);                                 \
                if (p == (void *) -1) {                                                              \
                        p = dlsym(RTLD_DEFAULT, #func);                                              \
                        __atomic_store_n(&cache, p, __ATOMIC_RELEASE);                               \
                }                                                                                    \
                typeof(&func##_shim) fn = (typeof(&func##_shim)) p;                                  \
                if (fn)                                                                              \
                        return fn(_SHIM_NAME(__VA_ARGS__));                                          \
                errno = ENOSYS;                                                                      \
                return -1;                                                                           \
        }
