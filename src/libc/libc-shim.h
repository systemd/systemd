/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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

/* Defines a wrapper that calls the libc symbol if available at runtime, or falls back to the
 * corresponding direct syscall otherwise. The libc symbol is redeclared as a weak reference so the
 * binary still loads on libc versions that don't provide it. Each parameter is passed as type,
 * name pairs (flat).
 *
 * The weak reference is bound to the libc symbol via an __asm__("label") rename so that the bare
 * libc identifier never appears as a C token. This matters because override/musl headers
 * sometimes #define the libc name to redirect it to the _shim variant — without the rename the
 * caller would have to #undef each name before invoking the macro. # and ## operators don't
 * macro-expand their operands, so the parameter "func" stays a literal token everywhere. */
#define DEFINE_SYSCALL_SHIM(func, ret, ...)                                                          \
        extern typeof(func##_shim) func##_libc_weak __asm__(#func) __attribute__((__weak__));        \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                if (func##_libc_weak)                                                                \
                        return func##_libc_weak(_SHIM_NAME(__VA_ARGS__));                            \
                return syscall(__NR_##func, _SHIM_NAME(__VA_ARGS__));                                \
        }

/* Like DEFINE_SYSCALL_SHIM but for libc helpers that have no corresponding syscall and report errors
 * by returning the positive errno value directly (posix_spawn-family convention). If the libc symbol
 * is missing at runtime, ENOSYS is returned. */
#define DEFINE_LIBC_SHIM(func, ret, ...)                                                             \
        extern typeof(func##_shim) func##_libc_weak __asm__(#func) __attribute__((__weak__));        \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                if (func##_libc_weak)                                                                \
                        return func##_libc_weak(_SHIM_NAME(__VA_ARGS__));                            \
                return ENOSYS;                                                                       \
        }

/* Like DEFINE_LIBC_SHIM but for libc helpers that report errors via errno + -1 return value. If the
 * libc symbol is missing at runtime, errno is set to ENOSYS and -1 is returned. */
#define DEFINE_LIBC_ERRNO_SHIM(func, ret, ...)                                                       \
        extern typeof(func##_shim) func##_libc_weak __asm__(#func) __attribute__((__weak__));        \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                if (func##_libc_weak)                                                                \
                        return func##_libc_weak(_SHIM_NAME(__VA_ARGS__));                            \
                errno = ENOSYS;                                                                      \
                return -1;                                                                           \
        }
