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

/* The shim resolves the libc symbol via dlsym(RTLD_DEFAULT) at DSO-load time using a constructor
 * and caches the result in a file-scope static. Constructors run single-threaded before main() and
 * before any signal handler can fire, so the cached pointer needs no atomics: subsequent reads from
 * any thread observe the value stored during init. Resolving eagerly also keeps dlsym() out of
 * contexts where it is not async-signal-safe (signal handlers, between fork() and exec()).
 *
 * The asm barrier after dlsym() is load-bearing: without it, when LTO determines the cache store
 * is dead (because no caller of func##_shim survives DCE) the compiler is free to tail-call
 * dlsym() (jmp dlsym@plt). Under glibc, dlsym reads __builtin_return_address(0) to find its
 * caller's link map; with a tail call that read lands inside ld.so's call_init(), the resulting
 * link map has no l_scope, and _dl_lookup_symbol_x SIGSEGVs. Filed upstream in glibc by
 * https://sourceware.org/bugzilla/show_bug.cgi?id=34156. The barrier keeps us working on
 * unpatched libc.
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
        static typeof(&func##_shim) func##_shim_cache;                                               \
        __attribute__((constructor)) static void func##_shim_init(void) {                            \
                void *p = dlsym(RTLD_DEFAULT, #func);                                                \
                __asm__ volatile("" ::: "memory");                                                   \
                func##_shim_cache = (typeof(&func##_shim)) p;                                        \
        }                                                                                            \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                if (func##_shim_cache)                                                               \
                        return func##_shim_cache(_SHIM_NAME(__VA_ARGS__));                           \
                return syscall(__NR_##func, _SHIM_NAME(__VA_ARGS__));                                \
        }

/* Like DEFINE_SYSCALL_SHIM but for libc helpers that have no corresponding syscall and report errors
 * by returning the positive errno value directly (posix_spawn-family convention). If the libc symbol
 * is missing at runtime, ENOSYS is returned. */
#define DEFINE_LIBC_SHIM(func, ret, ...)                                                             \
        static typeof(&func##_shim) func##_shim_cache;                                               \
        __attribute__((constructor)) static void func##_shim_init(void) {                            \
                void *p = dlsym(RTLD_DEFAULT, #func);                                                \
                __asm__ volatile("" ::: "memory");                                                   \
                func##_shim_cache = (typeof(&func##_shim)) p;                                        \
        }                                                                                            \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                if (func##_shim_cache)                                                               \
                        return func##_shim_cache(_SHIM_NAME(__VA_ARGS__));                           \
                return ENOSYS;                                                                       \
        }

/* Like DEFINE_LIBC_SHIM but for libc helpers that report errors via errno + -1 return value. If the
 * libc symbol is missing at runtime, errno is set to ENOSYS and -1 is returned. */
#define DEFINE_LIBC_ERRNO_SHIM(func, ret, ...)                                                       \
        static typeof(&func##_shim) func##_shim_cache;                                               \
        __attribute__((constructor)) static void func##_shim_init(void) {                            \
                void *p = dlsym(RTLD_DEFAULT, #func);                                                \
                __asm__ volatile("" ::: "memory");                                                   \
                func##_shim_cache = (typeof(&func##_shim)) p;                                        \
        }                                                                                            \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                if (func##_shim_cache)                                                               \
                        return func##_shim_cache(_SHIM_NAME(__VA_ARGS__));                           \
                errno = ENOSYS;                                                                      \
                return -1;                                                                           \
        }

/* Like DEFINE_LIBC_ERRNO_SHIM but with an explicit string for the libc symbol name to dlsym. This is
 * needed for functions whose libc symbol is renamed via __asm__() in the header (e.g. when glibc
 * redirects time-related calls to their __*_time64 aliases on 32-bit systems built with
 * _TIME_BITS=64) since dlsym() doesn't see those header-level renames, so the caller has to spell out
 * the actual ABI symbol name that matches the struct layout the compiler picked. We can't forward to
 * DEFINE_LIBC_ERRNO_SHIM since passing `func` as a regular argument would let the override-header
 * #define rewrite the token (e.g. `epoll_pwait2` to `epoll_pwait2_shim`) before the inner macro
 * could paste it, so we duplicate the body and keep every `func` reference behind `#` or `##`. */
#define DEFINE_LIBC_ERRNO_SHIM_NAMED(func, sym_name, ret, ...)                                       \
        static typeof(&func##_shim) func##_shim_cache;                                               \
        __attribute__((constructor)) static void func##_shim_init(void) {                            \
                void *p = dlsym(RTLD_DEFAULT, sym_name);                                             \
                __asm__ volatile("" ::: "memory");                                                   \
                func##_shim_cache = (typeof(&func##_shim)) p;                                        \
        }                                                                                            \
        ret func##_shim(_SHIM_DECL(__VA_ARGS__)) {                                                   \
                if (func##_shim_cache)                                                               \
                        return func##_shim_cache(_SHIM_NAME(__VA_ARGS__));                           \
                errno = ENOSYS;                                                                      \
                return -1;                                                                           \
        }
