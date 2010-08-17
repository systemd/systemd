/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foomacrohfoo
#define foomacrohfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <sys/types.h>

#define _printf_attr_(a,b) __attribute__ ((format (printf, a, b)))
#define _sentinel_ __attribute__ ((sentinel))
#define _noreturn_ __attribute__((noreturn))
#define _unused_ __attribute__ ((unused))
#define _destructor_ __attribute__ ((destructor))
#define _pure_ __attribute__ ((pure))
#define _const_ __attribute__ ((const))
#define _deprecated_ __attribute__ ((deprecated))
#define _packed_ __attribute__ ((packed))
#define _malloc_ __attribute__ ((malloc))
#define _weak_ __attribute__ ((weak))
#define _likely_(x) (__builtin_expect(!!(x),1))
#define _unlikely_(x) (__builtin_expect(!!(x),0))
#define _public_ __attribute__ ((visibility("default")))
#define _hidden_ __attribute__ ((visibility("hidden")))
#define _weakref_(x) __attribute__((weakref(#x)))

/* Rounds up */
static inline size_t ALIGN(size_t l) {
        return ((l + sizeof(void*) - 1) & ~(sizeof(void*) - 1));
}

#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

#define MAX(a,b)                                \
        __extension__ ({                        \
                        typeof(a) _a = (a);     \
                        typeof(b) _b = (b);     \
                        _a > _b ? _a : _b;      \
                })

#define MIN(a,b)                                \
        __extension__ ({                        \
                        typeof(a) _a = (a);     \
                        typeof(b) _b = (b);     \
                        _a < _b ? _a : _b;      \
                })

#define CLAMP(x, low, high)                                             \
        __extension__ ({                                                \
                        typeof(x) _x = (x);                             \
                        typeof(low) _low = (low);                       \
                        typeof(high) _high = (high);                    \
                        ((_x > _high) ? _high : ((_x < _low) ? _low : _x)); \
                })

#define assert_se(expr)                                                 \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert(__FILE__, __LINE__, __PRETTY_FUNCTION__, \
                                   "Assertion '%s' failed at %s:%u, function %s(). Aborting.", \
                                   #expr , __FILE__, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)                                                 \

/* We override the glibc assert() here. */
#undef assert
#ifdef NDEBUG
#define assert(expr) do {} while(false)
#else
#define assert(expr) assert_se(expr)
#endif

#define assert_not_reached(t)                                           \
        do {                                                            \
                log_assert(__FILE__, __LINE__, __PRETTY_FUNCTION__,     \
                           "Code should not be reached '%s' at %s:%u, function %s(). Aborting.", \
                           t, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)

#define assert_cc(expr)                            \
        do {                                       \
                switch (0) {                       \
                        case 0:                    \
                        case !!(expr):             \
                                ;                  \
                }                                  \
        } while (false)

#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_UINT32(p) ((uint32_t) ((uintptr_t) (p)))
#define UINT32_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_ULONG(p) ((unsigned long) ((uintptr_t) (p)))
#define ULONG_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(u) ((void*) ((intptr_t) (u)))

#define TO_INT32(p) ((int32_t) ((intptr_t) (p)))
#define INT32_TO_PTR(u) ((void*) ((intptr_t) (u)))

#define PTR_TO_LONG(p) ((long) ((intptr_t) (p)))
#define LONG_TO_PTR(u) ((void*) ((intptr_t) (u)))

#define memzero(x,l) (memset((x), 0, (l)))
#define zero(x) (memzero(&(x), sizeof(x)))

#define char_array_0(x) x[sizeof(x)-1] = 0;

#define IOVEC_SET_STRING(i, s)                  \
        do {                                    \
                struct iovec *_i = &(i);        \
                char *_s = (char *)(s);         \
                _i->iov_base = _s;              \
                _i->iov_len = strlen(_s);       \
        } while(false);

#include "log.h"

#endif
