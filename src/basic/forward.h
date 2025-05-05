/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/types.h>
#include <uchar.h>

#include "forward-fundamental.h"

struct stat;
struct statfs;
struct statx;
struct statx_timestamp;
struct iovec;
struct siphash;
struct tm;
struct dirent;
struct msghdr;
struct glob_t;
struct pollfd;
struct file_handle;
struct rlimit;
struct termios;
struct passwd;
struct shadow;
struct spwd;
struct group;
struct sgrp;

/* To forward declare FILE and DIR, we have to declare the internal struct names for them. Since these are
 * used for C++ symbol name mangling, they're effectively part of the ABI and won't actually change. */
typedef struct _IO_FILE FILE;
typedef struct __dirstream DIR;

typedef void (*free_func_t)(void *p);
typedef void* (*mfree_func_t)(void *p);

typedef void (*hash_func_t)(const void *p, struct siphash *state);
typedef int (*compare_func_t)(const void *a, const void *b);

typedef compare_func_t comparison_fn_t;

/* This is the same as glibc's internal __compar_d_fn_t type. glibc exports a public comparison_fn_t, for the
 * external type __compar_fn_t, but doesn't do anything similar for __compar_d_fn_t. Let's hence do that
 * ourselves, picking a name that is obvious, but likely enough to not clash with glibc's choice of naming if
 * they should ever add one. */
typedef int (*comparison_userdata_fn_t)(const void *, const void *, void *);

struct hash_ops;

/* The base type for all hashmap and set types. Many functions in the implementation take (HashmapBase*)
 * parameters and are run-time polymorphic, though the API is not meant to be polymorphic (do not call
 * underscore-prefixed functions directly). */
typedef struct HashmapBase HashmapBase;

/* Specific hashmap/set types */
typedef struct Hashmap Hashmap;               /* Maps keys to values */
typedef struct OrderedHashmap OrderedHashmap; /* Like Hashmap, but also remembers entry insertion order */
typedef struct Set Set;                       /* Stores just keys */
typedef struct OrderedSet OrderedSet;         /* Like Set, but also remembers entry insertion order */

typedef struct IteratedCache IteratedCache;   /* Caches the iterated order of one of the above */
typedef struct Iterator Iterator;

typedef struct Prioq Prioq;

typedef struct FDSet FDSet;

typedef struct PidRef PidRef;

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

typedef unsigned long loadavg_t;

typedef struct dual_timestamp dual_timestamp;
typedef struct triple_timestamp triple_timestamp;

union in_addr_union;
struct in_addr_data;
struct in_addr_prefix;
struct hw_addr_data;

typedef union sd_id128 sd_id128_t;

typedef struct sd_event sd_event;
typedef struct sd_event_source sd_event_source;

typedef struct sd_json_variant sd_json_variant;

typedef struct sd_bus sd_bus;
typedef struct sd_bus_error sd_bus_error;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_creds sd_bus_creds;
typedef struct sd_bus_track sd_bus_track;

typedef struct sd_device sd_device;
typedef struct sd_device_enumerator sd_device_enumerator;
typedef struct sd_device_monitor sd_device_monitor;

typedef struct sd_netlink sd_netlink;
typedef struct sd_netlink_message sd_netlink_message;
typedef struct sd_netlink_slot sd_netlink_slot;

typedef struct sd_varlink sd_varlink;
typedef struct sd_varlink_server sd_varlink_server;

#define AT_FDCWD                -100
#define AT_EMPTY_PATH           0x1000
#define AT_SYMLINK_FOLLOW       0x400
#define AT_SYMLINK_NOFOLLOW	0x100

#define MODE_INVALID ((mode_t) -1)

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

#define USEC_INFINITY ((usec_t) UINT64_MAX)
#define NSEC_INFINITY ((nsec_t) UINT64_MAX)

#define	EXIT_FAILURE	1
#define	EXIT_SUCCESS	0

/*
 * MAX_ERRNO is defined as 4095 in linux/err.h
 * We use the same value here.
 */
#define ERRNO_MAX 4095

#define free_and_replace_full(a, b, free_func)  \
        ({                                      \
                typeof(a)* _a = &(a);           \
                typeof(b)* _b = &(b);           \
                free_func(*_a);                 \
                *_a = *_b;                      \
                *_b = NULL;                     \
                0;                              \
        })

/* This is similar to free_and_replace_full(), but NULL is not assigned to 'b', and its reference counter is
 * increased. */
#define unref_and_replace_full(a, b, ref_func, unref_func)      \
        ({                                       \
                typeof(a)* _a = &(a);            \
                typeof(b) _b = ref_func(b);      \
                unref_func(*_a);                 \
                *_a = _b;                        \
                0;                               \
        })

#define _DEFINE_TRIVIAL_REF_FUNC(type, name, scope)             \
        scope type *name##_ref(type *p) {                       \
                if (!p)                                         \
                        return NULL;                            \
                                                                \
                /* For type check. */                           \
                unsigned *q = &p->n_ref;                        \
                assert(*q > 0);                                 \
                assert_se(*q < UINT_MAX);                       \
                                                                \
                (*q)++;                                         \
                return p;                                       \
        }

#define _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, scope) \
        scope type *name##_unref(type *p) {                      \
                if (!p)                                          \
                        return NULL;                             \
                                                                 \
                assert(p->n_ref > 0);                            \
                p->n_ref--;                                      \
                if (p->n_ref > 0)                                \
                        return NULL;                             \
                                                                 \
                return free_func(p);                             \
        }

#define DEFINE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name,)
#define DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, static)
#define DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name)      \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, _public_)

#define DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func,)
#define DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, static)
#define DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func)         \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, _public_)

#define DEFINE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define saturate_add(x, y, limit)                                       \
        ({                                                              \
                typeof(limit) _x = (x);                                 \
                typeof(limit) _y = (y);                                 \
                _x > (limit) || _y >= (limit) - _x ? (limit) : _x + _y; \
        })

static inline size_t size_add(size_t x, size_t y) {
        return saturate_add(x, y, SIZE_MAX);
}

#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))
#define STRV_MAKE_EMPTY ((char*[1]) { NULL })
#define STRV_MAKE_CONST(...) ((const char* const*) ((const char*[]) { __VA_ARGS__, NULL }))

/* Pointers range from NULL to POINTER_MAX */
#define POINTER_MAX ((void*) UINTPTR_MAX)
