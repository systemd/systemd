/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdlib.h>

#include "macro.h"

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
