/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 comparison_userdata_fn_t compar, void *arg);

#define typesafe_bsearch_r(k, b, n, func, userdata)                     \
        ({                                                              \
                const typeof((b)[0]) *_k = k;                           \
                int (*_func_)(const typeof((b)[0])*, const typeof((b)[0])*, typeof(userdata)) = func; \
                (typeof((b)[0])*) xbsearch_r((const void*) _k, (b), (n), sizeof((b)[0]), (comparison_userdata_fn_t) _func_, userdata); \
        })

void* bsearch_safe(const void *key, const void *base, size_t nmemb, size_t size, comparison_fn_t compar);

#define typesafe_bsearch(k, b, n, func)                                 \
        ({                                                              \
                const typeof((b)[0]) *_k = k;                           \
                int (*_func_)(const typeof((b)[0])*, const typeof((b)[0])*) = func; \
                (typeof((b)[0])*) bsearch_safe((const void*) _k, (b), (n), sizeof((b)[0]), (comparison_fn_t) _func_); \
        })

void qsort_safe(void *base, size_t nmemb, size_t size, comparison_fn_t compar);

/* A wrapper around the above, but that adds typesafety: the element size is automatically derived from the type and so
 * is the prototype for the comparison function */
#define typesafe_qsort(p, n, func)                                      \
        ({                                                              \
                int (*_func_)(const typeof((p)[0])*, const typeof((p)[0])*) = func; \
                qsort_safe((p), (n), sizeof((p)[0]), (comparison_fn_t) _func_); \
        })

void qsort_r_safe(void *base, size_t nmemb, size_t size, comparison_userdata_fn_t compar, void *userdata);

#define typesafe_qsort_r(p, n, func, userdata)                          \
        ({                                                              \
                int (*_func_)(const typeof((p)[0])*, const typeof((p)[0])*, typeof(userdata)) = func; \
                qsort_r_safe((p), (n), sizeof((p)[0]), (comparison_userdata_fn_t) _func_, userdata); \
        })

int cmp_int(const int *a, const int *b);
int cmp_uint16(const uint16_t *a, const uint16_t *b);
