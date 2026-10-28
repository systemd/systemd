/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "string-util.h"

#define _STRV_FOREACH(s, l, i)                                          \
        for (typeof(*(l)) *s, *i = (l); (s = i) && *i; i++)

#define STRV_FOREACH(s, l)                      \
        _STRV_FOREACH(s, l, UNIQ_T(i, UNIQ))

static inline bool strv_isempty(sd_char * const *l) {
        return !l || !*l;
}

sd_char* strv_find(sd_char * const *l, const sd_char *name) _pure_;
#define strv_contains(l, s) (!!strv_find((l), (s)))
