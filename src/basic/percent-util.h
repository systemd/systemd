/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <inttypes.h>

#include "macro.h"

int parse_percent_unbounded(const char *p);
int parse_percent(const char *p);

int parse_permille_unbounded(const char *p);
int parse_permille(const char *p);

int parse_permyriad_unbounded(const char *p);
int parse_permyriad(const char *p);

/* Some macro-like helpers that convert a percent/permille/permyriad value (as parsed by parse_percent()) to
 * a value relative to 100% == 2^32-1. Rounds to closest. */
static inline uint32_t UINT32_SCALE_FROM_PERCENT(int percent) {
        assert_cc(INT_MAX <= UINT32_MAX);

        return (uint32_t) (((uint64_t) CLAMP(percent, 0, 100) * UINT32_MAX + 50) / 100U);
}

static inline uint32_t UINT32_SCALE_FROM_PERMILLE(int permille) {
        return (uint32_t) (((uint64_t) CLAMP(permille, 0, 1000) * UINT32_MAX + 500) / 1000U);
}

static inline uint32_t UINT32_SCALE_FROM_PERMYRIAD(int permyriad) {
        return (uint32_t) (((uint64_t) CLAMP(permyriad, 0, 10000) * UINT32_MAX + 5000) / 10000U);
}

static inline int UINT32_SCALE_TO_PERCENT(uint32_t scale) {
        uint32_t u;

        u = (uint32_t) ((((uint64_t) scale) * 100U + UINT32_MAX/2) / UINT32_MAX);
        if (u > INT_MAX)
                return -ERANGE;

        return (int) u;
}

static inline int UINT32_SCALE_TO_PERMILLE(uint32_t scale) {
        uint32_t u;

        u = (uint32_t) ((((uint64_t) scale) * 1000U + UINT32_MAX/2) / UINT32_MAX);
        if (u > INT_MAX)
                return -ERANGE;

        return (int) u;
}

static inline int UINT32_SCALE_TO_PERMYRIAD(uint32_t scale) {
        uint32_t u;

        u = (uint32_t) ((((uint64_t) scale) * 10000U + UINT32_MAX/2) / UINT32_MAX);
        if (u > INT_MAX)
                return -ERANGE;

        return (int) u;
}

#define PERMYRIAD_AS_PERCENT_FORMAT_STR "%i.%02i%%"
#define PERMYRIAD_AS_PERCENT_FORMAT_VAL(x) ((x)/100), ((x)%100)
