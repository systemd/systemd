/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int genuine_random_bytes(void *p, size_t n, bool high_quality_required); /* returns "genuine" randomness, optionally filled upwith pseudo random, if not enough is available */
void pseudo_random_bytes(void *p, size_t n);                             /* returns only pseudo-randommess (but possibly seeded from something better) */
void random_bytes(void *p, size_t n);                                    /* returns genuine randomness if cheaply available, and pseudo randomness if not. */

void initialize_srand(void);

static inline uint64_t random_u64(void) {
        uint64_t u;
        random_bytes(&u, sizeof(u));
        return u;
}

static inline uint32_t random_u32(void) {
        uint32_t u;
        random_bytes(&u, sizeof(u));
        return u;
}

int rdrand64(uint64_t *ret);
