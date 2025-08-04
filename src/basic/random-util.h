/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

void random_bytes(void *p, size_t n) _nonnull_if_nonzero_(1, 2); /* Returns random bytes suitable for most uses, but may be insecure sometimes. */
int crypto_random_bytes(void *p, size_t n) _nonnull_if_nonzero_(1, 2); /* Returns secure random bytes after waiting for the RNG to initialize. */
int crypto_random_bytes_allocate_iovec(size_t n, struct iovec *ret);

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

/* Some limits on the pool sizes when we deal with the kernel random pool */
#define RANDOM_POOL_SIZE_MIN 32U
#define RANDOM_POOL_SIZE_MAX (10U*1024U*1024U)
#define RANDOM_EFI_SEED_SIZE 32U

size_t random_pool_size(void);

int random_write_entropy(int fd, const void *seed, size_t size, bool credit) _nonnull_if_nonzero_(2, 3);

uint64_t random_u64_range(uint64_t max);
