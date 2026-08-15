/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

struct pool;

struct mempool {
        struct pool *first_pool;
        void *freelist;
        size_t tile_size;
        size_t at_least;
};

void* mempool_alloc_tile(struct mempool *mp);
void* mempool_alloc0_tile(struct mempool *mp);
void* mempool_free_tile(struct mempool *mp, void *p);

#define DEFINE_MEMPOOL(pool_name, tile_type, alloc_at_least) \
static struct mempool pool_name = { \
        .tile_size = sizeof(tile_type), \
        .at_least = alloc_at_least, \
}

bool mempool_enabled(void) _weak_ _pure_;

void mempool_trim(struct mempool *mp);
