/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2014 Michal Schmidt
***/

#include <stddef.h>

struct pool;

struct mempool {
        struct pool *first_pool;
        void *freelist;
        size_t tile_size;
        unsigned at_least;
};

void* mempool_alloc_tile(struct mempool *mp);
void* mempool_alloc0_tile(struct mempool *mp);
void mempool_free_tile(struct mempool *mp, void *p);

#define DEFINE_MEMPOOL(pool_name, tile_type, alloc_at_least) \
static struct mempool pool_name = { \
        .tile_size = sizeof(tile_type), \
        .at_least = alloc_at_least, \
}

#if VALGRIND
void mempool_drop(struct mempool *mp);
#endif
