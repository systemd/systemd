/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdint.h>
#include <stdlib.h>

#include "env-util.h"
#include "macro.h"
#include "mempool.h"
#include "process-util.h"
#include "util.h"

struct pool {
        struct pool *next;
        size_t n_tiles;
        size_t n_used;
};

void* mempool_alloc_tile(struct mempool *mp) {
        size_t i;

        /* When a tile is released we add it to the list and simply
         * place the next pointer at its offset 0. */

        assert(mp->tile_size >= sizeof(void*));
        assert(mp->at_least > 0);

        if (mp->freelist) {
                void *r;

                r = mp->freelist;
                mp->freelist = * (void**) mp->freelist;
                return r;
        }

        if (_unlikely_(!mp->first_pool) ||
            _unlikely_(mp->first_pool->n_used >= mp->first_pool->n_tiles)) {
                size_t size, n;
                struct pool *p;

                n = mp->first_pool ? mp->first_pool->n_tiles : 0;
                n = MAX(mp->at_least, n * 2);
                size = PAGE_ALIGN(ALIGN(sizeof(struct pool)) + n*mp->tile_size);
                n = (size - ALIGN(sizeof(struct pool))) / mp->tile_size;

                p = malloc(size);
                if (!p)
                        return NULL;

                p->next = mp->first_pool;
                p->n_tiles = n;
                p->n_used = 0;

                mp->first_pool = p;
        }

        i = mp->first_pool->n_used++;

        return ((uint8_t*) mp->first_pool) + ALIGN(sizeof(struct pool)) + i*mp->tile_size;
}

void* mempool_alloc0_tile(struct mempool *mp) {
        void *p;

        p = mempool_alloc_tile(mp);
        if (p)
                memzero(p, mp->tile_size);
        return p;
}

void mempool_free_tile(struct mempool *mp, void *p) {
        * (void**) p = mp->freelist;
        mp->freelist = p;
}

bool mempool_enabled(void) {
        static int b = -1;

        if (!is_main_thread())
                return false;

        if (!mempool_use_allowed)
                b = false;
        if (b < 0)
                b = getenv_bool("SYSTEMD_MEMPOOL") != 0;

        return b;
}

#if VALGRIND
void mempool_drop(struct mempool *mp) {
        struct pool *p = mp->first_pool;
        while (p) {
                struct pool *n;
                n = p->next;
                free(p);
                p = n;
        }
}
#endif
