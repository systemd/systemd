/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2014 Lennart Poettering
  Copyright 2014 Michal Schmidt

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "macro.h"
#include "mempool.h"
#include "util.h"

struct pool {
        struct pool *next;
        unsigned n_tiles;
        unsigned n_used;
};

void* mempool_alloc_tile(struct mempool *mp) {
        unsigned i;

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
                unsigned n;
                size_t size;
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

#ifdef VALGRIND

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
