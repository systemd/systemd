/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011-2014 Lennart Poettering
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
struct mempool pool_name = { \
        .tile_size = sizeof(tile_type), \
        .at_least = alloc_at_least, \
}


#ifdef VALGRIND
void mempool_drop(struct mempool *mp);
#endif
