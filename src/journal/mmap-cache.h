/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdbool.h>
#include <sys/stat.h>

/* One context per object type, plus one of the header, plus one "additional" one */
#define MMAP_CACHE_MAX_CONTEXTS 9

typedef struct MMapCache MMapCache;

MMapCache* mmap_cache_new(void);
MMapCache* mmap_cache_ref(MMapCache *m);
MMapCache* mmap_cache_unref(MMapCache *m);

int mmap_cache_get(
        MMapCache *m,
        int fd,
        int prot,
        unsigned context,
        bool keep_always,
        uint64_t offset,
        size_t size,
        struct stat *st,
        void **ret);
void mmap_cache_close_fd(MMapCache *m, int fd);

unsigned mmap_cache_get_hit(MMapCache *m);
unsigned mmap_cache_get_missed(MMapCache *m);

bool mmap_cache_got_sigbus(MMapCache *m, int fd);
