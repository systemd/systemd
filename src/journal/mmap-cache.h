/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <sys/stat.h>

/* One context per object type, plus one of the header, plus one "additional" one */
#define MMAP_CACHE_MAX_CONTEXTS 9

typedef struct MMapCache MMapCache;
typedef struct MMapFileDescriptor MMapFileDescriptor;

MMapCache* mmap_cache_new(void);
MMapCache* mmap_cache_ref(MMapCache *m);
MMapCache* mmap_cache_unref(MMapCache *m);

int mmap_cache_get(
        MMapCache *m,
        MMapFileDescriptor *f,
        int prot,
        unsigned context,
        bool keep_always,
        uint64_t offset,
        size_t size,
        struct stat *st,
        void **ret,
        size_t *ret_size);
MMapFileDescriptor * mmap_cache_add_fd(MMapCache *m, int fd);
void mmap_cache_free_fd(MMapCache *m, MMapFileDescriptor *f);

unsigned mmap_cache_get_hit(MMapCache *m);
unsigned mmap_cache_get_missed(MMapCache *m);

bool mmap_cache_got_sigbus(MMapCache *m, MMapFileDescriptor *f);
