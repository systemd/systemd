/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
DEFINE_TRIVIAL_CLEANUP_FUNC(MMapCache*, mmap_cache_unref);

int mmap_cache_fd_get(
        MMapFileDescriptor *f,
        unsigned context,
        bool keep_always,
        uint64_t offset,
        size_t size,
        struct stat *st,
        void **ret);
MMapFileDescriptor* mmap_cache_add_fd(MMapCache *m, int fd, int prot);
MMapCache* mmap_cache_fd_cache(MMapFileDescriptor *f);
void mmap_cache_fd_free(MMapFileDescriptor *f);

void mmap_cache_stats_log_debug(MMapCache *m);

bool mmap_cache_fd_got_sigbus(MMapFileDescriptor *f);
