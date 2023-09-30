/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>

typedef struct MMapCache MMapCache;
typedef struct MMapFileDescriptor MMapFileDescriptor;

typedef enum MMapCacheContext {
        MMAP_CACHE_CONTEXT_ANY,
        MMAP_CACHE_CONTEXT_DATA,
        MMAP_CACHE_CONTEXT_FIELD,
        MMAP_CACHE_CONTEXT_ENTRY,
        MMAP_CACHE_CONTEXT_DATA_HASH_TABLE,
        MMAP_CACHE_CONTEXT_FIELD_HASH_TABLE,
        MMAP_CACHE_CONTEXT_ENTRY_ARRAY,
        MMAP_CACHE_CONTEXT_TAG,
        MMAP_CACHE_CONTEXT_HEADER, /* for reading file header */
        _MMAP_CACHE_CONTEXT_MAX,
        _MMAP_CACHE_CONTEXT_INVALID = -EINVAL,
} MMapCacheContext;

MMapCache* mmap_cache_new(void);
MMapCache* mmap_cache_ref(MMapCache *m);
MMapCache* mmap_cache_unref(MMapCache *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(MMapCache*, mmap_cache_unref);

int mmap_cache_fd_get(
        MMapFileDescriptor *f,
        MMapCacheContext c,
        bool keep_always,
        uint64_t offset,
        size_t size,
        struct stat *st,
        void **ret);
int mmap_cache_add_fd(MMapCache *m, int fd, int prot, MMapFileDescriptor **ret);
MMapCache* mmap_cache_fd_cache(MMapFileDescriptor *f);
MMapFileDescriptor* mmap_cache_fd_free(MMapFileDescriptor *f);

void mmap_cache_stats_log_debug(MMapCache *m);

bool mmap_cache_fd_got_sigbus(MMapFileDescriptor *f);
