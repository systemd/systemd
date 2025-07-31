/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "journal-def.h"

typedef struct MMapCache MMapCache;
typedef struct MMapFileDescriptor MMapFileDescriptor;

typedef enum MMapCacheCategory {
        MMAP_CACHE_CATEGORY_ANY              = OBJECT_UNUSED,
        MMAP_CACHE_CATEGORY_DATA             = OBJECT_DATA,
        MMAP_CACHE_CATEGORY_FIELD            = OBJECT_FIELD,
        MMAP_CACHE_CATEGORY_ENTRY            = OBJECT_ENTRY,
        MMAP_CACHE_CATEGORY_DATA_HASH_TABLE  = OBJECT_DATA_HASH_TABLE,
        MMAP_CACHE_CATEGORY_FIELD_HASH_TABLE = OBJECT_FIELD_HASH_TABLE,
        MMAP_CACHE_CATEGORY_ENTRY_ARRAY      = OBJECT_ENTRY_ARRAY,
        MMAP_CACHE_CATEGORY_TAG              = OBJECT_TAG,
        MMAP_CACHE_CATEGORY_HEADER, /* for reading file header */
        MMAP_CACHE_CATEGORY_PIN,    /* for temporary pinning a object */
        _MMAP_CACHE_CATEGORY_MAX,
        _MMAP_CACHE_CATEGORY_INVALID         = -EINVAL,
} MMapCacheCategory;

assert_cc((int) _OBJECT_TYPE_MAX < (int) _MMAP_CACHE_CATEGORY_MAX);

static inline MMapCacheCategory type_to_category(ObjectType type) {
        return type >= 0 && type < _OBJECT_TYPE_MAX ? (MMapCacheCategory) type : MMAP_CACHE_CATEGORY_ANY;
}

MMapCache* mmap_cache_new(void);
MMapCache* mmap_cache_ref(MMapCache *m);
MMapCache* mmap_cache_unref(MMapCache *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(MMapCache*, mmap_cache_unref);

int mmap_cache_fd_get(
        MMapFileDescriptor *f,
        MMapCacheCategory c,
        bool keep_always,
        uint64_t offset,
        size_t size,
        struct stat *st,
        void **ret);

int mmap_cache_fd_pin(
        MMapFileDescriptor *f,
        MMapCacheCategory c,
        void *addr,
        size_t size);

int mmap_cache_add_fd(MMapCache *m, int fd, int prot, MMapFileDescriptor **ret);
MMapCache* mmap_cache_fd_cache(MMapFileDescriptor *f);
MMapFileDescriptor* mmap_cache_fd_free(MMapFileDescriptor *f);

void mmap_cache_stats_log_debug(MMapCache *m);

bool mmap_cache_fd_got_sigbus(MMapFileDescriptor *f);
