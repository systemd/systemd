/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/stat.h>

#include "list.h"

/* One context per object type, plus one of the header, plus one "additional" one */
#define MMAP_CACHE_MAX_CONTEXTS 9

typedef struct MMapCache MMapCache;
typedef struct MMapFileDescriptor MMapFileDescriptor;
typedef struct MMapContext MMapContext;
typedef struct MMapContextCache MMapContextCache;
typedef struct MMapMapping MMapMapping;

struct MMapMapping {
        MMapFileDescriptor *fd;
        uint64_t offset;
        size_t size;
        void *ptr;
        bool keep_always:1;
};

struct MMapContext {
        MMapMapping *mapping;

        LIST_FIELDS(MMapContext, by_window);
};

struct MMapContextCache {
        MMapContext contexts[MMAP_CACHE_MAX_CONTEXTS];
        unsigned n_context_cache_hit;
};

MMapCache* mmap_cache_new(void);
MMapCache* mmap_cache_ref(MMapCache *m);
MMapCache* mmap_cache_unref(MMapCache *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(MMapCache*, mmap_cache_unref);

int mmap_cache_fd_get_slow(
        MMapFileDescriptor *f,
        unsigned context,
        bool keep_always,
        uint64_t offset,
        size_t size,
        struct stat *st,
        void **ret);

_pure_ static inline bool mmap_mapping_matches(MMapMapping *m, uint64_t offset, size_t size) {
        assert(m);
        assert(size > 0);

        return
                offset >= m->offset &&
                offset + size <= m->offset + m->size;
}

_pure_ static inline bool mmap_mapping_matches_fd(MMapMapping *m, MMapFileDescriptor *f, uint64_t offset, size_t size) {
        assert(m);
        assert(f);

        return
                m->fd == f &&
                mmap_mapping_matches(m, offset, size);
}

/* XXX: keep this inline as it's quite hot for users like journalctl */
static inline int mmap_cache_fd_get(
                MMapFileDescriptor *f,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                struct stat *st,
                void **ret) {

        MMapContextCache *cc;
        MMapContext *c;

        assert(f);
        assert(size > 0);
        assert(ret);
        assert(context < MMAP_CACHE_MAX_CONTEXTS);

        cc = *((MMapContextCache **)f);
        assert(cc);

        /* Check whether the current context is the right one already */
        c = &cc->contexts[context];
        if (c->mapping && mmap_mapping_matches_fd(c->mapping, f, offset, size)) {
                c->mapping->keep_always = c->mapping->keep_always || keep_always;

                *ret = (uint8_t*) c->mapping->ptr + (offset - c->mapping->offset);
                cc->n_context_cache_hit++;

                return 1;
        }

        return mmap_cache_fd_get_slow(f, context, keep_always, offset, size, st, ret);
}

MMapFileDescriptor* mmap_cache_add_fd(MMapCache *m, int fd, int prot);
MMapCache* mmap_cache_fd_cache(MMapFileDescriptor *f);
void mmap_cache_fd_free(MMapFileDescriptor *f);

void mmap_cache_stats_log_debug(MMapCache *m);

bool mmap_cache_fd_got_sigbus(MMapFileDescriptor *f);
