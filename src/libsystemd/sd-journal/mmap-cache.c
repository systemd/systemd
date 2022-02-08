/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "list.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "mmap-cache.h"
#include "sigbus.h"

typedef struct Window Window;
typedef struct Context Context;
typedef struct ContextCache ContextCache;
typedef struct Mapping Mapping;

struct Mapping {
        MMapFileDescriptor *fd;
        uint64_t offset;
        size_t size;
        void *ptr;
        bool keep_always:1;
};

struct Window {
        Mapping mapping; /* XXX: this must stay first member */

        MMapCache *cache;

        bool invalidated:1;
        bool in_unused:1;

        LIST_FIELDS(Window, by_fd);
        LIST_FIELDS(Window, unused);

        LIST_HEAD(Context, contexts);
};

struct Context {
        Mapping *mapping;

        LIST_FIELDS(Context, by_window);
};

struct ContextCache {
        Context contexts[MMAP_CACHE_MAX_CONTEXTS];
        unsigned n_context_cache_hit;
};

struct MMapFileDescriptor {
        MMapCache *cache;
        int fd;
        int prot;
        bool sigbus;
        LIST_HEAD(Window, windows);
};

struct MMapCache {
        unsigned n_ref;
        unsigned n_windows;

        unsigned n_window_list_hit, n_missed;

        Hashmap *fds;

        LIST_HEAD(Window, unused);
        Window *last_unused;

        ContextCache context_cache;
};

#define WINDOWS_MIN 64

#if ENABLE_DEBUG_MMAP_CACHE
/* Tiny windows increase mmap activity and the chance of exposing unsafe use. */
# define WINDOW_SIZE (page_size())
#else
# define WINDOW_SIZE (8ULL*1024ULL*1024ULL)
#endif

MMapCache* mmap_cache_new(void) {
        MMapCache *m;

        m = new0(MMapCache, 1);
        if (!m)
                return NULL;

        m->n_ref = 1;
        return m;
}

static void window_detach_contexts(Window *w) {
        Context *c;

        assert (w);

        LIST_FOREACH(by_window, c, w->contexts) {
                assert((Window *)c->mapping == w);
                c->mapping = NULL;
        }
}

static void window_unlink(Window *w) {
        assert(w);

        if (w->mapping.ptr)
                munmap(w->mapping.ptr, w->mapping.size);

        if (w->mapping.fd)
                LIST_REMOVE(by_fd, w->mapping.fd->windows, w);

        if (w->in_unused) {
                if (w->cache->last_unused == w)
                        w->cache->last_unused = w->unused_prev;

                LIST_REMOVE(unused, w->cache->unused, w);
        }

        window_detach_contexts(w);
}

static void window_invalidate(Window *w) {
        assert(w);
        assert(w->mapping.fd);

        if (w->invalidated)
                return;

        window_detach_contexts(w);

        /* Replace the window with anonymous pages. This is useful
         * when we hit a SIGBUS and want to make sure the file cannot
         * trigger any further SIGBUS, possibly overrunning the sigbus
         * queue. */

        assert_se(mmap(w->mapping.ptr, w->mapping.size, w->mapping.fd->prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == w->mapping.ptr);
        w->invalidated = true;
}

static void window_free(Window *w) {
        assert(w);

        window_unlink(w);
        w->cache->n_windows--;
        free(w);
}

_pure_ static inline bool mapping_matches(Mapping *m, uint64_t offset, size_t size) {
        assert(m);
        assert(size > 0);

        return
                offset >= m->offset &&
                offset + size <= m->offset + m->size;
}

_pure_ static bool mapping_matches_fd(Mapping *m, MMapFileDescriptor *f, uint64_t offset, size_t size) {
        assert(m);
        assert(f);

        return
                m->fd == f &&
                mapping_matches(m, offset, size);
}

_pure_ static bool window_matches(Window *w, uint64_t offset, size_t size) {
        return mapping_matches(&w->mapping, offset, size);
}

static Window *window_add(MMapCache *m, MMapFileDescriptor *f, bool keep_always, uint64_t offset, size_t size, void *ptr) {
        Window *w;

        assert(m);
        assert(f);

        if (!m->last_unused || m->n_windows <= WINDOWS_MIN) {

                /* Allocate a new window */
                w = new(Window, 1);
                if (!w)
                        return NULL;
                m->n_windows++;
        } else {

                /* Reuse an existing one */
                w = m->last_unused;
                window_unlink(w);
        }

        *w = (Window) {
                .cache = m,
                .mapping.fd = f,
                .mapping.offset = offset,
                .mapping.size = size,
                .mapping.ptr = ptr,
                .mapping.keep_always = keep_always,
        };

        LIST_PREPEND(by_fd, f->windows, w);

        return w;
}

static void context_detach_window(MMapCache *m, Context *c) {
        Window *w;

        assert(m);
        assert(c);

        if (!c->mapping)
                return;

        w = ((Window *)TAKE_PTR(c->mapping));
        LIST_REMOVE(by_window, w->contexts, c);

        if (!w->contexts && !w->mapping.keep_always) {
                /* Not used anymore? */
#if ENABLE_DEBUG_MMAP_CACHE
                /* Unmap unused windows immediately to expose use-after-unmap
                 * by SIGSEGV. */
                window_free(w);
#else
                LIST_PREPEND(unused, m->unused, w);
                if (!m->last_unused)
                        m->last_unused = w;

                w->in_unused = true;
#endif
        }
}

static void context_attach_window(MMapCache *m, Context *c, Window *w) {
        assert(m);
        assert(c);
        assert(w);

        if ((Window *)c->mapping == w)
                return;

        context_detach_window(m, c);

        if (w->in_unused) {
                /* Used again? */
                if (m->last_unused == w)
                        m->last_unused = w->unused_prev;
                LIST_REMOVE(unused, m->unused, w);

                w->in_unused = false;
        }

        c->mapping = (Mapping *)w;
        LIST_PREPEND(by_window, w->contexts, c);
}

static MMapCache *mmap_cache_free(MMapCache *m) {
        assert(m);

        for (int i = 0; i < MMAP_CACHE_MAX_CONTEXTS; i++)
                context_detach_window(m, &m->context_cache.contexts[i]);

        hashmap_free(m->fds);

        while (m->unused)
                window_free(m->unused);

        return mfree(m);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(MMapCache, mmap_cache, mmap_cache_free);

static int make_room(MMapCache *m) {
        assert(m);

        if (!m->last_unused)
                return 0;

        window_free(m->last_unused);
        return 1;
}

static int try_context(
                MMapFileDescriptor *f,
                Context *c,
                bool keep_always,
                uint64_t offset,
                size_t size,
                void **ret) {

        assert(f);
        assert(f->cache);
        assert(f->cache->n_ref > 0);
        assert(c);
        assert(size > 0);
        assert(ret);

        if (!c->mapping)
                return 0;

        if (!mapping_matches_fd(c->mapping, f, offset, size))
                return 0;

        c->mapping->keep_always = c->mapping->keep_always || keep_always;

        *ret = (uint8_t*) c->mapping->ptr + (offset - c->mapping->offset);
        f->cache->context_cache.n_context_cache_hit++;

        return 1;
}

static int find_mmap(
                MMapFileDescriptor *f,
                Context *c,
                bool keep_always,
                uint64_t offset,
                size_t size,
                void **ret) {

        Window *w;

        assert(f);
        assert(f->cache);
        assert(f->cache->n_ref > 0);
        assert(c);
        assert(size > 0);

        if (f->sigbus)
                return -EIO;

        LIST_FOREACH(by_fd, w, f->windows)
                if (window_matches(w, offset, size))
                        break;

        if (!w)
                return 0;

        context_attach_window(f->cache, c, w);
        w->mapping.keep_always = w->mapping.keep_always || keep_always;

        *ret = (uint8_t*) w->mapping.ptr + (offset - w->mapping.offset);
        f->cache->n_window_list_hit++;

        return 1;
}

static int mmap_try_harder(MMapFileDescriptor *f, void *addr, int flags, uint64_t offset, size_t size, void **res) {
        void *ptr;

        assert(f);
        assert(res);

        for (;;) {
                int r;

                ptr = mmap(addr, size, f->prot, flags, f->fd, offset);
                if (ptr != MAP_FAILED)
                        break;
                if (errno != ENOMEM)
                        return negative_errno();

                r = make_room(f->cache);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOMEM;
        }

        *res = ptr;
        return 0;
}

static int add_mmap(
                MMapFileDescriptor *f,
                Context *c,
                bool keep_always,
                uint64_t offset,
                size_t size,
                struct stat *st,
                void **ret) {

        uint64_t woffset, wsize;
        Window *w;
        void *d;
        int r;

        assert(f);
        assert(f->cache);
        assert(f->cache->n_ref > 0);
        assert(c);
        assert(size > 0);
        assert(ret);

        woffset = offset & ~((uint64_t) page_size() - 1ULL);
        wsize = size + (offset - woffset);
        wsize = PAGE_ALIGN(wsize);

        if (wsize < WINDOW_SIZE) {
                uint64_t delta;

                delta = PAGE_ALIGN((WINDOW_SIZE - wsize) / 2);

                if (delta > offset)
                        woffset = 0;
                else
                        woffset -= delta;

                wsize = WINDOW_SIZE;
        }

        if (st) {
                /* Memory maps that are larger then the files
                   underneath have undefined behavior. Hence, clamp
                   things to the file size if we know it */

                if (woffset >= (uint64_t) st->st_size)
                        return -EADDRNOTAVAIL;

                if (woffset + wsize > (uint64_t) st->st_size)
                        wsize = PAGE_ALIGN(st->st_size - woffset);
        }

        r = mmap_try_harder(f, NULL, MAP_SHARED, woffset, wsize, &d);
        if (r < 0)
                return r;

        w = window_add(f->cache, f, keep_always, woffset, wsize, d);
        if (!w)
                goto outofmem;

        context_attach_window(f->cache, c, w);

        *ret = (uint8_t*) w->mapping.ptr + (offset - w->mapping.offset);

        return 1;

outofmem:
        (void) munmap(d, wsize);
        return -ENOMEM;
}

int mmap_cache_fd_get(
                MMapFileDescriptor *f,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                struct stat *st,
                void **ret) {

        Context *c;
        int r;

        assert(f);
        assert(f->cache);
        assert(f->cache->n_ref > 0);
        assert(size > 0);
        assert(ret);
        assert(context < MMAP_CACHE_MAX_CONTEXTS);

        c = &f->cache->context_cache.contexts[context];

        /* Check whether the current context is the right one already */
        r = try_context(f, c, keep_always, offset, size, ret);
        if (r != 0)
                return r;

        /* Drop the reference to the window, since it's unnecessary now */
        context_detach_window(f->cache, c);

        /* Search for a matching mmap */
        r = find_mmap(f, c, keep_always, offset, size, ret);
        if (r != 0)
                return r;

        f->cache->n_missed++;

        /* Create a new mmap */
        return add_mmap(f, c, keep_always, offset, size, st, ret);
}

void mmap_cache_stats_log_debug(MMapCache *m) {
        assert(m);

        unsigned n_total_context_cache_hit = 0;

        /* TODO: sum per-fd context cache hits */

        log_debug("mmap cache statistics: %u context cache hit, %u window list hit, %u miss", n_total_context_cache_hit, m->n_window_list_hit, m->n_missed);
}

static void mmap_cache_process_sigbus(MMapCache *m) {
        bool found = false;
        MMapFileDescriptor *f;
        int r;

        assert(m);

        /* Iterate through all triggered pages and mark their files as
         * invalidated */
        for (;;) {
                bool ours;
                void *addr;

                r = sigbus_pop(&addr);
                if (_likely_(r == 0))
                        break;
                if (r < 0) {
                        log_error_errno(r, "SIGBUS handling failed: %m");
                        abort();
                }

                ours = false;
                HASHMAP_FOREACH(f, m->fds) {
                        Window *w;

                        LIST_FOREACH(by_fd, w, f->windows) {
                                if ((uint8_t*) addr >= (uint8_t*) w->mapping.ptr &&
                                    (uint8_t*) addr < (uint8_t*) w->mapping.ptr + w->mapping.size) {
                                        found = ours = f->sigbus = true;
                                        break;
                                }
                        }

                        if (ours)
                                break;
                }

                /* Didn't find a matching window, give up */
                if (!ours) {
                        log_error("Unknown SIGBUS page, aborting.");
                        abort();
                }
        }

        /* The list of triggered pages is now empty. Now, let's remap
         * all windows of the triggered file to anonymous maps, so
         * that no page of the file in question is triggered again, so
         * that we can be sure not to hit the queue size limit. */
        if (_likely_(!found))
                return;

        HASHMAP_FOREACH(f, m->fds) {
                Window *w;

                if (!f->sigbus)
                        continue;

                LIST_FOREACH(by_fd, w, f->windows)
                        window_invalidate(w);
        }
}

bool mmap_cache_fd_got_sigbus(MMapFileDescriptor *f) {
        assert(f);

        mmap_cache_process_sigbus(f->cache);

        return f->sigbus;
}

MMapFileDescriptor* mmap_cache_add_fd(MMapCache *m, int fd, int prot) {
        MMapFileDescriptor *f;
        int r;

        assert(m);
        assert(fd >= 0);

        f = hashmap_get(m->fds, FD_TO_PTR(fd));
        if (f)
                return f;

        r = hashmap_ensure_allocated(&m->fds, NULL);
        if (r < 0)
                return NULL;

        f = new0(MMapFileDescriptor, 1);
        if (!f)
                return NULL;

        r = hashmap_put(m->fds, FD_TO_PTR(fd), f);
        if (r < 0)
                return mfree(f);

        f->cache = mmap_cache_ref(m);
        f->fd = fd;
        f->prot = prot;

        return f;
}

void mmap_cache_fd_free(MMapFileDescriptor *f) {
        assert(f);
        assert(f->cache);

        /* Make sure that any queued SIGBUS are first dispatched, so
         * that we don't end up with a SIGBUS entry we cannot relate
         * to any existing memory map */

        mmap_cache_process_sigbus(f->cache);

        while (f->windows)
                window_free(f->windows);

        if (f->cache) {
                assert_se(hashmap_remove(f->cache->fds, FD_TO_PTR(f->fd)));
                f->cache = mmap_cache_unref(f->cache);
        }

        free(f);
}

MMapCache* mmap_cache_fd_cache(MMapFileDescriptor *f) {
        assert(f);

        return f->cache;
}
