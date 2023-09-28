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

struct Window {
        MMapCache *cache;

        bool invalidated:1;
        bool keep_always:1;
        bool in_unused:1;

        void *ptr;
        uint64_t offset;
        size_t size;

        MMapFileDescriptor *fd;

        LIST_FIELDS(Window, by_fd);
        LIST_FIELDS(Window, unused);

        LIST_HEAD(Context, contexts);
};

struct Context {
        Window *window;

        LIST_FIELDS(Context, by_window);
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

        unsigned n_context_cache_hit;
        unsigned n_window_list_hit;
        unsigned n_missed;

        Hashmap *fds;

        LIST_HEAD(Window, unused);
        Window *last_unused;

        Context contexts[MMAP_CACHE_MAX_CONTEXTS];
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

        m = new(MMapCache, 1);
        if (!m)
                return NULL;

        *m = (MMapCache) {
                .n_ref = 1,
        };

        return m;
}

static Window* window_unlink(Window *w) {
        assert(w);

        MMapCache *m = mmap_cache_fd_cache(w->fd);

        if (w->ptr)
                munmap(w->ptr, w->size);

        if (w->in_unused) {
                if (m->last_unused == w)
                        m->last_unused = w->unused_prev;

                LIST_REMOVE(unused, m->unused, w);
        }

        LIST_FOREACH(by_window, c, w->contexts) {
                assert(c->window == w);
                c->window = NULL;
        }

        return LIST_REMOVE(by_fd, w->fd->windows, w);
}

static void window_invalidate(Window *w) {
        assert(w);
        assert(w->fd);

        if (w->invalidated)
                return;

        /* Replace the window with anonymous pages. This is useful when we hit a SIGBUS and want to make sure
         * the file cannot trigger any further SIGBUS, possibly overrunning the sigbus queue. */

        assert_se(mmap(w->ptr, w->size, w->fd->prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == w->ptr);
        w->invalidated = true;
}

static Window* window_free(Window *w) {
        if (!w)
                return NULL;

        window_unlink(w);
        w->cache->n_windows--;

        return mfree(w);
}

static bool window_matches(Window *w, uint64_t offset, size_t size) {
        assert(w);
        assert(size > 0);

        return
                offset >= w->offset &&
                offset + size <= w->offset + w->size;
}

static bool window_matches_fd(Window *w, MMapFileDescriptor *f, uint64_t offset, size_t size) {
        assert(w);
        assert(f);

        return
                w->fd == f &&
                window_matches(w, offset, size);
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
        } else
                /* Reuse an existing one */
                w = window_unlink(m->last_unused);

        *w = (Window) {
                .cache = m,
                .fd = f,
                .keep_always = keep_always,
                .offset = offset,
                .size = size,
                .ptr = ptr,
        };

        LIST_PREPEND(by_fd, f->windows, w);

        return w;
}

static void context_detach_window(MMapCache *m, Context *c) {
        Window *w;

        assert(m);
        assert(c);

        if (!c->window)
                return;

        w = TAKE_PTR(c->window);
        LIST_REMOVE(by_window, w->contexts, c);

        if (!w->contexts && !w->keep_always) {
                /* Not used anymore? */
#if ENABLE_DEBUG_MMAP_CACHE
                /* Unmap unused windows immediately to expose use-after-unmap by SIGSEGV. */
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

        if (c->window == w)
                return;

        context_detach_window(m, c);

        if (w->in_unused) {
                /* Used again? */
                if (m->last_unused == w)
                        m->last_unused = w->unused_prev;
                LIST_REMOVE(unused, m->unused, w);

                w->in_unused = false;
        }

        c->window = w;
        LIST_PREPEND(by_window, w->contexts, c);
}

static MMapCache* mmap_cache_free(MMapCache *m) {
        if (!m)
                return NULL;

        /* All windows are owned by fds, and each fd takes a reference of MMapCache. So, when this is called,
         * all fds are already freed, and hence there is no window. */

        assert(hashmap_isempty(m->fds));
        hashmap_free(m->fds);

        assert(!m->unused);
        assert(m->n_windows == 0);

        return mfree(m);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(MMapCache, mmap_cache, mmap_cache_free);

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

        if (!c->window)
                return 0;

        if (!window_matches_fd(c->window, f, offset, size)) {

                /* Drop the reference to the window, since it's unnecessary now */
                context_detach_window(f->cache, c);
                return 0;
        }

        if (c->window->fd->sigbus)
                return -EIO;

        c->window->keep_always = c->window->keep_always || keep_always;

        *ret = (uint8_t*) c->window->ptr + (offset - c->window->offset);
        f->cache->n_context_cache_hit++;

        return 1;
}

static int find_mmap(
                MMapFileDescriptor *f,
                Context *c,
                bool keep_always,
                uint64_t offset,
                size_t size,
                void **ret) {

        Window *found = NULL;

        assert(f);
        assert(f->cache);
        assert(f->cache->n_ref > 0);
        assert(c);
        assert(size > 0);

        if (f->sigbus)
                return -EIO;

        LIST_FOREACH(by_fd, w, f->windows)
                if (window_matches(w, offset, size)) {
                        found = w;
                        break;
                }

        if (!found)
                return 0;

        context_attach_window(f->cache, c, found);
        found->keep_always = found->keep_always || keep_always;

        *ret = (uint8_t*) found->ptr + (offset - found->offset);
        f->cache->n_window_list_hit++;

        return 1;
}

static int mmap_try_harder(MMapFileDescriptor *f, void *addr, int flags, uint64_t offset, size_t size, void **ret) {
        MMapCache *m = mmap_cache_fd_cache(f);

        assert(ret);

        for (;;) {
                void *ptr;

                ptr = mmap(addr, size, f->prot, flags, f->fd, offset);
                if (ptr != MAP_FAILED) {
                        *ret = ptr;
                        return 0;
                }
                if (errno != ENOMEM)
                        return negative_errno();

                /* When failed with ENOMEM, try again after making a room by freeing an unused window. */

                if (!m->last_unused)
                        return -ENOMEM; /* no free window, propagate the original error. */

                window_free(m->last_unused);
        }
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
                /* Memory maps that are larger then the files underneath have undefined behavior. Hence,
                 * clamp things to the file size if we know it */

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

        *ret = (uint8_t*) w->ptr + (offset - w->offset);

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

        c = &f->cache->contexts[context];

        /* Check whether the current context is the right one already */
        r = try_context(f, c, keep_always, offset, size, ret);
        if (r != 0)
                return r;

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

        log_debug("mmap cache statistics: %u context cache hit, %u window list hit, %u miss",
                  m->n_context_cache_hit, m->n_window_list_hit, m->n_missed);
}

static void mmap_cache_process_sigbus(MMapCache *m) {
        bool found = false;
        MMapFileDescriptor *f;
        int r;

        assert(m);

        /* Iterate through all triggered pages and mark their files as invalidated. */
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
                        LIST_FOREACH(by_fd, w, f->windows) {
                                if ((uint8_t*) addr >= (uint8_t*) w->ptr &&
                                    (uint8_t*) addr < (uint8_t*) w->ptr + w->size) {
                                        found = ours = f->sigbus = true;
                                        break;
                                }
                        }

                        if (ours)
                                break;
                }

                /* Didn't find a matching window, give up. */
                if (!ours) {
                        log_error("Unknown SIGBUS page, aborting.");
                        abort();
                }
        }

        /* The list of triggered pages is now empty. Now, let's remap all windows of the triggered file to
         * anonymous maps, so that no page of the file in question is triggered again, so that we can be sure
         * not to hit the queue size limit. */
        if (_likely_(!found))
                return;

        HASHMAP_FOREACH(f, m->fds) {
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

int mmap_cache_add_fd(MMapCache *m, int fd, int prot, MMapFileDescriptor **ret) {
        _cleanup_free_ MMapFileDescriptor *f = NULL;
        MMapFileDescriptor *existing;
        int r;

        assert(m);
        assert(fd >= 0);

        existing = hashmap_get(m->fds, FD_TO_PTR(fd));
        if (existing) {
                if (existing->prot != prot)
                        return -EEXIST;
                if (ret)
                        *ret = existing;
                return 0;
        }

        f = new(MMapFileDescriptor, 1);
        if (!f)
                return -ENOMEM;

        *f = (MMapFileDescriptor) {
                .fd = fd,
                .prot = prot,
        };

        r = hashmap_ensure_put(&m->fds, NULL, FD_TO_PTR(fd), f);
        if (r < 0)
                return r;
        assert(r > 0);

        f->cache = mmap_cache_ref(m);

        if (ret)
                *ret = f;

        TAKE_PTR(f);
        return 1;
}

MMapFileDescriptor* mmap_cache_fd_free(MMapFileDescriptor *f) {
        if (!f)
                return NULL;

        /* Make sure that any queued SIGBUS are first dispatched, so that we don't end up with a SIGBUS entry
         * we cannot relate to any existing memory map. */

        mmap_cache_process_sigbus(f->cache);

        while (f->windows)
                window_free(f->windows);

        assert_se(hashmap_remove(f->cache->fds, FD_TO_PTR(f->fd)) == f);

        /* Unref the cache at the end. Otherwise, the assertions in mmap_cache_free() may be triggered. */
        f->cache = mmap_cache_unref(f->cache);

        return mfree(f);
}

MMapCache* mmap_cache_fd_cache(MMapFileDescriptor *f) {
        assert(f);
        return ASSERT_PTR(f->cache);
}
