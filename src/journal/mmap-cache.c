/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "list.h"
#include "log.h"
#include "macro.h"
#include "mmap-cache.h"
#include "sigbus.h"
#include "util.h"

typedef struct Window Window;
typedef struct Context Context;

struct Window {
        MMapCache *cache;

        bool invalidated:1;
        bool keep_always:1;
        bool in_unused:1;

        int prot;
        void *ptr;
        uint64_t offset;
        size_t size;

        MMapFileDescriptor *fd;

        LIST_FIELDS(Window, by_fd);
        LIST_FIELDS(Window, unused);

        LIST_HEAD(Context, contexts);
};

struct Context {
        MMapCache *cache;
        unsigned id;
        Window *window;

        LIST_FIELDS(Context, by_window);
};

struct MMapFileDescriptor {
        MMapCache *cache;
        int fd;
        bool sigbus;
        LIST_HEAD(Window, windows);
};

struct MMapCache {
        unsigned n_ref;
        unsigned n_windows;

        unsigned n_hit, n_missed;

        Hashmap *fds;
        Context *contexts[MMAP_CACHE_MAX_CONTEXTS];

        LIST_HEAD(Window, unused);
        Window *last_unused;
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

static void window_unlink(Window *w) {
        Context *c;

        assert(w);

        if (w->ptr)
                munmap(w->ptr, w->size);

        if (w->fd)
                LIST_REMOVE(by_fd, w->fd->windows, w);

        if (w->in_unused) {
                if (w->cache->last_unused == w)
                        w->cache->last_unused = w->unused_prev;

                LIST_REMOVE(unused, w->cache->unused, w);
        }

        LIST_FOREACH(by_window, c, w->contexts) {
                assert(c->window == w);
                c->window = NULL;
        }
}

static void window_invalidate(Window *w) {
        assert(w);

        if (w->invalidated)
                return;

        /* Replace the window with anonymous pages. This is useful
         * when we hit a SIGBUS and want to make sure the file cannot
         * trigger any further SIGBUS, possibly overrunning the sigbus
         * queue. */

        assert_se(mmap(w->ptr, w->size, w->prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == w->ptr);
        w->invalidated = true;
}

static void window_free(Window *w) {
        assert(w);

        window_unlink(w);
        w->cache->n_windows--;
        free(w);
}

_pure_ static inline bool window_matches(Window *w, int prot, uint64_t offset, size_t size) {
        assert(w);
        assert(size > 0);

        return
                prot == w->prot &&
                offset >= w->offset &&
                offset + size <= w->offset + w->size;
}

_pure_ static bool window_matches_fd(Window *w, MMapFileDescriptor *f, int prot, uint64_t offset, size_t size) {
        assert(w);
        assert(f);

        return
                w->fd &&
                f->fd == w->fd->fd &&
                window_matches(w, prot, offset, size);
}

static Window *window_add(MMapCache *m, MMapFileDescriptor *f, int prot, bool keep_always, uint64_t offset, size_t size, void *ptr) {
        Window *w;

        assert(m);
        assert(f);

        if (!m->last_unused || m->n_windows <= WINDOWS_MIN) {

                /* Allocate a new window */
                w = new0(Window, 1);
                if (!w)
                        return NULL;
                m->n_windows++;
        } else {

                /* Reuse an existing one */
                w = m->last_unused;
                window_unlink(w);
                zero(*w);
        }

        w->cache = m;
        w->fd = f;
        w->prot = prot;
        w->keep_always = keep_always;
        w->offset = offset;
        w->size = size;
        w->ptr = ptr;

        LIST_PREPEND(by_fd, f->windows, w);

        return w;
}

static void context_detach_window(Context *c) {
        Window *w;

        assert(c);

        if (!c->window)
                return;

        w = TAKE_PTR(c->window);
        LIST_REMOVE(by_window, w->contexts, c);

        if (!w->contexts && !w->keep_always) {
                /* Not used anymore? */
#if ENABLE_DEBUG_MMAP_CACHE
                /* Unmap unused windows immediately to expose use-after-unmap
                 * by SIGSEGV. */
                window_free(w);
#else
                LIST_PREPEND(unused, c->cache->unused, w);
                if (!c->cache->last_unused)
                        c->cache->last_unused = w;

                w->in_unused = true;
#endif
        }
}

static void context_attach_window(Context *c, Window *w) {
        assert(c);
        assert(w);

        if (c->window == w)
                return;

        context_detach_window(c);

        if (w->in_unused) {
                /* Used again? */
                LIST_REMOVE(unused, c->cache->unused, w);
                if (c->cache->last_unused == w)
                        c->cache->last_unused = w->unused_prev;

                w->in_unused = false;
        }

        c->window = w;
        LIST_PREPEND(by_window, w->contexts, c);
}

static Context *context_add(MMapCache *m, unsigned id) {
        Context *c;

        assert(m);

        c = m->contexts[id];
        if (c)
                return c;

        c = new0(Context, 1);
        if (!c)
                return NULL;

        c->cache = m;
        c->id = id;

        assert(!m->contexts[id]);
        m->contexts[id] = c;

        return c;
}

static void context_free(Context *c) {
        assert(c);

        context_detach_window(c);

        if (c->cache) {
                assert(c->cache->contexts[c->id] == c);
                c->cache->contexts[c->id] = NULL;
        }

        free(c);
}

static MMapCache *mmap_cache_free(MMapCache *m) {
        int i;

        assert(m);

        for (i = 0; i < MMAP_CACHE_MAX_CONTEXTS; i++)
                if (m->contexts[i])
                        context_free(m->contexts[i]);

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
                MMapCache *m,
                MMapFileDescriptor *f,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                void **ret,
                size_t *ret_size) {

        Context *c;

        assert(m);
        assert(m->n_ref > 0);
        assert(f);
        assert(size > 0);
        assert(ret);

        c = m->contexts[context];
        if (!c)
                return 0;

        assert(c->id == context);

        if (!c->window)
                return 0;

        if (!window_matches_fd(c->window, f, prot, offset, size)) {

                /* Drop the reference to the window, since it's unnecessary now */
                context_detach_window(c);
                return 0;
        }

        if (c->window->fd->sigbus)
                return -EIO;

        c->window->keep_always = c->window->keep_always || keep_always;

        *ret = (uint8_t*) c->window->ptr + (offset - c->window->offset);
        if (ret_size)
                *ret_size = c->window->size - (offset - c->window->offset);

        return 1;
}

static int find_mmap(
                MMapCache *m,
                MMapFileDescriptor *f,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                void **ret,
                size_t *ret_size) {

        Window *w;
        Context *c;

        assert(m);
        assert(m->n_ref > 0);
        assert(f);
        assert(size > 0);

        if (f->sigbus)
                return -EIO;

        LIST_FOREACH(by_fd, w, f->windows)
                if (window_matches(w, prot, offset, size))
                        break;

        if (!w)
                return 0;

        c = context_add(m, context);
        if (!c)
                return -ENOMEM;

        context_attach_window(c, w);
        w->keep_always = w->keep_always || keep_always;

        *ret = (uint8_t*) w->ptr + (offset - w->offset);
        if (ret_size)
                *ret_size = w->size - (offset - w->offset);

        return 1;
}

static int mmap_try_harder(MMapCache *m, void *addr, MMapFileDescriptor *f, int prot, int flags, uint64_t offset, size_t size, void **res) {
        void *ptr;

        assert(m);
        assert(f);
        assert(res);

        for (;;) {
                int r;

                ptr = mmap(addr, size, prot, flags, f->fd, offset);
                if (ptr != MAP_FAILED)
                        break;
                if (errno != ENOMEM)
                        return negative_errno();

                r = make_room(m);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOMEM;
        }

        *res = ptr;
        return 0;
}

static int add_mmap(
                MMapCache *m,
                MMapFileDescriptor *f,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                struct stat *st,
                void **ret,
                size_t *ret_size) {

        uint64_t woffset, wsize;
        Context *c;
        Window *w;
        void *d;
        int r;

        assert(m);
        assert(m->n_ref > 0);
        assert(f);
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

        r = mmap_try_harder(m, NULL, f, prot, MAP_SHARED, woffset, wsize, &d);
        if (r < 0)
                return r;

        c = context_add(m, context);
        if (!c)
                goto outofmem;

        w = window_add(m, f, prot, keep_always, woffset, wsize, d);
        if (!w)
                goto outofmem;

        context_attach_window(c, w);

        *ret = (uint8_t*) w->ptr + (offset - w->offset);
        if (ret_size)
                *ret_size = w->size - (offset - w->offset);

        return 1;

outofmem:
        (void) munmap(d, wsize);
        return -ENOMEM;
}

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
                size_t *ret_size) {

        int r;

        assert(m);
        assert(m->n_ref > 0);
        assert(f);
        assert(size > 0);
        assert(ret);
        assert(context < MMAP_CACHE_MAX_CONTEXTS);

        /* Check whether the current context is the right one already */
        r = try_context(m, f, prot, context, keep_always, offset, size, ret, ret_size);
        if (r != 0) {
                m->n_hit++;
                return r;
        }

        /* Search for a matching mmap */
        r = find_mmap(m, f, prot, context, keep_always, offset, size, ret, ret_size);
        if (r != 0) {
                m->n_hit++;
                return r;
        }

        m->n_missed++;

        /* Create a new mmap */
        return add_mmap(m, f, prot, context, keep_always, offset, size, st, ret, ret_size);
}

unsigned mmap_cache_get_hit(MMapCache *m) {
        assert(m);

        return m->n_hit;
}

unsigned mmap_cache_get_missed(MMapCache *m) {
        assert(m);

        return m->n_missed;
}

static void mmap_cache_process_sigbus(MMapCache *m) {
        bool found = false;
        MMapFileDescriptor *f;
        Iterator i;
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
                HASHMAP_FOREACH(f, m->fds, i) {
                        Window *w;

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

        HASHMAP_FOREACH(f, m->fds, i) {
                Window *w;

                if (!f->sigbus)
                        continue;

                LIST_FOREACH(by_fd, w, f->windows)
                        window_invalidate(w);
        }
}

bool mmap_cache_got_sigbus(MMapCache *m, MMapFileDescriptor *f) {
        assert(m);
        assert(f);

        mmap_cache_process_sigbus(m);

        return f->sigbus;
}

MMapFileDescriptor* mmap_cache_add_fd(MMapCache *m, int fd) {
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

        f->cache = m;
        f->fd = fd;

        r = hashmap_put(m->fds, FD_TO_PTR(fd), f);
        if (r < 0)
                return mfree(f);

        return f;
}

void mmap_cache_free_fd(MMapCache *m, MMapFileDescriptor *f) {
        assert(m);
        assert(f);

        /* Make sure that any queued SIGBUS are first dispatched, so
         * that we don't end up with a SIGBUS entry we cannot relate
         * to any existing memory map */

        mmap_cache_process_sigbus(m);

        while (f->windows)
                window_free(f->windows);

        if (f->cache)
                assert_se(hashmap_remove(f->cache->fds, FD_TO_PTR(f->fd)));

        free(f);
}
