/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "hashmap.h"
#include "list.h"
#include "log.h"
#include "util.h"
#include "macro.h"
#include "sigbus.h"
#include "mmap-cache.h"

typedef struct Window Window;
typedef struct Context Context;
typedef struct FileDescriptor FileDescriptor;

struct Window {
        MMapCache *cache;

        bool invalidated;
        bool keep_always;
        bool in_unused;

        int prot;
        void *ptr;
        uint64_t offset;
        size_t size;

        FileDescriptor *fd;

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

struct FileDescriptor {
        MMapCache *cache;
        int fd;
        bool sigbus;
        LIST_HEAD(Window, windows);
};

struct MMapCache {
        int n_ref;
        unsigned n_windows;

        unsigned n_hit, n_missed;


        Hashmap *fds;
        Context *contexts[MMAP_CACHE_MAX_CONTEXTS];

        LIST_HEAD(Window, unused);
        Window *last_unused;
};

#define WINDOWS_MIN 64

#ifdef ENABLE_DEBUG_MMAP_CACHE
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

MMapCache* mmap_cache_ref(MMapCache *m) {
        assert(m);
        assert(m->n_ref > 0);

        m->n_ref ++;
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

_pure_ static bool window_matches(Window *w, int fd, int prot, uint64_t offset, size_t size) {
        assert(w);
        assert(fd >= 0);
        assert(size > 0);

        return
                w->fd &&
                fd == w->fd->fd &&
                prot == w->prot &&
                offset >= w->offset &&
                offset + size <= w->offset + w->size;
}

static Window *window_add(MMapCache *m) {
        Window *w;

        assert(m);

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
        return w;
}

static void context_detach_window(Context *c) {
        Window *w;

        assert(c);

        if (!c->window)
                return;

        w = c->window;
        c->window = NULL;
        LIST_REMOVE(by_window, w->contexts, c);

        if (!w->contexts && !w->keep_always) {
                /* Not used anymore? */
#ifdef ENABLE_DEBUG_MMAP_CACHE
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

static void fd_free(FileDescriptor *f) {
        assert(f);

        while (f->windows)
                window_free(f->windows);

        if (f->cache)
                assert_se(hashmap_remove(f->cache->fds, INT_TO_PTR(f->fd + 1)));

        free(f);
}

static FileDescriptor* fd_add(MMapCache *m, int fd) {
        FileDescriptor *f;
        int r;

        assert(m);
        assert(fd >= 0);

        f = hashmap_get(m->fds, INT_TO_PTR(fd + 1));
        if (f)
                return f;

        r = hashmap_ensure_allocated(&m->fds, NULL);
        if (r < 0)
                return NULL;

        f = new0(FileDescriptor, 1);
        if (!f)
                return NULL;

        f->cache = m;
        f->fd = fd;

        r = hashmap_put(m->fds, UINT_TO_PTR(fd + 1), f);
        if (r < 0) {
                free(f);
                return NULL;
        }

        return f;
}

static void mmap_cache_free(MMapCache *m) {
        FileDescriptor *f;
        int i;

        assert(m);

        for (i = 0; i < MMAP_CACHE_MAX_CONTEXTS; i++)
                if (m->contexts[i])
                        context_free(m->contexts[i]);

        while ((f = hashmap_first(m->fds)))
                fd_free(f);

        hashmap_free(m->fds);

        while (m->unused)
                window_free(m->unused);

        free(m);
}

MMapCache* mmap_cache_unref(MMapCache *m) {
        assert(m);
        assert(m->n_ref > 0);

        m->n_ref --;
        if (m->n_ref == 0)
                mmap_cache_free(m);

        return NULL;
}

static int make_room(MMapCache *m) {
        assert(m);

        if (!m->last_unused)
                return 0;

        window_free(m->last_unused);
        return 1;
}

static int try_context(
                MMapCache *m,
                int fd,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                void **ret) {

        Context *c;

        assert(m);
        assert(m->n_ref > 0);
        assert(fd >= 0);
        assert(size > 0);
        assert(ret);

        c = m->contexts[context];
        if (!c)
                return 0;

        assert(c->id == context);

        if (!c->window)
                return 0;

        if (!window_matches(c->window, fd, prot, offset, size)) {

                /* Drop the reference to the window, since it's unnecessary now */
                context_detach_window(c);
                return 0;
        }

        if (c->window->fd->sigbus)
                return -EIO;

        c->window->keep_always |= keep_always;

        *ret = (uint8_t*) c->window->ptr + (offset - c->window->offset);
        return 1;
}

static int find_mmap(
                MMapCache *m,
                int fd,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                void **ret) {

        FileDescriptor *f;
        Window *w;
        Context *c;

        assert(m);
        assert(m->n_ref > 0);
        assert(fd >= 0);
        assert(size > 0);

        f = hashmap_get(m->fds, INT_TO_PTR(fd + 1));
        if (!f)
                return 0;

        assert(f->fd == fd);

        if (f->sigbus)
                return -EIO;

        LIST_FOREACH(by_fd, w, f->windows)
                if (window_matches(w, fd, prot, offset, size))
                        break;

        if (!w)
                return 0;

        c = context_add(m, context);
        if (!c)
                return -ENOMEM;

        context_attach_window(c, w);
        w->keep_always += keep_always;

        *ret = (uint8_t*) w->ptr + (offset - w->offset);
        return 1;
}

static int add_mmap(
                MMapCache *m,
                int fd,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                struct stat *st,
                void **ret) {

        uint64_t woffset, wsize;
        Context *c;
        FileDescriptor *f;
        Window *w;
        void *d;
        int r;

        assert(m);
        assert(m->n_ref > 0);
        assert(fd >= 0);
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

        for (;;) {
                d = mmap(NULL, wsize, prot, MAP_SHARED, fd, woffset);
                if (d != MAP_FAILED)
                        break;
                if (errno != ENOMEM)
                        return -errno;

                r = make_room(m);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOMEM;
        }

        c = context_add(m, context);
        if (!c)
                goto outofmem;

        f = fd_add(m, fd);
        if (!f)
                goto outofmem;

        w = window_add(m);
        if (!w)
                goto outofmem;

        w->keep_always = keep_always;
        w->ptr = d;
        w->offset = woffset;
        w->prot = prot;
        w->size = wsize;
        w->fd = f;

        LIST_PREPEND(by_fd, f->windows, w);

        context_detach_window(c);
        c->window = w;
        LIST_PREPEND(by_window, w->contexts, c);

        *ret = (uint8_t*) w->ptr + (offset - w->offset);
        return 1;

outofmem:
        munmap(d, wsize);
        return -ENOMEM;
}

int mmap_cache_get(
                MMapCache *m,
                int fd,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                size_t size,
                struct stat *st,
                void **ret) {

        int r;

        assert(m);
        assert(m->n_ref > 0);
        assert(fd >= 0);
        assert(size > 0);
        assert(ret);
        assert(context < MMAP_CACHE_MAX_CONTEXTS);

        /* Check whether the current context is the right one already */
        r = try_context(m, fd, prot, context, keep_always, offset, size, ret);
        if (r != 0) {
                m->n_hit ++;
                return r;
        }

        /* Search for a matching mmap */
        r = find_mmap(m, fd, prot, context, keep_always, offset, size, ret);
        if (r != 0) {
                m->n_hit ++;
                return r;
        }

        m->n_missed++;

        /* Create a new mmap */
        return add_mmap(m, fd, prot, context, keep_always, offset, size, st, ret);
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
        FileDescriptor *f;
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

bool mmap_cache_got_sigbus(MMapCache *m, int fd) {
        FileDescriptor *f;

        assert(m);
        assert(fd >= 0);

        mmap_cache_process_sigbus(m);

        f = hashmap_get(m->fds, INT_TO_PTR(fd + 1));
        if (!f)
                return false;

        return f->sigbus;
}

void mmap_cache_close_fd(MMapCache *m, int fd) {
        FileDescriptor *f;

        assert(m);
        assert(fd >= 0);

        /* Make sure that any queued SIGBUS are first dispatched, so
         * that we don't end up with a SIGBUS entry we cannot relate
         * to any existing memory map */

        mmap_cache_process_sigbus(m);

        f = hashmap_get(m->fds, INT_TO_PTR(fd + 1));
        if (!f)
                return;

        fd_free(f);
}
