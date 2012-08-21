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

#include <assert.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#include "mmap-cache.h"

#define WINDOW_SIZE (8ULL*1024ULL*1024ULL)

#define DEFAULT_WINDOWS_MAX 64
#define DEFAULT_FDS_MAX 32
#define DEFAULT_CONTEXTS_MAX 32

typedef struct Window {
        int fd;
        void *ptr;
        uint64_t offset;
        uint64_t size;

        unsigned n_ref;
        unsigned lru_prev;
        unsigned lru_next;

        unsigned by_fd_prev;
        unsigned by_fd_next;
} Window;

typedef struct FileDescriptor {
        int fd;
        unsigned windows;
} FileDescriptor;

struct MMapCache {
        unsigned n_ref;

        unsigned contexts_max;
        unsigned windows_max;
        unsigned fds_max;

        unsigned n_windows;
        unsigned n_fds;

        unsigned lru_first, lru_last;

        Window *windows;
        unsigned *by_context;
        FileDescriptor *by_fd;
};

static int mmap_cache_peek_fd_index(MMapCache *m, int fd, unsigned *fd_index);

static void mmap_cache_window_unmap(MMapCache *m, unsigned w) {
        Window *v;

        assert(m);
        assert(w < m->n_windows);

        v = m->windows + w;
        if (!v->ptr)
                return;

        munmap(v->ptr, v->size);
        v->ptr = NULL;
}

static void mmap_cache_window_add_lru(MMapCache *m, unsigned w) {
        Window *v;

        assert(m);
        assert(w < m->n_windows);

        v = m->windows + w;
        assert(v->n_ref == 0);

        if (m->lru_last != (unsigned) -1) {
                assert(m->windows[m->lru_last].lru_next == (unsigned) -1);
                m->windows[m->lru_last].lru_next = w;
        }

        v->lru_prev = m->lru_last;
        v->lru_next = (unsigned) -1;

        m->lru_last = w;
        if (m->lru_first == (unsigned) -1)
                m->lru_first = w;
}

static void mmap_cache_window_remove_lru(MMapCache *m, unsigned w) {
        Window *v;

        assert(m);
        assert(w < m->n_windows);

        v = m->windows + w;

        if (v->lru_prev == (unsigned) -1) {
                assert(m->lru_first == w);
                m->lru_first = v->lru_next;
        } else {
                assert(m->windows[v->lru_prev].lru_next == w);
                m->windows[v->lru_prev].lru_next = v->lru_next;
        }

        if (v->lru_next == (unsigned) -1) {
                assert(m->lru_last == w);
                m->lru_last = v->lru_prev;
        } else {
                assert(m->windows[v->lru_next].lru_prev == w);
                m->windows[v->lru_next].lru_prev = v->lru_prev;
        }
}

static void mmap_cache_fd_add(MMapCache *m, unsigned fd_index, unsigned w) {
        Window *v;

        assert(m);
        assert(fd_index < m->n_fds);

        v = m->windows + w;
        assert(m->by_fd[fd_index].fd == v->fd);

        if (m->by_fd[fd_index].windows != (unsigned) -1) {
                assert(m->windows[m->by_fd[fd_index].windows].by_fd_prev == (unsigned) -1);
                m->windows[m->by_fd[fd_index].windows].by_fd_prev = w;
        }

        v->by_fd_next = m->by_fd[fd_index].windows;
        v->by_fd_prev = (unsigned) -1;

        m->by_fd[fd_index].windows = w;
}

static void mmap_cache_fd_remove(MMapCache *m, unsigned fd_index, unsigned w) {
        Window *v;

        assert(m);
        assert(fd_index < m->n_fds);

        v = m->windows + w;
        assert(m->by_fd[fd_index].fd == v->fd);
        assert(v->by_fd_next == (unsigned) -1 || m->windows[v->by_fd_next].fd == v->fd);
        assert(v->by_fd_prev == (unsigned) -1 || m->windows[v->by_fd_prev].fd == v->fd);

        if (v->by_fd_prev == (unsigned) -1) {
                assert(m->by_fd[fd_index].windows == w);
                m->by_fd[fd_index].windows = v->by_fd_next;
        } else {
                assert(m->windows[v->by_fd_prev].by_fd_next == w);
                m->windows[v->by_fd_prev].by_fd_next = v->by_fd_next;
        }

        if (v->by_fd_next != (unsigned) -1) {
                assert(m->windows[v->by_fd_next].by_fd_prev == w);
                m->windows[v->by_fd_next].by_fd_prev = v->by_fd_prev;
        }
}

static void mmap_cache_context_unset(MMapCache *m, unsigned c) {
        Window *v;
        unsigned w;

        assert(m);
        assert(c < m->contexts_max);

        if (m->by_context[c] == (unsigned) -1)
                return;

        w = m->by_context[c];
        m->by_context[c] = (unsigned) -1;

        v = m->windows + w;
        assert(v->n_ref > 0);
        v->n_ref --;

        if (v->n_ref == 0)
                mmap_cache_window_add_lru(m, w);
}

static void mmap_cache_context_set(MMapCache *m, unsigned c, unsigned w) {
        Window *v;

        assert(m);
        assert(c < m->contexts_max);
        assert(w < m->n_windows);

        if (m->by_context[c] == w)
                return;

        mmap_cache_context_unset(m, c);

        m->by_context[c] = w;

        v = m->windows + w;
        v->n_ref ++;

        if (v->n_ref == 1)
                mmap_cache_window_remove_lru(m, w);
}

static void mmap_cache_free(MMapCache *m) {

        assert(m);

        if (m->windows) {
                unsigned w;

                for (w = 0; w < m->n_windows; w++)
                        mmap_cache_window_unmap(m, w);

                free(m->windows);
        }

        free(m->by_context);
        free(m->by_fd);
        free(m);
}

MMapCache* mmap_cache_new(void) {
        MMapCache *m;

        m = new0(MMapCache, 1);
        if (!m)
                return NULL;

        m->contexts_max = DEFAULT_CONTEXTS_MAX;
        m->fds_max = DEFAULT_FDS_MAX;
        m->windows_max = DEFAULT_WINDOWS_MAX;
        m->n_ref = 1;
        m->lru_first = (unsigned) -1;
        m->lru_last = (unsigned) -1;

        m->windows = new(Window, m->windows_max);
        if (!m->windows) {
                mmap_cache_free(m);
                return NULL;
        }

        m->by_context = new(unsigned, m->contexts_max);
        if (!m->by_context) {
                mmap_cache_free(m);
                return NULL;
        }
        memset(m->by_context, -1, m->contexts_max * sizeof(unsigned));

        m->by_fd = new(FileDescriptor, m->fds_max);
        if (!m->by_fd) {
                mmap_cache_free(m);
                return NULL;
        }

        return m;
}

MMapCache* mmap_cache_ref(MMapCache *m) {
        assert(m);
        assert(m->n_ref > 0);

        m->n_ref++;
        return m;
}

MMapCache* mmap_cache_unref(MMapCache *m) {
        assert(m);
        assert(m->n_ref > 0);

        if (m->n_ref == 1)
                mmap_cache_free(m);
        else
                m->n_ref--;

        return NULL;
}

static int mmap_cache_allocate_window(MMapCache *m, unsigned *w) {
        Window *v;
        unsigned fd_index;

        assert(m);
        assert(w);

        if (m->n_windows < m->windows_max) {
                *w = m->n_windows ++;
                return 0;
        }

        if (m->lru_first == (unsigned) -1)
                return -E2BIG;

        *w = m->lru_first;
        v = m->windows + *w;
        assert(v->n_ref == 0);

        mmap_cache_window_unmap(m, *w);

        if (v->fd >= 0) {
                assert_se(mmap_cache_peek_fd_index(m, v->fd, &fd_index) > 0);
                mmap_cache_fd_remove(m, fd_index, *w);
        }

        mmap_cache_window_remove_lru(m, *w);

        return 0;
}

static int mmap_cache_make_room(MMapCache *m) {
        unsigned w;

        assert(m);

        w = m->lru_first;
        while (w != (unsigned) -1) {
                Window *v;

                v = m->windows + w;
                assert(v->n_ref == 0);

                if (v->ptr) {
                        mmap_cache_window_unmap(m, w);
                        return 1;
                }

                w = v->lru_next;
        }

        return 0;
}

static int mmap_cache_put(
                MMapCache *m,
                int fd,
                unsigned fd_index,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                uint64_t size,
                struct stat *st,
                void **ret) {

        unsigned w;
        Window *v;
        void *d;
        uint64_t woffset, wsize;
        int r;

        assert(m);
        assert(fd >= 0);
        assert(context < m->contexts_max);
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
                   underneath have undefined behaviour. Hence, clamp
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

                r = mmap_cache_make_room(m);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOMEM;
        }

        r = mmap_cache_allocate_window(m, &w);
        if (r < 0) {
                munmap(d, wsize);
                return r;
        }

        v = m->windows + w;
        v->fd = fd;
        v->ptr = d;
        v->offset = woffset;
        v->size = wsize;

        if (keep_always)
                v->n_ref = 1;
        else {
                v->n_ref = 0;
                mmap_cache_window_add_lru(m, w);
        }

        mmap_cache_fd_add(m, fd_index, w);
        mmap_cache_context_set(m, context, w);

        *ret = (uint8_t*) d + (offset - woffset);
        return 1;
}

static int fd_cmp(const void *_a, const void *_b) {
        const FileDescriptor *a = _a, *b = _b;

        if (a->fd < b->fd)
                return -1;
        if (a->fd > b->fd)
                return 1;

        return 0;
}

static int mmap_cache_peek_fd_index(MMapCache *m, int fd, unsigned *fd_index) {
        FileDescriptor *j;
        unsigned r;

        assert(m);
        assert(fd >= 0);
        assert(fd_index);

        for (r = 0; r < m->n_fds; r++)
                assert(m->by_fd[r].windows == (unsigned) -1 ||
                       m->windows[m->by_fd[r].windows].fd == m->by_fd[r].fd);

        j = bsearch(&fd, m->by_fd, m->n_fds, sizeof(FileDescriptor), fd_cmp);
        if (!j)
                return 0;

        *fd_index = (unsigned) (j - m->by_fd);
        return 1;
}

static int mmap_cache_get_fd_index(MMapCache *m, int fd, unsigned *fd_index) {
        FileDescriptor *j;
        int r;

        assert(m);
        assert(fd >= 0);
        assert(fd_index);

        r = mmap_cache_peek_fd_index(m, fd, fd_index);
        if (r != 0)
                return r;

        if (m->n_fds >= m->fds_max) {
                unsigned k;
                FileDescriptor *n;

                k = m->n_fds * 2;
                n = realloc(m->by_fd, sizeof(FileDescriptor) * k);
                if (!n)
                        return -ENOMEM;

                m->fds_max = k;
                m->by_fd = n;
        }

        j = m->by_fd + m->n_fds ++;
        j->fd = fd;
        j->windows = (unsigned) -1;

        qsort(m->by_fd, m->n_fds, sizeof(FileDescriptor), fd_cmp);

        return mmap_cache_peek_fd_index(m, fd, fd_index);
}

static bool mmap_cache_test_window(
                MMapCache *m,
                unsigned w,
                uint64_t offset,
                uint64_t size) {
        Window *v;

        assert(m);
        assert(w < m->n_windows);
        assert(size > 0);

        v = m->windows + w;

        return offset >= v->offset &&
                offset + size <= v->offset + v->size;
}

static int mmap_cache_current(
                MMapCache *m,
                int fd,
                unsigned context,
                uint64_t offset,
                uint64_t size,
                void **ret) {

        Window *v;
        unsigned w;

        assert(m);
        assert(fd >= 0);
        assert(context < m->contexts_max);
        assert(size > 0);
        assert(ret);

        if (m->by_context[context] == (unsigned) -1)
                return 0;

        w = m->by_context[context];
        v = m->windows + w;

        if (v->fd != fd)
                return 0;

        if (!mmap_cache_test_window(m, w, offset, size))
                return 0;

        *ret = (uint8_t*) v->ptr + (offset - v->offset);
        return 1;
}

static int mmap_cache_find(
                MMapCache *m,
                int fd,
                unsigned fd_index,
                unsigned context,
                uint64_t offset,
                uint64_t size,
                void **ret) {

        Window *v = NULL;
        unsigned w;

        assert(m);
        assert(fd >= 0);
        assert(fd_index < m->n_fds);
        assert(context < m->contexts_max);
        assert(size > 0);
        assert(ret);

        w = m->by_fd[fd_index].windows;
        while (w != (unsigned) -1) {
                v = m->windows + w;
                assert(v->fd == fd);

                if (mmap_cache_test_window(m, w, offset, size))
                        break;

                w = v->by_fd_next;
        }

        if (w == (unsigned) -1)
                return 0;

        mmap_cache_context_set(m, context, w);

        *ret = (uint8_t*) v->ptr + (offset - v->offset);
        return 1;
}

int mmap_cache_get(
                MMapCache *m,
                int fd,
                int prot,
                unsigned context,
                bool keep_always,
                uint64_t offset,
                uint64_t size,
                struct stat *st,
                void **ret) {

        unsigned fd_index;
        int r;

        assert(m);
        assert(fd >= 0);
        assert(size > 0);
        assert(ret);

        if (context >= m->contexts_max) {
                unsigned k, *n;
                Window *w;

                /* Increase the number of contexts if necessary, and
                 * make sure we have twice the number of windows */

                k = context * 2;
                n = realloc(m->by_context, sizeof(unsigned) * k);
                if (!n)
                        return -ENOMEM;
                memset(n + m->contexts_max, -1, (k - m->contexts_max) * sizeof(unsigned));
                m->contexts_max = k;
                m->by_context = n;

                k = MAX(m->windows_max, m->contexts_max*2);
                w = realloc(m->windows, sizeof(Window) * k);
                if (!w)
                        return -ENOMEM;

                m->windows_max = k;
                m->windows = w;
        }

        /* Maybe the current pointer for this context is already the
         * right one? */
        r = mmap_cache_current(m, fd, context, offset, size, ret);
        if (r != 0)
                return r;

        /* Hmm, drop the reference to the current one, since it wasn't
         * good enough */
        mmap_cache_context_unset(m, context);

        /* OK, let's find the chain for this FD */
        r = mmap_cache_get_fd_index(m, fd, &fd_index);
        if (r < 0)
                return r;

        /* And let's look through the available mmaps */
        r = mmap_cache_find(m, fd, fd_index, context, offset, size, ret);
        if (r != 0)
                return r;

        /* Not found? Then, let's add it */
        return mmap_cache_put(m, fd, fd_index, prot, context, keep_always, offset, size, st, ret);
}

void mmap_cache_close_fd(MMapCache *m, int fd) {
        unsigned fd_index, c, w;
        int r;

        assert(m);
        assert(fd > 0);

        r = mmap_cache_peek_fd_index(m, fd, &fd_index);
        if (r <= 0)
                return;

        for (c = 0; c < m->contexts_max; c++) {
                w = m->by_context[c];
                if (w == (unsigned) -1)
                        continue;

                if (m->windows[w].fd == fd)
                        mmap_cache_context_unset(m, c);
        }

        w = m->by_fd[fd_index].windows;
        while (w != (unsigned) -1) {
                Window *v;

                v = m->windows + w;
                assert(v->fd == fd);

                mmap_cache_window_unmap(m, w);
                mmap_cache_fd_remove(m, fd_index, w);
                v->fd = -1;

                w = m->by_fd[fd_index].windows;
        }

        memmove(m->by_fd + fd_index, m->by_fd + fd_index + 1, (m->n_fds - (fd_index + 1)) * sizeof(FileDescriptor));
        m->n_fds --;
}

void mmap_cache_close_context(MMapCache *m, unsigned context) {
        mmap_cache_context_unset(m, context);
}
