/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "set.h"
#include "stat-util.h"

#define MAKE_SET(s) ((Set*) s)
#define MAKE_FDSET(s) ((FDSet*) s)

FDSet *fdset_new(void) {
        return MAKE_FDSET(set_new(NULL));
}

static inline void fdset_shallow_freep(FDSet **s) {
        /* Destroys the set, but does not free the fds inside, like fdset_free()! */
        set_free(MAKE_SET(*ASSERT_PTR(s)));
}

int fdset_new_array(FDSet **ret, const int fds[], size_t n_fds) {
        _cleanup_(fdset_shallow_freep) FDSet *s = NULL;
        int r;

        assert(ret);
        assert(fds || n_fds == 0);

        s = fdset_new();
        if (!s)
                return -ENOMEM;

        for (size_t i = 0; i < n_fds; i++) {
                r = fdset_put(s, fds[i]);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

void fdset_close(FDSet *s) {
        void *p;

        while ((p = set_steal_first(MAKE_SET(s)))) {
                /* Valgrind's fd might have ended up in this set here, due to fdset_new_fill(). We'll ignore
                 * all failures here, so that the EBADFD that valgrind will return us on close() doesn't
                 * influence us */

                /* When reloading duplicates of the private bus connection fds and suchlike are closed here,
                 * which has no effect at all, since they are only duplicates. So don't be surprised about
                 * these log messages. */

                log_debug("Closing set fd %i", PTR_TO_FD(p));
                (void) close_nointr(PTR_TO_FD(p));
        }
}

FDSet* fdset_free(FDSet *s) {
        fdset_close(s);
        set_free(MAKE_SET(s));
        return NULL;
}

int fdset_put(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        return set_put(MAKE_SET(s), FD_TO_PTR(fd));
}

int fdset_put_dup(FDSet *s, int fd) {
        _cleanup_close_ int copy = -EBADF;
        int r;

        assert(s);
        assert(fd >= 0);

        copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        r = fdset_put(s, copy);
        if (r < 0)
                return r;

        return TAKE_FD(copy);
}

bool fdset_contains(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        return !!set_get(MAKE_SET(s), FD_TO_PTR(fd));
}

int fdset_remove(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        return set_remove(MAKE_SET(s), FD_TO_PTR(fd)) ? fd : -ENOENT;
}

int fdset_new_fill(FDSet **ret) {
        _cleanup_(fdset_shallow_freep) FDSet *s = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(ret);

        /* Creates an fdset and fills in all currently open file descriptors. */

        d = opendir("/proc/self/fd");
        if (!d) {
                if (errno == ENOENT && proc_mounted() == 0)
                        return -ENOSYS;

                return -errno;
        }

        s = fdset_new();
        if (!s)
                return -ENOMEM;

        FOREACH_DIRENT(de, d, return -errno) {
                int fd = -EBADF;

                r = safe_atoi(de->d_name, &fd);
                if (r < 0)
                        return r;

                if (fd < 3)
                        continue;
                if (fd == dirfd(d))
                        continue;

                r = fdset_put(s, fd);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

int fdset_cloexec(FDSet *fds, bool b) {
        void *p;
        int r;

        assert(fds);

        SET_FOREACH(p, MAKE_SET(fds)) {
                r = fd_cloexec(PTR_TO_FD(p), b);
                if (r < 0)
                        return r;
        }

        return 0;
}

int fdset_new_listen_fds(FDSet **ret, bool unset) {
        _cleanup_(fdset_shallow_freep) FDSet *s = NULL;
        int n, fd, r;

        assert(ret);

        /* Creates an fdset and fills in all passed file descriptors */

        s = fdset_new();
        if (!s)
                return -ENOMEM;

        n = sd_listen_fds(unset);
        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd ++) {
                r = fdset_put(s, fd);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

int fdset_to_array(FDSet *fds, int **ret) {
        unsigned j = 0, m;
        void *e;
        int *a;

        assert(ret);

        m = fdset_size(fds);
        if (m > INT_MAX) /* We want to be able to return an "int" */
                return -ENOMEM;
        if (m == 0) {
                *ret = NULL; /* suppress array allocation if empty */
                return 0;
        }

        a = new(int, m);
        if (!a)
                return -ENOMEM;

        SET_FOREACH(e, MAKE_SET(fds))
                a[j++] = PTR_TO_FD(e);

        assert(j == m);

        *ret = TAKE_PTR(a);
        return (int) m;
}

int fdset_close_others(FDSet *fds) {
        _cleanup_free_ int *a = NULL;
        int n;

        n = fdset_to_array(fds, &a);
        if (n < 0)
                return n;

        return close_all_fds(a, n);
}

unsigned fdset_size(FDSet *fds) {
        return set_size(MAKE_SET(fds));
}

bool fdset_isempty(FDSet *fds) {
        return set_isempty(MAKE_SET(fds));
}

int fdset_iterate(FDSet *s, Iterator *i) {
        void *p;

        if (!set_iterate(MAKE_SET(s), i, &p))
                return -ENOENT;

        return PTR_TO_FD(p);
}

int fdset_steal_first(FDSet *fds) {
        void *p;

        p = set_steal_first(MAKE_SET(fds));
        if (!p)
                return -ENOENT;

        return PTR_TO_FD(p);
}
