/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"

#define MAKE_HASHMAP(s) ((Hashmap*) s)
#define MAKE_FDSET(s) ((FDSet*) s)

FDSet *fdset_new(void) {
        return MAKE_FDSET(hashmap_new(NULL));
}

static void fdset_shallow_freep(FDSet **s) {
        /* Destroys the set, but does not free the fds inside, like fdset_free()! */
        hashmap_free(MAKE_HASHMAP(*ASSERT_PTR(s)));
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

        while ((p = hashmap_steal_first(MAKE_HASHMAP(s)))) {
                int fd = PTR_TO_FD(p);

                if (fd < 0) /* This is an index, ignore it */
                        continue;

                /* Valgrind's fd might have ended up in this set here, due to fdset_new_fill(). We'll ignore
                 * all failures here, so that the EBADFD that valgrind will return us on close() doesn't
                 * influence us */

                /* When reloading duplicates of the private bus connection fds and suchlike are closed here,
                 * which has no effect at all, since they are only duplicates. So don't be surprised about
                 * these log messages. */

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *path = NULL;

                        (void) fd_get_path(fd, &path);
                        log_debug("Closing set fd %i (%s)", fd, strna(path));
                }

                (void) close_nointr(fd);
        }
}

FDSet* fdset_free(FDSet *s) {
        fdset_close(s);
        hashmap_free(MAKE_HASHMAP(s));
        return NULL;
}

int fdset_put(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        /* Avoid integer overflow in FD_TO_PTR() */
        if (fd == INT_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Refusing invalid fd: %d", fd);

        return hashmap_put(MAKE_HASHMAP(s), FD_TO_PTR(fd), FD_TO_PTR(fd));
}

int fdset_consume(FDSet *s, int fd) {
        int r;

        assert(s);
        assert(fd >= 0);

        r = fdset_put(s, fd);
        if (r < 0)
                safe_close(fd);

        return r;
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

        /* Avoid integer overflow in FD_TO_PTR() */
        if (fd == INT_MAX) {
                log_debug("Refusing invalid fd: %d", fd);
                return false;
        }

        return hashmap_contains(MAKE_HASHMAP(s), FD_TO_PTR(fd));
}

int fdset_remove(FDSet *s, int fd) {
        assert(s);

        /* Avoid integer overflow in FD_TO_PTR() */
        if (fd == INT_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Refusing invalid fd: %d", fd);

        void *raw = hashmap_remove(MAKE_HASHMAP(s), fd >= 0 ? FD_TO_PTR(fd) : INT_TO_PTR(fd));
        if (!raw)
                return -ENOENT;

        int ret = fd >= 0 ? PTR_TO_INT(raw) : PTR_TO_FD(raw);
        if (ret >= 0 && fd >= 0)
                return fd; /* No indexes (negative value), return immediately */

        if (fd >= 0)
                return hashmap_remove(MAKE_HASHMAP(s), INT_TO_PTR(ret)) ? fd : -ENOENT;

        return hashmap_remove(MAKE_HASHMAP(s), FD_TO_PTR(ret)) ? ret : -ENOENT;
}

int fdset_new_fill(
                int filter_cloexec, /* if < 0 takes all fds, otherwise only those with O_CLOEXEC set (1) or unset (0) */
                FDSet **ret) {
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
                int fd;

                if (!IN_SET(de->d_type, DT_LNK, DT_UNKNOWN))
                        continue;

                fd = parse_fd(de->d_name);
                if (fd < 0)
                        return fd;

                if (fd < 3)
                        continue;
                if (fd == dirfd(d))
                        continue;

                if (filter_cloexec >= 0) {
                        int fl;

                        /* If user asked for that filter by O_CLOEXEC. This is useful so that fds that have
                         * been passed in can be collected and fds which have been created locally can be
                         * ignored, under the assumption that only the latter have O_CLOEXEC set. */
                        fl = fcntl(fd, F_GETFD);
                        if (fl < 0)
                                return -errno;

                        if (FLAGS_SET(fl, FD_CLOEXEC) != !!filter_cloexec)
                                continue;
                }

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

        HASHMAP_FOREACH(p, MAKE_HASHMAP(fds)) {
                if (PTR_TO_FD(p) < 0)
                        continue;

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

static int to_array(FDSet *fds, bool indexed, int **ret) {
        _cleanup_free_ int *a = NULL;
        unsigned m, j = 0;

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

        for (size_t i = 0; i < m; ++i)
                a[i] = -EBADF;

        if (indexed) {
                void *k, *e;

                HASHMAP_FOREACH_KEY(e, k, MAKE_HASHMAP(fds)) {
                        int fd = PTR_TO_FD(k), index = -(1 + PTR_TO_INT(e));

                        if (fd < 0)
                                continue;

                        assert(index >= 0);
                        if (index >= m)
                                return -ERANGE;

                        a[index] = fd;
                        ++j;
                }
                assert(j == m / 2);
        } else {
                void *e;

                HASHMAP_FOREACH(e, MAKE_HASHMAP(fds))
                        a[j++] = PTR_TO_FD(e);

                assert(j == m);
        }

        *ret = TAKE_PTR(a);
        return (int) j;
}


int fdset_to_array(FDSet *fds, int **ret) {
        return to_array(fds, /* indexed= */ false, ret);
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
        return hashmap_size(MAKE_HASHMAP(fds));
}

bool fdset_isempty(FDSet *fds) {
        return hashmap_isempty(MAKE_HASHMAP(fds));
}

int fdset_iterate(FDSet *s, Iterator *i) {
        const void *k;
        void *v;

        if (!hashmap_iterate(MAKE_HASHMAP(s), i, &v, &k))
                return -ENOENT;

        return PTR_TO_FD(v);
}

int fdset_steal_first(FDSet *fds) {
        void *p;

        p = hashmap_steal_first(MAKE_HASHMAP(fds));
        if (!p)
                return -ENOENT;

        return PTR_TO_FD(p);
}
