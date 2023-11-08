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

/* FDs can be stored in two modes: simply by value, or also by index. The latter is useful when sending
 * arrays over SCM_RIGHTS, and is implemented by storing each FD both as key, with the index as value,
 * and viceversa. To distinguish indexes from FDs, indexes will be stored as negative integers, since FDs
 * are always >=0. */

#define MAKE_HASHMAP(s) ((Hashmap*) s)
#define MAKE_FDSET(s) ((FDSet*) s)
#define FD_INDEX_TO_PTR(i) INT_TO_PTR(-(i) - 1)
#define PTR_TO_FD_INDEX(p) (-(PTR_TO_INT(p) + 1))
#define PTR_IS_FD_INDEX(p) (PTR_TO_INT(p) < 0)

static bool fdset_is_indexed(FDSet *s) {
        if (hashmap_size(MAKE_HASHMAP(s)) == 0)
                return false;

        void *p = hashmap_first(MAKE_HASHMAP(s));
        if (PTR_IS_FD_INDEX(p))
                return true;

        return PTR_IS_FD_INDEX(hashmap_get(MAKE_HASHMAP(s), p));
}

FDSet *fdset_new(void) {
        return MAKE_FDSET(hashmap_new(NULL));
}

static void fdset_shallow_freep(FDSet **s) {
        /* Destroys the set, but does not free the fds inside, like fdset_free()! */
        hashmap_free(MAKE_HASHMAP(*ASSERT_PTR(s)));
}

static int new_array(FDSet **ret, const int fds[], size_t n_fds, bool indexed) {
        _cleanup_(fdset_shallow_freep) FDSet *s = NULL;
        int r;

        assert(ret);
        assert(fds || n_fds == 0);

        s = fdset_new();
        if (!s)
                return -ENOMEM;

        for (size_t i = 0; i < n_fds; i++) {
                if (indexed)
                        r = fdset_put_indexed(s, fds[i], i);
                else
                        r = fdset_put(s, fds[i]);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

int fdset_new_array(FDSet **ret, const int fds[], size_t n_fds) {
        return new_array(ret, fds, n_fds, /* indexed= */ false);
}

int fdset_new_array_indexed(FDSet **ret, const int fds[], size_t n_fds) {
        return new_array(ret, fds, n_fds, /* indexed= */ true);
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

int fdset_put_indexed(FDSet *s, int fd, int index) {
        int r;

        assert(s);
        assert(fd >= 0);

        if (index < 0) /* Automatically append at the end of the range */
                index = fdset_size(s);

        /* Avoid integer overflow in FD_TO_PTR() */
        if (fd == INT_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Refusing invalid fd: %d", fd);

        if (hashmap_contains(MAKE_HASHMAP(s), FD_INDEX_TO_PTR(index)))
                return -EEXIST;

        if (hashmap_contains(MAKE_HASHMAP(s), FD_TO_PTR(fd)))
                return -EEXIST;

        /* Store both the fd and the index, so that either can be used for lookups. Store the index as
         * a negative number, so that we know there can be no overlap, since a fd must be >= 0. */

        r = hashmap_put(MAKE_HASHMAP(s), FD_TO_PTR(fd), FD_INDEX_TO_PTR(index));
        if (r < 0)
                return r;

        r = hashmap_put(MAKE_HASHMAP(s), FD_INDEX_TO_PTR(index), FD_TO_PTR(fd));
        if (r < 0) {
                (void) hashmap_remove(MAKE_HASHMAP(s), FD_TO_PTR(fd));
                return r;
        }

        return index;
}

int fdset_put_dup_indexed(FDSet *s, int fd, int index) {
        _cleanup_close_ int copy = -EBADF;
        int r;

        assert(s);
        assert(fd >= 0);

        copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        r = fdset_put_indexed(s, copy, index);
        if (r < 0)
                return r;

        TAKE_FD(copy);
        return r;
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

bool fdset_contains_index(FDSet *s, int index) {
        assert(s);
        assert(index >= 0);

        return hashmap_contains(MAKE_HASHMAP(s), FD_INDEX_TO_PTR(index));
}

int fdset_remove(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        /* Avoid integer overflow in FD_TO_PTR() */
        if (fd == INT_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Refusing invalid fd: %d", fd);

        void *raw = hashmap_remove(MAKE_HASHMAP(s), FD_TO_PTR(fd));
        if (!raw)
                return -ENOENT;

        int ret = PTR_TO_INT(raw);
        if (ret >= 0)
                return fd; /* No indexes (negative value), return immediately */

        return hashmap_remove(MAKE_HASHMAP(s), raw) ? fd : -ENOENT;
}

int fdset_remove_indexed(FDSet *s, int index) {
        _cleanup_close_ int fd = -EBADF;

        assert(s);
        assert(index >= 0);

        /* First, remove the index -> fd entry */
        void *raw = hashmap_remove(MAKE_HASHMAP(s), FD_INDEX_TO_PTR(index));
        if (!raw)
                return -ENOENT;

        fd = PTR_TO_FD(raw);

        /* Now remove the fd -> index entry */
        return hashmap_remove(MAKE_HASHMAP(s), raw) ? TAKE_FD(fd) : -ENOENT;
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

int fdset_to_array(FDSet *fds, int **ret) {
        _cleanup_free_ int *a = NULL;
        size_t m, j = 0;

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

        if (fdset_is_indexed(fds)) {
                void *k, *e;

                HASHMAP_FOREACH_KEY(e, k, MAKE_HASHMAP(fds)) {
                        int fd = PTR_TO_FD(k), index = PTR_TO_FD_INDEX(e);

                        if (fd < 0)
                                continue;

                        assert(index >= 0);
                        assert((unsigned) index < m);

                        a[index] = fd;
                        ++j;
                }
        } else {
                void *e;

                HASHMAP_FOREACH(e, MAKE_HASHMAP(fds))
                        a[j++] = PTR_TO_FD(e);
        }
        assert(j == m);

        *ret = TAKE_PTR(a);
        return (int) j;
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
        unsigned size = hashmap_size(MAKE_HASHMAP(fds));

        return fdset_is_indexed(fds) ? size / 2 : size;
}

bool fdset_isempty(FDSet *fds) {
        return hashmap_isempty(MAKE_HASHMAP(fds));
}

int fdset_iterate(FDSet *s, Iterator *i) {
        const void *k;
        void *v;

        for (;;) {
                if (!hashmap_iterate(MAKE_HASHMAP(s), i, &v, &k))
                        return -ENOENT;

                if (!PTR_IS_FD_INDEX(v))
                        break;
        }

        return PTR_TO_FD(v);
}

int fdset_steal_first(FDSet *fds) {
        void *p;

        p = hashmap_steal_first(MAKE_HASHMAP(fds));
        if (!p)
                return -ENOENT;

        if (!PTR_IS_FD_INDEX(p))
                return PTR_TO_FD(p);

        p = hashmap_remove(MAKE_HASHMAP(fds), p);
        if (!p)
                return -ENOENT;

        return PTR_TO_FD(p);
}
