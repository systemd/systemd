/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/xattr.h>
#include <threads.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "xattr-util.h"

/* Use a single cache for all of *xattrat syscalls (added in kernel 6.13) */
static thread_local bool have_xattrat = true;

static int normalize_and_maybe_pin_inode(
                int *fd,
                const char **path,
                int *at_flags,
                int *ret_tfd,
                bool *ret_opath) {

        int r;

        assert(fd);
        assert(*fd >= 0 || *fd == AT_FDCWD);
        assert(path);
        assert(at_flags);
        assert(ret_tfd);
        assert(ret_opath);

        if (isempty(*path))
                *path = NULL; /* Normalize "" to NULL */

        if (*fd == AT_FDCWD) {
                if (!*path) /* Both unspecified? Then operate on current working directory */
                        *path = ".";

                *ret_tfd = -EBADF;
                *ret_opath = false;
                return 0;
        }

        *at_flags |= AT_EMPTY_PATH;

        if (!*path) {
                r = fd_is_opath(*fd);
                if (r < 0)
                        return r;
                *ret_opath = r;
                *ret_tfd = -EBADF;
                return 0;
        }

        /* If both have been specified, then we go via O_PATH */

        int tfd = openat(*fd, *path, O_PATH|O_CLOEXEC|(FLAGS_SET(*at_flags, AT_SYMLINK_FOLLOW) ? 0 : O_NOFOLLOW));
        if (tfd < 0)
                return -errno;

        *fd = *ret_tfd = tfd;
        *path = NULL;
        *ret_opath = true;

        return 0;
}

static ssize_t getxattr_pinned_internal(
                int fd,
                const char *path,
                int at_flags,
                bool by_procfs,
                const char *name,
                char *buf,
                size_t size) {

        ssize_t n;

        assert(!path || !isempty(path));
        assert((fd >= 0) == !path);
        assert(path || FLAGS_SET(at_flags, AT_EMPTY_PATH));
        assert(name);
        assert(buf || size == 0);

        if (path)
                n = FLAGS_SET(at_flags, AT_SYMLINK_FOLLOW) ? getxattr(path, name, buf, size)
                                                           : lgetxattr(path, name, buf, size);
        else
                n = by_procfs ? getxattr(FORMAT_PROC_FD_PATH(fd), name, buf, size)
                              : fgetxattr(fd, name, buf, size);
        if (n < 0)
                return -errno;

        assert(size == 0 || (size_t) n <= size);
        return n;
}

int getxattr_at_malloc(
                int fd,
                const char *path,
                const char *name,
                int at_flags,
                char **ret,
                size_t *ret_size) {

        _cleanup_close_ int opened_fd = -EBADF;
        bool by_procfs;
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert(name);
        assert((at_flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);
        assert(ret);

        /* So, this is single function that does what getxattr()/lgetxattr()/fgetxattr() does, but in one go,
         * and with additional bells and whistles. Specifically:
         *
         * 1. This works on O_PATH fds (via /proc/self/fd/, since getxattrat() syscall refuses them...)
         * 2. As extension to openat()-style semantics implies AT_EMPTY_PATH if path is empty
         * 3. Does a malloc() loop, automatically sizing the allocation
         * 4. NUL-terminates the returned buffer (for safety)
         */

        r = normalize_and_maybe_pin_inode(&fd, &path, &at_flags, &opened_fd, &by_procfs);
        if (r < 0)
                return r;

        size_t l = 100;
        for (unsigned n_attempts = 7;;) {
                _cleanup_free_ char *v = NULL;

                if (n_attempts == 0) /* If someone is racing against us, give up eventually */
                        return -EBUSY;
                n_attempts--;

                v = new(char, l+1);
                if (!v)
                        return -ENOMEM;

                l = MALLOC_ELEMENTSOF(v) - 1;

                ssize_t n;
                n = getxattr_pinned_internal(fd, path, at_flags, by_procfs, name, v, l);
                if (n >= 0) {
                        /* Refuse extended attributes with embedded NUL bytes if the caller isn't interested
                         * in the size. After all this must mean the caller assumes we return a NUL
                         * terminated strings, but if there's a NUL byte embedded they are definitely not
                         * regular strings */
                        if (!ret_size && n > 1 && memchr(v, 0, n - 1))
                                return -EBADMSG;

                        v[n] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        if (ret_size)
                                *ret_size = (size_t) n;

                        return 0;
                }
                if (n != -ERANGE)
                        return (int) n;

                n = getxattr_pinned_internal(fd, path, at_flags, by_procfs, name, NULL, 0);
                if (n < 0)
                        return (int) n;

                l = (size_t) n;
        }
}

int getxattr_at_bool(int fd, const char *path, const char *name, int at_flags) {
        _cleanup_free_ char *v = NULL;
        int r;

        r = getxattr_at_malloc(fd, path, name, at_flags, &v, /* ret_size= */ NULL);
        if (r < 0)
                return r;

        return parse_boolean(v);
}

int getxattr_at_strv(int fd, const char *path, const char *name, int at_flags, char ***ret_strv) {
        _cleanup_free_ char *nulstr = NULL;
        size_t nulstr_size;
        int r;

        assert(ret_strv);

        r = getxattr_at_malloc(fd, path, name, at_flags, &nulstr, &nulstr_size);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **l = strv_parse_nulstr(nulstr, nulstr_size);
        if (!l)
                return -ENOMEM;

        *ret_strv = TAKE_PTR(l);
        return 0;
}

static int listxattr_pinned_internal(
                int fd,
                const char *path,
                int at_flags,
                bool by_procfs,
                char *buf,
                size_t size) {

        ssize_t n;

        assert(!path || !isempty(path));
        assert((fd >= 0) == !path);
        assert(path || FLAGS_SET(at_flags, AT_EMPTY_PATH));
        assert(buf || size == 0);

        if (path)
                n = FLAGS_SET(at_flags, AT_SYMLINK_FOLLOW) ? listxattr(path, buf, size)
                                                           : llistxattr(path, buf, size);
        else
                n = by_procfs ? listxattr(FORMAT_PROC_FD_PATH(fd), buf, size)
                              : flistxattr(fd, buf, size);
        if (n < 0)
                return -errno;

        assert(size == 0 || (size_t) n <= size);

        if (n > INT_MAX) /* We couldn't return this as 'int' anymore */
                return -E2BIG;

        return (int) n;
}

int listxattr_at_malloc(int fd, const char *path, int at_flags, char **ret) {
        _cleanup_close_ int opened_fd = -EBADF;
        bool by_procfs;
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert((at_flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);
        assert(ret);

        /* This is to listxattr()/llistattr()/flistattr() what getxattr_at_malloc() is to getxattr()/… */

        r = normalize_and_maybe_pin_inode(&fd, &path, &at_flags, &opened_fd, &by_procfs);
        if (r < 0)
                return r;

        size_t l = 100;
        for (unsigned n_attempts = 7;;) {
                _cleanup_free_ char *v = NULL;

                if (n_attempts == 0) /* If someone is racing against us, give up eventually */
                        return -EBUSY;
                n_attempts--;

                v = new(char, l+1);
                if (!v)
                        return -ENOMEM;

                l = MALLOC_ELEMENTSOF(v) - 1;

                r = listxattr_pinned_internal(fd, path, at_flags, by_procfs, v, l);
                if (r >= 0) {
                        v[r] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        return r;
                }
                if (r != -ERANGE)
                        return r;

                r = listxattr_pinned_internal(fd, path, at_flags, by_procfs, NULL, 0);
                if (r < 0)
                        return r;

                l = (size_t) r;
        }
}

int xsetxattr_full(
                int fd,
                const char *path,
                int at_flags,
                const char *name,
                const char *value,
                size_t size,
                int xattr_flags) {

        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert((at_flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);
        assert(name);
        assert(value);

        if (size == SIZE_MAX)
                size = strlen(value);

        if (have_xattrat && !isempty(path)) {
                struct xattr_args args = {
                        .value = PTR_TO_UINT64(value),
                        .size = size,
                        .flags = xattr_flags,
                };

                r = RET_NERRNO(setxattrat(fd, path,
                                          at_flags_normalize_nofollow(at_flags),
                                          name,
                                          &args, sizeof(args)));
                if (r != -ENOSYS) /* No ERRNO_IS_NOT_SUPPORTED here, as EOPNOTSUPP denotes the fs doesn't
                                     support xattr */
                        return r;

                have_xattrat = false;
        }

        _cleanup_close_ int opened_fd = -EBADF;
        bool by_procfs;

        r = normalize_and_maybe_pin_inode(&fd, &path, &at_flags, &opened_fd, &by_procfs);
        if (r < 0)
                return r;

        if (path)
                r = FLAGS_SET(at_flags, AT_SYMLINK_FOLLOW) ? setxattr(path, name, value, size, xattr_flags)
                                                           : lsetxattr(path, name, value, size, xattr_flags);
        else
                r = by_procfs ? setxattr(FORMAT_PROC_FD_PATH(fd), name, value, size, xattr_flags)
                              : fsetxattr(fd, name, value, size, xattr_flags);
        if (r < 0)
                return -errno;

        return 0;
}

int xsetxattr_strv(int fd, const char *path, int at_flags, const char *name, char * const *l) {
        _cleanup_free_ char *nulstr = NULL;
        size_t size;
        int r;

        assert(name);

        r = strv_make_nulstr(l, &nulstr, &size);
        if (r < 0)
                return r;

        return xsetxattr_full(fd, path, at_flags, name, nulstr, size, /* xattr_flags= */ 0);
}

int xremovexattr(int fd, const char *path, int at_flags, const char *name) {
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert((at_flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);
        assert(name);

        if (have_xattrat && !isempty(path)) {
                r = RET_NERRNO(removexattrat(fd, path,
                                             at_flags_normalize_nofollow(at_flags),
                                             name));
                if (r != -ENOSYS) /* No ERRNO_IS_NOT_SUPPORTED here, as EOPNOTSUPP denotes the fs doesn't
                                     support xattr */
                        return r;

                have_xattrat = false;
        }

        _cleanup_close_ int tfd = -EBADF;
        bool by_procfs;

        r = normalize_and_maybe_pin_inode(&fd, &path, &at_flags, &tfd, &by_procfs);
        if (r < 0)
                return r;

        if (path)
                r = FLAGS_SET(at_flags, AT_SYMLINK_FOLLOW) ? removexattr(path, name)
                                                           : lremovexattr(path, name);
        else
                r = by_procfs ? removexattr(FORMAT_PROC_FD_PATH(fd), name)
                              : fremovexattr(fd, name);
        if (r < 0)
                return -errno;

        return 0;
}

static int parse_crtime(le64_t le, usec_t *ret) {
        usec_t u;

        assert(ret);

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));
        assert_cc((usec_t) UINT64_MAX == USEC_INFINITY);

        u = (usec_t) le64toh(le);
        if (!timestamp_is_set(u))
                return -EIO;

        *ret = u;
        return 0;
}

int getcrtime_at(
                int fd,
                const char *path,
                int at_flags,
                usec_t *ret) {

        _cleanup_free_ le64_t *le = NULL;
        struct statx sx;
        usec_t a, b;
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert((at_flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        if (isempty(path))
                at_flags |= AT_EMPTY_PATH;

        /* So here's the deal: the creation/birth time (crtime/btime) of a file is a relatively newly supported concept
         * on Linux (or more strictly speaking: a concept that only recently got supported in the API, it was
         * implemented on various file systems on the lower level since a while, but never was accessible). However, we
         * needed a concept like that for vacuuming algorithms and such, hence we emulated it via a user xattr for a
         * long time. Starting with Linux 4.11 there's statx() which exposes the timestamp to userspace for the first
         * time, where it is available. This function will read it, but it tries to keep some compatibility with older
         * systems: we try to read both the crtime/btime and the xattr, and then use whatever is older. After all the
         * concept is useful for determining how "old" a file really is, and hence using the older of the two makes
         * most sense. */

        if (statx(fd, strempty(path),
                  at_flags_normalize_nofollow(at_flags)|AT_STATX_DONT_SYNC,
                  STATX_BTIME,
                  &sx) >= 0 &&
            FLAGS_SET(sx.stx_mask, STATX_BTIME) && sx.stx_btime.tv_sec != 0)
                a = statx_timestamp_load(&sx.stx_btime);
        else
                a = USEC_INFINITY;

        size_t le_size;
        r = getxattr_at_malloc(fd, path, "user.crtime_usec", at_flags, (char**) &le, &le_size);
        if (r >= 0) {
                if (le_size != sizeof(*le))
                        r = -EIO;
                else
                        r = parse_crtime(*le, &b);
        }
        if (r < 0) {
                if (a != USEC_INFINITY) {
                        if (ret)
                                *ret = a;
                        return 0;
                }

                return r;
        }

        if (ret)
                *ret = MIN(a, b);
        return 0;
}

int fd_setcrtime(int fd, usec_t usec) {
        le64_t le;

        assert(fd >= 0);

        if (!timestamp_is_set(usec))
                usec = now(CLOCK_REALTIME);

        le = htole64((uint64_t) usec);
        return xsetxattr_full(fd, /* path = */ NULL, AT_EMPTY_PATH,
                              "user.crtime_usec", (const char*) &le, sizeof(le),
                              /* xattr_flags = */ 0);
}
