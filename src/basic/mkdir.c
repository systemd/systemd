/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "user-util.h"

int mkdir_safe_internal(
                const char *path,
                mode_t mode,
                uid_t uid, gid_t gid,
                MkdirFlags flags,
                mkdir_func_t _mkdir) {

        struct stat st;
        int r;

        assert(path);
        assert(_mkdir && _mkdir != mkdir);

        if (_mkdir(path, mode) >= 0) {
                r = chmod_and_chown(path, mode, uid, gid);
                if (r < 0)
                        return r;
        }

        if (lstat(path, &st) < 0)
                return -errno;

        if ((flags & MKDIR_FOLLOW_SYMLINK) && S_ISLNK(st.st_mode)) {
                _cleanup_free_ char *p = NULL;

                r = chase_symlinks(path, NULL, CHASE_NONEXISTENT, &p, NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        return mkdir_safe_internal(p, mode, uid, gid,
                                                   flags & ~MKDIR_FOLLOW_SYMLINK,
                                                   _mkdir);

                if (lstat(p, &st) < 0)
                        return -errno;
        }

        if (!S_ISDIR(st.st_mode))
                return log_full_errno(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG, SYNTHETIC_ERRNO(ENOTDIR),
                                      "Path \"%s\" already exists and is not a directory, refusing.", path);
        if ((st.st_mode & 0007) > (mode & 0007) ||
            (st.st_mode & 0070) > (mode & 0070) ||
            (st.st_mode & 0700) > (mode & 0700))
                return log_full_errno(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG, SYNTHETIC_ERRNO(EEXIST),
                                      "Directory \"%s\" already exists, but has mode %04o that is too permissive (%04o was requested), refusing.",
                                      path, st.st_mode & 0777, mode);

        if ((uid != UID_INVALID && st.st_uid != uid) ||
            (gid != GID_INVALID && st.st_gid != gid)) {
                char u[DECIMAL_STR_MAX(uid_t)] = "-", g[DECIMAL_STR_MAX(gid_t)] = "-";

                if (uid != UID_INVALID)
                        xsprintf(u, UID_FMT, uid);
                if (gid != UID_INVALID)
                        xsprintf(g, GID_FMT, gid);
                return log_full_errno(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG, SYNTHETIC_ERRNO(EEXIST),
                                      "Directory \"%s\" already exists, but is owned by "UID_FMT":"GID_FMT" (%s:%s was requested), refusing.",
                                      path, st.st_uid, st.st_gid, u, g);
        }

        return 0;
}

int mkdir_errno_wrapper(const char *pathname, mode_t mode) {
        if (mkdir(pathname, mode) < 0)
                return -errno;
        return 0;
}

int mkdirat_errno_wrapper(int dirfd, const char *pathname, mode_t mode) {
        if (mkdirat(dirfd, pathname, mode) < 0)
                return -errno;
        return 0;
}

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_safe_internal(path, mode, uid, gid, flags, mkdir_errno_wrapper);
}

int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdir_func_t _mkdir) {
        const char *p, *e;
        int r;

        assert(path);
        assert(_mkdir != mkdir);

        if (prefix && !path_startswith(path, prefix))
                return -ENOTDIR;

        /* return immediately if directory exists */
        e = strrchr(path, '/');
        if (!e)
                return 0;

        if (e == path)
                return 0;

        p = strndupa(path, e - path);
        r = is_dir(p, true);
        if (r > 0)
                return 0;
        if (r == 0)
                return -ENOTDIR;

        /* create every parent directory in the path, except the last component */
        p = path + strspn(path, "/");
        for (;;) {
                char t[strlen(path) + 1];

                e = p + strcspn(p, "/");
                p = e + strspn(e, "/");

                /* Is this the last component? If so, then we're done */
                if (*p == 0)
                        return 0;

                memcpy(t, path, e - path);
                t[e-path] = 0;

                if (prefix && path_startswith(prefix, t))
                        continue;

                if (!uid_is_valid(uid) && !gid_is_valid(gid) && flags == 0) {
                        r = _mkdir(t, mode);
                        if (r < 0 && r != -EEXIST)
                                return r;
                } else {
                        r = mkdir_safe_internal(t, mode, uid, gid, flags, _mkdir);
                        if (r < 0 && r != -EEXIST)
                                return r;
                }
        }
}

int mkdir_parents(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdir_errno_wrapper);
}

int mkdir_parents_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_parents_internal(prefix, path, mode, uid, gid, flags, mkdir_errno_wrapper);
}

int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdir_func_t _mkdir) {
        int r;

        /* Like mkdir -p */

        assert(_mkdir != mkdir);

        r = mkdir_parents_internal(prefix, path, mode, uid, gid, flags, _mkdir);
        if (r < 0)
                return r;

        if (!uid_is_valid(uid) && !gid_is_valid(gid) && flags == 0) {
                r = _mkdir(path, mode);
                if (r < 0 && (r != -EEXIST || is_dir(path, true) <= 0))
                        return r;
        } else {
                r = mkdir_safe_internal(path, mode, uid, gid, flags, _mkdir);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

int mkdir_p(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdir_errno_wrapper);
}

int mkdir_p_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_p_internal(prefix, path, mode, uid, gid, flags, mkdir_errno_wrapper);
}

int mkdir_p_root(const char *root, const char *p, uid_t uid, gid_t gid, mode_t m) {
        _cleanup_free_ char *pp = NULL;
        _cleanup_close_ int dfd = -1;
        const char *bn;
        int r;

        pp = dirname_malloc(p);
        if (!pp)
                return -ENOMEM;

        /* Not top-level? */
        if (!(path_equal(pp, "/") || isempty(pp) || path_equal(pp, "."))) {

                /* Recurse up */
                r = mkdir_p_root(root, pp, uid, gid, m);
                if (r < 0)
                        return r;
        }

        bn = basename(p);
        if (path_equal(bn, "/") || isempty(bn) || path_equal(bn, "."))
                return 0;

        if (!filename_is_valid(bn))
                return -EINVAL;

        dfd = chase_symlinks_and_open(pp, root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_DIRECTORY, NULL);
        if (dfd < 0)
                return dfd;

        if (mkdirat(dfd, bn, m) < 0) {
                if (errno == EEXIST)
                        return 0;

                return -errno;
        }

        if (uid_is_valid(uid) || gid_is_valid(gid)) {
                _cleanup_close_ int nfd = -1;

                nfd = openat(dfd, bn, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (nfd < 0)
                        return -errno;

                if (fchown(nfd, uid, gid) < 0)
                        return -errno;
        }

        return 1;
}
