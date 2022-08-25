/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "alloc-util.h"
#include "chase-symlinks.h"
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
                uid_t uid,
                gid_t gid,
                MkdirFlags flags,
                mkdirat_func_t _mkdirat) {

        struct stat st;
        int r;

        assert(path);
        assert(mode != MODE_INVALID);
        assert(_mkdirat && _mkdirat != mkdirat);

        if (_mkdirat(AT_FDCWD, path, mode) >= 0) {
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
                                                   _mkdirat);

                if (lstat(p, &st) < 0)
                        return -errno;
        }

        if (flags & MKDIR_IGNORE_EXISTING)
                return 0;

        if (!S_ISDIR(st.st_mode))
                return log_full_errno(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG, SYNTHETIC_ERRNO(ENOTDIR),
                                      "Path \"%s\" already exists and is not a directory, refusing.", path);

        if ((st.st_mode & ~mode & 0777) != 0)
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

int mkdirat_errno_wrapper(int dirfd, const char *pathname, mode_t mode) {
        return RET_NERRNO(mkdirat(dirfd, pathname, mode));
}

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_safe_internal(path, mode, uid, gid, flags, mkdirat_errno_wrapper);
}

int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdirat) {
        const char *p, *e = NULL;
        int r;

        assert(path);
        assert(_mkdirat != mkdirat);

        if (prefix) {
                p = path_startswith_full(path, prefix, /* accept_dot_dot= */ false);
                if (!p)
                        return -ENOTDIR;
        } else
                p = path;

        if (isempty(p))
                return 0;

        if (!path_is_safe(p))
                return -ENOTDIR;

        /* return immediately if directory exists */
        r = path_find_last_component(p, /* accept_dot_dot= */ false, &e, NULL);
        if (r <= 0) /* r == 0 means path is equivalent to prefix. */
                return r;
        if (e == p)
                return 0;

        assert(e > p);
        assert(*e == '/');

        /* drop the last component */
        path = strndupa_safe(path, e - path);
        r = is_dir(path, true);
        if (r > 0)
                return 0;
        if (r == 0)
                return -ENOTDIR;

        /* create every parent directory in the path, except the last component */
        for (p = path;;) {
                char *s;
                int n;

                n = path_find_first_component(&p, /* accept_dot_dot= */ false, (const char **) &s);
                if (n <= 0)
                        return n;

                assert(p);
                assert(s >= path);
                assert(IN_SET(s[n], '/', '\0'));

                s[n] = '\0';

                if (!prefix || !path_startswith_full(prefix, path, /* accept_dot_dot= */ false)) {
                        r = mkdir_safe_internal(path, mode, uid, gid, flags | MKDIR_IGNORE_EXISTING, _mkdirat);
                        if (r < 0 && r != -EEXIST)
                                return r;
                }

                s[n] = *p == '\0' ? '\0' : '/';
        }
}

int mkdir_parents(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_errno_wrapper);
}

int mkdir_parents_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_parents_internal(prefix, path, mode, uid, gid, flags, mkdirat_errno_wrapper);
}

int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdirat) {
        int r;

        /* Like mkdir -p */

        assert(_mkdirat != mkdirat);

        r = mkdir_parents_internal(prefix, path, mode, uid, gid, flags | MKDIR_FOLLOW_SYMLINK, _mkdirat);
        if (r < 0)
                return r;

        if (!uid_is_valid(uid) && !gid_is_valid(gid) && flags == 0) {
                r = _mkdirat(AT_FDCWD, path, mode);
                if (r < 0 && (r != -EEXIST || is_dir(path, true) <= 0))
                        return r;
        } else {
                r = mkdir_safe_internal(path, mode, uid, gid, flags, _mkdirat);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

int mkdir_p(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_errno_wrapper);
}

int mkdir_p_safe(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_p_internal(prefix, path, mode, uid, gid, flags, mkdirat_errno_wrapper);
}

int mkdir_p_root(const char *root, const char *p, uid_t uid, gid_t gid, mode_t m) {
        _cleanup_free_ char *pp = NULL, *bn = NULL;
        _cleanup_close_ int dfd = -1;
        int r;

        r = path_extract_directory(p, &pp);
        if (r == -EDESTADDRREQ) {
                /* only fname is passed, no prefix to operate on */
                dfd = open(".", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (dfd < 0)
                        return -errno;
        } else if (r == -EADDRNOTAVAIL)
                /* only root dir or "." was passed, i.e. there is no parent to extract, in that case there's nothing to do. */
                return 0;
        else if (r < 0)
                return r;
        else {
                /* Extracting the parent dir worked, hence we aren't top-level? Recurse up first. */
                r = mkdir_p_root(root, pp, uid, gid, m);
                if (r < 0)
                        return r;

                dfd = chase_symlinks_and_open(pp, root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_DIRECTORY, NULL);
                if (dfd < 0)
                        return dfd;
        }

        r = path_extract_filename(p, &bn);
        if (r == -EADDRNOTAVAIL) /* Already top-level */
                return 0;
        if (r < 0)
                return r;

        if (mkdirat(dfd, bn, m) < 0) {
                if (errno == EEXIST)
                        return 0;

                return -errno;
        }

        if (uid_is_valid(uid) || gid_is_valid(gid)) {
                _cleanup_close_ int nfd = -1;

                nfd = openat(dfd, bn, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (nfd < 0)
                        return -errno;

                if (fchown(nfd, uid, gid) < 0)
                        return -errno;
        }

        return 1;
}
