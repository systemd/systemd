/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "user-util.h"

int mkdir_safe_internal(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdir_func_t _mkdir) {
        struct stat st;
        int r;

        assert(_mkdir != mkdir);

        if (_mkdir(path, mode) >= 0) {
                r = chmod_and_chown(path, mode, uid, gid);
                if (r < 0)
                        return r;
        }

        if (lstat(path, &st) < 0)
                return -errno;

        if ((flags & MKDIR_FOLLOW_SYMLINK) && S_ISLNK(st.st_mode)) {
                _cleanup_free_ char *p = NULL;

                r = chase_symlinks(path, NULL, CHASE_NONEXISTENT, &p);
                if (r < 0)
                        return r;
                if (r == 0)
                        return mkdir_safe_internal(p, mode, uid, gid,
                                                   flags & ~MKDIR_FOLLOW_SYMLINK,
                                                   _mkdir);

                if (lstat(p, &st) < 0)
                        return -errno;
        }

        if (!S_ISDIR(st.st_mode)) {
                log_full(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG,
                         "Path \"%s\" already exists and is not a directory, refusing.", path);
                return -ENOTDIR;
        }
        if ((st.st_mode & 0007) > (mode & 0007) ||
            (st.st_mode & 0070) > (mode & 0070) ||
            (st.st_mode & 0700) > (mode & 0700)) {
                log_full(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG,
                         "Directory \"%s\" already exists, but has mode %04o that is too permissive (%04o was requested), refusing.",
                         path, st.st_mode & 0777, mode);
                return -EEXIST;
        }
        if ((uid != UID_INVALID && st.st_uid != uid) ||
            (gid != GID_INVALID && st.st_gid != gid)) {
                char u[DECIMAL_STR_MAX(uid_t)] = "-", g[DECIMAL_STR_MAX(gid_t)] = "-";

                if (uid != UID_INVALID)
                        xsprintf(u, UID_FMT, uid);
                if (gid != UID_INVALID)
                        xsprintf(g, GID_FMT, gid);
                log_full(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG,
                         "Directory \"%s\" already exists, but is owned by "UID_FMT":"GID_FMT" (%s:%s was requested), refusing.",
                         path, st.st_uid, st.st_gid, u, g);
                return -EEXIST;
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

int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir) {
        const char *p, *e;
        int r;

        assert(path);
        assert(_mkdir != mkdir);

        if (prefix && !path_startswith(path, prefix))
                return -ENOTDIR;

        /* return immediately if directory exists */
        e = strrchr(path, '/');
        if (!e)
                return -EINVAL;

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

                r = _mkdir(t, mode);
                if (r < 0 && r != -EEXIST)
                        return r;
        }
}

int mkdir_parents(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, mkdir_errno_wrapper);
}

int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir) {
        int r;

        /* Like mkdir -p */

        assert(_mkdir != mkdir);

        r = mkdir_parents_internal(prefix, path, mode, _mkdir);
        if (r < 0)
                return r;

        r = _mkdir(path, mode);
        if (r < 0 && (r != -EEXIST || is_dir(path, true) <= 0))
                return r;

        return 0;
}

int mkdir_p(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, mkdir_errno_wrapper);
}
