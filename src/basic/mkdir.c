/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "btrfs.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "mkdir.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "time-util.h"
#include "user-util.h"

int mkdirat_safe_internal(
                int dir_fd,
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

        r = _mkdirat(dir_fd, path, mode);
        if (r >= 0)
                return chmod_and_chown_at(dir_fd, path, mode, uid, gid);
        if (r != -EEXIST)
                return r;

        if (fstatat(dir_fd, path, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        if ((flags & MKDIR_FOLLOW_SYMLINK) && S_ISLNK(st.st_mode)) {
                _cleanup_free_ char *p = NULL;

                r = chaseat(dir_fd, path, CHASE_NONEXISTENT, &p, NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        return mkdirat_safe_internal(dir_fd, p, mode, uid, gid,
                                                     flags & ~MKDIR_FOLLOW_SYMLINK,
                                                     _mkdirat);

                if (fstatat(dir_fd, p, &st, AT_SYMLINK_NOFOLLOW) < 0)
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
            (gid != GID_INVALID && st.st_gid != gid))
                return log_full_errno(flags & MKDIR_WARN_MODE ? LOG_WARNING : LOG_DEBUG, SYNTHETIC_ERRNO(EEXIST),
                                      "Directory \"%s\" already exists, but is owned by "UID_FMT":"GID_FMT" (%s:%s was requested), refusing.",
                                      path, st.st_uid, st.st_gid, uid != UID_INVALID ? FORMAT_UID(uid) : "-",
                                      gid != UID_INVALID ? FORMAT_GID(gid) : "-");

        return 0;
}

int mkdirat_errno_wrapper(int dirfd, const char *pathname, mode_t mode) {
        return RET_NERRNO(mkdirat(dirfd, pathname, mode));
}

int mkdirat_safe(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdirat_safe_internal(dir_fd, path, mode, uid, gid, flags, mkdirat_errno_wrapper);
}

int mkdirat_parents_internal(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdirat) {
        const char *e = NULL;
        int r;

        assert(path);
        assert(_mkdirat != mkdirat);

        if (isempty(path))
                return 0;

        if (!path_is_safe(path))
                return -ENOTDIR;

        /* return immediately if directory exists */
        r = path_find_last_component(path, /* accept_dot_dot= */ false, &e, NULL);
        if (r <= 0) /* r == 0 means path is equivalent to prefix. */
                return r;
        if (e == path)
                return 0;

        assert(e > path);
        assert(*e == '/');

        /* drop the last component */
        path = strndupa_safe(path, e - path);
        r = is_dir_at(dir_fd, path, /* follow = */ true);
        if (r > 0)
                return 0;
        if (r == 0)
                return -ENOTDIR;

        /* create every parent directory in the path, except the last component */
        for (const char *p = path;;) {
                char *s;
                int n;

                n = path_find_first_component(&p, /* accept_dot_dot= */ false, (const char **) &s);
                if (n <= 0)
                        return n;

                assert(p);
                assert(s >= path);
                assert(IN_SET(s[n], '/', '\0'));

                s[n] = '\0';

                r = mkdirat_safe_internal(dir_fd, path, mode, uid, gid, flags | MKDIR_IGNORE_EXISTING, _mkdirat);
                if (r < 0 && r != -EEXIST)
                        return r;

                s[n] = *p == '\0' ? '\0' : '/';
        }
}

int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, mkdirat_func_t _mkdirat) {
        _cleanup_close_ int fd = AT_FDCWD;
        const char *p;

        assert(path);
        assert(_mkdirat != mkdirat);

        if (prefix) {
                p = path_startswith_full(path, prefix, PATH_STARTSWITH_REFUSE_DOT_DOT);
                if (!p)
                        return -EINVAL;

                fd = open(prefix, O_PATH|O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return -errno;
        } else
                p = path;

        return mkdirat_parents_internal(fd, p, mode, uid, gid, flags, _mkdirat);
}

int mkdirat_parents(int dir_fd, const char *path, mode_t mode) {
        return mkdirat_parents_internal(dir_fd, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_errno_wrapper);
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

int mkdir_p_root_full(const char *root, const char *p, uid_t uid, gid_t gid, mode_t m, usec_t ts, Hashmap *subvolumes) {
        _cleanup_free_ char *pp = NULL, *bn = NULL;
        _cleanup_close_ int dfd = -EBADF;
        int r;

        assert(p);

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
                r = mkdir_p_root_full(root, pp, uid, gid, m, ts, subvolumes);
                if (r < 0)
                        return r;

                dfd = chase_and_open(pp, root, CHASE_PREFIX_ROOT, O_CLOEXEC|O_DIRECTORY, NULL);
                if (dfd < 0)
                        return dfd;
        }

        r = path_extract_filename(p, &bn);
        if (r == -EADDRNOTAVAIL) /* Already top-level */
                return 0;
        if (r < 0)
                return r;

        XOpenFlags flags = 0;
        if (hashmap_contains(subvolumes, p)) {
                flags = XO_SUBVOLUME;
                if ((PTR_TO_INT(hashmap_get(subvolumes, p)) & BTRFS_SUBVOL_NODATACOW))
                        flags |= XO_NOCOW;
        }

        _cleanup_close_ int nfd = xopenat_full(
                                dfd, bn,
                                O_DIRECTORY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
                                flags,
                                m);
        if (nfd == -EEXIST)
                return 0;
        if (nfd < 0)
                return nfd;

        if (ts == USEC_INFINITY && !uid_is_valid(uid) && !gid_is_valid(gid))
                return 1;

        if (ts != USEC_INFINITY) {
                struct timespec tspec;
                timespec_store(&tspec, ts);

                if (futimens(dfd, (const struct timespec[2]) { TIMESPEC_OMIT, tspec }) < 0)
                        return -errno;

                if (futimens(nfd, (const struct timespec[2]) { tspec, tspec }) < 0)
                        return -errno;
        }

        if ((uid_is_valid(uid) || gid_is_valid(gid)) && fchown(nfd, uid, gid) < 0)
                return -errno;

        return 1;
}
