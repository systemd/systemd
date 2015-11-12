/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

int unlink_noerrno(const char *path) {
        PROTECT_ERRNO;
        int r;

        r = unlink(path);
        if (r < 0)
                return -errno;

        return 0;
}

int rmdir_parents(const char *path, const char *stop) {
        size_t l;
        int r = 0;

        assert(path);
        assert(stop);

        l = strlen(path);

        /* Skip trailing slashes */
        while (l > 0 && path[l-1] == '/')
                l--;

        while (l > 0) {
                char *t;

                /* Skip last component */
                while (l > 0 && path[l-1] != '/')
                        l--;

                /* Skip trailing slashes */
                while (l > 0 && path[l-1] == '/')
                        l--;

                if (l <= 0)
                        break;

                t = strndup(path, l);
                if (!t)
                        return -ENOMEM;

                if (path_startswith(stop, t)) {
                        free(t);
                        return 0;
                }

                r = rmdir(t);
                free(t);

                if (r < 0)
                        if (errno != ENOENT)
                                return -errno;
        }

        return 0;
}


int rename_noreplace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
        struct stat buf;
        int ret;

        ret = renameat2(olddirfd, oldpath, newdirfd, newpath, RENAME_NOREPLACE);
        if (ret >= 0)
                return 0;

        /* renameat2() exists since Linux 3.15, btrfs added support for it later.
         * If it is not implemented, fallback to another method. */
        if (!IN_SET(errno, EINVAL, ENOSYS))
                return -errno;

        /* The link()/unlink() fallback does not work on directories. But
         * renameat() without RENAME_NOREPLACE gives the same semantics on
         * directories, except when newpath is an *empty* directory. This is
         * good enough. */
        ret = fstatat(olddirfd, oldpath, &buf, AT_SYMLINK_NOFOLLOW);
        if (ret >= 0 && S_ISDIR(buf.st_mode)) {
                ret = renameat(olddirfd, oldpath, newdirfd, newpath);
                return ret >= 0 ? 0 : -errno;
        }

        /* If it is not a directory, use the link()/unlink() fallback. */
        ret = linkat(olddirfd, oldpath, newdirfd, newpath, 0);
        if (ret < 0)
                return -errno;

        ret = unlinkat(olddirfd, oldpath, 0);
        if (ret < 0) {
                /* backup errno before the following unlinkat() alters it */
                ret = errno;
                (void) unlinkat(newdirfd, newpath, 0);
                errno = ret;
                return -errno;
        }

        return 0;
}

int readlinkat_malloc(int fd, const char *p, char **ret) {
        size_t l = 100;
        int r;

        assert(p);
        assert(ret);

        for (;;) {
                char *c;
                ssize_t n;

                c = new(char, l);
                if (!c)
                        return -ENOMEM;

                n = readlinkat(fd, p, c, l-1);
                if (n < 0) {
                        r = -errno;
                        free(c);
                        return r;
                }

                if ((size_t) n < l-1) {
                        c[n] = 0;
                        *ret = c;
                        return 0;
                }

                free(c);
                l *= 2;
        }
}

int readlink_malloc(const char *p, char **ret) {
        return readlinkat_malloc(AT_FDCWD, p, ret);
}

int readlink_value(const char *p, char **ret) {
        _cleanup_free_ char *link = NULL;
        char *value;
        int r;

        r = readlink_malloc(p, &link);
        if (r < 0)
                return r;

        value = basename(link);
        if (!value)
                return -ENOENT;

        value = strdup(value);
        if (!value)
                return -ENOMEM;

        *ret = value;

        return 0;
}

int readlink_and_make_absolute(const char *p, char **r) {
        _cleanup_free_ char *target = NULL;
        char *k;
        int j;

        assert(p);
        assert(r);

        j = readlink_malloc(p, &target);
        if (j < 0)
                return j;

        k = file_in_same_dir(p, target);
        if (!k)
                return -ENOMEM;

        *r = k;
        return 0;
}

int readlink_and_canonicalize(const char *p, char **r) {
        char *t, *s;
        int j;

        assert(p);
        assert(r);

        j = readlink_and_make_absolute(p, &t);
        if (j < 0)
                return j;

        s = canonicalize_file_name(t);
        if (s) {
                free(t);
                *r = s;
        } else
                *r = t;

        path_kill_slashes(*r);

        return 0;
}

int readlink_and_make_absolute_root(const char *root, const char *path, char **ret) {
        _cleanup_free_ char *target = NULL, *t = NULL;
        const char *full;
        int r;

        full = prefix_roota(root, path);
        r = readlink_malloc(full, &target);
        if (r < 0)
                return r;

        t = file_in_same_dir(path, target);
        if (!t)
                return -ENOMEM;

        *ret = t;
        t = NULL;

        return 0;
}

int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        assert(path);

        /* Under the assumption that we are running privileged we
         * first change the access mode and only then hand out
         * ownership to avoid a window where access is too open. */

        if (mode != MODE_INVALID)
                if (chmod(path, mode) < 0)
                        return -errno;

        if (uid != UID_INVALID || gid != GID_INVALID)
                if (chown(path, uid, gid) < 0)
                        return -errno;

        return 0;
}

int fchmod_and_fchown(int fd, mode_t mode, uid_t uid, gid_t gid) {
        assert(fd >= 0);

        /* Under the assumption that we are running privileged we
         * first change the access mode and only then hand out
         * ownership to avoid a window where access is too open. */

        if (mode != MODE_INVALID)
                if (fchmod(fd, mode) < 0)
                        return -errno;

        if (uid != UID_INVALID || gid != GID_INVALID)
                if (fchown(fd, uid, gid) < 0)
                        return -errno;

        return 0;
}

int fchmod_umask(int fd, mode_t m) {
        mode_t u;
        int r;

        u = umask(0777);
        r = fchmod(fd, m & (~u)) < 0 ? -errno : 0;
        umask(u);

        return r;
}

int fd_warn_permissions(const char *path, int fd) {
        struct stat st;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (st.st_mode & 0111)
                log_warning("Configuration file %s is marked executable. Please remove executable permission bits. Proceeding anyway.", path);

        if (st.st_mode & 0002)
                log_warning("Configuration file %s is marked world-writable. Please remove world writability permission bits. Proceeding anyway.", path);

        if (getpid() == 1 && (st.st_mode & 0044) != 0044)
                log_warning("Configuration file %s is marked world-inaccessible. This has no effect as configuration data is accessible via APIs without restrictions. Proceeding anyway.", path);

        return 0;
}

int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid, gid_t gid, mode_t mode) {
        _cleanup_close_ int fd;
        int r;

        assert(path);

        if (parents)
                mkdir_parents(path, 0755);

        fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, mode > 0 ? mode : 0644);
        if (fd < 0)
                return -errno;

        if (mode != MODE_INVALID) {
                r = fchmod(fd, mode);
                if (r < 0)
                        return -errno;
        }

        if (uid != UID_INVALID || gid != GID_INVALID) {
                r = fchown(fd, uid, gid);
                if (r < 0)
                        return -errno;
        }

        if (stamp != USEC_INFINITY) {
                struct timespec ts[2];

                timespec_store(&ts[0], stamp);
                ts[1] = ts[0];
                r = futimens(fd, ts);
        } else
                r = futimens(fd, NULL);
        if (r < 0)
                return -errno;

        return 0;
}

int touch(const char *path) {
        return touch_file(path, false, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID);
}

int symlink_idempotent(const char *from, const char *to) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(from);
        assert(to);

        if (symlink(from, to) < 0) {
                if (errno != EEXIST)
                        return -errno;

                r = readlink_malloc(to, &p);
                if (r < 0)
                        return r;

                if (!streq(p, from))
                        return -EINVAL;
        }

        return 0;
}

int symlink_atomic(const char *from, const char *to) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(from);
        assert(to);

        r = tempfn_random(to, NULL, &t);
        if (r < 0)
                return r;

        if (symlink(from, t) < 0)
                return -errno;

        if (rename(t, to) < 0) {
                unlink_noerrno(t);
                return -errno;
        }

        return 0;
}

int mknod_atomic(const char *path, mode_t mode, dev_t dev) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(path);

        r = tempfn_random(path, NULL, &t);
        if (r < 0)
                return r;

        if (mknod(t, mode, dev) < 0)
                return -errno;

        if (rename(t, path) < 0) {
                unlink_noerrno(t);
                return -errno;
        }

        return 0;
}

int mkfifo_atomic(const char *path, mode_t mode) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(path);

        r = tempfn_random(path, NULL, &t);
        if (r < 0)
                return r;

        if (mkfifo(t, mode) < 0)
                return -errno;

        if (rename(t, path) < 0) {
                unlink_noerrno(t);
                return -errno;
        }

        return 0;
}

int get_files_in_directory(const char *path, char ***list) {
        _cleanup_closedir_ DIR *d = NULL;
        size_t bufsize = 0, n = 0;
        _cleanup_strv_free_ char **l = NULL;

        assert(path);

        /* Returns all files in a directory in *list, and the number
         * of files as return value. If list is NULL returns only the
         * number. */

        d = opendir(path);
        if (!d)
                return -errno;

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0)
                        return -errno;
                if (!de)
                        break;

                dirent_ensure_type(d, de);

                if (!dirent_is_file(de))
                        continue;

                if (list) {
                        /* one extra slot is needed for the terminating NULL */
                        if (!GREEDY_REALLOC(l, bufsize, n + 2))
                                return -ENOMEM;

                        l[n] = strdup(de->d_name);
                        if (!l[n])
                                return -ENOMEM;

                        l[++n] = NULL;
                } else
                        n++;
        }

        if (list) {
                *list = l;
                l = NULL; /* avoid freeing */
        }

        return n;
}
