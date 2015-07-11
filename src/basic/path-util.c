/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering

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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/statvfs.h>

#include "macro.h"
#include "util.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"
#include "missing.h"
#include "fileio.h"

bool path_is_absolute(const char *p) {
        return p[0] == '/';
}

bool is_path(const char *p) {
        return !!strchr(p, '/');
}

int path_get_parent(const char *path, char **_r) {
        const char *e, *a = NULL, *b = NULL, *p;
        char *r;
        bool slash = false;

        assert(path);
        assert(_r);

        if (!*path)
                return -EINVAL;

        for (e = path; *e; e++) {

                if (!slash && *e == '/') {
                        a = b;
                        b = e;
                        slash = true;
                } else if (slash && *e != '/')
                        slash = false;
        }

        if (*(e-1) == '/')
                p = a;
        else
                p = b;

        if (!p)
                return -EINVAL;

        if (p == path)
                r = strdup("/");
        else
                r = strndup(path, p-path);

        if (!r)
                return -ENOMEM;

        *_r = r;
        return 0;
}

char **path_split_and_make_absolute(const char *p) {
        char **l;
        assert(p);

        l = strv_split(p, ":");
        if (!l)
                return NULL;

        if (!path_strv_make_absolute_cwd(l)) {
                strv_free(l);
                return NULL;
        }

        return l;
}

char *path_make_absolute(const char *p, const char *prefix) {
        assert(p);

        /* Makes every item in the list an absolute path by prepending
         * the prefix, if specified and necessary */

        if (path_is_absolute(p) || !prefix)
                return strdup(p);

        return strjoin(prefix, "/", p, NULL);
}

char *path_make_absolute_cwd(const char *p) {
        _cleanup_free_ char *cwd = NULL;

        assert(p);

        /* Similar to path_make_absolute(), but prefixes with the
         * current working directory. */

        if (path_is_absolute(p))
                return strdup(p);

        cwd = get_current_dir_name();
        if (!cwd)
                return NULL;

        return strjoin(cwd, "/", p, NULL);
}

int path_make_relative(const char *from_dir, const char *to_path, char **_r) {
        char *r, *p;
        unsigned n_parents;

        assert(from_dir);
        assert(to_path);
        assert(_r);

        /* Strips the common part, and adds ".." elements as necessary. */

        if (!path_is_absolute(from_dir))
                return -EINVAL;

        if (!path_is_absolute(to_path))
                return -EINVAL;

        /* Skip the common part. */
        for (;;) {
                size_t a;
                size_t b;

                from_dir += strspn(from_dir, "/");
                to_path += strspn(to_path, "/");

                if (!*from_dir) {
                        if (!*to_path)
                                /* from_dir equals to_path. */
                                r = strdup(".");
                        else
                                /* from_dir is a parent directory of to_path. */
                                r = strdup(to_path);

                        if (!r)
                                return -ENOMEM;

                        path_kill_slashes(r);

                        *_r = r;
                        return 0;
                }

                if (!*to_path)
                        break;

                a = strcspn(from_dir, "/");
                b = strcspn(to_path, "/");

                if (a != b)
                        break;

                if (memcmp(from_dir, to_path, a) != 0)
                        break;

                from_dir += a;
                to_path += b;
        }

        /* If we're here, then "from_dir" has one or more elements that need to
         * be replaced with "..". */

        /* Count the number of necessary ".." elements. */
        for (n_parents = 0;;) {
                from_dir += strspn(from_dir, "/");

                if (!*from_dir)
                        break;

                from_dir += strcspn(from_dir, "/");
                n_parents++;
        }

        r = malloc(n_parents * 3 + strlen(to_path) + 1);
        if (!r)
                return -ENOMEM;

        for (p = r; n_parents > 0; n_parents--, p += 3)
                memcpy(p, "../", 3);

        strcpy(p, to_path);
        path_kill_slashes(r);

        *_r = r;
        return 0;
}

char **path_strv_make_absolute_cwd(char **l) {
        char **s;

        /* Goes through every item in the string list and makes it
         * absolute. This works in place and won't rollback any
         * changes on failure. */

        STRV_FOREACH(s, l) {
                char *t;

                t = path_make_absolute_cwd(*s);
                if (!t)
                        return NULL;

                free(*s);
                *s = t;
        }

        return l;
}

char **path_strv_resolve(char **l, const char *prefix) {
        char **s;
        unsigned k = 0;
        bool enomem = false;

        if (strv_isempty(l))
                return l;

        /* Goes through every item in the string list and canonicalize
         * the path. This works in place and won't rollback any
         * changes on failure. */

        STRV_FOREACH(s, l) {
                char *t, *u;
                _cleanup_free_ char *orig = NULL;

                if (!path_is_absolute(*s)) {
                        free(*s);
                        continue;
                }

                if (prefix) {
                        orig = *s;
                        t = strappend(prefix, orig);
                        if (!t) {
                                enomem = true;
                                continue;
                        }
                } else
                        t = *s;

                errno = 0;
                u = canonicalize_file_name(t);
                if (!u) {
                        if (errno == ENOENT) {
                                if (prefix) {
                                        u = orig;
                                        orig = NULL;
                                        free(t);
                                } else
                                        u = t;
                        } else {
                                free(t);
                                if (errno == ENOMEM || errno == 0)
                                        enomem = true;

                                continue;
                        }
                } else if (prefix) {
                        char *x;

                        free(t);
                        x = path_startswith(u, prefix);
                        if (x) {
                                /* restore the slash if it was lost */
                                if (!startswith(x, "/"))
                                        *(--x) = '/';

                                t = strdup(x);
                                free(u);
                                if (!t) {
                                        enomem = true;
                                        continue;
                                }
                                u = t;
                        } else {
                                /* canonicalized path goes outside of
                                 * prefix, keep the original path instead */
                                free(u);
                                u = orig;
                                orig = NULL;
                        }
                } else
                        free(t);

                l[k++] = u;
        }

        l[k] = NULL;

        if (enomem)
                return NULL;

        return l;
}

char **path_strv_resolve_uniq(char **l, const char *prefix) {

        if (strv_isempty(l))
                return l;

        if (!path_strv_resolve(l, prefix))
                return NULL;

        return strv_uniq(l);
}

char *path_kill_slashes(char *path) {
        char *f, *t;
        bool slash = false;

        /* Removes redundant inner and trailing slashes. Modifies the
         * passed string in-place.
         *
         * ///foo///bar/ becomes /foo/bar
         */

        for (f = path, t = path; *f; f++) {

                if (*f == '/') {
                        slash = true;
                        continue;
                }

                if (slash) {
                        slash = false;
                        *(t++) = '/';
                }

                *(t++) = *f;
        }

        /* Special rule, if we are talking of the root directory, a
        trailing slash is good */

        if (t == path && slash)
                *(t++) = '/';

        *t = 0;
        return path;
}

char* path_startswith(const char *path, const char *prefix) {
        assert(path);
        assert(prefix);

        if ((path[0] == '/') != (prefix[0] == '/'))
                return NULL;

        for (;;) {
                size_t a, b;

                path += strspn(path, "/");
                prefix += strspn(prefix, "/");

                if (*prefix == 0)
                        return (char*) path;

                if (*path == 0)
                        return NULL;

                a = strcspn(path, "/");
                b = strcspn(prefix, "/");

                if (a != b)
                        return NULL;

                if (memcmp(path, prefix, a) != 0)
                        return NULL;

                path += a;
                prefix += b;
        }
}

int path_compare(const char *a, const char *b) {
        int d;

        assert(a);
        assert(b);

        /* A relative path and an abolute path must not compare as equal.
         * Which one is sorted before the other does not really matter.
         * Here a relative path is ordered before an absolute path. */
        d = (a[0] == '/') - (b[0] == '/');
        if (d)
                return d;

        for (;;) {
                size_t j, k;

                a += strspn(a, "/");
                b += strspn(b, "/");

                if (*a == 0 && *b == 0)
                        return 0;

                /* Order prefixes first: "/foo" before "/foo/bar" */
                if (*a == 0)
                        return -1;
                if (*b == 0)
                        return 1;

                j = strcspn(a, "/");
                k = strcspn(b, "/");

                /* Alphabetical sort: "/foo/aaa" before "/foo/b" */
                d = memcmp(a, b, MIN(j, k));
                if (d)
                        return (d > 0) - (d < 0); /* sign of d */

                /* Sort "/foo/a" before "/foo/aaa" */
                d = (j > k) - (j < k);  /* sign of (j - k) */
                if (d)
                        return d;

                a += j;
                b += k;
        }
}

bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

bool path_equal_or_files_same(const char *a, const char *b) {
        return path_equal(a, b) || files_same(a, b) > 0;
}

char* path_join(const char *root, const char *path, const char *rest) {
        assert(path);

        if (!isempty(root))
                return strjoin(root, endswith(root, "/") ? "" : "/",
                               path[0] == '/' ? path+1 : path,
                               rest ? (endswith(path, "/") ? "" : "/") : NULL,
                               rest && rest[0] == '/' ? rest+1 : rest,
                               NULL);
        else
                return strjoin(path,
                               rest ? (endswith(path, "/") ? "" : "/") : NULL,
                               rest && rest[0] == '/' ? rest+1 : rest,
                               NULL);
}

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *mnt_id) {
        char path[strlen("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        _cleanup_close_ int subfd = -1;
        char *p;
        int r;

        if ((flags & AT_EMPTY_PATH) && isempty(filename))
                xsprintf(path, "/proc/self/fdinfo/%i", fd);
        else {
                subfd = openat(fd, filename, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_PATH);
                if (subfd < 0)
                        return -errno;

                xsprintf(path, "/proc/self/fdinfo/%i", subfd);
        }

        r = read_full_file(path, &fdinfo, NULL);
        if (r == -ENOENT) /* The fdinfo directory is a relatively new addition */
                return -EOPNOTSUPP;
        if (r < 0)
                return -errno;

        p = startswith(fdinfo, "mnt_id:");
        if (!p) {
                p = strstr(fdinfo, "\nmnt_id:");
                if (!p) /* The mnt_id field is a relatively new addition */
                        return -EOPNOTSUPP;

                p += 8;
        }

        p += strspn(p, WHITESPACE);
        p[strcspn(p, WHITESPACE)] = 0;

        return safe_atoi(p, mnt_id);
}

int fd_is_mount_point(int fd, const char *filename, int flags) {
        union file_handle_union h = FILE_HANDLE_INIT, h_parent = FILE_HANDLE_INIT;
        int mount_id = -1, mount_id_parent = -1;
        bool nosupp = false, check_st_dev = true;
        struct stat a, b;
        int r;

        assert(fd >= 0);
        assert(filename);

        /* First we will try the name_to_handle_at() syscall, which
         * tells us the mount id and an opaque file "handle". It is
         * not supported everywhere though (kernel compile-time
         * option, not all file systems are hooked up). If it works
         * the mount id is usually good enough to tell us whether
         * something is a mount point.
         *
         * If that didn't work we will try to read the mount id from
         * /proc/self/fdinfo/<fd>. This is almost as good as
         * name_to_handle_at(), however, does not return the
         * opaque file handle. The opaque file handle is pretty useful
         * to detect the root directory, which we should always
         * consider a mount point. Hence we use this only as
         * fallback. Exporting the mnt_id in fdinfo is a pretty recent
         * kernel addition.
         *
         * As last fallback we do traditional fstat() based st_dev
         * comparisons. This is how things were traditionally done,
         * but unionfs breaks breaks this since it exposes file
         * systems with a variety of st_dev reported. Also, btrfs
         * subvolumes have different st_dev, even though they aren't
         * real mounts of their own. */

        r = name_to_handle_at(fd, filename, &h.handle, &mount_id, flags);
        if (r < 0) {
                if (errno == ENOSYS)
                        /* This kernel does not support name_to_handle_at()
                         * fall back to simpler logic. */
                        goto fallback_fdinfo;
                else if (errno == EOPNOTSUPP)
                        /* This kernel or file system does not support
                         * name_to_handle_at(), hence let's see if the
                         * upper fs supports it (in which case it is a
                         * mount point), otherwise fallback to the
                         * traditional stat() logic */
                        nosupp = true;
                else
                        return -errno;
        }

        r = name_to_handle_at(fd, "", &h_parent.handle, &mount_id_parent, AT_EMPTY_PATH);
        if (r < 0) {
                if (errno == EOPNOTSUPP) {
                        if (nosupp)
                                /* Neither parent nor child do name_to_handle_at()?
                                   We have no choice but to fall back. */
                                goto fallback_fdinfo;
                        else
                                /* The parent can't do name_to_handle_at() but the
                                 * directory we are interested in can?
                                 * If so, it must be a mount point. */
                                return 1;
                } else
                        return -errno;
        }

        /* The parent can do name_to_handle_at() but the
         * directory we are interested in can't? If so, it
         * must be a mount point. */
        if (nosupp)
                return 1;

        /* If the file handle for the directory we are
         * interested in and its parent are identical, we
         * assume this is the root directory, which is a mount
         * point. */

        if (h.handle.handle_bytes == h_parent.handle.handle_bytes &&
            h.handle.handle_type == h_parent.handle.handle_type &&
            memcmp(h.handle.f_handle, h_parent.handle.f_handle, h.handle.handle_bytes) == 0)
                return 1;

        return mount_id != mount_id_parent;

fallback_fdinfo:
        r = fd_fdinfo_mnt_id(fd, filename, flags, &mount_id);
        if (r == -EOPNOTSUPP)
                goto fallback_fstat;
        if (r < 0)
                return r;

        r = fd_fdinfo_mnt_id(fd, "", AT_EMPTY_PATH, &mount_id_parent);
        if (r < 0)
                return r;

        if (mount_id != mount_id_parent)
                return 1;

        /* Hmm, so, the mount ids are the same. This leaves one
         * special case though for the root file system. For that,
         * let's see if the parent directory has the same inode as we
         * are interested in. Hence, let's also do fstat() checks now,
         * too, but avoid the st_dev comparisons, since they aren't
         * that useful on unionfs mounts. */
        check_st_dev = false;

fallback_fstat:
        /* yay for fstatat() taking a different set of flags than the other
         * _at() above */
        if (flags & AT_SYMLINK_FOLLOW)
                flags &= ~AT_SYMLINK_FOLLOW;
        else
                flags |= AT_SYMLINK_NOFOLLOW;
        if (fstatat(fd, filename, &a, flags) < 0)
                return -errno;

        if (fstatat(fd, "", &b, AT_EMPTY_PATH) < 0)
                return -errno;

        /* A directory with same device and inode as its parent? Must
         * be the root directory */
        if (a.st_dev == b.st_dev &&
            a.st_ino == b.st_ino)
                return 1;

        return check_st_dev && (a.st_dev != b.st_dev);
}

/* flags can be AT_SYMLINK_FOLLOW or 0 */
int path_is_mount_point(const char *t, int flags) {
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *canonical = NULL, *parent = NULL;
        int r;

        assert(t);

        if (path_equal(t, "/"))
                return 1;

        /* we need to resolve symlinks manually, we can't just rely on
         * fd_is_mount_point() to do that for us; if we have a structure like
         * /bin -> /usr/bin/ and /usr is a mount point, then the parent that we
         * look at needs to be /usr, not /. */
        if (flags & AT_SYMLINK_FOLLOW) {
                canonical = canonicalize_file_name(t);
                if (!canonical)
                        return -errno;

                t = canonical;
        }

        r = path_get_parent(t, &parent);
        if (r < 0)
                return r;

        fd = openat(AT_FDCWD, parent, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_PATH);
        if (fd < 0)
                return -errno;

        return fd_is_mount_point(fd, basename(t), flags);
}

int path_is_read_only_fs(const char *path) {
        struct statvfs st;

        assert(path);

        if (statvfs(path, &st) < 0)
                return -errno;

        if (st.f_flag & ST_RDONLY)
                return true;

        /* On NFS, statvfs() might not reflect whether we can actually
         * write to the remote share. Let's try again with
         * access(W_OK) which is more reliable, at least sometimes. */
        if (access(path, W_OK) < 0 && errno == EROFS)
                return true;

        return false;
}

int path_is_os_tree(const char *path) {
        char *p;
        int r;

        /* We use /usr/lib/os-release as flag file if something is an OS */
        p = strjoina(path, "/usr/lib/os-release");
        r = access(p, F_OK);

        if (r >= 0)
                return 1;

        /* Also check for the old location in /etc, just in case. */
        p = strjoina(path, "/etc/os-release");
        r = access(p, F_OK);

        return r >= 0;
}

int find_binary(const char *name, bool local, char **filename) {
        assert(name);

        if (is_path(name)) {
                if (local && access(name, X_OK) < 0)
                        return -errno;

                if (filename) {
                        char *p;

                        p = path_make_absolute_cwd(name);
                        if (!p)
                                return -ENOMEM;

                        *filename = p;
                }

                return 0;
        } else {
                const char *path;
                const char *word, *state;
                size_t l;

                /**
                 * Plain getenv, not secure_getenv, because we want
                 * to actually allow the user to pick the binary.
                 */
                path = getenv("PATH");
                if (!path)
                        path = DEFAULT_PATH;

                FOREACH_WORD_SEPARATOR(word, l, path, ":", state) {
                        _cleanup_free_ char *p = NULL;

                        if (asprintf(&p, "%.*s/%s", (int) l, word, name) < 0)
                                return -ENOMEM;

                        if (access(p, X_OK) < 0)
                                continue;

                        if (filename) {
                                *filename = path_kill_slashes(p);
                                p = NULL;
                        }

                        return 0;
                }

                return -ENOENT;
        }
}

bool paths_check_timestamp(const char* const* paths, usec_t *timestamp, bool update) {
        bool changed = false;
        const char* const* i;

        assert(timestamp);

        if (paths == NULL)
                return false;

        STRV_FOREACH(i, paths) {
                struct stat stats;
                usec_t u;

                if (stat(*i, &stats) < 0)
                        continue;

                u = timespec_load(&stats.st_mtim);

                /* first check */
                if (*timestamp >= u)
                        continue;

                log_debug("timestamp of '%s' changed", *i);

                /* update timestamp */
                if (update) {
                        *timestamp = u;
                        changed = true;
                } else
                        return true;
        }

        return changed;
}

int fsck_exists(const char *fstype) {
        _cleanup_free_ char *p = NULL, *d = NULL;
        const char *checker;
        int r;

        checker = strjoina("fsck.", fstype);

        r = find_binary(checker, true, &p);
        if (r < 0)
                return r;

        /* An fsck that is linked to /bin/true is a non-existent
         * fsck */

        r = readlink_malloc(p, &d);
        if (r >= 0 &&
            (path_equal(d, "/bin/true") ||
             path_equal(d, "/usr/bin/true") ||
             path_equal(d, "/dev/null")))
                return -ENOENT;

        return 0;
}

char *prefix_root(const char *root, const char *path) {
        char *n, *p;
        size_t l;

        /* If root is passed, prefixes path with it. Otherwise returns
         * it as is. */

        assert(path);

        /* First, drop duplicate prefixing slashes from the path */
        while (path[0] == '/' && path[1] == '/')
                path++;

        if (isempty(root) || path_equal(root, "/"))
                return strdup(path);

        l = strlen(root) + 1 + strlen(path) + 1;

        n = new(char, l);
        if (!n)
                return NULL;

        p = stpcpy(n, root);

        while (p > n && p[-1] == '/')
                p--;

        if (path[0] != '/')
                *(p++) = '/';

        strcpy(p, path);
        return n;
}
