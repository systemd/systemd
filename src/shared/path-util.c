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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/statvfs.h>

#include "macro.h"
#include "util.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"
#include "missing.h"

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

        return path_make_absolute(p, cwd);
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

bool path_equal(const char *a, const char *b) {
        assert(a);
        assert(b);

        if ((a[0] == '/') != (b[0] == '/'))
                return false;

        for (;;) {
                size_t j, k;

                a += strspn(a, "/");
                b += strspn(b, "/");

                if (*a == 0 && *b == 0)
                        return true;

                if (*a == 0 || *b == 0)
                        return false;

                j = strcspn(a, "/");
                k = strcspn(b, "/");

                if (j != k)
                        return false;

                if (memcmp(a, b, j) != 0)
                        return false;

                a += j;
                b += k;
        }
}

int path_is_mount_point(const char *t, bool allow_symlink) {

        union file_handle_union h = {
                .handle.handle_bytes = MAX_HANDLE_SZ
        };

        int mount_id, mount_id_parent;
        _cleanup_free_ char *parent = NULL;
        struct stat a, b;
        int r;

        /* We are not actually interested in the file handles, but
         * name_to_handle_at() also passes us the mount ID, hence use
         * it but throw the handle away */

        if (path_equal(t, "/"))
                return 1;

        r = name_to_handle_at(AT_FDCWD, t, &h.handle, &mount_id, allow_symlink ? AT_SYMLINK_FOLLOW : 0);
        if (r < 0) {
                if (IN_SET(errno, ENOSYS, EOPNOTSUPP))
                        /* This kernel or file system does not support
                         * name_to_handle_at(), hence fallback to the
                         * traditional stat() logic */
                        goto fallback;

                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        r = path_get_parent(t, &parent);
        if (r < 0)
                return r;

        h.handle.handle_bytes = MAX_HANDLE_SZ;
        r = name_to_handle_at(AT_FDCWD, parent, &h.handle, &mount_id_parent, 0);
        if (r < 0) {
                /* The parent can't do name_to_handle_at() but the
                 * directory we are interested in can? If so, it must
                 * be a mount point */
                if (errno == EOPNOTSUPP)
                        return 1;

                return -errno;
        }

        return mount_id != mount_id_parent;

fallback:
        if (allow_symlink)
                r = stat(t, &a);
        else
                r = lstat(t, &a);

        if (r < 0) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        r = path_get_parent(t, &parent);
        if (r < 0)
                return r;

        r = lstat(parent, &b);
        if (r < 0)
                return -errno;

        return a.st_dev != b.st_dev;
}

int path_is_read_only_fs(const char *path) {
        struct statvfs st;

        assert(path);

        if (statvfs(path, &st) < 0)
                return -errno;

        return !!(st.f_flag & ST_RDONLY);
}

int path_is_os_tree(const char *path) {
        char *p;
        int r;

        /* We use /usr/lib/os-release as flag file if something is an OS */
        p = strappenda(path, "/usr/lib/os-release");
        r = access(p, F_OK);

        if (r >= 0)
                return 1;

        /* Also check for the old location in /etc, just in case. */
        p = strappenda(path, "/etc/os-release");
        r = access(p, F_OK);

        return r >= 0;
}

int find_binary(const char *name, char **filename) {
        assert(name);

        if (is_path(name)) {
                if (access(name, X_OK) < 0)
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
                char *state, *w;
                size_t l;

                /**
                 * Plain getenv, not secure_getenv, because we want
                 * to actually allow the user to pick the binary.
                 */
                path = getenv("PATH");
                if (!path)
                        path = DEFAULT_PATH;

                FOREACH_WORD_SEPARATOR(w, l, path, ":", state) {
                        _cleanup_free_ char *p = NULL;

                        if (asprintf(&p, "%.*s/%s", (int) l, w, name) < 0)
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

        checker = strappenda("fsck.", fstype);

        r = find_binary(checker, &p);
        if (r < 0)
                return r;

        /* An fsck that is linked to /bin/true is a non-existant
         * fsck */

        r = readlink_malloc(p, &d);
        if (r >= 0 &&
            (path_equal(d, "/bin/true") ||
             path_equal(d, "/usr/bin/true") ||
             path_equal(d, "/dev/null")))
                return -ENOENT;

        return 0;
}
