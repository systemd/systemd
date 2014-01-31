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

char **path_strv_canonicalize_absolute(char **l, const char *prefix) {
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

                if (!path_is_absolute(*s))
                        continue;

                if (prefix) {
                        t = strappend(prefix, *s);
                        free(*s);
                        *s = NULL;

                        if (!t) {
                                enomem = true;
                                continue;
                        }
                } else {
                        t = *s;
                        *s = NULL;
                }

                errno = 0;
                u = canonicalize_file_name(t);
                if (!u) {
                        if (errno == ENOENT)
                                u = t;
                        else {
                                free(t);
                                if (errno == ENOMEM || errno == 0)
                                        enomem = true;

                                continue;
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

char **path_strv_canonicalize_absolute_uniq(char **l, const char *prefix) {

        if (strv_isempty(l))
                return l;

        if (!path_strv_canonicalize_absolute(l, prefix))
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
        char *parent;
        int r;
        struct file_handle *h;
        int mount_id, mount_id_parent;
        struct stat a, b;

        /* We are not actually interested in the file handles, but
         * name_to_handle_at() also passes us the mount ID, hence use
         * it but throw the handle away */

        if (path_equal(t, "/"))
                return 1;

        h = alloca(MAX_HANDLE_SZ);
        h->handle_bytes = MAX_HANDLE_SZ;

        r = name_to_handle_at(AT_FDCWD, t, h, &mount_id, allow_symlink ? AT_SYMLINK_FOLLOW : 0);
        if (r < 0) {
                if (errno == ENOSYS || errno == ENOTSUP)
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

        h->handle_bytes = MAX_HANDLE_SZ;
        r = name_to_handle_at(AT_FDCWD, parent, h, &mount_id_parent, 0);
        free(parent);

        if (r < 0) {
                /* The parent can't do name_to_handle_at() but the
                 * directory we are interested in can? If so, it must
                 * be a mount point */
                if (errno == ENOTSUP)
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
        free(parent);

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

        /* We use /etc/os-release as flag file if something is an OS */

        p = strappenda(path, "/etc/os-release");
        r = access(p, F_OK);

        return r < 0 ? 0 : 1;
}

int find_binary(const char *name, char **filename) {
        assert(name);
        assert(filename);

        if (strchr(name, '/')) {
                char *p;

                if (path_is_absolute(name))
                        p = strdup(name);
                else
                        p = path_make_absolute_cwd(name);
                if (!p)
                        return -ENOMEM;

                *filename = p;
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
                        char *p;

                        if (asprintf(&p, "%.*s/%s", (int) l, w, name) < 0)
                                return -ENOMEM;

                        if (access(p, X_OK) < 0) {
                                free(p);
                                continue;
                        }

                        path_kill_slashes(p);
                        *filename = p;

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
