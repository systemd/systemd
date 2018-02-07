/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf-files.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int files_add(Hashmap *h, const char *suffix, const char *root, unsigned flags, const char *path) {
        _cleanup_closedir_ DIR *dir = NULL;
        const char *dirpath;
        struct dirent *de;
        int r;

        assert(path);

        dirpath = prefix_roota(root, path);

        dir = opendir(dirpath);
        if (!dir) {
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        FOREACH_DIRENT(de, dir, return -errno) {
                char *p;

                if (!dirent_is_file_with_suffix(de, suffix)) {
                        log_debug("Ignoring %s/%s, because it's not a regular file with suffix %s.", dirpath, de->d_name, strna(suffix));
                        continue;
                }

                if (flags & CONF_FILES_EXECUTABLE) {
                        struct stat st;

                        /* As requested: check if the file is marked exectuable. Note that we don't check access(X_OK)
                         * here, as we care about whether the file is marked executable at all, and not whether it is
                         * executable for us, because if such errors are stuff we should log about. */

                        if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) {
                                log_debug_errno(errno, "Failed to stat %s/%s, ignoring: %m", dirpath, de->d_name);
                                continue;
                        }

                        if (!null_or_empty(&st)) {
                                /* A mask is a symlink to /dev/null or an empty file. It does not even
                                 * have to be executable. Other entries must be regular executable files
                                 * or symlinks to them. */
                                if (S_ISREG(st.st_mode)) {
                                        if ((st.st_mode & 0111) == 0) { /* not executable */
                                                log_debug("Ignoring %s/%s, as it is not marked executable.",
                                                          dirpath, de->d_name);
                                                continue;
                                        }
                                } else {
                                        log_debug("Ignoring %s/%s, as it is neither a regular file nor a mask.",
                                                  dirpath, de->d_name);
                                        continue;
                                }
                        }
                }

                p = strjoin(dirpath, "/", de->d_name);
                if (!p)
                        return -ENOMEM;

                r = hashmap_put(h, basename(p), p);
                if (r == -EEXIST) {
                        log_debug("Skipping overridden file: %s.", p);
                        free(p);
                } else if (r < 0) {
                        free(p);
                        return r;
                } else if (r == 0) {
                        log_debug("Duplicate file %s", p);
                        free(p);
                }
        }

        return 0;
}

static int base_cmp(const void *a, const void *b) {
        const char *s1, *s2;

        s1 = *(char * const *)a;
        s2 = *(char * const *)b;
        return strcmp(basename(s1), basename(s2));
}

static int conf_files_list_strv_internal(char ***strv, const char *suffix, const char *root, unsigned flags, char **dirs) {
        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        char **files, **p;
        int r;

        assert(strv);

        /* This alters the dirs string array */
        if (!path_strv_resolve_uniq(dirs, root))
                return -ENOMEM;

        fh = hashmap_new(&string_hash_ops);
        if (!fh)
                return -ENOMEM;

        STRV_FOREACH(p, dirs) {
                r = files_add(fh, suffix, root, flags, *p);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to search for files in %s, ignoring: %m", *p);
        }

        files = hashmap_get_strv(fh);
        if (!files)
                return -ENOMEM;

        qsort_safe(files, hashmap_size(fh), sizeof(char *), base_cmp);
        *strv = files;

        return 0;
}

int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path) {
        /* Insert a path into strv, at the place honouring the usual sorting rules:
         * - we first compare by the basename
         * - and then we compare by dirname, allowing just one file with the given
         *   basename.
         * This means that we will
         * - add a new entry if basename(path) was not on the list,
         * - do nothing if an entry with higher priority was already present,
         * - do nothing if our new entry matches the existing entry,
         * - replace the existing entry if our new entry has higher priority.
         */
        char *t;
        unsigned i;
        int r;

        for (i = 0; i < strv_length(*strv); i++) {
                int c;

                c = base_cmp(*strv + i, &path);
                if (c == 0) {
                        char **dir;

                        /* Oh, we found our spot and it already contains something. */
                        STRV_FOREACH(dir, dirs) {
                                char *p1, *p2;

                                p1 = path_startswith((*strv)[i], root);
                                if (p1)
                                        /* Skip "/" in *dir, because p1 is without "/" too */
                                        p1 = path_startswith(p1, *dir + 1);
                                if (p1)
                                        /* Existing entry with higher priority
                                         * or same priority, no need to do anything. */
                                        return 0;

                                p2 = path_startswith(path, *dir);
                                if (p2) {
                                        /* Our new entry has higher priority */
                                        t = path_join(root, path, NULL);
                                        if (!t)
                                                return log_oom();

                                        return free_and_replace((*strv)[i], t);
                                }
                        }

                } else if (c > 0)
                        /* Following files have lower priority, let's go insert our
                         * new entry. */
                        break;

                /* … we are not there yet, let's continue */
        }

        t = path_join(root, path, NULL);
        if (!t)
                return log_oom();

        r = strv_insert(strv, i, t);
        if (r < 0)
                free(t);
        return r;
}

int conf_files_insert_nulstr(char ***strv, const char *root, const char *dirs, const char *path) {
        _cleanup_strv_free_ char **d = NULL;

        assert(strv);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_insert(strv, root, d, path);
}

int conf_files_list_strv(char ***strv, const char *suffix, const char *root, unsigned flags, const char* const* dirs) {
        _cleanup_strv_free_ char **copy = NULL;

        assert(strv);

        copy = strv_copy((char**) dirs);
        if (!copy)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, flags, copy);
}

int conf_files_list(char ***strv, const char *suffix, const char *root, unsigned flags, const char *dir, ...) {
        _cleanup_strv_free_ char **dirs = NULL;
        va_list ap;

        assert(strv);

        va_start(ap, dir);
        dirs = strv_new_ap(dir, ap);
        va_end(ap);

        if (!dirs)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, flags, dirs);
}

int conf_files_list_nulstr(char ***strv, const char *suffix, const char *root, unsigned flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(strv);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, flags, d);
}
