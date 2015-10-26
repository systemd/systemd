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

#include <dirent.h>
#include <errno.h>
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
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int files_add(Hashmap *h, const char *root, const char *path, const char *suffix) {
        _cleanup_closedir_ DIR *dir = NULL;
        const char *dirpath;
        int r;

        assert(path);
        assert(suffix);

        dirpath = prefix_roota(root, path);

        dir = opendir(dirpath);
        if (!dir) {
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        for (;;) {
                struct dirent *de;
                char *p;

                errno = 0;
                de = readdir(dir);
                if (!de && errno != 0)
                        return -errno;

                if (!de)
                        break;

                if (!dirent_is_file_with_suffix(de, suffix))
                        continue;

                p = strjoin(dirpath, "/", de->d_name, NULL);
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

static int conf_files_list_strv_internal(char ***strv, const char *suffix, const char *root, char **dirs) {
        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        char **files, **p;
        int r;

        assert(strv);
        assert(suffix);

        /* This alters the dirs string array */
        if (!path_strv_resolve_uniq(dirs, root))
                return -ENOMEM;

        fh = hashmap_new(&string_hash_ops);
        if (!fh)
                return -ENOMEM;

        STRV_FOREACH(p, dirs) {
                r = files_add(fh, root, *p, suffix);
                if (r == -ENOMEM) {
                        return r;
                } else if (r < 0)
                        log_debug_errno(r, "Failed to search for files in %s: %m",
                                        *p);
        }

        files = hashmap_get_strv(fh);
        if (files == NULL) {
                return -ENOMEM;
        }

        qsort_safe(files, hashmap_size(fh), sizeof(char *), base_cmp);
        *strv = files;

        return 0;
}

int conf_files_list_strv(char ***strv, const char *suffix, const char *root, const char* const* dirs) {
        _cleanup_strv_free_ char **copy = NULL;

        assert(strv);
        assert(suffix);

        copy = strv_copy((char**) dirs);
        if (!copy)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, copy);
}

int conf_files_list(char ***strv, const char *suffix, const char *root, const char *dir, ...) {
        _cleanup_strv_free_ char **dirs = NULL;
        va_list ap;

        assert(strv);
        assert(suffix);

        va_start(ap, dir);
        dirs = strv_new_ap(dir, ap);
        va_end(ap);

        if (!dirs)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, dirs);
}

int conf_files_list_nulstr(char ***strv, const char *suffix, const char *root, const char *d) {
        _cleanup_strv_free_ char **dirs = NULL;

        assert(strv);
        assert(suffix);

        dirs = strv_split_nulstr(d);
        if (!dirs)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, dirs);
}
