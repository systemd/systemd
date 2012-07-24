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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>

#include "macro.h"
#include "util.h"
#include "missing.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"
#include "hashmap.h"
#include "conf-files.h"

static int files_add(Hashmap *h, const char *path, const char *suffix) {
        DIR *dir;
        struct dirent buffer, *de;
        int r = 0;

        dir = opendir(path);
        if (!dir) {
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        for (;;) {
                int k;
                char *p;

                k = readdir_r(dir, &buffer, &de);
                if (k != 0) {
                        r = -k;
                        goto finish;
                }

                if (!de)
                        break;

                if (!dirent_is_file_with_suffix(de, suffix))
                        continue;

                if (asprintf(&p, "%s/%s", path, de->d_name) < 0) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (hashmap_put(h, path_get_file_name(p), p) <= 0) {
                        log_debug("Skip overridden file: %s.", p);
                        free(p);
                }
        }

finish:
        closedir(dir);
        return r;
}

static int base_cmp(const void *a, const void *b) {
        const char *s1, *s2;

        s1 = *(char * const *)a;
        s2 = *(char * const *)b;
        return strcmp(path_get_file_name(s1), path_get_file_name(s2));
}

int conf_files_list_strv(char ***strv, const char *suffix, const char **dirs) {
        Hashmap *fh = NULL;
        char **files = NULL;
        const char **p;
        int r;

        assert(dirs);

        fh = hashmap_new(string_hash_func, string_compare_func);
        if (!fh) {
                r = -ENOMEM;
                goto finish;
        }

        STRV_FOREACH(p, dirs) {
                r = files_add(fh, *p, suffix);
                if (r < 0)
                        log_warning("Failed to search for files in %s: %s",
                                    *p, strerror(-r));
        }

        files = hashmap_get_strv(fh);
        if (files == NULL) {
                log_error("Failed to compose list of files.");
                r = -ENOMEM;
                goto finish;
        }
        qsort(files, hashmap_size(fh), sizeof(char *), base_cmp);
        r = 0;

finish:
        hashmap_free(fh);
        *strv = files;
        return r;
}

int conf_files_list(char ***strv, const char *suffix, const char *dir, ...) {
        char **dirs = NULL;
        va_list ap;
        int r;

        va_start(ap, dir);
        dirs = strv_new_ap(dir, ap);
        va_end(ap);
        if (!dirs) {
                r = -ENOMEM;
                goto finish;
        }

        if (!path_strv_canonicalize(dirs)) {
                r = -ENOMEM;
                goto finish;
        }
        strv_uniq(dirs);

        r = conf_files_list_strv(strv, suffix, (const char **)dirs);

finish:
        strv_free(dirs);
        return r;
}
