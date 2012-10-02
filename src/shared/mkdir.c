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

#include "mkdir.h"
#include "label.h"
#include "util.h"

int mkdir_label(const char *path, mode_t mode) {
        return label_mkdir(path, mode, true);
}

static int makedir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid, bool apply) {
        struct stat st;

        if (label_mkdir(path, mode, apply) >= 0)
                if (chmod_and_chown(path, mode, uid, gid) < 0)
                        return -errno;

        if (lstat(path, &st) < 0)
                return -errno;

        if ((st.st_mode & 0777) != mode ||
            st.st_uid != uid ||
            st.st_gid != gid ||
            !S_ISDIR(st.st_mode)) {
                errno = EEXIST;
                return -errno;
        }

        return 0;
}

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        return makedir_safe(path, mode, uid, gid, false);
}

int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        return makedir_safe(path, mode, uid, gid, true);
}

static int makedir_parents(const char *path, mode_t mode, bool apply) {
        struct stat st;
        const char *p, *e;

        assert(path);

        /* return immediately if directory exists */
        e = strrchr(path, '/');
        if (!e)
                return -EINVAL;
        p = strndupa(path, e - path);
        if (stat(p, &st) >= 0) {
                if ((st.st_mode & S_IFMT) == S_IFDIR)
                        return 0;
                else
                        return -ENOTDIR;
        }

        /* create every parent directory in the path, except the last component */
        p = path + strspn(path, "/");
        for (;;) {
                int r;
                char *t;

                e = p + strcspn(p, "/");
                p = e + strspn(e, "/");

                /* Is this the last component? If so, then we're
                 * done */
                if (*p == 0)
                        return 0;

                t = strndup(path, e - path);
                if (!t)
                        return -ENOMEM;

                r = label_mkdir(t, mode, apply);
                free(t);

                if (r < 0 && errno != EEXIST)
                        return -errno;
        }
}

int mkdir_parents(const char *path, mode_t mode) {
        return makedir_parents(path, mode, false);
}

int mkdir_parents_label(const char *path, mode_t mode) {
        return makedir_parents(path, mode, true);
}

static int is_dir(const char* path) {
        struct stat st;
        if (stat(path, &st) < 0)
                return -errno;
        return S_ISDIR(st.st_mode);
}

static int makedir_p(const char *path, mode_t mode, bool apply) {
        int r;

        /* Like mkdir -p */

        r = makedir_parents(path, mode, apply);
        if (r < 0)
                return r;

        r = label_mkdir(path, mode, apply);
        if (r < 0 && (errno != EEXIST || is_dir(path) <= 0))
                return -errno;

        return 0;
}

int mkdir_p(const char *path, mode_t mode) {
        return makedir_p(path, mode, false);
}

int mkdir_p_label(const char *path, mode_t mode) {
        return makedir_p(path, mode, true);
}
