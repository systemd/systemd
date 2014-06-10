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

#include "label.h"
#include "util.h"
#include "path-util.h"
#include "mkdir.h"

int mkdir_safe_internal(const char *path, mode_t mode, uid_t uid, gid_t gid, mkdir_func_t _mkdir) {
        struct stat st;

        if (_mkdir(path, mode) >= 0)
                if (chmod_and_chown(path, mode, uid, gid) < 0)
                        return -errno;

        if (lstat(path, &st) < 0)
                return -errno;

        if ((st.st_mode & 0007) > (mode & 0007) ||
            (st.st_mode & 0070) > (mode & 0070) ||
            (st.st_mode & 0700) > (mode & 0700) ||
            (uid != (uid_t) -1 && st.st_uid != uid) ||
            (gid != (gid_t) -1 && st.st_gid != gid) ||
            !S_ISDIR(st.st_mode)) {
                errno = EEXIST;
                return -errno;
        }

        return 0;
}

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        return mkdir_safe_internal(path, mode, uid, gid, mkdir);
}

int is_dir(const char* path, bool follow) {
        struct stat st;

        if (follow) {
                if (stat(path, &st) < 0)
                        return -errno;
        } else {
                if (lstat(path, &st) < 0)
                        return -errno;
        }

        return S_ISDIR(st.st_mode);
}

int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir) {
        const char *p, *e;
        int r;

        assert(path);

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

                /* Is this the last component? If so, then we're
                 * done */
                if (*p == 0)
                        return 0;

                memcpy(t, path, e - path);
                t[e-path] = 0;

                if (prefix && path_startswith(prefix, t))
                        continue;

                r = _mkdir(t, mode);
                if (r < 0 && errno != EEXIST)
                        return -errno;
        }
}

int mkdir_parents(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, mkdir);
}

int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir) {
        int r;

        /* Like mkdir -p */

        r = mkdir_parents_internal(prefix, path, mode, _mkdir);
        if (r < 0)
                return r;

        r = _mkdir(path, mode);
        if (r < 0 && (errno != EEXIST || is_dir(path, true) <= 0))
                return -errno;

        return 0;
}

int mkdir_p(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, mkdir);
}

int mkdir_p_prefix(const char *prefix, const char *path, mode_t mode) {
        return mkdir_p_internal(prefix, path, mode, mkdir);
}
