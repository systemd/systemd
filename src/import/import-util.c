/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "util.h"
#include "strv.h"
#include "copy.h"
#include "btrfs-util.h"
#include "import-util.h"

#define FILENAME_ESCAPE "/.#\"\'"

bool http_etag_is_valid(const char *etag) {
        if (!endswith(etag, "\""))
                return false;

        if (!startswith(etag, "\"") && !startswith(etag, "W/\""))
                return false;

        return true;
}

int import_find_old_etags(const char *url, const char *image_root, int dt, const char *prefix, const char *suffix, char ***etags) {
        _cleanup_free_ char *escaped_url = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_strv_free_ char **l = NULL;
        struct dirent *de;
        int r;

        assert(url);
        assert(etags);

        if (!image_root)
                image_root = "/var/lib/machines";

        escaped_url = xescape(url, FILENAME_ESCAPE);
        if (!escaped_url)
                return -ENOMEM;

        d = opendir(image_root);
        if (!d) {
                if (errno == ENOENT) {
                        *etags = NULL;
                        return 0;
                }

                return -errno;
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                const char *a, *b;
                char *u;

                if (de->d_type != DT_UNKNOWN &&
                    de->d_type != dt)
                        continue;

                if (prefix) {
                        a = startswith(de->d_name, prefix);
                        if (!a)
                                continue;
                } else
                        a = de->d_name;

                a = startswith(a, escaped_url);
                if (!a)
                        continue;

                a = startswith(a, ".");
                if (!a)
                        continue;

                if (suffix) {
                        b = endswith(de->d_name, suffix);
                        if (!b)
                                continue;
                } else
                        b = strchr(de->d_name, 0);

                if (a >= b)
                        continue;

                u = cunescape_length(a, b - a);
                if (!u)
                        return -ENOMEM;

                if (!http_etag_is_valid(u)) {
                        free(u);
                        continue;
                }

                r = strv_consume(&l, u);
                if (r < 0)
                        return r;
        }

        *etags = l;
        l = NULL;

        return 0;
}

int import_make_local_copy(const char *final, const char *image_root, const char *local, bool force_local) {
        const char *p;
        int r;

        assert(final);
        assert(local);

        if (!image_root)
                image_root = "/var/lib/machines";

        p = strappenda(image_root, "/", local);

        if (force_local) {
                (void) btrfs_subvol_remove(p);
                (void) rm_rf_dangerous(p, false, true, false);
        }

        r = btrfs_subvol_snapshot(final, p, false, false);
        if (r == -ENOTTY) {
                r = copy_tree(final, p, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy image: %m");
        } else if (r < 0)
                return log_error_errno(r, "Failed to create local image: %m");

        log_info("Created new local image '%s'.", local);

        return 0;
}

int import_make_read_only_fd(int fd) {
        int r;

        assert(fd >= 0);

        /* First, let's make this a read-only subvolume if it refers
         * to a subvolume */
        r = btrfs_subvol_set_read_only_fd(fd, true);
        if (r == -ENOTTY || r == -ENOTDIR || r == -EINVAL) {
                struct stat st;

                /* This doesn't refer to a subvolume, or the file
                 * system isn't even btrfs. In that, case fall back to
                 * chmod()ing */

                r = fstat(fd, &st);
                if (r < 0)
                        return log_error_errno(errno, "Failed to stat temporary image: %m");

                /* Drop "w" flag */
                if (fchmod(fd, st.st_mode & 07555) < 0)
                        return log_error_errno(errno, "Failed to chmod() final image: %m");

                return 0;

        } else if (r < 0)
                return log_error_errno(r, "Failed to make subvolume read-only: %m");

        return 0;
}

int import_make_read_only(const char *path) {
        _cleanup_close_ int fd = 1;

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        return import_make_read_only_fd(fd);
}

int import_make_path(const char *url, const char *etag, const char *image_root, const char *prefix, const char *suffix, char **ret) {
        _cleanup_free_ char *escaped_url = NULL;
        char *path;

        assert(url);
        assert(ret);

        if (!image_root)
                image_root = "/var/lib/machines";

        escaped_url = xescape(url, FILENAME_ESCAPE);
        if (!escaped_url)
                return -ENOMEM;

        if (etag) {
                _cleanup_free_ char *escaped_etag = NULL;

                escaped_etag = xescape(etag, FILENAME_ESCAPE);
                if (!escaped_etag)
                        return -ENOMEM;

                path = strjoin(image_root, "/", strempty(prefix), escaped_url, ".", escaped_etag, strempty(suffix), NULL);
        } else
                path = strjoin(image_root, "/", strempty(prefix), escaped_url, strempty(suffix), NULL);
        if (!path)
                return -ENOMEM;

        *ret = path;
        return 0;
}

int import_url_last_component(const char *url, char **ret) {
        const char *e, *p;
        char *s;

        e = strchrnul(url, '?');

        while (e > url && e[-1] == '/')
                e--;

        p = e;
        while (p > url && p[-1] != '/')
                p--;

        if (e <= p)
                return -EINVAL;

        s = strndup(p, e - p);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}


int import_url_change_last_component(const char *url, const char *suffix, char **ret) {
        const char *e;
        char *s;

        assert(url);
        assert(ret);

        e = strchrnul(url, '?');

        while (e > url && e[-1] == '/')
                e--;

        while (e > url && e[-1] != '/')
                e--;

        if (e <= url)
                return -EINVAL;

        s = new(char, (e - url) + strlen(suffix) + 1);
        if (!s)
                return -ENOMEM;

        strcpy(mempcpy(s, url, e - url), suffix);
        *ret = s;
        return 0;
}

static const char* const import_verify_table[_IMPORT_VERIFY_MAX] = {
        [IMPORT_VERIFY_NO] = "no",
        [IMPORT_VERIFY_SUM] = "sum",
        [IMPORT_VERIFY_SIGNATURE] = "signature",
};

DEFINE_STRING_TABLE_LOOKUP(import_verify, ImportVerify);
