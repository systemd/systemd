/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <sys/statfs.h>

#include "strv.h"
#include "utf8.h"
#include "btrfs-util.h"
#include "path-util.h"
#include "image.h"

static const char image_search_path[] =
        "/var/lib/container\0"
        "/var/lib/machine\0";

Image *image_unref(Image *i) {
        if (!i)
                return NULL;

        free(i->name);
        free(i->path);
        free(i);
        return NULL;
}

static int image_new(
                ImageType t,
                const char *name,
                const char *path,
                bool read_only,
                usec_t crtime,
                usec_t mtime,
                Image **ret) {

        _cleanup_(image_unrefp) Image *i = NULL;

        assert(t >= 0);
        assert(t < _IMAGE_TYPE_MAX);
        assert(name);
        assert(ret);

        i = new0(Image, 1);
        if (!i)
                return -ENOMEM;

        i->type = t;
        i->read_only = read_only;
        i->crtime = crtime;
        i->mtime = mtime;

        i->name = strdup(name);
        if (!i->name)
                return -ENOMEM;

        if (path) {
                i->path = strjoin(path, "/", name, NULL);
                if (!i->path)
                        return -ENOMEM;

                path_kill_slashes(i->path);
        }

        *ret = i;
        i = NULL;

        return 0;
}

static int image_make(int dfd, const char *name, const char *path, Image **ret) {
        struct stat st;
        bool writable;
        int r;

        assert(dfd >= 0);
        assert(name);

        /* We explicitly *do* follow symlinks here, since we want to
         * allow symlinking trees into /var/lib/container/, and treat
         * them normally. */

        if (fstatat(dfd, name, &st, 0) < 0)
                return -errno;

        writable = faccessat(dfd, name, W_OK, AT_EACCESS) >= 0;

        if (S_ISDIR(st.st_mode)) {

                if (!ret)
                        return 1;

                /* btrfs subvolumes have inode 256 */
                if (st.st_ino == 256) {
                        _cleanup_close_ int fd = -1;
                        struct statfs sfs;

                        fd = openat(dfd, name, O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                        if (fd < 0)
                                return -errno;

                        if (fstatfs(fd, &sfs) < 0)
                                return -errno;

                        if (F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC)) {
                                BtrfsSubvolInfo info;

                                /* It's a btrfs subvolume */

                                r = btrfs_subvol_get_info_fd(fd, &info);
                                if (r < 0)
                                        return r;

                                r = image_new(IMAGE_SUBVOLUME,
                                              name,
                                              path,
                                              info.read_only || !writable,
                                              info.otime,
                                              0,
                                              ret);
                                if (r < 0)
                                        return r;

                                return 1;
                        }
                }

                /* It's just a normal directory. */

                r = image_new(IMAGE_DIRECTORY,
                              name,
                              path,
                              !writable,
                              0,
                              0,
                              ret);
                if (r < 0)
                        return r;

                return 1;

        } else if (S_ISREG(st.st_mode) && endswith(name, ".gpt")) {
                const char *truncated;
                usec_t crtime = 0;

                /* It's a GPT block device */

                if (!ret)
                        return 1;

                fd_getcrtime_at(dfd, name, &crtime, 0);

                truncated = strndupa(name, strlen(name) - 4);

                r = image_new(IMAGE_GPT,
                              truncated,
                              path,
                              !(st.st_mode & 0222) || !writable,
                              crtime,
                              timespec_load(&st.st_mtim),
                              ret);
                if (r < 0)
                        return r;

                return 1;
        }

        return 0;
}

int image_find(const char *name, Image **ret) {
        const char *path;
        int r;

        assert(name);

        /* There are no images with invalid names */
        if (!image_name_is_valid(name))
                return 0;

        NULSTR_FOREACH(path, image_search_path) {
                _cleanup_closedir_ DIR *d = NULL;

                d = opendir(path);
                if (!d) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                r = image_make(dirfd(d), name, path, ret);
                if (r == 0 || r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                return 1;
        }

        return 0;
};

int image_discover(Hashmap *h) {
        const char *path;
        int r;

        assert(h);

        NULSTR_FOREACH(path, image_search_path) {
                _cleanup_closedir_ DIR *d = NULL;
                struct dirent *de;

                d = opendir(path);
                if (!d) {
                        if (errno == ENOENT)
                                return 0;

                        return -errno;
                }

                FOREACH_DIRENT_ALL(de, d, return -errno) {
                        _cleanup_(image_unrefp) Image *image = NULL;

                        if (!image_name_is_valid(de->d_name))
                                continue;

                        if (hashmap_contains(h, de->d_name))
                                continue;

                        r = image_make(dirfd(d), de->d_name, path, &image);
                        if (r == 0 || r == -ENOENT)
                                continue;
                        if (r < 0)
                                return r;

                        r = hashmap_put(h, image->name, image);
                        if (r < 0)
                                return r;

                        image = NULL;
                }
        }

        return 0;
}

void image_hashmap_free(Hashmap *map) {
        Image *i;

        while ((i = hashmap_steal_first(map)))
                image_unref(i);

        hashmap_free(map);
}

static const char* const image_type_table[_IMAGE_TYPE_MAX] = {
        [IMAGE_DIRECTORY] = "directory",
        [IMAGE_SUBVOLUME] = "subvolume",
        [IMAGE_GPT] = "gpt",
};

DEFINE_STRING_TABLE_LOOKUP(image_type, ImageType);
