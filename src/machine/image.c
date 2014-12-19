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
#include "image.h"
#include "bus-label.h"

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
                usec_t mtime,
                usec_t btime,
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
        i->mtime = mtime;
        i->btime = btime;

        i->name = strdup(name);
        if (!i->name)
                return -ENOMEM;

        if (path) {
                i->path = strdup(path);
                if (!i->path)
                        return -ENOMEM;
        }

        *ret = i;
        i = NULL;

        return 0;
}

static int image_make(int dfd, const char *name, const char *path, Image **ret) {
        struct stat st;
        int r;

        assert(dfd >= 0);
        assert(name);

        /* We explicitly *do* follow symlinks here, since we want to
         * allow symlinking trees into /var/lib/container/, and treat
         * them normally. */

        if (fstatat(dfd, name, &st, 0) < 0)
                return -errno;

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
                                usec_t btime = 0;
                                int ro;

                                /* It's a btrfs subvolume */

                                ro = btrfs_subvol_is_read_only_fd(fd);
                                if (ro < 0)
                                        return ro;

                                /* r = btrfs_subvol_get_btime(fd, &btime); */
                                /* if (r < 0) */
                                /*         return r; */

                                r = image_new(IMAGE_SUBVOLUME,
                                              name,
                                              path,
                                              ro,
                                              0,
                                              btime,
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
                              false,
                              0,
                              0,
                              ret);
                if (r < 0)
                        return r;

                return 1;

        } else if (S_ISREG(st.st_mode) && endswith(name, ".gpt")) {

                /* It's a GPT block device */

                if (!ret)
                        return 1;

                r = image_new(IMAGE_GPT,
                              name,
                              path,
                              !!(st.st_mode & 0111),
                              timespec_load(&st.st_mtim),
                              0,
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

char *image_bus_path(const char *name) {
        _cleanup_free_ char *e = NULL;

        assert(name);

        e = bus_label_escape(name);
        if (!e)
                return NULL;

        return strappend("/org/freedesktop/machine1/image/", e);
}

static const char* const image_type_table[_IMAGE_TYPE_MAX] = {
        [IMAGE_DIRECTORY] = "directory",
        [IMAGE_SUBVOLUME] = "subvolume",
        [IMAGE_GPT] = "gpt",
};

DEFINE_STRING_TABLE_LOOKUP(image_type, ImageType);
