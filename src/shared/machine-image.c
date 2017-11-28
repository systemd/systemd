/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/fs.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "chattr-util.h"
#include "copy.h"
#include "dirent-util.h"
#include "dissect-image.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "lockfile-util.h"
#include "log.h"
#include "loop-util.h"
#include "machine-image.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "util.h"
#include "xattr-util.h"

static const char image_search_path[] =
        "/var/lib/machines\0"
        "/var/lib/container\0" /* legacy */
        "/usr/local/lib/machines\0"
        "/usr/lib/machines\0";

Image *image_unref(Image *i) {
        if (!i)
                return NULL;

        free(i->name);
        free(i->path);

        free(i->hostname);
        strv_free(i->machine_info);
        strv_free(i->os_release);

        return mfree(i);
}

static char **image_settings_path(Image *image) {
        _cleanup_strv_free_ char **l = NULL;
        char **ret;
        const char *fn, *s;
        unsigned i = 0;

        assert(image);

        l = new0(char*, 4);
        if (!l)
                return NULL;

        fn = strjoina(image->name, ".nspawn");

        FOREACH_STRING(s, "/etc/systemd/nspawn/", "/run/systemd/nspawn/") {
                l[i] = strappend(s, fn);
                if (!l[i])
                        return NULL;

                i++;
        }

        l[i] = file_in_same_dir(image->path, fn);
        if (!l[i])
                return NULL;

        ret = l;
        l = NULL;

        return ret;
}

static char *image_roothash_path(Image *image) {
        const char *fn;

        assert(image);

        fn = strjoina(image->name, ".roothash");

        return file_in_same_dir(image->path, fn);
}

static int image_new(
                ImageType t,
                const char *pretty,
                const char *path,
                const char *filename,
                bool read_only,
                usec_t crtime,
                usec_t mtime,
                Image **ret) {

        _cleanup_(image_unrefp) Image *i = NULL;

        assert(t >= 0);
        assert(t < _IMAGE_TYPE_MAX);
        assert(pretty);
        assert(filename);
        assert(ret);

        i = new0(Image, 1);
        if (!i)
                return -ENOMEM;

        i->type = t;
        i->read_only = read_only;
        i->crtime = crtime;
        i->mtime = mtime;
        i->usage = i->usage_exclusive = (uint64_t) -1;
        i->limit = i->limit_exclusive = (uint64_t) -1;

        i->name = strdup(pretty);
        if (!i->name)
                return -ENOMEM;

        if (path)
                i->path = strjoin(path, "/", filename);
        else
                i->path = strdup(filename);

        if (!i->path)
                return -ENOMEM;

        path_kill_slashes(i->path);

        *ret = i;
        i = NULL;

        return 0;
}

static int image_make(
                const char *pretty,
                int dfd,
                const char *path,
                const char *filename,
                Image **ret) {

        struct stat st;
        bool read_only;
        int r;

        assert(filename);

        /* We explicitly *do* follow symlinks here, since we want to allow symlinking trees, raw files and block
         * devices into /var/lib/machines/, and treat them normally. */

        if (fstatat(dfd, filename, &st, 0) < 0)
                return -errno;

        read_only =
                (path && path_startswith(path, "/usr")) ||
                (faccessat(dfd, filename, W_OK, AT_EACCESS) < 0 && errno == EROFS);

        if (S_ISDIR(st.st_mode)) {
                _cleanup_close_ int fd = -1;
                unsigned file_attr = 0;

                if (!ret)
                        return 1;

                if (!pretty)
                        pretty = filename;

                fd = openat(dfd, filename, O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                if (fd < 0)
                        return -errno;

                /* btrfs subvolumes have inode 256 */
                if (st.st_ino == 256) {

                        r = btrfs_is_filesystem(fd);
                        if (r < 0)
                                return r;
                        if (r) {
                                BtrfsSubvolInfo info;

                                /* It's a btrfs subvolume */

                                r = btrfs_subvol_get_info_fd(fd, 0, &info);
                                if (r < 0)
                                        return r;

                                r = image_new(IMAGE_SUBVOLUME,
                                              pretty,
                                              path,
                                              filename,
                                              info.read_only || read_only,
                                              info.otime,
                                              0,
                                              ret);
                                if (r < 0)
                                        return r;

                                if (btrfs_quota_scan_ongoing(fd) == 0) {
                                        BtrfsQuotaInfo quota;

                                        r = btrfs_subvol_get_subtree_quota_fd(fd, 0, &quota);
                                        if (r >= 0) {
                                                (*ret)->usage = quota.referenced;
                                                (*ret)->usage_exclusive = quota.exclusive;

                                                (*ret)->limit = quota.referenced_max;
                                                (*ret)->limit_exclusive = quota.exclusive_max;
                                        }
                                }

                                return 1;
                        }
                }

                /* If the IMMUTABLE bit is set, we consider the
                 * directory read-only. Since the ioctl is not
                 * supported everywhere we ignore failures. */
                (void) read_attr_fd(fd, &file_attr);

                /* It's just a normal directory. */
                r = image_new(IMAGE_DIRECTORY,
                              pretty,
                              path,
                              filename,
                              read_only || (file_attr & FS_IMMUTABLE_FL),
                              0,
                              0,
                              ret);
                if (r < 0)
                        return r;

                return 1;

        } else if (S_ISREG(st.st_mode) && endswith(filename, ".raw")) {
                usec_t crtime = 0;

                /* It's a RAW disk image */

                if (!ret)
                        return 1;

                fd_getcrtime_at(dfd, filename, &crtime, 0);

                if (!pretty)
                        pretty = strndupa(filename, strlen(filename) - 4);

                r = image_new(IMAGE_RAW,
                              pretty,
                              path,
                              filename,
                              !(st.st_mode & 0222) || read_only,
                              crtime,
                              timespec_load(&st.st_mtim),
                              ret);
                if (r < 0)
                        return r;

                (*ret)->usage = (*ret)->usage_exclusive = st.st_blocks * 512;
                (*ret)->limit = (*ret)->limit_exclusive = st.st_size;

                return 1;

        } else if (S_ISBLK(st.st_mode)) {
                _cleanup_close_ int block_fd = -1;
                uint64_t size = UINT64_MAX;

                /* A block device */

                if (!ret)
                        return 1;

                if (!pretty)
                        pretty = filename;

                block_fd = openat(dfd, filename, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                if (block_fd < 0)
                        log_debug_errno(errno, "Failed to open block device %s/%s, ignoring: %m", path, filename);
                else {
                        if (fstat(block_fd, &st) < 0)
                                return -errno;
                        if (!S_ISBLK(st.st_mode)) /* Verify that what we opened is actually what we think it is */
                                return -ENOTTY;

                        if (!read_only) {
                                int state = 0;

                                if (ioctl(block_fd, BLKROGET, &state) < 0)
                                        log_debug_errno(errno, "Failed to issue BLKROGET on device %s/%s, ignoring: %m", path, filename);
                                else if (state)
                                        read_only = true;
                        }

                        if (ioctl(block_fd, BLKGETSIZE64, &size) < 0)
                                log_debug_errno(errno, "Failed to issue BLKFLSBUF on device %s/%s, ignoring: %m", path, filename);

                        block_fd = safe_close(block_fd);
                }

                r = image_new(IMAGE_BLOCK,
                              pretty,
                              path,
                              filename,
                              !(st.st_mode & 0222) || read_only,
                              0,
                              0,
                              ret);
                if (r < 0)
                        return r;

                if (size != 0 && size != UINT64_MAX)
                        (*ret)->usage = (*ret)->usage_exclusive = (*ret)->limit = (*ret)->limit_exclusive = size;

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

                r = image_make(NULL, dirfd(d), path, name, ret);
                if (IN_SET(r, 0, -ENOENT)) {
                        _cleanup_free_ char *raw = NULL;

                        raw = strappend(name, ".raw");
                        if (!raw)
                                return -ENOMEM;

                        r = image_make(NULL, dirfd(d), path, raw, ret);
                        if (IN_SET(r, 0, -ENOENT))
                                continue;
                }
                if (r < 0)
                        return r;

                return 1;
        }

        if (streq(name, ".host"))
                return image_make(".host", AT_FDCWD, NULL, "/", ret);

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
                                continue;

                        return -errno;
                }

                FOREACH_DIRENT_ALL(de, d, return -errno) {
                        _cleanup_(image_unrefp) Image *image = NULL;

                        if (!image_name_is_valid(de->d_name))
                                continue;

                        if (hashmap_contains(h, de->d_name))
                                continue;

                        r = image_make(NULL, dirfd(d), path, de->d_name, &image);
                        if (IN_SET(r, 0, -ENOENT))
                                continue;
                        if (r < 0)
                                return r;

                        r = hashmap_put(h, image->name, image);
                        if (r < 0)
                                return r;

                        image = NULL;
                }
        }

        if (!hashmap_contains(h, ".host")) {
                _cleanup_(image_unrefp) Image *image = NULL;

                r = image_make(".host", AT_FDCWD, NULL, "/", &image);
                if (r < 0)
                        return r;

                r = hashmap_put(h, image->name, image);
                if (r < 0)
                        return r;

                image = NULL;

        }

        return 0;
}

int image_remove(Image *i) {
        _cleanup_release_lock_file_ LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        _cleanup_strv_free_ char **settings = NULL;
        _cleanup_free_ char *roothash = NULL;
        char **j;
        int r;

        assert(i);

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        settings = image_settings_path(i);
        if (!settings)
                return -ENOMEM;

        roothash = image_roothash_path(i);
        if (!roothash)
                return -ENOMEM;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:

                /* Let's unlink first, maybe it is a symlink? If that works we are happy. Otherwise, let's get out the
                 * big guns */
                if (unlink(i->path) < 0) {
                        r = btrfs_subvol_remove(i->path, BTRFS_REMOVE_RECURSIVE|BTRFS_REMOVE_QUOTA);
                        if (r < 0)
                                return r;
                }

                break;

        case IMAGE_DIRECTORY:
                /* Allow deletion of read-only directories */
                (void) chattr_path(i->path, 0, FS_IMMUTABLE_FL);
                r = rm_rf(i->path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                if (r < 0)
                        return r;

                break;

        case IMAGE_BLOCK:

                /* If this is inside of /dev, then it's a real block device, hence let's not touch the device node
                 * itself (but let's remove the stuff stored alongside it). If it's anywhere else, let's try to unlink
                 * the thing (it's most likely a symlink after all). */

                if (path_startswith(i->path, "/dev"))
                        break;

                _fallthrough_;
        case IMAGE_RAW:
                if (unlink(i->path) < 0)
                        return -errno;
                break;

        default:
                return -EOPNOTSUPP;
        }

        STRV_FOREACH(j, settings) {
                if (unlink(*j) < 0 && errno != ENOENT)
                        log_debug_errno(errno, "Failed to unlink %s, ignoring: %m", *j);
        }

        if (unlink(roothash) < 0 && errno != ENOENT)
                log_debug_errno(errno, "Failed to unlink %s, ignoring: %m", roothash);

        return 0;
}

static int rename_auxiliary_file(const char *path, const char *new_name, const char *suffix) {
        _cleanup_free_ char *rs = NULL;
        const char *fn;

        fn = strjoina(new_name, suffix);

        rs = file_in_same_dir(path, fn);
        if (!rs)
                return -ENOMEM;

        return rename_noreplace(AT_FDCWD, path, AT_FDCWD, rs);
}

int image_rename(Image *i, const char *new_name) {
        _cleanup_release_lock_file_ LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT, name_lock = LOCK_FILE_INIT;
        _cleanup_free_ char *new_path = NULL, *nn = NULL, *roothash = NULL;
        _cleanup_strv_free_ char **settings = NULL;
        unsigned file_attr = 0;
        char **j;
        int r;

        assert(i);

        if (!image_name_is_valid(new_name))
                return -EINVAL;

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        settings = image_settings_path(i);
        if (!settings)
                return -ENOMEM;

        roothash = image_roothash_path(i);
        if (!roothash)
                return -ENOMEM;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        /* Make sure nobody takes the new name, between the time we
         * checked it is currently unused in all search paths, and the
         * time we take possession of it */
        r = image_name_lock(new_name, LOCK_EX|LOCK_NB, &name_lock);
        if (r < 0)
                return r;

        r = image_find(new_name, NULL);
        if (r < 0)
                return r;
        if (r > 0)
                return -EEXIST;

        switch (i->type) {

        case IMAGE_DIRECTORY:
                /* Turn of the immutable bit while we rename the image, so that we can rename it */
                (void) read_attr_path(i->path, &file_attr);

                if (file_attr & FS_IMMUTABLE_FL)
                        (void) chattr_path(i->path, 0, FS_IMMUTABLE_FL);

                _fallthrough_;
        case IMAGE_SUBVOLUME:
                new_path = file_in_same_dir(i->path, new_name);
                break;

        case IMAGE_BLOCK:

                /* Refuse renaming raw block devices in /dev, the names are picked by udev after all. */
                if (path_startswith(i->path, "/dev"))
                        return -EROFS;

                new_path = file_in_same_dir(i->path, new_name);
                break;

        case IMAGE_RAW: {
                const char *fn;

                fn = strjoina(new_name, ".raw");
                new_path = file_in_same_dir(i->path, fn);
                break;
        }

        default:
                return -EOPNOTSUPP;
        }

        if (!new_path)
                return -ENOMEM;

        nn = strdup(new_name);
        if (!nn)
                return -ENOMEM;

        r = rename_noreplace(AT_FDCWD, i->path, AT_FDCWD, new_path);
        if (r < 0)
                return r;

        /* Restore the immutable bit, if it was set before */
        if (file_attr & FS_IMMUTABLE_FL)
                (void) chattr_path(new_path, FS_IMMUTABLE_FL, FS_IMMUTABLE_FL);

        free_and_replace(i->path, new_path);
        free_and_replace(i->name, nn);

        STRV_FOREACH(j, settings) {
                r = rename_auxiliary_file(*j, new_name, ".nspawn");
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to rename settings file %s, ignoring: %m", *j);
        }

        r = rename_auxiliary_file(roothash, new_name, ".roothash");
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to rename roothash file %s, ignoring: %m", roothash);

        return 0;
}

static int clone_auxiliary_file(const char *path, const char *new_name, const char *suffix) {
        _cleanup_free_ char *rs = NULL;
        const char *fn;

        fn = strjoina(new_name, suffix);

        rs = file_in_same_dir(path, fn);
        if (!rs)
                return -ENOMEM;

        return copy_file_atomic(path, rs, 0664, 0, COPY_REFLINK);
}

int image_clone(Image *i, const char *new_name, bool read_only) {
        _cleanup_release_lock_file_ LockFile name_lock = LOCK_FILE_INIT;
        _cleanup_strv_free_ char **settings = NULL;
        _cleanup_free_ char *roothash = NULL;
        const char *new_path;
        char **j;
        int r;

        assert(i);

        if (!image_name_is_valid(new_name))
                return -EINVAL;

        settings = image_settings_path(i);
        if (!settings)
                return -ENOMEM;

        roothash = image_roothash_path(i);
        if (!roothash)
                return -ENOMEM;

        /* Make sure nobody takes the new name, between the time we
         * checked it is currently unused in all search paths, and the
         * time we take possession of it */
        r = image_name_lock(new_name, LOCK_EX|LOCK_NB, &name_lock);
        if (r < 0)
                return r;

        r = image_find(new_name, NULL);
        if (r < 0)
                return r;
        if (r > 0)
                return -EEXIST;

        switch (i->type) {

        case IMAGE_SUBVOLUME:
        case IMAGE_DIRECTORY:
                /* If we can we'll always try to create a new btrfs subvolume here, even if the source is a plain
                 * directory. */

                new_path = strjoina("/var/lib/machines/", new_name);

                r = btrfs_subvol_snapshot(i->path, new_path,
                                          (read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                          BTRFS_SNAPSHOT_FALLBACK_COPY |
                                          BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                          BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE |
                                          BTRFS_SNAPSHOT_RECURSIVE |
                                          BTRFS_SNAPSHOT_QUOTA);
                if (r >= 0)
                        /* Enable "subtree" quotas for the copy, if we didn't copy any quota from the source. */
                        (void) btrfs_subvol_auto_qgroup(new_path, 0, true);

                break;

        case IMAGE_RAW:
                new_path = strjoina("/var/lib/machines/", new_name, ".raw");

                r = copy_file_atomic(i->path, new_path, read_only ? 0444 : 0644, FS_NOCOW_FL, COPY_REFLINK);
                break;

        case IMAGE_BLOCK:
        default:
                return -EOPNOTSUPP;
        }

        if (r < 0)
                return r;

        STRV_FOREACH(j, settings) {
                r = clone_auxiliary_file(*j, new_name, ".nspawn");
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to clone settings %s, ignoring: %m", *j);
        }

        r = clone_auxiliary_file(roothash, new_name, ".roothash");
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to clone root hash file %s, ignoring: %m", roothash);

        return 0;
}

int image_read_only(Image *i, bool b) {
        _cleanup_release_lock_file_ LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        int r;

        assert(i);

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:

                /* Note that we set the flag only on the top-level
                 * subvolume of the image. */

                r = btrfs_subvol_set_read_only(i->path, b);
                if (r < 0)
                        return r;

                break;

        case IMAGE_DIRECTORY:
                /* For simple directory trees we cannot use the access
                   mode of the top-level directory, since it has an
                   effect on the container itself.  However, we can
                   use the "immutable" flag, to at least make the
                   top-level directory read-only. It's not as good as
                   a read-only subvolume, but at least something, and
                   we can read the value back. */

                r = chattr_path(i->path, b ? FS_IMMUTABLE_FL : 0, FS_IMMUTABLE_FL);
                if (r < 0)
                        return r;

                break;

        case IMAGE_RAW: {
                struct stat st;

                if (stat(i->path, &st) < 0)
                        return -errno;

                if (chmod(i->path, (st.st_mode & 0444) | (b ? 0000 : 0200)) < 0)
                        return -errno;

                /* If the images is now read-only, it's a good time to
                 * defrag it, given that no write patterns will
                 * fragment it again. */
                if (b)
                        (void) btrfs_defrag(i->path);
                break;
        }

        case IMAGE_BLOCK: {
                _cleanup_close_ int fd = -1;
                struct stat st;
                int state = b;

                fd = open(i->path, O_CLOEXEC|O_RDONLY|O_NONBLOCK|O_NOCTTY);
                if (fd < 0)
                        return -errno;

                if (fstat(fd, &st) < 0)
                        return -errno;
                if (!S_ISBLK(st.st_mode))
                        return -ENOTTY;

                if (ioctl(fd, BLKROSET, &state) < 0)
                        return -errno;

                break;
        }

        default:
                return -EOPNOTSUPP;
        }

        return 0;
}

int image_path_lock(const char *path, int operation, LockFile *global, LockFile *local) {
        _cleanup_free_ char *p = NULL;
        LockFile t = LOCK_FILE_INIT;
        struct stat st;
        int r;

        assert(path);
        assert(global);
        assert(local);

        /* Locks an image path. This actually creates two locks: one
         * "local" one, next to the image path itself, which might be
         * shared via NFS. And another "global" one, in /run, that
         * uses the device/inode number. This has the benefit that we
         * can even lock a tree that is a mount point, correctly. */

        if (!path_is_absolute(path))
                return -EINVAL;

        if (getenv_bool("SYSTEMD_NSPAWN_LOCK") == 0) {
                *local = *global = (LockFile) LOCK_FILE_INIT;
                return 0;
        }

        if (path_equal(path, "/"))
                return -EBUSY;

        if (stat(path, &st) >= 0) {
                if (S_ISBLK(st.st_mode))
                        r = asprintf(&p, "/run/systemd/nspawn/locks/block-%u:%u", major(st.st_rdev), minor(st.st_rdev));
                else if (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))
                        r = asprintf(&p, "/run/systemd/nspawn/locks/inode-%lu:%lu", (unsigned long) st.st_dev, (unsigned long) st.st_ino);
                else
                        return -ENOTTY;

                if (r < 0)
                        return -ENOMEM;
        }

        /* For block devices we don't need the "local" lock, as the major/minor lock above should be sufficient, since
         * block devices are device local anyway. */
        if (!path_startswith(path, "/dev")) {
                r = make_lock_file_for(path, operation, &t);
                if (r < 0)
                        return r;
        }

        if (p) {
                mkdir_p("/run/systemd/nspawn/locks", 0700);

                r = make_lock_file(p, operation, global);
                if (r < 0) {
                        release_lock_file(&t);
                        return r;
                }
        } else
                *global = (LockFile) LOCK_FILE_INIT;

        *local = t;
        return 0;
}

int image_set_limit(Image *i, uint64_t referenced_max) {
        assert(i);

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        if (i->type != IMAGE_SUBVOLUME)
                return -EOPNOTSUPP;

        /* We set the quota both for the subvolume as well as for the
         * subtree. The latter is mostly for historical reasons, since
         * we didn't use to have a concept of subtree quota, and hence
         * only modified the subvolume quota. */

        (void) btrfs_qgroup_set_limit(i->path, 0, referenced_max);
        (void) btrfs_subvol_auto_qgroup(i->path, 0, true);
        return btrfs_subvol_set_subtree_quota_limit(i->path, 0, referenced_max);
}

int image_read_metadata(Image *i) {
        _cleanup_release_lock_file_ LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        int r;

        assert(i);

        r = image_path_lock(i->path, LOCK_SH|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:
        case IMAGE_DIRECTORY: {
                _cleanup_strv_free_ char **machine_info = NULL, **os_release = NULL;
                sd_id128_t machine_id = SD_ID128_NULL;
                _cleanup_free_ char *hostname = NULL;
                _cleanup_free_ char *path = NULL;

                r = chase_symlinks("/etc/hostname", i->path, CHASE_PREFIX_ROOT, &path);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to chase /etc/hostname in image %s: %m", i->name);
                else if (r >= 0) {
                        r = read_etc_hostname(path, &hostname);
                        if (r < 0)
                                log_debug_errno(errno, "Failed to read /etc/hostname of image %s: %m", i->name);
                }

                path = mfree(path);

                r = chase_symlinks("/etc/machine-id", i->path, CHASE_PREFIX_ROOT, &path);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to chase /etc/machine-id in image %s: %m", i->name);
                else if (r >= 0) {
                        _cleanup_close_ int fd = -1;

                        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (fd < 0)
                                log_debug_errno(errno, "Failed to open %s: %m", path);
                        else {
                                r = id128_read_fd(fd, ID128_PLAIN, &machine_id);
                                if (r < 0)
                                        log_debug_errno(r, "Image %s contains invalid machine ID.", i->name);
                        }
                }

                path = mfree(path);

                r = chase_symlinks("/etc/machine-info", i->path, CHASE_PREFIX_ROOT, &path);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to chase /etc/machine-info in image %s: %m", i->name);
                else if (r >= 0) {
                        r = load_env_file_pairs(NULL, path, NULL, &machine_info);
                        if (r < 0)
                                log_debug_errno(r, "Failed to parse machine-info data of %s: %m", i->name);
                }

                path = mfree(path);

                r = chase_symlinks("/etc/os-release", i->path, CHASE_PREFIX_ROOT, &path);
                if (r == -ENOENT)
                        r = chase_symlinks("/usr/lib/os-release", i->path, CHASE_PREFIX_ROOT, &path);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to chase os-release in image: %m");
                else if (r >= 0) {
                        r = load_env_file_pairs(NULL, path, NULL, &os_release);
                        if (r < 0)
                                log_debug_errno(r, "Failed to parse os-release data of %s: %m", i->name);
                }

                free_and_replace(i->hostname, hostname);
                i->machine_id = machine_id;
                strv_free_and_replace(i->machine_info, machine_info);
                strv_free_and_replace(i->os_release, os_release);

                break;
        }

        case IMAGE_RAW:
        case IMAGE_BLOCK: {
                _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;

                r = loop_device_make_by_path(i->path, O_RDONLY, &d);
                if (r < 0)
                        return r;

                r = dissect_image(d->fd, NULL, 0, DISSECT_IMAGE_REQUIRE_ROOT, &m);
                if (r < 0)
                        return r;

                r = dissected_image_acquire_metadata(m);
                if (r < 0)
                        return r;

                free_and_replace(i->hostname, m->hostname);
                i->machine_id = m->machine_id;
                strv_free_and_replace(i->machine_info, m->machine_info);
                strv_free_and_replace(i->os_release, m->os_release);

                break;
        }

        default:
                return -EOPNOTSUPP;
        }

        i->metadata_valid = true;

        return 0;
}

int image_name_lock(const char *name, int operation, LockFile *ret) {
        const char *p;

        assert(name);
        assert(ret);

        /* Locks an image name, regardless of the precise path used. */

        if (!image_name_is_valid(name))
                return -EINVAL;

        if (getenv_bool("SYSTEMD_NSPAWN_LOCK") == 0) {
                *ret = (LockFile) LOCK_FILE_INIT;
                return 0;
        }

        if (streq(name, ".host"))
                return -EBUSY;

        mkdir_p("/run/systemd/nspawn/locks", 0700);
        p = strjoina("/run/systemd/nspawn/locks/name-", name);

        return make_lock_file(p, operation, ret);
}

bool image_name_is_valid(const char *s) {
        if (!filename_is_valid(s))
                return false;

        if (string_has_cc(s, NULL))
                return false;

        if (!utf8_is_valid(s))
                return false;

        /* Temporary files for atomically creating new files */
        if (startswith(s, ".#"))
                return false;

        return true;
}

static const char* const image_type_table[_IMAGE_TYPE_MAX] = {
        [IMAGE_DIRECTORY] = "directory",
        [IMAGE_SUBVOLUME] = "subvolume",
        [IMAGE_RAW] = "raw",
        [IMAGE_BLOCK] = "block",
};

DEFINE_STRING_TABLE_LOOKUP(image_type, ImageType);
