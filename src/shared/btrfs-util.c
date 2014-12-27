/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <stdlib.h>
#include <sys/vfs.h>
#include <sys/stat.h>

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "missing.h"
#include "util.h"
#include "path-util.h"
#include "macro.h"
#include "strv.h"
#include "copy.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "btrfs-ctree.h"
#include "btrfs-util.h"

static int validate_subvolume_name(const char *name) {

        if (!filename_is_valid(name))
                return -EINVAL;

        if (strlen(name) > BTRFS_SUBVOL_NAME_MAX)
                return -E2BIG;

        return 0;
}

static int open_parent(const char *path, int flags) {
        _cleanup_free_ char *parent = NULL;
        int r, fd;

        assert(path);

        r = path_get_parent(path, &parent);
        if (r < 0)
                return r;

        fd = open(parent, flags);
        if (fd < 0)
                return -errno;

        return fd;
}

static int extract_subvolume_name(const char *path, const char **subvolume) {
        const char *fn;
        int r;

        assert(path);
        assert(subvolume);

        fn = basename(path);

        r = validate_subvolume_name(fn);
        if (r < 0)
                return r;

        *subvolume = fn;
        return 0;
}

int btrfs_is_snapshot(int fd) {
        struct stat st;
        struct statfs sfs;

        /* On btrfs subvolumes always have the inode 256 */

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode) || st.st_ino != 256)
                return 0;

        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        return F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC);
}

int btrfs_subvol_snapshot(const char *old_path, const char *new_path, bool read_only, bool fallback_copy) {
        struct btrfs_ioctl_vol_args_v2 args = {
                .flags = read_only ? BTRFS_SUBVOL_RDONLY : 0,
        };
        _cleanup_close_ int old_fd = -1, new_fd = -1;
        const char *subvolume;
        int r;

        assert(old_path);

        old_fd = open(old_path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (old_fd < 0)
                return -errno;

        r = btrfs_is_snapshot(old_fd);
        if (r < 0)
                return r;
        if (r == 0) {

                if (fallback_copy) {
                        r = btrfs_subvol_make(new_path);
                        if (r < 0)
                                return r;

                        r = copy_directory_fd(old_fd, new_path, true);
                        if (r < 0) {
                                btrfs_subvol_remove(new_path);
                                return r;
                        }

                        if (read_only) {
                                r = btrfs_subvol_set_read_only(new_path, true);
                                if (r < 0) {
                                        btrfs_subvol_remove(new_path);
                                        return r;
                                }
                        }

                        return 0;
                }

                return -EISDIR;
        }

        r = extract_subvolume_name(new_path, &subvolume);
        if (r < 0)
                return r;

        new_fd = open_parent(new_path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (new_fd < 0)
                return new_fd;

        strncpy(args.name, subvolume, sizeof(args.name)-1);
        args.fd = old_fd;

        if (ioctl(new_fd, BTRFS_IOC_SNAP_CREATE_V2, &args) < 0)
                return -errno;

        return 0;
}

int btrfs_subvol_make(const char *path) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_close_ int fd = -1;
        const char *subvolume;
        int r;

        assert(path);

        r = extract_subvolume_name(path, &subvolume);
        if (r < 0)
                return r;

        fd = open_parent(path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return fd;

        strncpy(args.name, subvolume, sizeof(args.name)-1);

        if (ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args) < 0)
                return -errno;

        return 0;
}

int btrfs_subvol_make_label(const char *path) {
        int r;

        assert(path);

        r = mac_selinux_create_file_prepare(path, S_IFDIR);
        if (r < 0)
                return r;

        r = btrfs_subvol_make(path);
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(path, false, false);
}

int btrfs_subvol_remove(const char *path) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_close_ int fd = -1;
        const char *subvolume;
        int r;

        assert(path);

        r = extract_subvolume_name(path, &subvolume);
        if (r < 0)
                return r;

        fd = open_parent(path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return fd;

        strncpy(args.name, subvolume, sizeof(args.name)-1);

        if (ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &args) < 0)
                return -errno;

        return 0;
}

int btrfs_subvol_set_read_only(const char *path, bool b) {
        _cleanup_close_ int fd = -1;
        uint64_t flags, nflags;

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, BTRFS_IOC_SUBVOL_GETFLAGS, &flags) < 0)
                return -errno;

        if (b)
                nflags = flags | BTRFS_SUBVOL_RDONLY;
        else
                nflags = flags & ~BTRFS_SUBVOL_RDONLY;

        if (flags == nflags)
                return 0;

        if (ioctl(fd, BTRFS_IOC_SUBVOL_SETFLAGS, &nflags) < 0)
                return -errno;

        return 0;
}

int btrfs_subvol_get_read_only_fd(int fd) {
        uint64_t flags;

        if (ioctl(fd, BTRFS_IOC_SUBVOL_GETFLAGS, &flags) < 0)
                return -errno;

        return !!(flags & BTRFS_SUBVOL_RDONLY);
}

int btrfs_reflink(int infd, int outfd) {
        int r;

        assert(infd >= 0);
        assert(outfd >= 0);

        r = ioctl(outfd, BTRFS_IOC_CLONE, infd);
        if (r < 0)
                return -errno;

        return 0;
}

int btrfs_get_block_device(const char *path, dev_t *dev) {
        struct btrfs_ioctl_fs_info_args fsi = {};
        _cleanup_close_ int fd = -1;
        uint64_t id;

        assert(path);
        assert(dev);

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, BTRFS_IOC_FS_INFO, &fsi) < 0)
                return -errno;

        /* We won't do this for btrfs RAID */
        if (fsi.num_devices != 1)
                return 0;

        for (id = 1; id <= fsi.max_id; id++) {
                struct btrfs_ioctl_dev_info_args di = {
                        .devid = id,
                };
                struct stat st;

                if (ioctl(fd, BTRFS_IOC_DEV_INFO, &di) < 0) {
                        if (errno == ENODEV)
                                continue;

                        return -errno;
                }

                if (stat((char*) di.path, &st) < 0)
                        return -errno;

                if (!S_ISBLK(st.st_mode))
                        return -ENODEV;

                if (major(st.st_rdev) == 0)
                        return -ENODEV;

                *dev = st.st_rdev;
                return 1;
        }

        return -ENODEV;
}

int btrfs_subvol_get_id_fd(int fd, uint64_t *ret) {
        struct btrfs_ioctl_ino_lookup_args args = {
                .objectid = BTRFS_FIRST_FREE_OBJECTID
        };

        assert(fd >= 0);
        assert(ret);

        if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args) < 0)
                return -errno;

        *ret = args.treeid;
        return 0;
}

int btrfs_subvol_get_info_fd(int fd, BtrfsSubvolInfo *ret) {
        struct btrfs_ioctl_search_args args = {
                /* Tree of tree roots */
                .key.tree_id = 1,

                /* Look precisely for the subvolume items */
                .key.min_type = BTRFS_ROOT_ITEM_KEY,
                .key.max_type = BTRFS_ROOT_ITEM_KEY,

                /* No restrictions on the other components */
                .key.min_offset = 0,
                .key.max_offset = (uint64_t) -1,
                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,

                /* Some large value */
                .key.nr_items = 2,
        };

        struct btrfs_ioctl_search_header *sh;
        struct btrfs_root_item *ri;
        uint64_t subvol_id;
        int r;

        assert(fd >= 0);
        assert(ret);

        r = btrfs_subvol_get_id_fd(fd, &subvol_id);
        if (r < 0)
                return r;

        args.key.min_objectid = args.key.max_objectid = subvol_id;
        if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                return -errno;

        if (args.key.nr_items != 1)
                return -EIO;

        sh = (struct btrfs_ioctl_search_header*) args.buf;
        assert(sh->type == BTRFS_ROOT_ITEM_KEY);
        assert(sh->objectid == subvol_id);

        if (sh->len < offsetof(struct btrfs_root_item, otime) + sizeof(struct btrfs_timespec))
                return -ENOTSUP;

        ri = (struct btrfs_root_item *)(args.buf + sizeof(struct btrfs_ioctl_search_header));

        ret->otime = (usec_t) le64toh(ri->otime.sec) * USEC_PER_SEC +
                     (usec_t) le32toh(ri->otime.nsec) / NSEC_PER_USEC;

        ret->subvol_id = subvol_id;
        ret->read_only = !!(le64toh(ri->flags) & BTRFS_ROOT_SUBVOL_RDONLY);

        assert_cc(sizeof(ri->uuid) == sizeof(ret->uuid));
        memcpy(&ret->uuid, ri->uuid, sizeof(ret->uuid));
        memcpy(&ret->parent_uuid, ri->parent_uuid, sizeof(ret->parent_uuid));

        return 0;
}
