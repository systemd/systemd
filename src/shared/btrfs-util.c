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

int btrfs_subvol_set_read_only_fd(int fd, bool b) {
        uint64_t flags, nflags;
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode) || st.st_ino != 256)
                return -EINVAL;

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

int btrfs_subvol_set_read_only(const char *path, bool b) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        return btrfs_subvol_set_read_only_fd(fd, b);
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

int btrfs_clone_range(int infd, uint64_t in_offset, int outfd, uint64_t out_offset, uint64_t sz) {
        struct btrfs_ioctl_clone_range_args args = {
                .src_fd = infd,
                .src_offset = in_offset,
                .src_length = sz,
                .dest_offset = out_offset,
        };
        int r;

        assert(infd >= 0);
        assert(outfd >= 0);
        assert(sz > 0);

        r = ioctl(outfd, BTRFS_IOC_CLONE_RANGE, &args);
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

static bool btrfs_ioctl_search_args_inc(struct btrfs_ioctl_search_args *args) {
        assert(args);

        /* the objectid, type, offset together make up the btrfs key,
         * which is considered a single 136byte integer when
         * comparing. This call increases the counter by one, dealing
         * with the overflow between the overflows */

        if (args->key.min_offset < (uint64_t) -1) {
                args->key.min_offset++;
                return true;
        }

        if (args->key.min_type < (uint8_t) -1) {
                args->key.min_type++;
                args->key.min_offset = 0;
                return true;
        }

        if (args->key.min_objectid < (uint64_t) -1) {
                args->key.min_objectid++;
                args->key.min_offset = 0;
                args->key.min_type = 0;
                return true;
        }

        return 0;
}

static void btrfs_ioctl_search_args_set(struct btrfs_ioctl_search_args *args, const struct btrfs_ioctl_search_header *h) {
        assert(args);
        assert(h);

        args->key.min_objectid = h->objectid;
        args->key.min_type = h->type;
        args->key.min_offset = h->offset;
}

static int btrfs_ioctl_search_args_compare(const struct btrfs_ioctl_search_args *args) {
        assert(args);

        /* Compare min and max */

        if (args->key.min_objectid < args->key.max_objectid)
                return -1;
        if (args->key.min_objectid > args->key.max_objectid)
                return 1;

        if (args->key.min_type < args->key.max_type)
                return -1;
        if (args->key.min_type > args->key.max_type)
                return 1;

        if (args->key.min_offset < args->key.max_offset)
                return -1;
        if (args->key.min_offset > args->key.max_offset)
                return 1;

        return 0;
}

#define FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args)                  \
        for ((i) = 0,                                                   \
             (sh) = (const struct btrfs_ioctl_search_header*) (args).buf; \
             (i) < (args).key.nr_items;                                 \
             (i)++,                                                     \
             (sh) = (const struct btrfs_ioctl_search_header*) ((uint8_t*) (sh) + sizeof(struct btrfs_ioctl_search_header) + (sh)->len))

#define BTRFS_IOCTL_SEARCH_HEADER_BODY(sh)                              \
        ((void*) ((uint8_t*) sh + sizeof(struct btrfs_ioctl_search_header)))

int btrfs_subvol_get_info_fd(int fd, BtrfsSubvolInfo *ret) {
        struct btrfs_ioctl_search_args args = {
                /* Tree of tree roots */
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                /* Look precisely for the subvolume items */
                .key.min_type = BTRFS_ROOT_ITEM_KEY,
                .key.max_type = BTRFS_ROOT_ITEM_KEY,

                .key.min_offset = 0,
                .key.max_offset = (uint64_t) -1,

                /* No restrictions on the other components */
                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,
        };

        uint64_t subvol_id;
        bool found = false;
        int r;

        assert(fd >= 0);
        assert(ret);

        r = btrfs_subvol_get_id_fd(fd, &subvol_id);
        if (r < 0)
                return r;

        args.key.min_objectid = args.key.max_objectid = subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return -errno;

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {

                        const struct btrfs_root_item *ri;

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->objectid != subvol_id)
                                continue;
                        if (sh->type != BTRFS_ROOT_ITEM_KEY)
                                continue;

                        /* Older versions of the struct lacked the otime setting */
                        if (sh->len < offsetof(struct btrfs_root_item, otime) + sizeof(struct btrfs_timespec))
                                continue;

                        ri = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);

                        ret->otime = (usec_t) le64toh(ri->otime.sec) * USEC_PER_SEC +
                                (usec_t) le32toh(ri->otime.nsec) / NSEC_PER_USEC;

                        ret->subvol_id = subvol_id;
                        ret->read_only = !!(le64toh(ri->flags) & BTRFS_ROOT_SUBVOL_RDONLY);

                        assert_cc(sizeof(ri->uuid) == sizeof(ret->uuid));
                        memcpy(&ret->uuid, ri->uuid, sizeof(ret->uuid));
                        memcpy(&ret->parent_uuid, ri->parent_uuid, sizeof(ret->parent_uuid));

                        found = true;
                        goto finish;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

finish:
        if (!found)
                return -ENODATA;

        return 0;
}

int btrfs_subvol_get_quota_fd(int fd, BtrfsQuotaInfo *ret) {

        struct btrfs_ioctl_search_args args = {
                /* Tree of quota items */
                .key.tree_id = BTRFS_QUOTA_TREE_OBJECTID,

                /* The object ID is always 0 */
                .key.min_objectid = 0,
                .key.max_objectid = 0,

                /* Look precisely for the quota items */
                .key.min_type = BTRFS_QGROUP_STATUS_KEY,
                .key.max_type = BTRFS_QGROUP_LIMIT_KEY,

                /* No restrictions on the other components */
                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,
        };

        uint64_t subvol_id;
        bool found_info = false, found_limit = false;
        int r;

        assert(fd >= 0);
        assert(ret);

        r = btrfs_subvol_get_id_fd(fd, &subvol_id);
        if (r < 0)
                return r;

        args.key.min_offset = args.key.max_offset = subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return -errno;

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->objectid != 0)
                                continue;
                        if (sh->offset != subvol_id)
                                continue;

                        if (sh->type == BTRFS_QGROUP_INFO_KEY) {
                                const struct btrfs_qgroup_info_item *qii = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);

                                ret->referred = le64toh(qii->rfer);
                                ret->exclusive = le64toh(qii->excl);

                                found_info = true;

                        } else if (sh->type == BTRFS_QGROUP_LIMIT_KEY) {
                                const struct btrfs_qgroup_limit_item *qli = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);

                                ret->referred_max = le64toh(qli->max_rfer);
                                ret->exclusive_max = le64toh(qli->max_excl);

                                if (ret->referred_max == 0)
                                        ret->referred_max = (uint64_t) -1;
                                if (ret->exclusive_max == 0)
                                        ret->exclusive_max = (uint64_t) -1;

                                found_limit = true;
                        }

                        if (found_info && found_limit)
                                goto finish;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

finish:
        if (!found_limit && !found_info)
                return -ENODATA;

        if (!found_info) {
                ret->referred = (uint64_t) -1;
                ret->exclusive = (uint64_t) -1;
        }

        if (!found_limit) {
                ret->referred_max = (uint64_t) -1;
                ret->exclusive_max = (uint64_t) -1;
        }

        return 0;
}

int btrfs_defrag_fd(int fd) {
        assert(fd >= 0);

        if (ioctl(fd, BTRFS_IOC_DEFRAG, NULL) < 0)
                return -errno;

        return 0;
}

int btrfs_defrag(const char *p) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_defrag_fd(fd);
}
