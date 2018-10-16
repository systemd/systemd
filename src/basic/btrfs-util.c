/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#if HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "alloc-util.h"
#include "blockdev-util.h"
#include "btrfs-ctree.h"
#include "btrfs-util.h"
#include "chattr-util.h"
#include "copy.h"
#include "device-nodes.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "macro.h"
#include "missing.h"
#include "path-util.h"
#include "rm-rf.h"
#include "smack-util.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-util.h"
#include "time-util.h"
#include "util.h"

/* WARNING: Be careful with file system ioctls! When we get an fd, we
 * need to make sure it either refers to only a regular file or
 * directory, or that it is located on btrfs, before invoking any
 * btrfs ioctls. The ioctl numbers are reused by some device drivers
 * (such as DRM), and hence might have bad effects when invoked on
 * device nodes (that reference drivers) rather than fds to normal
 * files or directories. */

static int validate_subvolume_name(const char *name) {

        if (!filename_is_valid(name))
                return -EINVAL;

        if (strlen(name) > BTRFS_SUBVOL_NAME_MAX)
                return -E2BIG;

        return 0;
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

int btrfs_is_filesystem(int fd) {
        struct statfs sfs;

        assert(fd >= 0);

        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        return F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC);
}

int btrfs_is_subvol_fd(int fd) {
        struct stat st;

        assert(fd >= 0);

        /* On btrfs subvolumes always have the inode 256 */

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode) || st.st_ino != 256)
                return 0;

        return btrfs_is_filesystem(fd);
}

int btrfs_is_subvol(const char *path) {
        _cleanup_close_ int fd = -1;

        assert(path);

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        return btrfs_is_subvol_fd(fd);
}

int btrfs_subvol_make_fd(int fd, const char *subvolume) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_close_ int real_fd = -1;
        int r;

        assert(subvolume);

        r = validate_subvolume_name(subvolume);
        if (r < 0)
                return r;

        r = fcntl(fd, F_GETFL);
        if (r < 0)
                return -errno;
        if (FLAGS_SET(r, O_PATH)) {
                /* An O_PATH fd was specified, let's convert here to a proper one, as btrfs ioctl's can't deal with
                 * O_PATH. */

                real_fd = fd_reopen(fd, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (real_fd < 0)
                        return real_fd;

                fd = real_fd;
        }

        strncpy(args.name, subvolume, sizeof(args.name)-1);

        if (ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args) < 0)
                return -errno;

        return 0;
}

int btrfs_subvol_make(const char *path) {
        _cleanup_close_ int fd = -1;
        const char *subvolume;
        int r;

        assert(path);

        r = extract_subvolume_name(path, &subvolume);
        if (r < 0)
                return r;

        fd = open_parent(path, O_CLOEXEC, 0);
        if (fd < 0)
                return fd;

        return btrfs_subvol_make_fd(fd, subvolume);
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
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode) || st.st_ino != 256)
                return -EINVAL;

        if (ioctl(fd, BTRFS_IOC_SUBVOL_GETFLAGS, &flags) < 0)
                return -errno;

        return !!(flags & BTRFS_SUBVOL_RDONLY);
}

int btrfs_reflink(int infd, int outfd) {
        int r;

        assert(infd >= 0);
        assert(outfd >= 0);

        /* Make sure we invoke the ioctl on a regular file, so that no device driver accidentally gets it. */

        r = fd_verify_regular(outfd);
        if (r < 0)
                return r;

        if (ioctl(outfd, BTRFS_IOC_CLONE, infd) < 0)
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

        r = fd_verify_regular(outfd);
        if (r < 0)
                return r;

        if (ioctl(outfd, BTRFS_IOC_CLONE_RANGE, &args) < 0)
                return -errno;

        return 0;
}

int btrfs_get_block_device_fd(int fd, dev_t *dev) {
        struct btrfs_ioctl_fs_info_args fsi = {};
        uint64_t id;
        int r;

        assert(fd >= 0);
        assert(dev);

        r = btrfs_is_filesystem(fd);
        if (r < 0)
                return r;
        if (!r)
                return -ENOTTY;

        if (ioctl(fd, BTRFS_IOC_FS_INFO, &fsi) < 0)
                return -errno;

        /* We won't do this for btrfs RAID */
        if (fsi.num_devices != 1) {
                *dev = 0;
                return 0;
        }

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

int btrfs_get_block_device(const char *path, dev_t *dev) {
        _cleanup_close_ int fd = -1;

        assert(path);
        assert(dev);

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return btrfs_get_block_device_fd(fd, dev);
}

int btrfs_subvol_get_id_fd(int fd, uint64_t *ret) {
        struct btrfs_ioctl_ino_lookup_args args = {
                .objectid = BTRFS_FIRST_FREE_OBJECTID
        };
        int r;

        assert(fd >= 0);
        assert(ret);

        r = btrfs_is_filesystem(fd);
        if (r < 0)
                return r;
        if (!r)
                return -ENOTTY;

        if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args) < 0)
                return -errno;

        *ret = args.treeid;
        return 0;
}

int btrfs_subvol_get_id(int fd, const char *subvol, uint64_t *ret) {
        _cleanup_close_ int subvol_fd = -1;

        assert(fd >= 0);
        assert(ret);

        subvol_fd = openat(fd, subvol, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (subvol_fd < 0)
                return -errno;

        return btrfs_subvol_get_id_fd(subvol_fd, ret);
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
        int r;

        assert(args);

        /* Compare min and max */

        r = CMP(args->key.min_objectid, args->key.max_objectid);
        if (r != 0)
                return r;

        r = CMP(args->key.min_type, args->key.max_type);
        if (r != 0)
                return r;

        return CMP(args->key.min_offset, args->key.max_offset);
}

#define FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args)                  \
        for ((i) = 0,                                                   \
             (sh) = (const struct btrfs_ioctl_search_header*) (args).buf; \
             (i) < (args).key.nr_items;                                 \
             (i)++,                                                     \
             (sh) = (const struct btrfs_ioctl_search_header*) ((uint8_t*) (sh) + sizeof(struct btrfs_ioctl_search_header) + (sh)->len))

#define BTRFS_IOCTL_SEARCH_HEADER_BODY(sh)                              \
        ((void*) ((uint8_t*) sh + sizeof(struct btrfs_ioctl_search_header)))

int btrfs_subvol_get_info_fd(int fd, uint64_t subvol_id, BtrfsSubvolInfo *ret) {
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

        bool found = false;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        } else {
                r = btrfs_is_filesystem(fd);
                if (r < 0)
                        return r;
                if (!r)
                        return -ENOTTY;
        }

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
                        ret->read_only = le64toh(ri->flags) & BTRFS_ROOT_SUBVOL_RDONLY;

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

int btrfs_qgroup_get_quota_fd(int fd, uint64_t qgroupid, BtrfsQuotaInfo *ret) {

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

        bool found_info = false, found_limit = false;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (qgroupid == 0) {
                r = btrfs_subvol_get_id_fd(fd, &qgroupid);
                if (r < 0)
                        return r;
        } else {
                r = btrfs_is_filesystem(fd);
                if (r < 0)
                        return r;
                if (!r)
                        return -ENOTTY;
        }

        args.key.min_offset = args.key.max_offset = qgroupid;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0) {
                        if (errno == ENOENT) /* quota tree is missing: quota disabled */
                                break;

                        return -errno;
                }

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->objectid != 0)
                                continue;
                        if (sh->offset != qgroupid)
                                continue;

                        if (sh->type == BTRFS_QGROUP_INFO_KEY) {
                                const struct btrfs_qgroup_info_item *qii = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);

                                ret->referenced = le64toh(qii->rfer);
                                ret->exclusive = le64toh(qii->excl);

                                found_info = true;

                        } else if (sh->type == BTRFS_QGROUP_LIMIT_KEY) {
                                const struct btrfs_qgroup_limit_item *qli = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);

                                if (le64toh(qli->flags) & BTRFS_QGROUP_LIMIT_MAX_RFER)
                                        ret->referenced_max = le64toh(qli->max_rfer);
                                else
                                        ret->referenced_max = (uint64_t) -1;

                                if (le64toh(qli->flags) & BTRFS_QGROUP_LIMIT_MAX_EXCL)
                                        ret->exclusive_max = le64toh(qli->max_excl);
                                else
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
                ret->referenced = (uint64_t) -1;
                ret->exclusive = (uint64_t) -1;
        }

        if (!found_limit) {
                ret->referenced_max = (uint64_t) -1;
                ret->exclusive_max = (uint64_t) -1;
        }

        return 0;
}

int btrfs_qgroup_get_quota(const char *path, uint64_t qgroupid, BtrfsQuotaInfo *ret) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_qgroup_get_quota_fd(fd, qgroupid, ret);
}

int btrfs_subvol_find_subtree_qgroup(int fd, uint64_t subvol_id, uint64_t *ret) {
        uint64_t level, lowest = (uint64_t) -1, lowest_qgroupid = 0;
        _cleanup_free_ uint64_t *qgroups = NULL;
        int r, n, i;

        assert(fd >= 0);
        assert(ret);

        /* This finds the "subtree" qgroup for a specific
         * subvolume. This only works for subvolumes that have been
         * prepared with btrfs_subvol_auto_qgroup_fd() with
         * insert_intermediary_qgroup=true (or equivalent). For others
         * it will return the leaf qgroup instead. The two cases may
         * be distuingished via the return value, which is 1 in case
         * an appropriate "subtree" qgroup was found, and 0
         * otherwise. */

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        }

        r = btrfs_qgroupid_split(subvol_id, &level, NULL);
        if (r < 0)
                return r;
        if (level != 0) /* Input must be a leaf qgroup */
                return -EINVAL;

        n = btrfs_qgroup_find_parents(fd, subvol_id, &qgroups);
        if (n < 0)
                return n;

        for (i = 0; i < n; i++) {
                uint64_t id;

                r = btrfs_qgroupid_split(qgroups[i], &level, &id);
                if (r < 0)
                        return r;

                if (id != subvol_id)
                        continue;

                if (lowest == (uint64_t) -1 || level < lowest) {
                        lowest_qgroupid = qgroups[i];
                        lowest = level;
                }
        }

        if (lowest == (uint64_t) -1) {
                /* No suitable higher-level qgroup found, let's return
                 * the leaf qgroup instead, and indicate that with the
                 * return value. */

                *ret = subvol_id;
                return 0;
        }

        *ret = lowest_qgroupid;
        return 1;
}

int btrfs_subvol_get_subtree_quota_fd(int fd, uint64_t subvol_id, BtrfsQuotaInfo *ret) {
        uint64_t qgroupid;
        int r;

        assert(fd >= 0);
        assert(ret);

        /* This determines the quota data of the qgroup with the
         * lowest level, that shares the id part with the specified
         * subvolume. This is useful for determining the quota data
         * for entire subvolume subtrees, as long as the subtrees have
         * been set up with btrfs_qgroup_subvol_auto_fd() or in a
         * compatible way */

        r = btrfs_subvol_find_subtree_qgroup(fd, subvol_id, &qgroupid);
        if (r < 0)
                return r;

        return btrfs_qgroup_get_quota_fd(fd, qgroupid, ret);
}

int btrfs_subvol_get_subtree_quota(const char *path, uint64_t subvol_id, BtrfsQuotaInfo *ret) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_subvol_get_subtree_quota_fd(fd, subvol_id, ret);
}

int btrfs_defrag_fd(int fd) {
        int r;

        assert(fd >= 0);

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

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

int btrfs_quota_enable_fd(int fd, bool b) {
        struct btrfs_ioctl_quota_ctl_args args = {
                .cmd = b ? BTRFS_QUOTA_CTL_ENABLE : BTRFS_QUOTA_CTL_DISABLE,
        };
        int r;

        assert(fd >= 0);

        r = btrfs_is_filesystem(fd);
        if (r < 0)
                return r;
        if (!r)
                return -ENOTTY;

        if (ioctl(fd, BTRFS_IOC_QUOTA_CTL, &args) < 0)
                return -errno;

        return 0;
}

int btrfs_quota_enable(const char *path, bool b) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_quota_enable_fd(fd, b);
}

int btrfs_qgroup_set_limit_fd(int fd, uint64_t qgroupid, uint64_t referenced_max) {

        struct btrfs_ioctl_qgroup_limit_args args = {
                .lim.max_rfer = referenced_max,
                .lim.flags = BTRFS_QGROUP_LIMIT_MAX_RFER,
        };
        unsigned c;
        int r;

        assert(fd >= 0);

        if (qgroupid == 0) {
                r = btrfs_subvol_get_id_fd(fd, &qgroupid);
                if (r < 0)
                        return r;
        } else {
                r = btrfs_is_filesystem(fd);
                if (r < 0)
                        return r;
                if (!r)
                        return -ENOTTY;
        }

        args.qgroupid = qgroupid;

        for (c = 0;; c++) {
                if (ioctl(fd, BTRFS_IOC_QGROUP_LIMIT, &args) < 0) {

                        if (errno == EBUSY && c < 10) {
                                (void) btrfs_quota_scan_wait(fd);
                                continue;
                        }

                        return -errno;
                }

                break;
        }

        return 0;
}

int btrfs_qgroup_set_limit(const char *path, uint64_t qgroupid, uint64_t referenced_max) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_qgroup_set_limit_fd(fd, qgroupid, referenced_max);
}

int btrfs_subvol_set_subtree_quota_limit_fd(int fd, uint64_t subvol_id, uint64_t referenced_max) {
        uint64_t qgroupid;
        int r;

        assert(fd >= 0);

        r = btrfs_subvol_find_subtree_qgroup(fd, subvol_id, &qgroupid);
        if (r < 0)
                return r;

        return btrfs_qgroup_set_limit_fd(fd, qgroupid, referenced_max);
}

int btrfs_subvol_set_subtree_quota_limit(const char *path, uint64_t subvol_id, uint64_t referenced_max) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_subvol_set_subtree_quota_limit_fd(fd, subvol_id, referenced_max);
}

int btrfs_resize_loopback_fd(int fd, uint64_t new_size, bool grow_only) {
        struct btrfs_ioctl_vol_args args = {};
        char p[SYS_BLOCK_PATH_MAX("/loop/backing_file")], q[DEV_NUM_PATH_MAX];
        _cleanup_free_ char *backing = NULL;
        _cleanup_close_ int loop_fd = -1, backing_fd = -1;
        struct stat st;
        dev_t dev = 0;
        int r;

        /* In contrast to btrfs quota ioctls ftruncate() cannot make sense of "infinity" or file sizes > 2^31 */
        if (!FILE_SIZE_VALID(new_size))
                return -EINVAL;

        /* btrfs cannot handle file systems < 16M, hence use this as minimum */
        if (new_size < 16*1024*1024)
                new_size = 16*1024*1024;

        r = btrfs_get_block_device_fd(fd, &dev);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENODEV;

        xsprintf_sys_block_path(p, "/loop/backing_file", dev);
        r = read_one_line_file(p, &backing);
        if (r == -ENOENT)
                return -ENODEV;
        if (r < 0)
                return r;
        if (isempty(backing) || !path_is_absolute(backing))
                return -ENODEV;

        backing_fd = open(backing, O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (backing_fd < 0)
                return -errno;

        if (fstat(backing_fd, &st) < 0)
                return -errno;
        if (!S_ISREG(st.st_mode))
                return -ENODEV;

        if (new_size == (uint64_t) st.st_size)
                return 0;

        if (grow_only && new_size < (uint64_t) st.st_size)
                return -EINVAL;

        xsprintf_dev_num_path(q, "block", dev);
        loop_fd = open(q, O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (loop_fd < 0)
                return -errno;

        if (snprintf(args.name, sizeof(args.name), "%" PRIu64, new_size) >= (int) sizeof(args.name))
                return -EINVAL;

        if (new_size < (uint64_t) st.st_size) {
                /* Decrease size: first decrease btrfs size, then shorten loopback */
                if (ioctl(fd, BTRFS_IOC_RESIZE, &args) < 0)
                        return -errno;
        }

        if (ftruncate(backing_fd, new_size) < 0)
                return -errno;

        if (ioctl(loop_fd, LOOP_SET_CAPACITY, 0) < 0)
                return -errno;

        if (new_size > (uint64_t) st.st_size) {
                /* Increase size: first enlarge loopback, then increase btrfs size */
                if (ioctl(fd, BTRFS_IOC_RESIZE, &args) < 0)
                        return -errno;
        }

        /* Make sure the free disk space is correctly updated for both file systems */
        (void) fsync(fd);
        (void) fsync(backing_fd);

        return 1;
}

int btrfs_resize_loopback(const char *p, uint64_t new_size, bool grow_only) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return btrfs_resize_loopback_fd(fd, new_size, grow_only);
}

int btrfs_qgroupid_make(uint64_t level, uint64_t id, uint64_t *ret) {
        assert(ret);

        if (level >= (UINT64_C(1) << (64 - BTRFS_QGROUP_LEVEL_SHIFT)))
                return -EINVAL;

        if (id >= (UINT64_C(1) << BTRFS_QGROUP_LEVEL_SHIFT))
                return -EINVAL;

        *ret = (level << BTRFS_QGROUP_LEVEL_SHIFT) | id;
        return 0;
}

int btrfs_qgroupid_split(uint64_t qgroupid, uint64_t *level, uint64_t *id) {
        assert(level || id);

        if (level)
                *level = qgroupid >> BTRFS_QGROUP_LEVEL_SHIFT;

        if (id)
                *id = qgroupid & ((UINT64_C(1) << BTRFS_QGROUP_LEVEL_SHIFT) - 1);

        return 0;
}

static int qgroup_create_or_destroy(int fd, bool b, uint64_t qgroupid) {

        struct btrfs_ioctl_qgroup_create_args args = {
                .create = b,
                .qgroupid = qgroupid,
        };
        unsigned c;
        int r;

        r = btrfs_is_filesystem(fd);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        for (c = 0;; c++) {
                if (ioctl(fd, BTRFS_IOC_QGROUP_CREATE, &args) < 0) {

                        /* If quota is not enabled, we get EINVAL. Turn this into a recognizable error */
                        if (errno == EINVAL)
                                return -ENOPROTOOPT;

                        if (errno == EBUSY && c < 10) {
                                (void) btrfs_quota_scan_wait(fd);
                                continue;
                        }

                        return -errno;
                }

                break;
        }

        return 0;
}

int btrfs_qgroup_create(int fd, uint64_t qgroupid) {
        return qgroup_create_or_destroy(fd, true, qgroupid);
}

int btrfs_qgroup_destroy(int fd, uint64_t qgroupid) {
        return qgroup_create_or_destroy(fd, false, qgroupid);
}

int btrfs_qgroup_destroy_recursive(int fd, uint64_t qgroupid) {
        _cleanup_free_ uint64_t *qgroups = NULL;
        uint64_t subvol_id;
        int i, n, r;

        /* Destroys the specified qgroup, but unassigns it from all
         * its parents first. Also, it recursively destroys all
         * qgroups it is assgined to that have the same id part of the
         * qgroupid as the specified group. */

        r = btrfs_qgroupid_split(qgroupid, NULL, &subvol_id);
        if (r < 0)
                return r;

        n = btrfs_qgroup_find_parents(fd, qgroupid, &qgroups);
        if (n < 0)
                return n;

        for (i = 0; i < n; i++) {
                uint64_t id;

                r = btrfs_qgroupid_split(qgroups[i], NULL, &id);
                if (r < 0)
                        return r;

                r = btrfs_qgroup_unassign(fd, qgroupid, qgroups[i]);
                if (r < 0)
                        return r;

                if (id != subvol_id)
                        continue;

                /* The parent qgroupid shares the same id part with
                 * us? If so, destroy it too. */

                (void) btrfs_qgroup_destroy_recursive(fd, qgroups[i]);
        }

        return btrfs_qgroup_destroy(fd, qgroupid);
}

int btrfs_quota_scan_start(int fd) {
        struct btrfs_ioctl_quota_rescan_args args = {};

        assert(fd >= 0);

        if (ioctl(fd, BTRFS_IOC_QUOTA_RESCAN, &args) < 0)
                return -errno;

        return 0;
}

int btrfs_quota_scan_wait(int fd) {
        assert(fd >= 0);

        if (ioctl(fd, BTRFS_IOC_QUOTA_RESCAN_WAIT) < 0)
                return -errno;

        return 0;
}

int btrfs_quota_scan_ongoing(int fd) {
        struct btrfs_ioctl_quota_rescan_args args = {};

        assert(fd >= 0);

        if (ioctl(fd, BTRFS_IOC_QUOTA_RESCAN_STATUS, &args) < 0)
                return -errno;

        return !!args.flags;
}

static int qgroup_assign_or_unassign(int fd, bool b, uint64_t child, uint64_t parent) {
        struct btrfs_ioctl_qgroup_assign_args args = {
                .assign = b,
                .src = child,
                .dst = parent,
        };
        unsigned c;
        int r;

        r = btrfs_is_filesystem(fd);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        for (c = 0;; c++) {
                r = ioctl(fd, BTRFS_IOC_QGROUP_ASSIGN, &args);
                if (r < 0) {
                        if (errno == EBUSY && c < 10) {
                                (void) btrfs_quota_scan_wait(fd);
                                continue;
                        }

                        return -errno;
                }

                if (r == 0)
                        return 0;

                /* If the return value is > 0, we need to request a rescan */

                (void) btrfs_quota_scan_start(fd);
                return 1;
        }
}

int btrfs_qgroup_assign(int fd, uint64_t child, uint64_t parent) {
        return qgroup_assign_or_unassign(fd, true, child, parent);
}

int btrfs_qgroup_unassign(int fd, uint64_t child, uint64_t parent) {
        return qgroup_assign_or_unassign(fd, false, child, parent);
}

static int subvol_remove_children(int fd, const char *subvolume, uint64_t subvol_id, BtrfsRemoveFlags flags) {
        struct btrfs_ioctl_search_args args = {
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                .key.min_objectid = BTRFS_FIRST_FREE_OBJECTID,
                .key.max_objectid = BTRFS_LAST_FREE_OBJECTID,

                .key.min_type = BTRFS_ROOT_BACKREF_KEY,
                .key.max_type = BTRFS_ROOT_BACKREF_KEY,

                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,
        };

        struct btrfs_ioctl_vol_args vol_args = {};
        _cleanup_close_ int subvol_fd = -1;
        struct stat st;
        bool made_writable = false;
        int r;

        assert(fd >= 0);
        assert(subvolume);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode))
                return -EINVAL;

        subvol_fd = openat(fd, subvolume, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (subvol_fd < 0)
                return -errno;

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(subvol_fd, &subvol_id);
                if (r < 0)
                        return r;
        }

        /* First, try to remove the subvolume. If it happens to be
         * already empty, this will just work. */
        strncpy(vol_args.name, subvolume, sizeof(vol_args.name)-1);
        if (ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &vol_args) >= 0) {
                (void) btrfs_qgroup_destroy_recursive(fd, subvol_id); /* for the leaf subvolumes, the qgroup id is identical to the subvol id */
                return 0;
        }
        if (!(flags & BTRFS_REMOVE_RECURSIVE) || errno != ENOTEMPTY)
                return -errno;

        /* OK, the subvolume is not empty, let's look for child
         * subvolumes, and remove them, first */

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
                        _cleanup_free_ char *p = NULL;
                        const struct btrfs_root_ref *ref;
                        struct btrfs_ioctl_ino_lookup_args ino_args;

                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->type != BTRFS_ROOT_BACKREF_KEY)
                                continue;
                        if (sh->offset != subvol_id)
                                continue;

                        ref = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);

                        p = strndup((char*) ref + sizeof(struct btrfs_root_ref), le64toh(ref->name_len));
                        if (!p)
                                return -ENOMEM;

                        zero(ino_args);
                        ino_args.treeid = subvol_id;
                        ino_args.objectid = htole64(ref->dirid);

                        if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &ino_args) < 0)
                                return -errno;

                        if (!made_writable) {
                                r = btrfs_subvol_set_read_only_fd(subvol_fd, false);
                                if (r < 0)
                                        return r;

                                made_writable = true;
                        }

                        if (isempty(ino_args.name))
                                /* Subvolume is in the top-level
                                 * directory of the subvolume. */
                                r = subvol_remove_children(subvol_fd, p, sh->objectid, flags);
                        else {
                                _cleanup_close_ int child_fd = -1;

                                /* Subvolume is somewhere further down,
                                 * hence we need to open the
                                 * containing directory first */

                                child_fd = openat(subvol_fd, ino_args.name, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                                if (child_fd < 0)
                                        return -errno;

                                r = subvol_remove_children(child_fd, p, sh->objectid, flags);
                        }
                        if (r < 0)
                                return r;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

        /* OK, the child subvolumes should all be gone now, let's try
         * again to remove the subvolume */
        if (ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &vol_args) < 0)
                return -errno;

        (void) btrfs_qgroup_destroy_recursive(fd, subvol_id);
        return 0;
}

int btrfs_subvol_remove(const char *path, BtrfsRemoveFlags flags) {
        _cleanup_close_ int fd = -1;
        const char *subvolume;
        int r;

        assert(path);

        r = extract_subvolume_name(path, &subvolume);
        if (r < 0)
                return r;

        fd = open_parent(path, O_CLOEXEC, 0);
        if (fd < 0)
                return fd;

        return subvol_remove_children(fd, subvolume, 0, flags);
}

int btrfs_subvol_remove_fd(int fd, const char *subvolume, BtrfsRemoveFlags flags) {
        return subvol_remove_children(fd, subvolume, 0, flags);
}

int btrfs_qgroup_copy_limits(int fd, uint64_t old_qgroupid, uint64_t new_qgroupid) {

        struct btrfs_ioctl_search_args args = {
                /* Tree of quota items */
                .key.tree_id = BTRFS_QUOTA_TREE_OBJECTID,

                /* The object ID is always 0 */
                .key.min_objectid = 0,
                .key.max_objectid = 0,

                /* Look precisely for the quota items */
                .key.min_type = BTRFS_QGROUP_LIMIT_KEY,
                .key.max_type = BTRFS_QGROUP_LIMIT_KEY,

                /* For our qgroup */
                .key.min_offset = old_qgroupid,
                .key.max_offset = old_qgroupid,

                /* No restrictions on the other components */
                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,
        };

        int r;

        r = btrfs_is_filesystem(fd);
        if (r < 0)
                return r;
        if (!r)
                return -ENOTTY;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0) {
                        if (errno == ENOENT) /* quota tree missing: quota is not enabled, hence nothing to copy */
                                break;

                        return -errno;
                }

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {
                        const struct btrfs_qgroup_limit_item *qli = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);
                        struct btrfs_ioctl_qgroup_limit_args qargs;
                        unsigned c;

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->objectid != 0)
                                continue;
                        if (sh->type != BTRFS_QGROUP_LIMIT_KEY)
                                continue;
                        if (sh->offset != old_qgroupid)
                                continue;

                        /* We found the entry, now copy things over. */

                        qargs = (struct btrfs_ioctl_qgroup_limit_args) {
                                .qgroupid = new_qgroupid,

                                .lim.max_rfer = le64toh(qli->max_rfer),
                                .lim.max_excl = le64toh(qli->max_excl),
                                .lim.rsv_rfer = le64toh(qli->rsv_rfer),
                                .lim.rsv_excl = le64toh(qli->rsv_excl),

                                .lim.flags = le64toh(qli->flags) & (BTRFS_QGROUP_LIMIT_MAX_RFER|
                                                                    BTRFS_QGROUP_LIMIT_MAX_EXCL|
                                                                    BTRFS_QGROUP_LIMIT_RSV_RFER|
                                                                    BTRFS_QGROUP_LIMIT_RSV_EXCL),
                        };

                        for (c = 0;; c++) {
                                if (ioctl(fd, BTRFS_IOC_QGROUP_LIMIT, &qargs) < 0) {
                                        if (errno == EBUSY && c < 10) {
                                                (void) btrfs_quota_scan_wait(fd);
                                                continue;
                                        }
                                        return -errno;
                                }

                                break;
                        }

                        return 1;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

        return 0;
}

static int copy_quota_hierarchy(int fd, uint64_t old_subvol_id, uint64_t new_subvol_id) {
        _cleanup_free_ uint64_t *old_qgroups = NULL, *old_parent_qgroups = NULL;
        bool copy_from_parent = false, insert_intermediary_qgroup = false;
        int n_old_qgroups, n_old_parent_qgroups, r, i;
        uint64_t old_parent_id;

        assert(fd >= 0);

        /* Copies a reduced form of quota information from the old to
         * the new subvolume. */

        n_old_qgroups = btrfs_qgroup_find_parents(fd, old_subvol_id, &old_qgroups);
        if (n_old_qgroups <= 0) /* Nothing to copy */
                return n_old_qgroups;

        r = btrfs_subvol_get_parent(fd, old_subvol_id, &old_parent_id);
        if (r == -ENXIO)
                /* We have no parent, hence nothing to copy. */
                n_old_parent_qgroups = 0;
        else if (r < 0)
                return r;
        else {
                n_old_parent_qgroups = btrfs_qgroup_find_parents(fd, old_parent_id, &old_parent_qgroups);
                if (n_old_parent_qgroups < 0)
                        return n_old_parent_qgroups;
        }

        for (i = 0; i < n_old_qgroups; i++) {
                uint64_t id;
                int j;

                r = btrfs_qgroupid_split(old_qgroups[i], NULL, &id);
                if (r < 0)
                        return r;

                if (id == old_subvol_id) {
                        /* The old subvolume was member of a qgroup
                         * that had the same id, but a different level
                         * as it self. Let's set up something similar
                         * in the destination. */
                        insert_intermediary_qgroup = true;
                        break;
                }

                for (j = 0; j < n_old_parent_qgroups; j++)
                        if (old_parent_qgroups[j] == old_qgroups[i]) {
                                /* The old subvolume shared a common
                                 * parent qgroup with its parent
                                 * subvolume. Let's set up something
                                 * similar in the destination. */
                                copy_from_parent = true;
                        }
        }

        if (!insert_intermediary_qgroup && !copy_from_parent)
                return 0;

        return btrfs_subvol_auto_qgroup_fd(fd, new_subvol_id, insert_intermediary_qgroup);
}

static int copy_subtree_quota_limits(int fd, uint64_t old_subvol, uint64_t new_subvol) {
        uint64_t old_subtree_qgroup, new_subtree_qgroup;
        bool changed;
        int r;

        /* First copy the leaf limits */
        r = btrfs_qgroup_copy_limits(fd, old_subvol, new_subvol);
        if (r < 0)
                return r;
        changed = r > 0;

        /* Then, try to copy the subtree limits, if there are any. */
        r = btrfs_subvol_find_subtree_qgroup(fd, old_subvol, &old_subtree_qgroup);
        if (r < 0)
                return r;
        if (r == 0)
                return changed;

        r = btrfs_subvol_find_subtree_qgroup(fd, new_subvol, &new_subtree_qgroup);
        if (r < 0)
                return r;
        if (r == 0)
                return changed;

        r = btrfs_qgroup_copy_limits(fd, old_subtree_qgroup, new_subtree_qgroup);
        if (r != 0)
                return r;

        return changed;
}

static int subvol_snapshot_children(int old_fd, int new_fd, const char *subvolume, uint64_t old_subvol_id, BtrfsSnapshotFlags flags) {

        struct btrfs_ioctl_search_args args = {
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                .key.min_objectid = BTRFS_FIRST_FREE_OBJECTID,
                .key.max_objectid = BTRFS_LAST_FREE_OBJECTID,

                .key.min_type = BTRFS_ROOT_BACKREF_KEY,
                .key.max_type = BTRFS_ROOT_BACKREF_KEY,

                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,
        };

        struct btrfs_ioctl_vol_args_v2 vol_args = {
                .flags = flags & BTRFS_SNAPSHOT_READ_ONLY ? BTRFS_SUBVOL_RDONLY : 0,
                .fd = old_fd,
        };
        _cleanup_close_ int subvolume_fd = -1;
        uint64_t new_subvol_id;
        int r;

        assert(old_fd >= 0);
        assert(new_fd >= 0);
        assert(subvolume);

        strncpy(vol_args.name, subvolume, sizeof(vol_args.name)-1);

        if (ioctl(new_fd, BTRFS_IOC_SNAP_CREATE_V2, &vol_args) < 0)
                return -errno;

        if (!(flags & BTRFS_SNAPSHOT_RECURSIVE) &&
            !(flags & BTRFS_SNAPSHOT_QUOTA))
                return 0;

        if (old_subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(old_fd, &old_subvol_id);
                if (r < 0)
                        return r;
        }

        r = btrfs_subvol_get_id(new_fd, vol_args.name, &new_subvol_id);
        if (r < 0)
                return r;

        if (flags & BTRFS_SNAPSHOT_QUOTA)
                (void) copy_quota_hierarchy(new_fd, old_subvol_id, new_subvol_id);

        if (!(flags & BTRFS_SNAPSHOT_RECURSIVE)) {

                if (flags & BTRFS_SNAPSHOT_QUOTA)
                        (void) copy_subtree_quota_limits(new_fd, old_subvol_id, new_subvol_id);

                return 0;
        }

        args.key.min_offset = args.key.max_offset = old_subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(old_fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return -errno;

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {
                        _cleanup_free_ char *p = NULL, *c = NULL, *np = NULL;
                        struct btrfs_ioctl_ino_lookup_args ino_args;
                        const struct btrfs_root_ref *ref;
                        _cleanup_close_ int old_child_fd = -1, new_child_fd = -1;

                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->type != BTRFS_ROOT_BACKREF_KEY)
                                continue;

                        /* Avoid finding the source subvolume a second
                         * time */
                        if (sh->offset != old_subvol_id)
                                continue;

                        /* Avoid running into loops if the new
                         * subvolume is below the old one. */
                        if (sh->objectid == new_subvol_id)
                                continue;

                        ref = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);
                        p = strndup((char*) ref + sizeof(struct btrfs_root_ref), le64toh(ref->name_len));
                        if (!p)
                                return -ENOMEM;

                        zero(ino_args);
                        ino_args.treeid = old_subvol_id;
                        ino_args.objectid = htole64(ref->dirid);

                        if (ioctl(old_fd, BTRFS_IOC_INO_LOOKUP, &ino_args) < 0)
                                return -errno;

                        /* The kernel returns an empty name if the
                         * subvolume is in the top-level directory,
                         * and otherwise appends a slash, so that we
                         * can just concatenate easily here, without
                         * adding a slash. */
                        c = strappend(ino_args.name, p);
                        if (!c)
                                return -ENOMEM;

                        old_child_fd = openat(old_fd, c, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                        if (old_child_fd < 0)
                                return -errno;

                        np = strjoin(subvolume, "/", ino_args.name);
                        if (!np)
                                return -ENOMEM;

                        new_child_fd = openat(new_fd, np, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                        if (new_child_fd < 0)
                                return -errno;

                        if (flags & BTRFS_SNAPSHOT_READ_ONLY) {
                                /* If the snapshot is read-only we
                                 * need to mark it writable
                                 * temporarily, to put the subsnapshot
                                 * into place. */

                                if (subvolume_fd < 0) {
                                        subvolume_fd = openat(new_fd, subvolume, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                                        if (subvolume_fd < 0)
                                                return -errno;
                                }

                                r = btrfs_subvol_set_read_only_fd(subvolume_fd, false);
                                if (r < 0)
                                        return r;
                        }

                        /* When btrfs clones the subvolumes, child
                         * subvolumes appear as empty directories. Remove
                         * them, so that we can create a new snapshot
                         * in their place */
                        if (unlinkat(new_child_fd, p, AT_REMOVEDIR) < 0) {
                                int k = -errno;

                                if (flags & BTRFS_SNAPSHOT_READ_ONLY)
                                        (void) btrfs_subvol_set_read_only_fd(subvolume_fd, true);

                                return k;
                        }

                        r = subvol_snapshot_children(old_child_fd, new_child_fd, p, sh->objectid, flags & ~BTRFS_SNAPSHOT_FALLBACK_COPY);

                        /* Restore the readonly flag */
                        if (flags & BTRFS_SNAPSHOT_READ_ONLY) {
                                int k;

                                k = btrfs_subvol_set_read_only_fd(subvolume_fd, true);
                                if (r >= 0 && k < 0)
                                        return k;
                        }

                        if (r < 0)
                                return r;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

        if (flags & BTRFS_SNAPSHOT_QUOTA)
                (void) copy_subtree_quota_limits(new_fd, old_subvol_id, new_subvol_id);

        return 0;
}

int btrfs_subvol_snapshot_fd(int old_fd, const char *new_path, BtrfsSnapshotFlags flags) {
        _cleanup_close_ int new_fd = -1;
        const char *subvolume;
        int r;

        assert(old_fd >= 0);
        assert(new_path);

        r = btrfs_is_subvol_fd(old_fd);
        if (r < 0)
                return r;
        if (r == 0) {
                bool plain_directory = false;

                /* If the source isn't a proper subvolume, fail unless fallback is requested */
                if (!(flags & BTRFS_SNAPSHOT_FALLBACK_COPY))
                        return -EISDIR;

                r = btrfs_subvol_make(new_path);
                if (r == -ENOTTY && (flags & BTRFS_SNAPSHOT_FALLBACK_DIRECTORY)) {
                        /* If the destination doesn't support subvolumes, then use a plain directory, if that's requested. */
                        if (mkdir(new_path, 0755) < 0)
                                return -errno;

                        plain_directory = true;
                } else if (r < 0)
                        return r;

                r = copy_directory_fd(old_fd, new_path, COPY_MERGE|COPY_REFLINK);
                if (r < 0)
                        goto fallback_fail;

                if (flags & BTRFS_SNAPSHOT_READ_ONLY) {

                        if (plain_directory) {
                                /* Plain directories have no recursive read-only flag, but something pretty close to
                                 * it: the IMMUTABLE bit. Let's use this here, if this is requested. */

                                if (flags & BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE)
                                        (void) chattr_path(new_path, FS_IMMUTABLE_FL, FS_IMMUTABLE_FL, NULL);
                        } else {
                                r = btrfs_subvol_set_read_only(new_path, true);
                                if (r < 0)
                                        goto fallback_fail;
                        }
                }

                return 0;

        fallback_fail:
                (void) rm_rf(new_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                return r;
        }

        r = extract_subvolume_name(new_path, &subvolume);
        if (r < 0)
                return r;

        new_fd = open_parent(new_path, O_CLOEXEC, 0);
        if (new_fd < 0)
                return new_fd;

        return subvol_snapshot_children(old_fd, new_fd, subvolume, 0, flags);
}

int btrfs_subvol_snapshot(const char *old_path, const char *new_path, BtrfsSnapshotFlags flags) {
        _cleanup_close_ int old_fd = -1;

        assert(old_path);
        assert(new_path);

        old_fd = open(old_path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (old_fd < 0)
                return -errno;

        return btrfs_subvol_snapshot_fd(old_fd, new_path, flags);
}

int btrfs_qgroup_find_parents(int fd, uint64_t qgroupid, uint64_t **ret) {

        struct btrfs_ioctl_search_args args = {
                /* Tree of quota items */
                .key.tree_id = BTRFS_QUOTA_TREE_OBJECTID,

                /* Look precisely for the quota relation items */
                .key.min_type = BTRFS_QGROUP_RELATION_KEY,
                .key.max_type = BTRFS_QGROUP_RELATION_KEY,

                /* No restrictions on the other components */
                .key.min_offset = 0,
                .key.max_offset = (uint64_t) -1,

                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,
        };

        _cleanup_free_ uint64_t *items = NULL;
        size_t n_items = 0, n_allocated = 0;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (qgroupid == 0) {
                r = btrfs_subvol_get_id_fd(fd, &qgroupid);
                if (r < 0)
                        return r;
        } else {
                r = btrfs_is_filesystem(fd);
                if (r < 0)
                        return r;
                if (!r)
                        return -ENOTTY;
        }

        args.key.min_objectid = args.key.max_objectid = qgroupid;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0) {
                        if (errno == ENOENT) /* quota tree missing: quota is disabled */
                                break;

                        return -errno;
                }

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->type != BTRFS_QGROUP_RELATION_KEY)
                                continue;
                        if (sh->offset < sh->objectid)
                                continue;
                        if (sh->objectid != qgroupid)
                                continue;

                        if (!GREEDY_REALLOC(items, n_allocated, n_items+1))
                                return -ENOMEM;

                        items[n_items++] = sh->offset;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

        if (n_items <= 0) {
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(items);

        return (int) n_items;
}

int btrfs_subvol_auto_qgroup_fd(int fd, uint64_t subvol_id, bool insert_intermediary_qgroup) {
        _cleanup_free_ uint64_t *qgroups = NULL;
        uint64_t parent_subvol;
        bool changed = false;
        int n = 0, r;

        assert(fd >= 0);

        /*
         * Sets up the specified subvolume's qgroup automatically in
         * one of two ways:
         *
         * If insert_intermediary_qgroup is false, the subvolume's
         * leaf qgroup will be assigned to the same parent qgroups as
         * the subvolume's parent subvolume.
         *
         * If insert_intermediary_qgroup is true a new intermediary
         * higher-level qgroup is created, with a higher level number,
         * but reusing the id of the subvolume. The level number is
         * picked as one smaller than the lowest level qgroup the
         * parent subvolume is a member of. If the parent subvolume's
         * leaf qgroup is assigned to no higher-level qgroup a new
         * qgroup of level 255 is created instead. Either way, the new
         * qgroup is then assigned to the parent's higher-level
         * qgroup, and the subvolume itself is assigned to it.
         *
         * If the subvolume is already assigned to a higher level
         * qgroup, no operation is executed.
         *
         * Effectively this means: regardless if
         * insert_intermediary_qgroup is true or not, after this
         * function is invoked the subvolume will be accounted within
         * the same qgroups as the parent. However, if it is true, it
         * will also get its own higher-level qgroup, which may in
         * turn be used by subvolumes created beneath this subvolume
         * later on.
         *
         * This hence defines a simple default qgroup setup for
         * subvolumes, as long as this function is invoked on each
         * created subvolume: each subvolume is always accounting
         * together with its immediate parents. Optionally, if
         * insert_intermediary_qgroup is true, it will also get a
         * qgroup that then includes all its own child subvolumes.
         */

        if (subvol_id == 0) {
                r = btrfs_is_subvol_fd(fd);
                if (r < 0)
                        return r;
                if (!r)
                        return -ENOTTY;

                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        }

        n = btrfs_qgroup_find_parents(fd, subvol_id, &qgroups);
        if (n < 0)
                return n;
        if (n > 0) /* already parent qgroups set up, let's bail */
                return 0;

        qgroups = mfree(qgroups);

        r = btrfs_subvol_get_parent(fd, subvol_id, &parent_subvol);
        if (r == -ENXIO)
                /* No parent, hence no qgroup memberships */
                n = 0;
        else if (r < 0)
                return r;
        else {
                n = btrfs_qgroup_find_parents(fd, parent_subvol, &qgroups);
                if (n < 0)
                        return n;
        }

        if (insert_intermediary_qgroup) {
                uint64_t lowest = 256, new_qgroupid;
                bool created = false;
                int i;

                /* Determine the lowest qgroup that the parent
                 * subvolume is assigned to. */

                for (i = 0; i < n; i++) {
                        uint64_t level;

                        r = btrfs_qgroupid_split(qgroups[i], &level, NULL);
                        if (r < 0)
                                return r;

                        if (level < lowest)
                                lowest = level;
                }

                if (lowest <= 1) /* There are no levels left we could use insert an intermediary qgroup at */
                        return -EBUSY;

                r = btrfs_qgroupid_make(lowest - 1, subvol_id, &new_qgroupid);
                if (r < 0)
                        return r;

                /* Create the new intermediary group, unless it already exists */
                r = btrfs_qgroup_create(fd, new_qgroupid);
                if (r < 0 && r != -EEXIST)
                        return r;
                if (r >= 0)
                        changed = created = true;

                for (i = 0; i < n; i++) {
                        r = btrfs_qgroup_assign(fd, new_qgroupid, qgroups[i]);
                        if (r < 0 && r != -EEXIST) {
                                if (created)
                                        (void) btrfs_qgroup_destroy_recursive(fd, new_qgroupid);

                                return r;
                        }
                        if (r >= 0)
                                changed = true;
                }

                r = btrfs_qgroup_assign(fd, subvol_id, new_qgroupid);
                if (r < 0 && r != -EEXIST) {
                        if (created)
                                (void) btrfs_qgroup_destroy_recursive(fd, new_qgroupid);
                        return r;
                }
                if (r >= 0)
                        changed = true;

        } else {
                int i;

                /* Assign our subvolume to all the same qgroups as the parent */

                for (i = 0; i < n; i++) {
                        r = btrfs_qgroup_assign(fd, subvol_id, qgroups[i]);
                        if (r < 0 && r != -EEXIST)
                                return r;
                        if (r >= 0)
                                changed = true;
                }
        }

        return changed;
}

int btrfs_subvol_auto_qgroup(const char *path, uint64_t subvol_id, bool create_intermediary_qgroup) {
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        return btrfs_subvol_auto_qgroup_fd(fd, subvol_id, create_intermediary_qgroup);
}

int btrfs_subvol_get_parent(int fd, uint64_t subvol_id, uint64_t *ret) {

        struct btrfs_ioctl_search_args args = {
                /* Tree of tree roots */
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                /* Look precisely for the subvolume items */
                .key.min_type = BTRFS_ROOT_BACKREF_KEY,
                .key.max_type = BTRFS_ROOT_BACKREF_KEY,

                /* No restrictions on the other components */
                .key.min_offset = 0,
                .key.max_offset = (uint64_t) -1,

                .key.min_transid = 0,
                .key.max_transid = (uint64_t) -1,
        };
        int r;

        assert(fd >= 0);
        assert(ret);

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        } else {
                r = btrfs_is_filesystem(fd);
                if (r < 0)
                        return r;
                if (!r)
                        return -ENOTTY;
        }

        args.key.min_objectid = args.key.max_objectid = subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return negative_errno();

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {

                        if (sh->type != BTRFS_ROOT_BACKREF_KEY)
                                continue;
                        if (sh->objectid != subvol_id)
                                continue;

                        *ret = sh->offset;
                        return 0;
                }
        }

        return -ENXIO;
}
