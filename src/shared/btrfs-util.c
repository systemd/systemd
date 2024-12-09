/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/btrfs_tree.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "chase.h"
#include "chattr-util.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "macro.h"
#include "path-util.h"
#include "rm-rf.h"
#include "smack-util.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-util.h"
#include "time-util.h"

/* WARNING: Be careful with file system ioctls! When we get an fd, we
 * need to make sure it either refers to only a regular file or
 * directory, or that it is located on btrfs, before invoking any
 * btrfs ioctls. The ioctl numbers are reused by some device drivers
 * (such as DRM), and hence might have bad effects when invoked on
 * device nodes (that reference drivers) rather than fds to normal
 * files or directories. */

int btrfs_is_subvol_at(int dir_fd, const char *path) {
        struct stat st;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        /* On btrfs subvolumes always have the inode 256 */

        if (fstatat(dir_fd, strempty(path), &st, isempty(path) ? AT_EMPTY_PATH : 0) < 0)
                return -errno;

        if (!btrfs_might_be_subvol(&st))
                return 0;

        return is_fs_type_at(dir_fd, path, BTRFS_SUPER_MAGIC);
}

int btrfs_subvol_set_read_only_at(int dir_fd, const char *path, bool b) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t flags, nflags;
        struct stat st;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        fd = xopenat(dir_fd, path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return fd;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!btrfs_might_be_subvol(&st))
                return -EINVAL;

        if (ioctl(fd, BTRFS_IOC_SUBVOL_GETFLAGS, &flags) < 0)
                return -errno;

        nflags = UPDATE_FLAG(flags, BTRFS_SUBVOL_RDONLY, b);
        if (flags == nflags)
                return 0;

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_SUBVOL_SETFLAGS, &nflags));
}

int btrfs_subvol_get_read_only_fd(int fd) {
        uint64_t flags;
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!btrfs_might_be_subvol(&st))
                return -EINVAL;

        if (ioctl(fd, BTRFS_IOC_SUBVOL_GETFLAGS, &flags) < 0)
                return -errno;

        return !!(flags & BTRFS_SUBVOL_RDONLY);
}

int btrfs_get_block_device_at(int dir_fd, const char *path, dev_t *ret) {
        struct btrfs_ioctl_fs_info_args fsi = {};
        _cleanup_close_ int fd = -EBADF;
        uint64_t id;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);
        assert(ret);

        fd = xopenat(dir_fd, path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return fd;

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        if (ioctl(fd, BTRFS_IOC_FS_INFO, &fsi) < 0)
                return -errno;

        /* We won't do this for btrfs RAID */
        if (fsi.num_devices != 1) {
                *ret = 0;
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

                /* For the root fs — when no initrd is involved — btrfs returns /dev/root on any kernels from
                 * the past few years. That sucks, as we have no API to determine the actual root then. let's
                 * return an recognizable error for this case, so that the caller can maybe print a nice
                 * message about this.
                 *
                 * https://bugzilla.kernel.org/show_bug.cgi?id=89721 */
                if (path_equal((char*) di.path, "/dev/root"))
                        return -EUCLEAN;

                if (stat((char*) di.path, &st) < 0)
                        return -errno;

                if (!S_ISBLK(st.st_mode))
                        return -ENOTBLK;

                if (major(st.st_rdev) == 0)
                        return -ENODEV;

                *ret = st.st_rdev;
                return 1;
        }

        return -ENODEV;
}

int btrfs_subvol_get_id_fd(int fd, uint64_t *ret) {
        struct btrfs_ioctl_ino_lookup_args args = {
                .objectid = BTRFS_FIRST_FREE_OBJECTID
        };
        int r;

        assert(fd >= 0);
        assert(ret);

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args) < 0)
                return -errno;

        *ret = args.treeid;
        return 0;
}

int btrfs_subvol_get_id(int fd, const char *subvol, uint64_t *ret) {
        _cleanup_close_ int subvol_fd = -EBADF;

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

        if (args->key.min_offset < UINT64_MAX) {
                args->key.min_offset++;
                return true;
        }

        if (args->key.min_type < UINT8_MAX) {
                args->key.min_type++;
                args->key.min_offset = 0;
                return true;
        }

        if (args->key.min_objectid < UINT64_MAX) {
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

typedef struct BtrfsForeachIterator {
        const struct btrfs_ioctl_search_args *args;
        size_t offset;
        unsigned index;
        struct btrfs_ioctl_search_header *header;
        const void **body;
} BtrfsForeachIterator;

static int btrfs_iterate(BtrfsForeachIterator *i) {
        assert(i);
        assert(i->args);
        assert(i->header);
        assert(i->body);

        if (i->index >= i->args->key.nr_items)
                return 0; /* end */

        assert_cc(BTRFS_SEARCH_ARGS_BUFSIZE >= sizeof(struct btrfs_ioctl_search_header));
        if (i->offset > BTRFS_SEARCH_ARGS_BUFSIZE - sizeof(struct btrfs_ioctl_search_header))
                return -EBADMSG;

        struct btrfs_ioctl_search_header h;
        memcpy(&h, (const uint8_t*) i->args->buf + i->offset, sizeof(struct btrfs_ioctl_search_header));

        if (i->offset > BTRFS_SEARCH_ARGS_BUFSIZE - sizeof(struct btrfs_ioctl_search_header) - h.len)
                return -EBADMSG;

        *i->body = (const uint8_t*) i->args->buf + i->offset + sizeof(struct btrfs_ioctl_search_header);
        *i->header = h;
        i->offset += sizeof(struct btrfs_ioctl_search_header) + h.len;
        i->index++;

        return 1;
}

/* Iterates through a series of struct btrfs_file_extent_item elements. They are unfortunately not aligned,
 * hence we copy out the header from them */
#define FOREACH_BTRFS_IOCTL_SEARCH_HEADER(_sh, _body, _args)            \
        for (BtrfsForeachIterator iterator = {                          \
                        .args = &(_args),                               \
                        .header = &(_sh),                               \
                        .body = &(_body),                               \
             };                                                         \
             btrfs_iterate(&iterator) > 0; )

int btrfs_subvol_get_info_fd(int fd, uint64_t subvol_id, BtrfsSubvolInfo *ret) {
        struct btrfs_ioctl_search_args args = {
                /* Tree of tree roots */
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                /* Look precisely for the subvolume items */
                .key.min_type = BTRFS_ROOT_ITEM_KEY,
                .key.max_type = BTRFS_ROOT_ITEM_KEY,

                .key.min_offset = 0,
                .key.max_offset = UINT64_MAX,

                /* No restrictions on the other components */
                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };

        bool found = false;
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Make sure this works on O_PATH fds */
        _cleanup_close_ int fd_close = -EBADF;
        fd = fd_reopen_condition(fd, O_CLOEXEC|O_RDONLY|O_DIRECTORY, O_PATH, &fd_close);
        if (fd < 0)
                return fd;

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        } else {
                r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTTY;
        }

        args.key.min_objectid = args.key.max_objectid = subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                const void *body;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return -errno;

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, args) {
                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, &sh);

                        if (sh.objectid != subvol_id)
                                continue;
                        if (sh.type != BTRFS_ROOT_ITEM_KEY)
                                continue;

                        /* Older versions of the struct lacked the otime setting */
                        if (sh.len < offsetof(struct btrfs_root_item, otime) + sizeof(struct btrfs_timespec))
                                continue;

                        const struct btrfs_root_item *ri = body;
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
        return found ? 0 : -ENODATA;
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
                .key.max_transid = UINT64_MAX,
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
                r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTTY;
        }

        args.key.min_offset = args.key.max_offset = qgroupid;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                const void *body;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0) {
                        if (errno == ENOENT) /* quota tree is missing: quota disabled */
                                break;

                        return -errno;
                }

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, args) {

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, &sh);

                        if (sh.objectid != 0)
                                continue;
                        if (sh.offset != qgroupid)
                                continue;

                        if (sh.type == BTRFS_QGROUP_INFO_KEY) {
                                const struct btrfs_qgroup_info_item *qii = body;

                                ret->referenced = le64toh(qii->rfer);
                                ret->exclusive = le64toh(qii->excl);

                                found_info = true;

                        } else if (sh.type == BTRFS_QGROUP_LIMIT_KEY) {
                                const struct btrfs_qgroup_limit_item *qli = body;

                                if (le64toh(qli->flags) & BTRFS_QGROUP_LIMIT_MAX_RFER)
                                        ret->referenced_max = le64toh(qli->max_rfer);
                                else
                                        ret->referenced_max = UINT64_MAX;

                                if (le64toh(qli->flags) & BTRFS_QGROUP_LIMIT_MAX_EXCL)
                                        ret->exclusive_max = le64toh(qli->max_excl);
                                else
                                        ret->exclusive_max = UINT64_MAX;

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
                ret->referenced = UINT64_MAX;
                ret->exclusive = UINT64_MAX;
        }

        if (!found_limit) {
                ret->referenced_max = UINT64_MAX;
                ret->exclusive_max = UINT64_MAX;
        }

        return 0;
}

int btrfs_qgroup_get_quota(const char *path, uint64_t qgroupid, BtrfsQuotaInfo *ret) {
        _cleanup_close_ int fd = -EBADF;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_qgroup_get_quota_fd(fd, qgroupid, ret);
}

int btrfs_subvol_find_subtree_qgroup(int fd, uint64_t subvol_id, uint64_t *ret) {
        uint64_t level, lowest = UINT64_MAX, lowest_qgroupid = 0;
        _cleanup_free_ uint64_t *qgroups = NULL;
        int r, n;

        assert(fd >= 0);
        assert(ret);

        /* This finds the "subtree" qgroup for a specific
         * subvolume. This only works for subvolumes that have been
         * prepared with btrfs_subvol_auto_qgroup_fd() with
         * insert_intermediary_qgroup=true (or equivalent). For others
         * it will return the leaf qgroup instead. The two cases may
         * be distinguished via the return value, which is 1 in case
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

        for (int i = 0; i < n; i++) {
                uint64_t id;

                r = btrfs_qgroupid_split(qgroups[i], &level, &id);
                if (r < 0)
                        return r;

                if (id != subvol_id)
                        continue;

                if (lowest == UINT64_MAX || level < lowest) {
                        lowest_qgroupid = qgroups[i];
                        lowest = level;
                }
        }

        if (lowest == UINT64_MAX) {
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
        _cleanup_close_ int fd = -EBADF;

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

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_DEFRAG, NULL));
}

int btrfs_defrag(const char *p) {
        _cleanup_close_ int fd = -EBADF;

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

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_QUOTA_CTL, &args));
}

int btrfs_quota_enable(const char *path, bool b) {
        _cleanup_close_ int fd = -EBADF;

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
        int r;

        assert(fd >= 0);

        if (qgroupid == 0) {
                r = btrfs_subvol_get_id_fd(fd, &qgroupid);
                if (r < 0)
                        return r;
        } else {
                r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTTY;
        }

        args.qgroupid = qgroupid;

        for (unsigned c = 0;; c++) {
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
        _cleanup_close_ int fd = -EBADF;

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
        _cleanup_close_ int fd = -EBADF;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_subvol_set_subtree_quota_limit_fd(fd, subvol_id, referenced_max);
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
        int r;

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        for (unsigned c = 0;; c++) {
                if (ioctl(fd, BTRFS_IOC_QGROUP_CREATE, &args) < 0) {

                        /* On old kernels if quota is not enabled, we get EINVAL. On newer kernels we get
                         * ENOTCONN. Let's always convert this to ENOTCONN to make this recognizable
                         * everywhere the same way. */

                        if (IN_SET(errno, EINVAL, ENOTCONN))
                                return -ENOTCONN;

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
        int n, r;

        /* Destroys the specified qgroup, but unassigns it from all
         * its parents first. Also, it recursively destroys all
         * qgroups it is assigned to that have the same id part of the
         * qgroupid as the specified group. */

        r = btrfs_qgroupid_split(qgroupid, NULL, &subvol_id);
        if (r < 0)
                return r;

        n = btrfs_qgroup_find_parents(fd, qgroupid, &qgroups);
        if (n < 0)
                return n;

        for (int i = 0; i < n; i++) {
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

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_QUOTA_RESCAN, &args));
}

int btrfs_quota_scan_wait(int fd) {
        assert(fd >= 0);

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_QUOTA_RESCAN_WAIT));
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
        int r;

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        for (unsigned c = 0;; c++) {
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
                .key.max_transid = UINT64_MAX,
        };

        struct btrfs_ioctl_vol_args vol_args = {};
        _cleanup_close_ int subvol_fd = -EBADF;
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

        /* Let's check if this is actually a subvolume. Note that this is mostly redundant, as BTRFS_IOC_SNAP_DESTROY
         * would fail anyway if it is not. However, it's a good thing to check this ahead of time so that we can return
         * ENOTTY unconditionally in this case. This is different from the ioctl() which will return EPERM/EACCES if we
         * don't have the privileges to remove subvolumes, regardless if the specified directory is actually a
         * subvolume or not. In order to make it easy for callers to cover the "this is not a btrfs subvolume" case
         * let's prefer ENOTTY over EPERM/EACCES though. */
        r = btrfs_is_subvol_fd(subvol_fd);
        if (r < 0)
                return r;
        if (r == 0) /* Not a btrfs subvolume */
                return -ENOTTY;

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
                struct btrfs_ioctl_search_header sh;
                const void *body;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return -errno;

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, args) {
                        _cleanup_free_ char *p = NULL;

                        btrfs_ioctl_search_args_set(&args, &sh);

                        if (sh.type != BTRFS_ROOT_BACKREF_KEY)
                                continue;
                        if (sh.offset != subvol_id)
                                continue;

                        const struct btrfs_root_ref *ref = body;
                        p = memdup_suffix0((char*) ref + sizeof(struct btrfs_root_ref), le64toh(ref->name_len));
                        if (!p)
                                return -ENOMEM;

                        struct btrfs_ioctl_ino_lookup_args ino_args = {
                                .treeid = subvol_id,
                                .objectid = htole64(ref->dirid),
                        };

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
                                r = subvol_remove_children(subvol_fd, p, sh.objectid, flags);
                        else {
                                _cleanup_close_ int child_fd = -EBADF;

                                /* Subvolume is somewhere further down,
                                 * hence we need to open the
                                 * containing directory first */

                                child_fd = openat(subvol_fd, ino_args.name, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                                if (child_fd < 0)
                                        return -errno;

                                r = subvol_remove_children(child_fd, p, sh.objectid, flags);
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

int btrfs_subvol_remove_at(int dir_fd, const char *path, BtrfsRemoveFlags flags) {
        _cleanup_free_ char *subvolume = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(path);

        fd = chase_and_openat(dir_fd, path, CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_CLOEXEC, &subvolume);
        if (fd < 0)
                return fd;

        r = btrfs_validate_subvolume_name(subvolume);
        if (r < 0)
                return r;

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
                .key.max_transid = UINT64_MAX,
        };

        int r;

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                const void *body;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0) {
                        if (errno == ENOENT) /* quota tree missing: quota is not enabled, hence nothing to copy */
                                break;

                        return -errno;
                }

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, args) {
                        struct btrfs_ioctl_qgroup_limit_args qargs;
                        unsigned c;

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, &sh);

                        if (sh.objectid != 0)
                                continue;
                        if (sh.type != BTRFS_QGROUP_LIMIT_KEY)
                                continue;
                        if (sh.offset != old_qgroupid)
                                continue;

                        /* We found the entry, now copy things over. */

                        const struct btrfs_qgroup_limit_item *qli = body;
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
        int n_old_qgroups, n_old_parent_qgroups, r;
        uint64_t old_parent_id;

        assert(fd >= 0);

        /* Copies a reduced form of quota information from the old to
         * the new subvolume. */

        n_old_qgroups = btrfs_qgroup_find_parents(fd, old_subvol_id, &old_qgroups);
        if (n_old_qgroups <= 0) /* Nothing to copy */
                return n_old_qgroups;

        assert(old_qgroups); /* Coverity gets confused by the macro iterator allocating this, add a hint */

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

        for (int i = 0; i < n_old_qgroups; i++) {
                uint64_t id;

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

                for (int j = 0; j < n_old_parent_qgroups; j++)
                        if (old_parent_qgroups[j] == old_qgroups[i])
                                /* The old subvolume shared a common
                                 * parent qgroup with its parent
                                 * subvolume. Let's set up something
                                 * similar in the destination. */
                                copy_from_parent = true;
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

static int subvol_snapshot_children(
                int old_fd,
                int new_fd,
                const char *subvolume,
                uint64_t old_subvol_id,
                BtrfsSnapshotFlags flags) {

        struct btrfs_ioctl_search_args args = {
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                .key.min_objectid = BTRFS_FIRST_FREE_OBJECTID,
                .key.max_objectid = BTRFS_LAST_FREE_OBJECTID,

                .key.min_type = BTRFS_ROOT_BACKREF_KEY,
                .key.max_type = BTRFS_ROOT_BACKREF_KEY,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };

        struct btrfs_ioctl_vol_args_v2 vol_args = {
                .flags = flags & BTRFS_SNAPSHOT_READ_ONLY ? BTRFS_SUBVOL_RDONLY : 0,
                .fd = old_fd,
        };
        _cleanup_close_ int subvolume_fd = -EBADF;
        uint64_t new_subvol_id;
        int r;

        assert(old_fd >= 0);
        assert(new_fd >= 0);
        assert(subvolume);

        strncpy(vol_args.name, subvolume, sizeof(vol_args.name)-1);

        if (ioctl(new_fd, BTRFS_IOC_SNAP_CREATE_V2, &vol_args) < 0)
                return -errno;

        if (FLAGS_SET(flags, BTRFS_SNAPSHOT_LOCK_BSD)) {
                subvolume_fd = xopenat_lock(new_fd, subvolume,
                                            O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW,
                                            LOCK_BSD,
                                            LOCK_EX);
                if (subvolume_fd < 0)
                        return subvolume_fd;

                r = btrfs_is_subvol_fd(subvolume_fd);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EEXIST;
        }

        if (!(flags & BTRFS_SNAPSHOT_RECURSIVE) &&
            !(flags & BTRFS_SNAPSHOT_QUOTA))
                return flags & BTRFS_SNAPSHOT_LOCK_BSD ? TAKE_FD(subvolume_fd) : 0;

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

                return flags & BTRFS_SNAPSHOT_LOCK_BSD ? TAKE_FD(subvolume_fd) : 0;
        }

        args.key.min_offset = args.key.max_offset = old_subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                const void *body;

                args.key.nr_items = 256;
                if (ioctl(old_fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return -errno;

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, args) {
                        _cleanup_free_ char *p = NULL, *c = NULL, *np = NULL;
                        _cleanup_close_ int old_child_fd = -EBADF, new_child_fd = -EBADF;

                        btrfs_ioctl_search_args_set(&args, &sh);

                        if (sh.type != BTRFS_ROOT_BACKREF_KEY)
                                continue;

                        /* Avoid finding the source subvolume a second time */
                        if (sh.offset != old_subvol_id)
                                continue;

                        /* Avoid running into loops if the new subvolume is below the old one. */
                        if (sh.objectid == new_subvol_id)
                                continue;

                        const struct btrfs_root_ref *ref = body;
                        p = memdup_suffix0((char*) ref + sizeof(struct btrfs_root_ref), le64toh(ref->name_len));
                        if (!p)
                                return -ENOMEM;

                        struct btrfs_ioctl_ino_lookup_args ino_args = {
                                .treeid = old_subvol_id,
                                .objectid = htole64(ref->dirid),
                        };

                        if (ioctl(old_fd, BTRFS_IOC_INO_LOOKUP, &ino_args) < 0)
                                return -errno;

                        c = path_join(ino_args.name, p);
                        if (!c)
                                return -ENOMEM;

                        old_child_fd = openat(old_fd, c, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                        if (old_child_fd < 0)
                                return -errno;

                        np = path_join(subvolume, ino_args.name);
                        if (!np)
                                return -ENOMEM;

                        new_child_fd = openat(new_fd, np, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                        if (new_child_fd < 0)
                                return -errno;

                        if (flags & BTRFS_SNAPSHOT_READ_ONLY) {
                                /* If the snapshot is read-only we need to mark it writable temporarily, to
                                 * put the subsnapshot into place. */

                                if (subvolume_fd < 0) {
                                        subvolume_fd = openat(new_fd, subvolume, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                                        if (subvolume_fd < 0)
                                                return -errno;
                                }

                                r = btrfs_subvol_set_read_only_fd(subvolume_fd, false);
                                if (r < 0)
                                        return r;
                        }

                        /* When btrfs clones the subvolumes, child subvolumes appear as empty
                         * directories. Remove them, so that we can create a new snapshot in their place */
                        if (unlinkat(new_child_fd, p, AT_REMOVEDIR) < 0) {
                                int k = -errno;

                                if (flags & BTRFS_SNAPSHOT_READ_ONLY)
                                        (void) btrfs_subvol_set_read_only_fd(subvolume_fd, true);

                                return k;
                        }

                        r = subvol_snapshot_children(old_child_fd, new_child_fd, p, sh.objectid,
                                                     flags & ~(BTRFS_SNAPSHOT_FALLBACK_COPY|BTRFS_SNAPSHOT_LOCK_BSD));

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

        return flags & BTRFS_SNAPSHOT_LOCK_BSD ? TAKE_FD(subvolume_fd) : 0;
}

int btrfs_subvol_snapshot_at_full(
                int dir_fdf,
                const char *from,
                int dir_fdt,
                const char *to,
                BtrfsSnapshotFlags flags,
                copy_progress_path_t progress_path,
                copy_progress_bytes_t progress_bytes,
                void *userdata) {

        _cleanup_free_ char *subvolume = NULL;
        _cleanup_close_ int old_fd = -EBADF, new_fd = -EBADF, subvolume_fd = -EBADF;
        int r;

        assert(dir_fdf >= 0 || dir_fdf == AT_FDCWD);
        assert(dir_fdt >= 0 || dir_fdt == AT_FDCWD);
        assert(to);

        old_fd = xopenat(dir_fdf, from, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (old_fd < 0)
                return old_fd;

        new_fd = chase_and_openat(dir_fdt, to, CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_CLOEXEC, &subvolume);
        if (new_fd < 0)
                return new_fd;

        r = btrfs_validate_subvolume_name(subvolume);
        if (r < 0)
                return r;

        r = btrfs_is_subvol_at(dir_fdf, from);
        if (r < 0)
                return r;
        if (r == 0) {
                bool plain_directory = false;

                /* If the source isn't a proper subvolume, fail unless fallback is requested */
                if (!(flags & BTRFS_SNAPSHOT_FALLBACK_COPY))
                        return -EISDIR;

                r = btrfs_subvol_make(new_fd, subvolume);
                if (r < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(r) && (flags & BTRFS_SNAPSHOT_FALLBACK_DIRECTORY)) {
                                /* If the destination doesn't support subvolumes, then use a plain directory, if that's requested. */
                                if (mkdirat(new_fd, subvolume, 0755) < 0)
                                        return -errno;

                                plain_directory = true;
                        } else
                                return r;
                }

                if (FLAGS_SET(flags, BTRFS_SNAPSHOT_LOCK_BSD)) {
                        subvolume_fd = xopenat_lock(new_fd, subvolume,
                                                    O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW,
                                                    LOCK_BSD,
                                                    LOCK_EX);
                        if (subvolume_fd < 0)
                                return subvolume_fd;

                        if (!plain_directory) {
                                r = btrfs_is_subvol_fd(subvolume_fd);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -EEXIST;
                        }
                }

                r = copy_directory_at_full(
                                dir_fdf, from,
                                new_fd, subvolume,
                                COPY_MERGE_EMPTY|
                                COPY_REFLINK|
                                COPY_SAME_MOUNT|
                                COPY_HARDLINKS|
                                COPY_ALL_XATTRS|
                                (FLAGS_SET(flags, BTRFS_SNAPSHOT_SIGINT) ? COPY_SIGINT : 0)|
                                (FLAGS_SET(flags, BTRFS_SNAPSHOT_SIGTERM) ? COPY_SIGTERM : 0),
                                progress_path,
                                progress_bytes,
                                userdata);
                if (r < 0)
                        goto fallback_fail;

                if (flags & BTRFS_SNAPSHOT_READ_ONLY) {

                        if (plain_directory) {
                                /* Plain directories have no recursive read-only flag, but something pretty close to
                                 * it: the IMMUTABLE bit. Let's use this here, if this is requested. */

                                if (flags & BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE)
                                        (void) chattr_at(new_fd, subvolume, FS_IMMUTABLE_FL, FS_IMMUTABLE_FL, NULL);
                        } else {
                                r = btrfs_subvol_set_read_only_at(new_fd, subvolume, true);
                                if (r < 0)
                                        goto fallback_fail;
                        }
                }

                return flags & BTRFS_SNAPSHOT_LOCK_BSD ? TAKE_FD(subvolume_fd) : 0;

        fallback_fail:
                (void) rm_rf_at(new_fd, subvolume, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                return r;
        }

        return subvol_snapshot_children(old_fd, new_fd, subvolume, 0, flags);
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
                .key.max_offset = UINT64_MAX,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };

        _cleanup_free_ uint64_t *items = NULL;
        size_t n_items = 0;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (qgroupid == 0) {
                r = btrfs_subvol_get_id_fd(fd, &qgroupid);
                if (r < 0)
                        return r;
        } else {
                r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTTY;
        }

        args.key.min_objectid = args.key.max_objectid = qgroupid;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                _unused_ const void *body;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0) {
                        if (errno == ENOENT) /* quota tree missing: quota is disabled */
                                break;

                        return -errno;
                }

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, args) {

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, &sh);

                        if (sh.type != BTRFS_QGROUP_RELATION_KEY)
                                continue;
                        if (sh.offset < sh.objectid)
                                continue;
                        if (sh.objectid != qgroupid)
                                continue;

                        if (!GREEDY_REALLOC(items, n_items+1))
                                return -ENOMEM;

                        items[n_items++] = sh.offset;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

        assert((n_items > 0) == !!items);
        assert(n_items <= INT_MAX);

        *ret = TAKE_PTR(items);
        return (int) n_items;
}

int btrfs_subvol_auto_qgroup_fd(int fd, uint64_t subvol_id, bool insert_intermediary_qgroup) {
        _cleanup_free_ uint64_t *qgroups = NULL;
        _cleanup_close_ int real_fd = -EBADF;
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

        /* Turn this into a proper fd, if it is currently O_PATH */
        fd = fd_reopen_condition(fd, O_RDONLY|O_CLOEXEC, O_PATH, &real_fd);
        if (fd < 0)
                return fd;

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

                /* Determine the lowest qgroup that the parent
                 * subvolume is assigned to. */

                for (int i = 0; i < n; i++) {
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

                for (int i = 0; i < n; i++) {
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
        _cleanup_close_ int fd = -EBADF;

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        return btrfs_subvol_auto_qgroup_fd(fd, subvol_id, create_intermediary_qgroup);
}

int btrfs_subvol_make_default(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t id;
        int r;

        assert(path);

        fd = open(path, O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        r = btrfs_subvol_get_id_fd(fd, &id);
        if (r < 0)
                return r;

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_DEFAULT_SUBVOL, &id));
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
                .key.max_offset = UINT64_MAX,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };
        int r;

        assert(fd >= 0);
        assert(ret);

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        } else {
                r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTTY;
        }

        args.key.min_objectid = args.key.max_objectid = subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                _unused_ const void *body = NULL;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return negative_errno();

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, args) {

                        if (sh.type != BTRFS_ROOT_BACKREF_KEY)
                                continue;
                        if (sh.objectid != subvol_id)
                                continue;

                        *ret = sh.offset;
                        return 0;
                }
        }

        return -ENXIO;
}

int btrfs_forget_device(const char *path) {
        _cleanup_close_ int control_fd = -EBADF;
        struct btrfs_ioctl_vol_args args = {};

        assert(path);

        if (strlen(path) > BTRFS_PATH_NAME_MAX)
                return -E2BIG;

        strcpy(args.name, path);

        control_fd = open("/dev/btrfs-control", O_RDWR|O_CLOEXEC);
        if (control_fd < 0)
                return -errno;

        return RET_NERRNO(ioctl(control_fd, BTRFS_IOC_FORGET_DEV, &args));
}

typedef struct BtrfsStripe {
        uint64_t devid;
        uint64_t offset;
} BtrfsStripe;

typedef struct BtrfsChunk {
        uint64_t offset;
        uint64_t length;
        uint64_t type;

        BtrfsStripe *stripes;
        uint16_t n_stripes;
        uint64_t stripe_len;
} BtrfsChunk;

typedef struct BtrfsChunkTree {
        BtrfsChunk **chunks;
        size_t n_chunks;
} BtrfsChunkTree;

static BtrfsChunk* btrfs_chunk_free(BtrfsChunk *chunk) {
        if (!chunk)
                return NULL;

        free(chunk->stripes);

        return mfree(chunk);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(BtrfsChunk*, btrfs_chunk_free);

static void btrfs_chunk_tree_done(BtrfsChunkTree *tree) {
        assert(tree);

        FOREACH_ARRAY(i, tree->chunks, tree->n_chunks)
                btrfs_chunk_free(*i);

        free(tree->chunks);
}

static int btrfs_read_chunk_tree_fd(int fd, BtrfsChunkTree *ret) {

        struct btrfs_ioctl_search_args search_args = {
                .key.tree_id = BTRFS_CHUNK_TREE_OBJECTID,

                .key.min_type = BTRFS_CHUNK_ITEM_KEY,
                .key.max_type = BTRFS_CHUNK_ITEM_KEY,

                .key.min_objectid = BTRFS_FIRST_CHUNK_TREE_OBJECTID,
                .key.max_objectid = BTRFS_FIRST_CHUNK_TREE_OBJECTID,

                .key.min_offset = 0,
                .key.max_offset = UINT64_MAX,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };

        _cleanup_(btrfs_chunk_tree_done) BtrfsChunkTree tree = {};

        assert(fd >= 0);
        assert(ret);

        while (btrfs_ioctl_search_args_compare(&search_args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                const void *body;

                search_args.key.nr_items = 256;

                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &search_args) < 0)
                        return -errno;

                if (search_args.key.nr_items == 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, search_args) {
                        _cleanup_(btrfs_chunk_freep) BtrfsChunk *chunk = NULL;

                        btrfs_ioctl_search_args_set(&search_args, &sh);

                        if (sh.objectid != BTRFS_FIRST_CHUNK_TREE_OBJECTID)
                                continue;
                        if (sh.type != BTRFS_CHUNK_ITEM_KEY)
                                continue;

                        chunk = new(BtrfsChunk, 1);
                        if (!chunk)
                                return -ENOMEM;

                        const struct btrfs_chunk *item = body;
                        *chunk = (BtrfsChunk) {
                                .offset = sh.offset,
                                .length = le64toh(item->length),
                                .type = le64toh(item->type),
                                .n_stripes = le16toh(item->num_stripes),
                                .stripe_len = le64toh(item->stripe_len),
                        };

                        chunk->stripes = new(BtrfsStripe, chunk->n_stripes);
                        if (!chunk->stripes)
                                return -ENOMEM;

                        for (size_t j = 0; j < chunk->n_stripes; j++) {
                                const struct btrfs_stripe *stripe = &item->stripe + j;

                                chunk->stripes[j] = (BtrfsStripe) {
                                        .devid = le64toh(stripe->devid),
                                        .offset = le64toh(stripe->offset),
                                };
                        }

                        if (!GREEDY_REALLOC(tree.chunks, tree.n_chunks + 1))
                                return -ENOMEM;

                        tree.chunks[tree.n_chunks++] = TAKE_PTR(chunk);
                }

                if (!btrfs_ioctl_search_args_inc(&search_args))
                        break;
        }

        *ret = TAKE_STRUCT(tree);
        return 0;
}

static BtrfsChunk* btrfs_find_chunk_from_logical_address(const BtrfsChunkTree *tree, uint64_t logical) {
        size_t min_index, max_index;

        assert(tree);
        assert(tree->chunks || tree->n_chunks == 0);

        if (tree->n_chunks == 0)
                return NULL;

        /* bisection */
        min_index = 0;
        max_index = tree->n_chunks - 1;

        while (min_index <= max_index) {
                size_t mid = (min_index + max_index) / 2;

                if (logical < tree->chunks[mid]->offset) {
                        if (mid < 1)
                                return NULL;

                        max_index = mid - 1;
                } else if (logical >= tree->chunks[mid]->offset + tree->chunks[mid]->length)
                        min_index = mid + 1;
                else
                        return tree->chunks[mid];
        }

        return NULL;
}

static int btrfs_is_nocow_fd(int fd) {
        unsigned flags;
        int r;

        assert(fd >= 0);

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        r = read_attr_fd(fd, &flags);
        if (r < 0)
                return r;

        return FLAGS_SET(flags, FS_NOCOW_FL) && !FLAGS_SET(flags, FS_COMPR_FL);
}

int btrfs_get_file_physical_offset_fd(int fd, uint64_t *ret) {

        struct btrfs_ioctl_search_args search_args = {
                .key.min_type = BTRFS_EXTENT_DATA_KEY,
                .key.max_type = BTRFS_EXTENT_DATA_KEY,

                .key.min_offset = 0,
                .key.max_offset = UINT64_MAX,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };

        _cleanup_(btrfs_chunk_tree_done) BtrfsChunkTree tree = {};
        uint64_t subvol_id;
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return -errno;

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        r = btrfs_is_nocow_fd(fd);
        if (r < 0)
                return r;
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot get physical address for btrfs extent: CoW enabled");

        r = btrfs_subvol_get_id_fd(fd, &subvol_id);
        if (r < 0)
                return r;

        r = btrfs_read_chunk_tree_fd(fd, &tree);
        if (r < 0)
                return r;

        search_args.key.tree_id = subvol_id;
        search_args.key.min_objectid = search_args.key.max_objectid = st.st_ino;

        while (btrfs_ioctl_search_args_compare(&search_args) <= 0) {
                struct btrfs_ioctl_search_header sh;
                const void *body;

                search_args.key.nr_items = 256;

                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &search_args) < 0)
                        return -errno;

                if (search_args.key.nr_items == 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(sh, body, search_args) {
                        uint64_t logical_offset;
                        BtrfsChunk *chunk;

                        btrfs_ioctl_search_args_set(&search_args, &sh);

                        if (sh.type != BTRFS_EXTENT_DATA_KEY)
                                continue;

                        if (sh.objectid != st.st_ino)
                                continue;

                        const struct btrfs_file_extent_item *item = body;
                        if (!IN_SET(item->type, BTRFS_FILE_EXTENT_REG, BTRFS_FILE_EXTENT_PREALLOC))
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot get physical address for btrfs extent: invalid type %" PRIu8,
                                                       item->type);

                        if (item->compression != 0 || item->encryption != 0 || item->other_encoding != 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot get physical address for btrfs extent: has incompatible property");

                        logical_offset = le64toh(item->disk_bytenr);
                        if (logical_offset == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot get physical address for btrfs extent: failed to get logical offset");

                        chunk = btrfs_find_chunk_from_logical_address(&tree, logical_offset);
                        if (!chunk)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot get physical address for btrfs extent: no matching chunk found");

                        if ((chunk->type & BTRFS_BLOCK_GROUP_PROFILE_MASK) != 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot get physical address for btrfs extent: unsupported profile");

                        uint64_t relative_chunk, relative_stripe, stripe_nr;
                        uint16_t stripe_index;

                        assert(logical_offset >= chunk->offset);
                        assert(chunk->n_stripes > 0);
                        assert(chunk->stripe_len > 0);

                        relative_chunk = logical_offset - chunk->offset;
                        stripe_nr = relative_chunk / chunk->stripe_len;
                        relative_stripe = relative_chunk - stripe_nr * chunk->stripe_len;
                        stripe_index = stripe_nr % chunk->n_stripes;

                        *ret = chunk->stripes[stripe_index].offset +
                                stripe_nr / chunk->n_stripes * chunk->stripe_len +
                                relative_stripe;

                        return 0;
                }

                if (!btrfs_ioctl_search_args_inc(&search_args))
                        break;
        }

        return -ENODATA;
}
