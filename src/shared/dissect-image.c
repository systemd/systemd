/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#ifdef HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h>
#endif
#include <sys/mount.h>

#include "architecture.h"
#include "ask-password-api.h"
#include "blkid-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "linux-3.13/dm-ioctl.h"
#include "mount-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "udev-util.h"
#include "xattr-util.h"

_unused_ static int probe_filesystem(const char *node, char **ret_fstype) {
#ifdef HAVE_BLKID
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        const char *fstype;
        int r;

        b = blkid_new_probe_from_filename(node);
        if (!b)
                return -ENOMEM;

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2 || r == 1) {
                log_debug("Failed to identify any partition type on partition %s", node);
                goto not_found;
        }
        if (r != 0)
                return -errno ?: -EIO;

        (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);

        if (fstype) {
                char *t;

                t = strdup(fstype);
                if (!t)
                        return -ENOMEM;

                *ret_fstype = t;
                return 1;
        }

not_found:
        *ret_fstype = NULL;
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int dissect_image(int fd, const void *root_hash, size_t root_hash_size, DissectImageFlags flags, DissectedImage **ret) {

#ifdef HAVE_BLKID
        sd_id128_t root_uuid = SD_ID128_NULL, verity_uuid = SD_ID128_NULL;
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        bool is_gpt, is_mbr, generic_rw, multiple_generic = false;
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_free_ char *generic_node = NULL;
        sd_id128_t generic_uuid = SD_ID128_NULL;
        const char *pttype = NULL;
        struct udev_list_entry *first, *item;
        blkid_partlist pl;
        int r, generic_nr;
        struct stat st;
        unsigned i;

        assert(fd >= 0);
        assert(ret);
        assert(root_hash || root_hash_size == 0);

        /* Probes a disk image, and returns information about what it found in *ret.
         *
         * Returns -ENOPKG if no suitable partition table or file system could be found.
         * Returns -EADDRNOTAVAIL if a root hash was specified but no matching root/verity partitions found. */

        if (root_hash) {
                /* If a root hash is supplied, then we use the root partition that has a UUID that match the first
                 * 128bit of the root hash. And we use the verity partition that has a UUID that match the final
                 * 128bit. */

                if (root_hash_size < sizeof(sd_id128_t))
                        return -EINVAL;

                memcpy(&root_uuid, root_hash, sizeof(sd_id128_t));
                memcpy(&verity_uuid, (const uint8_t*) root_hash + root_hash_size - sizeof(sd_id128_t), sizeof(sd_id128_t));

                if (sd_id128_is_null(root_uuid))
                        return -EINVAL;
                if (sd_id128_is_null(verity_uuid))
                        return -EINVAL;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        b = blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0)
                return -errno ?: -ENOMEM;

        if ((flags & DISSECT_IMAGE_GPT_ONLY) == 0) {
                /* Look for file system superblocks, unless we only shall look for GPT partition tables */
                blkid_probe_enable_superblocks(b, 1);
                blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_USAGE);
        }

        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2 || r == 1) {
                log_debug("Failed to identify any partition table.");
                return -ENOPKG;
        }
        if (r != 0)
                return -errno ?: -EIO;

        m = new0(DissectedImage, 1);
        if (!m)
                return -ENOMEM;

        if (!(flags & DISSECT_IMAGE_GPT_ONLY) &&
            (flags & DISSECT_IMAGE_REQUIRE_ROOT)) {
                const char *usage = NULL;

                (void) blkid_probe_lookup_value(b, "USAGE", &usage, NULL);
                if (STRPTR_IN_SET(usage, "filesystem", "crypto")) {
                        _cleanup_free_ char *t = NULL, *n = NULL;
                        const char *fstype = NULL;

                        /* OK, we have found a file system, that's our root partition then. */
                        (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);

                        if (fstype) {
                                t = strdup(fstype);
                                if (!t)
                                        return -ENOMEM;
                        }

                        if (asprintf(&n, "/dev/block/%u:%u", major(st.st_rdev), minor(st.st_rdev)) < 0)
                                return -ENOMEM;

                        m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                .found = true,
                                .rw = true,
                                .partno = -1,
                                .architecture = _ARCHITECTURE_INVALID,
                                .fstype = t,
                                .node = n,
                        };

                        t = n = NULL;

                        m->encrypted = streq(fstype, "crypto_LUKS");

                        *ret = m;
                        m = NULL;

                        return 0;
                }
        }

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!pttype)
                return -ENOPKG;

        is_gpt = streq_ptr(pttype, "gpt");
        is_mbr = streq_ptr(pttype, "dos");

        if (!is_gpt && ((flags & DISSECT_IMAGE_GPT_ONLY) || !is_mbr))
                return -ENOPKG;

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return -errno ?: -ENOMEM;

        udev = udev_new();
        if (!udev)
                return -errno;

        d = udev_device_new_from_devnum(udev, 'b', st.st_rdev);
        if (!d)
                return -ENOMEM;

        for (i = 0;; i++) {
                int n, z;

                if (i >= 10) {
                        log_debug("Kernel partitions never appeared.");
                        return -ENXIO;
                }

                e = udev_enumerate_new(udev);
                if (!e)
                        return -errno;

                r = udev_enumerate_add_match_parent(e, d);
                if (r < 0)
                        return r;

                r = udev_enumerate_scan_devices(e);
                if (r < 0)
                        return r;

                /* Count the partitions enumerated by the kernel */
                n = 0;
                first = udev_enumerate_get_list_entry(e);
                udev_list_entry_foreach(item, first)
                        n++;

                /* Count the partitions enumerated by blkid */
                z = blkid_partlist_numof_partitions(pl);
                if (n == z + 1)
                        break;
                if (n > z + 1) {
                        log_debug("blkid and kernel partition list do not match.");
                        return -EIO;
                }
                if (n < z + 1) {
                        unsigned j;

                        /* The kernel has probed fewer partitions than blkid? Maybe the kernel prober is still running
                         * or it got EBUSY because udev already opened the device. Let's reprobe the device, which is a
                         * synchronous call that waits until probing is complete. */

                        for (j = 0; j < 20; j++) {

                                r = ioctl(fd, BLKRRPART, 0);
                                if (r < 0)
                                        r = -errno;
                                if (r >= 0 || r != -EBUSY)
                                        break;

                                /* If something else has the device open, such as an udev rule, the ioctl will return
                                 * EBUSY. Since there's no way to wait until it isn't busy anymore, let's just wait a
                                 * bit, and try again.
                                 *
                                 * This is really something they should fix in the kernel! */

                                usleep(50 * USEC_PER_MSEC);
                        }

                        if (r < 0)
                                return r;
                }

                e = udev_enumerate_unref(e);
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                _cleanup_udev_device_unref_ struct udev_device *q;
                unsigned long long pflags;
                blkid_partition pp;
                const char *node, *sysname;
                dev_t qn;
                int nr;

                q = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                if (!q)
                        return -errno;

                qn = udev_device_get_devnum(q);
                if (major(qn) == 0)
                        continue;

                if (st.st_rdev == qn)
                        continue;

                /* Filter out weird MMC RPMB partitions, which cannot reasonably be read, see
                 * https://github.com/systemd/systemd/issues/5806 */
                sysname = udev_device_get_sysname(q);
                if (sysname && startswith(sysname, "mmcblk") && endswith(sysname, "rpmb"))
                        continue;

                node = udev_device_get_devnode(q);
                if (!node)
                        continue;

                pp = blkid_partlist_devno_to_partition(pl, qn);
                if (!pp)
                        continue;

                pflags = blkid_partition_get_flags(pp);

                nr = blkid_partition_get_partno(pp);
                if (nr < 0)
                        continue;

                if (is_gpt) {
                        int designator = _PARTITION_DESIGNATOR_INVALID, architecture = _ARCHITECTURE_INVALID;
                        const char *stype, *sid, *fstype = NULL;
                        sd_id128_t type_id, id;
                        bool rw = true;

                        sid = blkid_partition_get_uuid(pp);
                        if (!sid)
                                continue;
                        if (sd_id128_from_string(sid, &id) < 0)
                                continue;

                        stype = blkid_partition_get_type_string(pp);
                        if (!stype)
                                continue;
                        if (sd_id128_from_string(stype, &type_id) < 0)
                                continue;

                        if (sd_id128_equal(type_id, GPT_HOME)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_HOME;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);
                        } else if (sd_id128_equal(type_id, GPT_SRV)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_SRV;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);
                        } else if (sd_id128_equal(type_id, GPT_ESP)) {

                                /* Note that we don't check the GPT_FLAG_NO_AUTO flag for the ESP, as it is not defined
                                 * there. We instead check the GPT_FLAG_NO_BLOCK_IO_PROTOCOL, as recommended by the
                                 * UEFI spec (See "12.3.3 Number and Location of System Partitions"). */

                                if (pflags & GPT_FLAG_NO_BLOCK_IO_PROTOCOL)
                                        continue;

                                designator = PARTITION_ESP;
                                fstype = "vfat";
                        }
#ifdef GPT_ROOT_NATIVE
                        else if (sd_id128_equal(type_id, GPT_ROOT_NATIVE)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a root ID is specified, ignore everything but the root id */
                                if (!sd_id128_is_null(root_uuid) && !sd_id128_equal(root_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT;
                                architecture = native_architecture();
                                rw = !(pflags & GPT_FLAG_READ_ONLY);
                        } else if (sd_id128_equal(type_id, GPT_ROOT_NATIVE_VERITY)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                m->can_verity = true;

                                /* Ignore verity unless a root hash is specified */
                                if (sd_id128_is_null(verity_uuid) || !sd_id128_equal(verity_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT_VERITY;
                                fstype = "DM_verity_hash";
                                architecture = native_architecture();
                                rw = false;
                        }
#endif
#ifdef GPT_ROOT_SECONDARY
                        else if (sd_id128_equal(type_id, GPT_ROOT_SECONDARY)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a root ID is specified, ignore everything but the root id */
                                if (!sd_id128_is_null(root_uuid) && !sd_id128_equal(root_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT_SECONDARY;
                                architecture = SECONDARY_ARCHITECTURE;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);
                        } else if (sd_id128_equal(type_id, GPT_ROOT_SECONDARY_VERITY)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                m->can_verity = true;

                                /* Ignore verity unless root has is specified */
                                if (sd_id128_is_null(verity_uuid) || !sd_id128_equal(verity_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT_SECONDARY_VERITY;
                                fstype = "DM_verity_hash";
                                architecture = SECONDARY_ARCHITECTURE;
                                rw = false;
                        }
#endif
                        else if (sd_id128_equal(type_id, GPT_SWAP)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_SWAP;
                                fstype = "swap";
                        } else if (sd_id128_equal(type_id, GPT_LINUX_GENERIC)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                if (generic_node)
                                        multiple_generic = true;
                                else {
                                        generic_nr = nr;
                                        generic_rw = !(pflags & GPT_FLAG_READ_ONLY);
                                        generic_uuid = id;
                                        generic_node = strdup(node);
                                        if (!generic_node)
                                                return -ENOMEM;
                                }
                        }

                        if (designator != _PARTITION_DESIGNATOR_INVALID) {
                                _cleanup_free_ char *t = NULL, *n = NULL;

                                /* First one wins */
                                if (m->partitions[designator].found)
                                        continue;

                                if (fstype) {
                                        t = strdup(fstype);
                                        if (!t)
                                                return -ENOMEM;
                                }

                                n = strdup(node);
                                if (!n)
                                        return -ENOMEM;

                                m->partitions[designator] = (DissectedPartition) {
                                        .found = true,
                                        .partno = nr,
                                        .rw = rw,
                                        .architecture = architecture,
                                        .node = n,
                                        .fstype = t,
                                        .uuid = id,
                                };

                                n = t = NULL;
                        }

                } else if (is_mbr) {

                        if (pflags != 0x80) /* Bootable flag */
                                continue;

                        if (blkid_partition_get_type(pp) != 0x83) /* Linux partition */
                                continue;

                        if (generic_node)
                                multiple_generic = true;
                        else {
                                generic_nr = nr;
                                generic_rw = true;
                                generic_node = strdup(node);
                                if (!generic_node)
                                        return -ENOMEM;
                        }
                }
        }

        if (!m->partitions[PARTITION_ROOT].found) {
                /* No root partition found? Then let's see if ther's one for the secondary architecture. And if not
                 * either, then check if there's a single generic one, and use that. */

                if (m->partitions[PARTITION_ROOT_VERITY].found)
                        return -EADDRNOTAVAIL;

                if (m->partitions[PARTITION_ROOT_SECONDARY].found) {
                        m->partitions[PARTITION_ROOT] = m->partitions[PARTITION_ROOT_SECONDARY];
                        zero(m->partitions[PARTITION_ROOT_SECONDARY]);

                        m->partitions[PARTITION_ROOT_VERITY] = m->partitions[PARTITION_ROOT_SECONDARY_VERITY];
                        zero(m->partitions[PARTITION_ROOT_SECONDARY_VERITY]);

                } else if (flags & DISSECT_IMAGE_REQUIRE_ROOT) {

                        /* If the root has was set, then we won't fallback to a generic node, because the root hash
                         * decides */
                        if (root_hash)
                                return -EADDRNOTAVAIL;

                        /* If we didn't find a generic node, then we can't fix this up either */
                        if (!generic_node)
                                return -ENXIO;

                        /* If we didn't find a properly marked root partition, but we did find a single suitable
                         * generic Linux partition, then use this as root partition, if the caller asked for it. */
                        if (multiple_generic)
                                return -ENOTUNIQ;

                        m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                .found = true,
                                .rw = generic_rw,
                                .partno = generic_nr,
                                .architecture = _ARCHITECTURE_INVALID,
                                .node = generic_node,
                                .uuid = generic_uuid,
                        };

                        generic_node = NULL;
                }
        }

        if (root_hash) {
                if (!m->partitions[PARTITION_ROOT_VERITY].found || !m->partitions[PARTITION_ROOT].found)
                        return -EADDRNOTAVAIL;

                /* If we found the primary root with the hash, then we definitely want to suppress any secondary root
                 * (which would be weird, after all the root hash should only be assigned to one pair of
                 * partitions... */
                m->partitions[PARTITION_ROOT_SECONDARY].found = false;
                m->partitions[PARTITION_ROOT_SECONDARY_VERITY].found = false;

                /* If we found a verity setup, then the root partition is necessarily read-only. */
                m->partitions[PARTITION_ROOT].rw = false;

                m->verity = true;
        }

        blkid_free_probe(b);
        b = NULL;

        /* Fill in file system types if we don't know them yet. */
        for (i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                DissectedPartition *p = m->partitions + i;

                if (!p->found)
                        continue;

                if (!p->fstype && p->node) {
                        r = probe_filesystem(p->node, &p->fstype);
                        if (r < 0)
                                return r;
                }

                if (streq_ptr(p->fstype, "crypto_LUKS"))
                        m->encrypted = true;
        }

        *ret = m;
        m = NULL;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

DissectedImage* dissected_image_unref(DissectedImage *m) {
        unsigned i;

        if (!m)
                return NULL;

        for (i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                free(m->partitions[i].fstype);
                free(m->partitions[i].node);
                free(m->partitions[i].decrypted_fstype);
                free(m->partitions[i].decrypted_node);
        }

        free(m);
        return NULL;
}

static int is_loop_device(const char *path) {
        char s[strlen("/sys/dev/block/") + DECIMAL_STR_MAX(dev_t) + 1 + DECIMAL_STR_MAX(dev_t) + strlen("/../loop/")];
        struct stat st;

        assert(path);

        if (stat(path, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        xsprintf(s, "/sys/dev/block/%u:%u/loop/", major(st.st_rdev), minor(st.st_rdev));
        if (access(s, F_OK) < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* The device itself isn't a loop device, but maybe it's a partition and its parent is? */
                xsprintf(s, "/sys/dev/block/%u:%u/../loop/", major(st.st_rdev), minor(st.st_rdev));
                if (access(s, F_OK) < 0)
                        return errno == ENOENT ? false : -errno;
        }

        return true;
}

static int mount_partition(
                DissectedPartition *m,
                const char *where,
                const char *directory,
                DissectImageFlags flags) {

        const char *p, *options = NULL, *node, *fstype;
        _cleanup_free_ char *chased = NULL;
        bool rw;
        int r;

        assert(m);
        assert(where);

        node = m->decrypted_node ?: m->node;
        fstype = m->decrypted_fstype ?: m->fstype;

        if (!m->found || !node || !fstype)
                return 0;

        /* Stacked encryption? Yuck */
        if (streq_ptr(fstype, "crypto_LUKS"))
                return -ELOOP;

        rw = m->rw && !(flags & DISSECT_IMAGE_READ_ONLY);

        if (directory) {
                r = chase_symlinks(directory, where, CHASE_PREFIX_ROOT, &chased);
                if (r < 0)
                        return r;

                p = chased;
        } else
                p = where;

        /* If requested, turn on discard support. */
        if (STR_IN_SET(fstype, "btrfs", "ext4", "vfat", "xfs") &&
            ((flags & DISSECT_IMAGE_DISCARD) ||
             ((flags & DISSECT_IMAGE_DISCARD_ON_LOOP) && is_loop_device(m->node))))
                options = "discard";

        return mount_verbose(LOG_DEBUG, node, p, fstype, MS_NODEV|(rw ? 0 : MS_RDONLY), options);
}

int dissected_image_mount(DissectedImage *m, const char *where, DissectImageFlags flags) {
        int r;

        assert(m);
        assert(where);

        if (!m->partitions[PARTITION_ROOT].found)
                return -ENXIO;

        r = mount_partition(m->partitions + PARTITION_ROOT, where, NULL, flags);
        if (r < 0)
                return r;

        r = mount_partition(m->partitions + PARTITION_HOME, where, "/home", flags);
        if (r < 0)
                return r;

        r = mount_partition(m->partitions + PARTITION_SRV, where, "/srv", flags);
        if (r < 0)
                return r;

        if (m->partitions[PARTITION_ESP].found) {
                const char *mp;

                /* Mount the ESP to /efi if it exists and is empty. If it doesn't exist, use /boot instead. */

                FOREACH_STRING(mp, "/efi", "/boot") {
                        _cleanup_free_ char *p = NULL;

                        r = chase_symlinks(mp, where, CHASE_PREFIX_ROOT, &p);
                        if (r < 0)
                                continue;

                        r = dir_is_empty(p);
                        if (r > 0) {
                                r = mount_partition(m->partitions + PARTITION_ESP, where, mp, flags);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

#ifdef HAVE_LIBCRYPTSETUP
typedef struct DecryptedPartition {
        struct crypt_device *device;
        char *name;
        bool relinquished;
} DecryptedPartition;

struct DecryptedImage {
        DecryptedPartition *decrypted;
        size_t n_decrypted;
        size_t n_allocated;
};
#endif

DecryptedImage* decrypted_image_unref(DecryptedImage* d) {
#ifdef HAVE_LIBCRYPTSETUP
        size_t i;
        int r;

        if (!d)
                return NULL;

        for (i = 0; i < d->n_decrypted; i++) {
                DecryptedPartition *p = d->decrypted + i;

                if (p->device && p->name && !p->relinquished) {
                        r = crypt_deactivate(p->device, p->name);
                        if (r < 0)
                                log_debug_errno(r, "Failed to deactivate encrypted partition %s", p->name);
                }

                if (p->device)
                        crypt_free(p->device);
                free(p->name);
        }

        free(d);
#endif
        return NULL;
}

#ifdef HAVE_LIBCRYPTSETUP

static int make_dm_name_and_node(const void *original_node, const char *suffix, char **ret_name, char **ret_node) {
        _cleanup_free_ char *name = NULL, *node = NULL;
        const char *base;

        assert(original_node);
        assert(suffix);
        assert(ret_name);
        assert(ret_node);

        base = strrchr(original_node, '/');
        if (!base)
                return -EINVAL;
        base++;
        if (isempty(base))
                return -EINVAL;

        name = strjoin(base, suffix);
        if (!name)
                return -ENOMEM;
        if (!filename_is_valid(name))
                return -EINVAL;

        node = strjoin(crypt_get_dir(), "/", name);
        if (!node)
                return -ENOMEM;

        *ret_name = name;
        *ret_node = node;

        name = node = NULL;
        return 0;
}

static int decrypt_partition(
                DissectedPartition *m,
                const char *passphrase,
                DissectImageFlags flags,
                DecryptedImage *d) {

        _cleanup_free_ char *node = NULL, *name = NULL;
        struct crypt_device *cd;
        int r;

        assert(m);
        assert(d);

        if (!m->found || !m->node || !m->fstype)
                return 0;

        if (!streq(m->fstype, "crypto_LUKS"))
                return 0;

        r = make_dm_name_and_node(m->node, "-decrypted", &name, &node);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC0(d->decrypted, d->n_allocated, d->n_decrypted + 1))
                return -ENOMEM;

        r = crypt_init(&cd, m->node);
        if (r < 0)
                return r;

        r = crypt_load(cd, CRYPT_LUKS1, NULL);
        if (r < 0)
                goto fail;

        r = crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, passphrase, strlen(passphrase),
                                         ((flags & DISSECT_IMAGE_READ_ONLY) ? CRYPT_ACTIVATE_READONLY : 0) |
                                         ((flags & DISSECT_IMAGE_DISCARD_ON_CRYPTO) ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0));
        if (r == -EPERM) {
                r = -EKEYREJECTED;
                goto fail;
        }
        if (r < 0)
                goto fail;

        d->decrypted[d->n_decrypted].name = name;
        name = NULL;

        d->decrypted[d->n_decrypted].device = cd;
        d->n_decrypted++;

        m->decrypted_node = node;
        node = NULL;

        return 0;

fail:
        crypt_free(cd);
        return r;
}

static int verity_partition(
                DissectedPartition *m,
                DissectedPartition *v,
                const void *root_hash,
                size_t root_hash_size,
                DissectImageFlags flags,
                DecryptedImage *d) {

        _cleanup_free_ char *node = NULL, *name = NULL;
        struct crypt_device *cd;
        int r;

        assert(m);
        assert(v);

        if (!root_hash)
                return 0;

        if (!m->found || !m->node || !m->fstype)
                return 0;
        if (!v->found || !v->node || !v->fstype)
                return 0;

        if (!streq(v->fstype, "DM_verity_hash"))
                return 0;

        r = make_dm_name_and_node(m->node, "-verity", &name, &node);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC0(d->decrypted, d->n_allocated, d->n_decrypted + 1))
                return -ENOMEM;

        r = crypt_init(&cd, v->node);
        if (r < 0)
                return r;

        r = crypt_load(cd, CRYPT_VERITY, NULL);
        if (r < 0)
                goto fail;

        r = crypt_set_data_device(cd, m->node);
        if (r < 0)
                goto fail;

        r = crypt_activate_by_volume_key(cd, name, root_hash, root_hash_size, CRYPT_ACTIVATE_READONLY);
        if (r < 0)
                goto fail;

        d->decrypted[d->n_decrypted].name = name;
        name = NULL;

        d->decrypted[d->n_decrypted].device = cd;
        d->n_decrypted++;

        m->decrypted_node = node;
        node = NULL;

        return 0;

fail:
        crypt_free(cd);
        return r;
}
#endif

int dissected_image_decrypt(
                DissectedImage *m,
                const char *passphrase,
                const void *root_hash,
                size_t root_hash_size,
                DissectImageFlags flags,
                DecryptedImage **ret) {

        _cleanup_(decrypted_image_unrefp) DecryptedImage *d = NULL;
#ifdef HAVE_LIBCRYPTSETUP
        unsigned i;
        int r;
#endif

        assert(m);
        assert(root_hash || root_hash_size == 0);

        /* Returns:
         *
         *      = 0           → There was nothing to decrypt
         *      > 0           → Decrypted successfully
         *      -ENOKEY       → There's something to decrypt but no key was supplied
         *      -EKEYREJECTED → Passed key was not correct
         */

        if (root_hash && root_hash_size < sizeof(sd_id128_t))
                return -EINVAL;

        if (!m->encrypted && !m->verity) {
                *ret = NULL;
                return 0;
        }

#ifdef HAVE_LIBCRYPTSETUP
        if (m->encrypted && !passphrase)
                return -ENOKEY;

        d = new0(DecryptedImage, 1);
        if (!d)
                return -ENOMEM;

        for (i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                DissectedPartition *p = m->partitions + i;
                int k;

                if (!p->found)
                        continue;

                r = decrypt_partition(p, passphrase, flags, d);
                if (r < 0)
                        return r;

                k = PARTITION_VERITY_OF(i);
                if (k >= 0) {
                        r = verity_partition(p, m->partitions + k, root_hash, root_hash_size, flags, d);
                        if (r < 0)
                                return r;
                }

                if (!p->decrypted_fstype && p->decrypted_node) {
                        r = probe_filesystem(p->decrypted_node, &p->decrypted_fstype);
                        if (r < 0)
                                return r;
                }
        }

        *ret = d;
        d = NULL;

        return 1;
#else
        return -EOPNOTSUPP;
#endif
}

int dissected_image_decrypt_interactively(
                DissectedImage *m,
                const char *passphrase,
                const void *root_hash,
                size_t root_hash_size,
                DissectImageFlags flags,
                DecryptedImage **ret) {

        _cleanup_strv_free_erase_ char **z = NULL;
        int n = 3, r;

        if (passphrase)
                n--;

        for (;;) {
                r = dissected_image_decrypt(m, passphrase, root_hash, root_hash_size, flags, ret);
                if (r >= 0)
                        return r;
                if (r == -EKEYREJECTED)
                        log_error_errno(r, "Incorrect passphrase, try again!");
                else if (r != -ENOKEY) {
                        log_error_errno(r, "Failed to decrypt image: %m");
                        return r;
                }

                if (--n < 0) {
                        log_error("Too many retries.");
                        return -EKEYREJECTED;
                }

                z = strv_free(z);

                r = ask_password_auto("Please enter image passphrase!", NULL, "dissect", "dissect", USEC_INFINITY, 0, &z);
                if (r < 0)
                        return log_error_errno(r, "Failed to query for passphrase: %m");

                passphrase = z[0];
        }
}

#ifdef HAVE_LIBCRYPTSETUP
static int deferred_remove(DecryptedPartition *p) {

        struct dm_ioctl dm = {
                .version = {
                        DM_VERSION_MAJOR,
                        DM_VERSION_MINOR,
                        DM_VERSION_PATCHLEVEL
                },
                .data_size = sizeof(dm),
                .flags = DM_DEFERRED_REMOVE,
        };

        _cleanup_close_ int fd = -1;

        assert(p);

        /* Unfortunately, libcryptsetup doesn't provide a proper API for this, hence call the ioctl() directly. */

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        strncpy(dm.name, p->name, sizeof(dm.name));

        if (ioctl(fd, DM_DEV_REMOVE, &dm))
                return -errno;

        return 0;
}
#endif

int decrypted_image_relinquish(DecryptedImage *d) {

#ifdef HAVE_LIBCRYPTSETUP
        size_t i;
        int r;
#endif

        assert(d);

        /* Turns on automatic removal after the last use ended for all DM devices of this image, and sets a boolean so
         * that we don't clean it up ourselves either anymore */

#ifdef HAVE_LIBCRYPTSETUP
        for (i = 0; i < d->n_decrypted; i++) {
                DecryptedPartition *p = d->decrypted + i;

                if (p->relinquished)
                        continue;

                r = deferred_remove(p);
                if (r < 0)
                        return log_debug_errno(r, "Failed to mark %s for auto-removal: %m", p->name);

                p->relinquished = true;
        }
#endif

        return 0;
}

int root_hash_load(const char *image, void **ret, size_t *ret_size) {
        _cleanup_free_ char *text = NULL;
        _cleanup_free_ void *k = NULL;
        size_t l;
        int r;

        assert(image);
        assert(ret);
        assert(ret_size);

        if (is_device_path(image)) {
                /* If we are asked to load the root hash for a device node, exit early */
                *ret = NULL;
                *ret_size = 0;
                return 0;
        }

        r = getxattr_malloc(image, "user.verity.roothash", &text, true);
        if (r < 0) {
                char *fn, *e, *n;

                if (!IN_SET(r, -ENODATA, -EOPNOTSUPP, -ENOENT))
                        return r;

                fn = newa(char, strlen(image) + strlen(".roothash") + 1);
                n = stpcpy(fn, image);
                e = endswith(fn, ".raw");
                if (e)
                        n = e;

                strcpy(n, ".roothash");

                r = read_one_line_file(fn, &text);
                if (r == -ENOENT) {
                        *ret = NULL;
                        *ret_size = 0;
                        return 0;
                }
                if (r < 0)
                        return r;
        }

        r = unhexmem(text, strlen(text), &k, &l);
        if (r < 0)
                return r;
        if (l < sizeof(sd_id128_t))
                return -EINVAL;

        *ret = k;
        *ret_size = l;

        k = NULL;

        return 1;
}

static const char *const partition_designator_table[] = {
        [PARTITION_ROOT] = "root",
        [PARTITION_ROOT_SECONDARY] = "root-secondary",
        [PARTITION_HOME] = "home",
        [PARTITION_SRV] = "srv",
        [PARTITION_ESP] = "esp",
        [PARTITION_SWAP] = "swap",
        [PARTITION_ROOT_VERITY] = "root-verity",
        [PARTITION_ROOT_SECONDARY_VERITY] = "root-secondary-verity",
};

DEFINE_STRING_TABLE_LOOKUP(partition_designator, int);
