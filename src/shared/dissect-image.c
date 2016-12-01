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

#include <sys/mount.h>

#include "architecture.h"
#include "blkid-util.h"
#include "dissect-image.h"
#include "gpt.h"
#include "mount-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "udev-util.h"

int dissect_image(int fd, DissectedImage **ret) {

#ifdef HAVE_BLKID
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        bool is_gpt, is_mbr, generic_rw, multiple_generic = false;
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_free_ char *generic_node = NULL;
        const char *pttype = NULL, *usage = NULL;
        struct udev_list_entry *first, *item;
        blkid_partlist pl;
        int r, generic_nr;
        struct stat st;
        unsigned i;

        assert(fd >= 0);
        assert(ret);

        /* Probes a disk image, and returns information about what it found in *ret.
         *
         * Returns -ENOPKG if no suitable partition table or file system could be found. */

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        b = blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0) {
                if (errno == 0)
                        return -ENOMEM;

                return -errno;
        }

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_USAGE);
        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2 || r == 1) {
                log_debug("Failed to identify any partition table.");
                return -ENOPKG;
        }
        if (r != 0) {
                if (errno == 0)
                        return -EIO;

                return -errno;
        }

        m = new0(DissectedImage, 1);
        if (!m)
                return -ENOMEM;

        (void) blkid_probe_lookup_value(b, "USAGE", &usage, NULL);
        if (streq_ptr(usage, "filesystem")) {
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

                *ret = m;
                m = NULL;

                return 0;
        }

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!pttype)
                return -ENOPKG;

        is_gpt = streq_ptr(pttype, "gpt");
        is_mbr = streq_ptr(pttype, "dos");

        if (!is_gpt && !is_mbr)
                return -ENOPKG;

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl) {
                if (errno == 0)
                        return -ENOMEM;

                return -errno;
        }

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
                unsigned long long flags;
                blkid_partition pp;
                const char *node;
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

                node = udev_device_get_devnode(q);
                if (!node)
                        continue;

                pp = blkid_partlist_devno_to_partition(pl, qn);
                if (!pp)
                        continue;

                flags = blkid_partition_get_flags(pp);

                nr = blkid_partition_get_partno(pp);
                if (nr < 0)
                        continue;

                if (is_gpt) {
                        int designator = _PARTITION_DESIGNATOR_INVALID, architecture = _ARCHITECTURE_INVALID;
                        const char *stype, *fstype = NULL;
                        sd_id128_t type_id;
                        bool rw = true;

                        if (flags & GPT_FLAG_NO_AUTO)
                                continue;

                        stype = blkid_partition_get_type_string(pp);
                        if (!stype)
                                continue;

                        if (sd_id128_from_string(stype, &type_id) < 0)
                                continue;

                        if (sd_id128_equal(type_id, GPT_HOME)) {
                                designator = PARTITION_HOME;
                                rw = !(flags & GPT_FLAG_READ_ONLY);
                        } else if (sd_id128_equal(type_id, GPT_SRV)) {
                                designator = PARTITION_SRV;
                                rw = !(flags & GPT_FLAG_READ_ONLY);
                        } else if (sd_id128_equal(type_id, GPT_ESP)) {
                                designator = PARTITION_ESP;
                                fstype = "vfat";
                        }
#ifdef GPT_ROOT_NATIVE
                        else if (sd_id128_equal(type_id, GPT_ROOT_NATIVE)) {
                                designator = PARTITION_ROOT;
                                architecture = native_architecture();
                                rw = !(flags & GPT_FLAG_READ_ONLY);
                        }
#endif
#ifdef GPT_ROOT_SECONDARY
                        else if (sd_id128_equal(type_id, GPT_ROOT_SECONDARY)) {
                                designator = PARTITION_ROOT_SECONDARY;
                                architecture = SECONDARY_ARCHITECTURE;
                                rw = !(flags & GPT_FLAG_READ_ONLY);
                        }
#endif
                        else if (sd_id128_equal(type_id, GPT_SWAP)) {
                                designator = PARTITION_SWAP;
                                fstype = "swap";
                        } else if (sd_id128_equal(type_id, GPT_LINUX_GENERIC)) {

                                if (generic_node)
                                        multiple_generic = true;
                                else {
                                        generic_nr = nr;
                                        generic_rw = !(flags & GPT_FLAG_READ_ONLY);
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
                                };

                                n = t = NULL;
                        }

                } else if (is_mbr) {

                        if (flags != 0x80) /* Bootable flag */
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

                if (m->partitions[PARTITION_ROOT_SECONDARY].found) {
                        m->partitions[PARTITION_ROOT] = m->partitions[PARTITION_ROOT_SECONDARY];
                        zero(m->partitions[PARTITION_ROOT_SECONDARY]);
                } else if (generic_node) {

                        if (multiple_generic)
                                return -ENOTUNIQ;

                        m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                .found = true,
                                .rw = generic_rw,
                                .partno = generic_nr,
                                .architecture = _ARCHITECTURE_INVALID,
                                .node = generic_node,
                        };

                        generic_node = NULL;
                } else
                        return -ENXIO;
        }

        /* Fill in file system types if we don't know them yet. */
        for (i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                const char *fstype;

                if (!m->partitions[i].found) /* not found? */
                        continue;

                if (m->partitions[i].fstype) /* already know the type? */
                        continue;

                if (!m->partitions[i].node) /* have no device node for? */
                        continue;

                if (b)
                        blkid_free_probe(b);

                b = blkid_new_probe_from_filename(m->partitions[i].node);
                if (!b)
                        return -ENOMEM;

                blkid_probe_enable_superblocks(b, 1);
                blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);

                errno = 0;
                r = blkid_do_safeprobe(b);
                if (r == -2 || r == 1) {
                        log_debug("Failed to identify any partition type on partition %i", m->partitions[i].partno);
                        continue;
                }
                if (r != 0) {
                        if (errno == 0)
                                return -EIO;

                        return -errno;
                }

                (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);
                if (fstype) {
                        char *t;

                        t = strdup(fstype);
                        if (!t)
                                return -ENOMEM;

                        m->partitions[i].fstype = t;
                }
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
        }

        free(m);
        return NULL;
}

static int mount_partition(DissectedPartition *m, const char *where, const char *directory, DissectedImageMountFlags flags) {
        const char *p, *options = NULL;
        bool rw;

        assert(m);
        assert(where);

        if (!m->found || !m->node || !m->fstype)
                return 0;

        rw = m->rw && !(flags & DISSECTED_IMAGE_READ_ONLY);

        if (directory)
                p = strjoina(where, directory);
        else
                p = where;

        /* Not supported for now. */
        if (streq(m->fstype, "crypto_LUKS"))
                return -EOPNOTSUPP;

        /* If this is a loopback device then let's mount the image with discard, so that the underlying file remains
         * sparse when possible. */
        if ((flags & DISSECTED_IMAGE_DISCARD_ON_LOOP) &&
            STR_IN_SET(m->fstype, "btrfs", "ext4", "vfat", "xfs")) {
                const char *l;

                l = path_startswith(m->node, "/dev");
                if (l && startswith(l, "loop"))
                        options = "discard";
        }

        return mount_verbose(LOG_DEBUG, m->node, p, m->fstype, MS_NODEV|(rw ? 0 : MS_RDONLY), options);
}

int dissected_image_mount(DissectedImage *m, const char *where, DissectedImageMountFlags flags) {
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
                const char *mp, *x;

                /* Mount the ESP to /efi if it exists and is empty. If it doesn't exist, use /boot instead. */

                mp = "/efi";
                x = strjoina(where, mp);
                r = dir_is_empty(x);
                if (r == -ENOENT) {
                        mp = "/boot";
                        x = strjoina(where, mp);
                        r = dir_is_empty(x);
                }
                if (r > 0) {
                        r = mount_partition(m->partitions + PARTITION_ESP, where, mp, flags);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static const char *const partition_designator_table[] = {
        [PARTITION_ROOT] = "root",
        [PARTITION_ROOT_SECONDARY] = "root-secondary",
        [PARTITION_HOME] = "home",
        [PARTITION_SRV] = "srv",
        [PARTITION_ESP] = "esp",
        [PARTITION_SWAP] = "swap",
};

DEFINE_STRING_TABLE_LOOKUP(partition_designator, int);
