/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/dm-ioctl.h>
#include <linux/loop.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "sd-device.h"
#include "sd-id128.h"

#include "architecture.h"
#include "ask-password-api.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "copy.h"
#include "crypt-util.h"
#include "def.h"
#include "device-nodes.h"
#include "device-util.h"
#include "dissect-image.h"
#include "dm-util.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "missing.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "signal-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "user-util.h"
#include "xattr-util.h"

int probe_filesystem(const char *node, char **ret_fstype) {
        /* Try to find device content type and return it in *ret_fstype. If nothing is found,
         * 0/NULL will be returned. -EUCLEAN will be returned for ambiguous results, and an
         * different error otherwise. */

#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        const char *fstype;
        int r;

        errno = 0;
        b = blkid_new_probe_from_filename(node);
        if (!b)
                return errno_or_else(ENOMEM);

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == 1) {
                log_debug("No type detected on partition %s", node);
                goto not_found;
        }
        if (r == -2) {
                log_debug("Results ambiguous for partition %s", node);
                return -EUCLEAN;
        }
        if (r != 0)
                return errno_or_else(EIO);

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

#if HAVE_BLKID
/* Detect RPMB and Boot partitions, which are not listed by blkid.
 * See https://github.com/systemd/systemd/issues/5806. */
static bool device_is_mmc_special_partition(sd_device *d) {
        const char *sysname;

        assert(d);

        if (sd_device_get_sysname(d, &sysname) < 0)
                return false;

        return startswith(sysname, "mmcblk") &&
                (endswith(sysname, "rpmb") || endswith(sysname, "boot0") || endswith(sysname, "boot1"));
}

static bool device_is_block(sd_device *d) {
        const char *ss;

        assert(d);

        if (sd_device_get_subsystem(d, &ss) < 0)
                return false;

        return streq(ss, "block");
}

static int enumerator_for_parent(sd_device *d, sd_device_enumerator **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(d);
        assert(ret);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_parent(e, d);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(e);
        return 0;
}

/* how many times to wait for the device nodes to appear */
#define N_DEVICE_NODE_LIST_ATTEMPTS 10

static int wait_for_partitions_to_appear(
                int fd,
                sd_device *d,
                unsigned num_partitions,
                DissectImageFlags flags,
                sd_device_enumerator **ret_enumerator) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *q;
        unsigned n;
        int r;

        assert(fd >= 0);
        assert(d);
        assert(ret_enumerator);

        r = enumerator_for_parent(d, &e);
        if (r < 0)
                return r;

        /* Count the partitions enumerated by the kernel */
        n = 0;
        FOREACH_DEVICE(e, q) {
                if (sd_device_get_devnum(q, NULL) < 0)
                        continue;
                if (!device_is_block(q))
                        continue;
                if (device_is_mmc_special_partition(q))
                        continue;

                if (!FLAGS_SET(flags, DISSECT_IMAGE_NO_UDEV)) {
                        r = device_wait_for_initialization(q, "block", USEC_INFINITY, NULL);
                        if (r < 0)
                                return r;
                }

                n++;
        }

        if (n == num_partitions + 1) {
                *ret_enumerator = TAKE_PTR(e);
                return 0; /* success! */
        }
        if (n > num_partitions + 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "blkid and kernel partition lists do not match.");

        /* The kernel has probed fewer partitions than blkid? Maybe the kernel prober is still running or it
         * got EBUSY because udev already opened the device. Let's reprobe the device, which is a synchronous
         * call that waits until probing is complete. */

        for (unsigned j = 0; ; j++) {
                if (j++ > 20)
                        return -EBUSY;

                if (ioctl(fd, BLKRRPART, 0) >= 0)
                        break;
                r = -errno;
                if (r == -EINVAL) {
                        struct loop_info64 info;

                        /* If we are running on a loop device that has partition scanning off, return
                         * an explicit recognizable error about this, so that callers can generate a
                         * proper message explaining the situation. */

                        if (ioctl(fd, LOOP_GET_STATUS64, &info) >= 0 && (info.lo_flags & LO_FLAGS_PARTSCAN) == 0) {
                                log_debug("Device is a loop device and partition scanning is off!");
                                return -EPROTONOSUPPORT;
                        }
                }
                if (r != -EBUSY)
                        return r;

                /* If something else has the device open, such as an udev rule, the ioctl will return
                 * EBUSY. Since there's no way to wait until it isn't busy anymore, let's just wait a bit,
                 * and try again.
                 *
                 * This is really something they should fix in the kernel! */
                (void) usleep(50 * USEC_PER_MSEC);

        }

        return -EAGAIN; /* no success yet, try again */
}

static int loop_wait_for_partitions_to_appear(
                int fd,
                sd_device *d,
                unsigned num_partitions,
                DissectImageFlags flags,
                sd_device_enumerator **ret_enumerator) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        int r;

        assert(fd >= 0);
        assert(d);
        assert(ret_enumerator);

        log_debug("Waiting for device (parent + %d partitions) to appear...", num_partitions);

        if (!FLAGS_SET(flags, DISSECT_IMAGE_NO_UDEV)) {
                r = device_wait_for_initialization(d, "block", USEC_INFINITY, &device);
                if (r < 0)
                        return r;
        } else
                device = sd_device_ref(d);

        for (unsigned i = 0; i < N_DEVICE_NODE_LIST_ATTEMPTS; i++) {
                r = wait_for_partitions_to_appear(fd, device, num_partitions, flags, ret_enumerator);
                if (r != -EAGAIN)
                        return r;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(ENXIO),
                               "Kernel partitions dit not appear within %d attempts",
                               N_DEVICE_NODE_LIST_ATTEMPTS);
}

#endif

int dissect_image(
                int fd,
                const void *root_hash,
                size_t root_hash_size,
                DissectImageFlags flags,
                DissectedImage **ret) {

#if HAVE_BLKID
        sd_id128_t root_uuid = SD_ID128_NULL, verity_uuid = SD_ID128_NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool is_gpt, is_mbr, generic_rw, multiple_generic = false;
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *generic_node = NULL;
        sd_id128_t generic_uuid = SD_ID128_NULL;
        const char *pttype = NULL;
        blkid_partlist pl;
        int r, generic_nr;
        struct stat st;
        sd_device *q;
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
                return errno_or_else(ENOMEM);

        if ((flags & DISSECT_IMAGE_GPT_ONLY) == 0) {
                /* Look for file system superblocks, unless we only shall look for GPT partition tables */
                blkid_probe_enable_superblocks(b, 1);
                blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_USAGE);
        }

        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (IN_SET(r, -2, 1))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOPKG), "Failed to identify any partition table.");
        if (r != 0)
                return errno_or_else(EIO);

        m = new0(DissectedImage, 1);
        if (!m)
                return -ENOMEM;

        r = sd_device_new_from_devnum(&d, 'b', st.st_rdev);
        if (r < 0)
                return r;

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

                        r = device_path_make_major_minor(st.st_mode, st.st_rdev, &n);
                        if (r < 0)
                                return r;

                        m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                .found = true,
                                .rw = true,
                                .partno = -1,
                                .architecture = _ARCHITECTURE_INVALID,
                                .fstype = TAKE_PTR(t),
                                .node = TAKE_PTR(n),
                        };

                        m->encrypted = streq_ptr(fstype, "crypto_LUKS");

                        r = loop_wait_for_partitions_to_appear(fd, d, 0, flags, &e);
                        if (r < 0)
                                return r;

                        *ret = TAKE_PTR(m);

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
                return errno_or_else(ENOMEM);

        r = loop_wait_for_partitions_to_appear(fd, d, blkid_partlist_numof_partitions(pl), flags, &e);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, q) {
                unsigned long long pflags;
                blkid_partition pp;
                const char *node;
                dev_t qn;
                int nr;

                r = sd_device_get_devnum(q, &qn);
                if (r < 0)
                        continue;

                if (st.st_rdev == qn)
                        continue;

                if (!device_is_block(q))
                        continue;

                if (device_is_mmc_special_partition(q))
                        continue;

                r = sd_device_get_devname(q, &node);
                if (r < 0)
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

                        } else if (sd_id128_equal(type_id, GPT_XBOOTLDR)) {

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_XBOOTLDR;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);
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
                                        .node = TAKE_PTR(n),
                                        .fstype = TAKE_PTR(t),
                                        .uuid = id,
                                };
                        }

                } else if (is_mbr) {

                        switch (blkid_partition_get_type(pp)) {

                        case 0x83: /* Linux partition */

                                if (pflags != 0x80) /* Bootable flag */
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

                                break;

                        case 0xEA: { /* Boot Loader Spec extended $BOOT partition */
                                _cleanup_free_ char *n = NULL;
                                sd_id128_t id = SD_ID128_NULL;
                                const char *sid;

                                /* First one wins */
                                if (m->partitions[PARTITION_XBOOTLDR].found)
                                        continue;

                                sid = blkid_partition_get_uuid(pp);
                                if (sid)
                                        (void) sd_id128_from_string(sid, &id);

                                n = strdup(node);
                                if (!n)
                                        return -ENOMEM;

                                m->partitions[PARTITION_XBOOTLDR] = (DissectedPartition) {
                                        .found = true,
                                        .partno = nr,
                                        .rw = true,
                                        .architecture = _ARCHITECTURE_INVALID,
                                        .node = TAKE_PTR(n),
                                        .uuid = id,
                                };

                                break;
                        }}
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
                                .node = TAKE_PTR(generic_node),
                                .uuid = generic_uuid,
                        };
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
                        if (r < 0 && r != -EUCLEAN)
                                return r;
                }

                if (streq_ptr(p->fstype, "crypto_LUKS"))
                        m->encrypted = true;

                if (p->fstype && fstype_is_ro(p->fstype))
                        p->rw = false;
        }

        *ret = TAKE_PTR(m);

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

        free(m->hostname);
        strv_free(m->machine_info);
        strv_free(m->os_release);

        return mfree(m);
}

static int is_loop_device(const char *path) {
        char s[SYS_BLOCK_PATH_MAX("/../loop/")];
        struct stat st;

        assert(path);

        if (stat(path, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        xsprintf_sys_block_path(s, "/loop/", st.st_dev);
        if (access(s, F_OK) < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* The device itself isn't a loop device, but maybe it's a partition and its parent is? */
                xsprintf_sys_block_path(s, "/../loop/", st.st_dev);
                if (access(s, F_OK) < 0)
                        return errno == ENOENT ? false : -errno;
        }

        return true;
}

static int mount_partition(
                DissectedPartition *m,
                const char *where,
                const char *directory,
                uid_t uid_shift,
                DissectImageFlags flags) {

        _cleanup_free_ char *chased = NULL, *options = NULL;
        const char *p, *node, *fstype;
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
        if (fstype_can_discard(fstype) &&
            ((flags & DISSECT_IMAGE_DISCARD) ||
             ((flags & DISSECT_IMAGE_DISCARD_ON_LOOP) && is_loop_device(m->node)))) {
                options = strdup("discard");
                if (!options)
                        return -ENOMEM;
        }

        if (uid_is_valid(uid_shift) && uid_shift != 0 && fstype_can_uid_gid(fstype)) {
                _cleanup_free_ char *uid_option = NULL;

                if (asprintf(&uid_option, "uid=" UID_FMT ",gid=" GID_FMT, uid_shift, (gid_t) uid_shift) < 0)
                        return -ENOMEM;

                if (!strextend_with_separator(&options, ",", uid_option, NULL))
                        return -ENOMEM;
        }

        r = mount_verbose(LOG_DEBUG, node, p, fstype, MS_NODEV|(rw ? 0 : MS_RDONLY), options);
        if (r < 0)
                return r;

        return 1;
}

int dissected_image_mount(DissectedImage *m, const char *where, uid_t uid_shift, DissectImageFlags flags) {
        int r, boot_mounted;

        assert(m);
        assert(where);

        if (!m->partitions[PARTITION_ROOT].found)
                return -ENXIO;

        if ((flags & DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY) == 0) {
                r = mount_partition(m->partitions + PARTITION_ROOT, where, NULL, uid_shift, flags);
                if (r < 0)
                        return r;

                if (flags & DISSECT_IMAGE_VALIDATE_OS) {
                        r = path_is_os_tree(where);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EMEDIUMTYPE;
                }
        }

        if (flags & DISSECT_IMAGE_MOUNT_ROOT_ONLY)
                return 0;

        r = mount_partition(m->partitions + PARTITION_HOME, where, "/home", uid_shift, flags);
        if (r < 0)
                return r;

        r = mount_partition(m->partitions + PARTITION_SRV, where, "/srv", uid_shift, flags);
        if (r < 0)
                return r;

        boot_mounted = mount_partition(m->partitions + PARTITION_XBOOTLDR, where, "/boot", uid_shift, flags);
        if (boot_mounted < 0)
                return boot_mounted;

        if (m->partitions[PARTITION_ESP].found) {
                /* Mount the ESP to /efi if it exists. If it doesn't exist, use /boot instead, but only if it
                 * exists and is empty, and we didn't already mount the XBOOTLDR partition into it. */

                r = chase_symlinks("/efi", where, CHASE_PREFIX_ROOT, NULL);
                if (r >= 0) {
                        r = mount_partition(m->partitions + PARTITION_ESP, where, "/efi", uid_shift, flags);
                        if (r < 0)
                                return r;

                } else if (boot_mounted <= 0) {
                        _cleanup_free_ char *p = NULL;

                        r = chase_symlinks("/boot", where, CHASE_PREFIX_ROOT, &p);
                        if (r >= 0 && dir_is_empty(p) > 0) {
                                r = mount_partition(m->partitions + PARTITION_ESP, where, "/boot", uid_shift, flags);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

#if HAVE_LIBCRYPTSETUP
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
#if HAVE_LIBCRYPTSETUP
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

#if HAVE_LIBCRYPTSETUP

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

        node = path_join(crypt_get_dir(), name);
        if (!node)
                return -ENOMEM;

        *ret_name = TAKE_PTR(name);
        *ret_node = TAKE_PTR(node);

        return 0;
}

static int decrypt_partition(
                DissectedPartition *m,
                const char *passphrase,
                DissectImageFlags flags,
                DecryptedImage *d) {

        _cleanup_free_ char *node = NULL, *name = NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        assert(m);
        assert(d);

        if (!m->found || !m->node || !m->fstype)
                return 0;

        if (!streq(m->fstype, "crypto_LUKS"))
                return 0;

        if (!passphrase)
                return -ENOKEY;

        r = make_dm_name_and_node(m->node, "-decrypted", &name, &node);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC0(d->decrypted, d->n_allocated, d->n_decrypted + 1))
                return -ENOMEM;

        r = crypt_init(&cd, m->node);
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize dm-crypt: %m");

        r = crypt_load(cd, CRYPT_LUKS, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load LUKS metadata: %m");

        r = crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, passphrase, strlen(passphrase),
                                         ((flags & DISSECT_IMAGE_READ_ONLY) ? CRYPT_ACTIVATE_READONLY : 0) |
                                         ((flags & DISSECT_IMAGE_DISCARD_ON_CRYPTO) ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0));
        if (r < 0) {
                log_debug_errno(r, "Failed to activate LUKS device: %m");
                return r == -EPERM ? -EKEYREJECTED : r;
        }

        d->decrypted[d->n_decrypted].name = TAKE_PTR(name);
        d->decrypted[d->n_decrypted].device = TAKE_PTR(cd);
        d->n_decrypted++;

        m->decrypted_node = TAKE_PTR(node);

        return 0;
}

static int verity_partition(
                DissectedPartition *m,
                DissectedPartition *v,
                const void *root_hash,
                size_t root_hash_size,
                DissectImageFlags flags,
                DecryptedImage *d) {

        _cleanup_free_ char *node = NULL, *name = NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
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
                return r;

        r = crypt_set_data_device(cd, m->node);
        if (r < 0)
                return r;

        r = crypt_activate_by_volume_key(cd, name, root_hash, root_hash_size, CRYPT_ACTIVATE_READONLY);
        if (r < 0)
                return r;

        d->decrypted[d->n_decrypted].name = TAKE_PTR(name);
        d->decrypted[d->n_decrypted].device = TAKE_PTR(cd);
        d->n_decrypted++;

        m->decrypted_node = TAKE_PTR(node);

        return 0;
}
#endif

int dissected_image_decrypt(
                DissectedImage *m,
                const char *passphrase,
                const void *root_hash,
                size_t root_hash_size,
                DissectImageFlags flags,
                DecryptedImage **ret) {

#if HAVE_LIBCRYPTSETUP
        _cleanup_(decrypted_image_unrefp) DecryptedImage *d = NULL;
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

#if HAVE_LIBCRYPTSETUP
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
                        if (r < 0 && r != -EUCLEAN)
                                return r;
                }
        }

        *ret = TAKE_PTR(d);

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
                else if (r != -ENOKEY)
                        return log_error_errno(r, "Failed to decrypt image: %m");

                if (--n < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EKEYREJECTED),
                                               "Too many retries.");

                z = strv_free(z);

                r = ask_password_auto("Please enter image passphrase:", NULL, "dissect", "dissect", USEC_INFINITY, 0, &z);
                if (r < 0)
                        return log_error_errno(r, "Failed to query for passphrase: %m");

                passphrase = z[0];
        }
}

int decrypted_image_relinquish(DecryptedImage *d) {

#if HAVE_LIBCRYPTSETUP
        size_t i;
        int r;
#endif

        assert(d);

        /* Turns on automatic removal after the last use ended for all DM devices of this image, and sets a boolean so
         * that we don't clean it up ourselves either anymore */

#if HAVE_LIBCRYPTSETUP
        for (i = 0; i < d->n_decrypted; i++) {
                DecryptedPartition *p = d->decrypted + i;

                if (p->relinquished)
                        continue;

                r = dm_deferred_remove(p->name);
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

                fn = newa(char, strlen(image) + STRLEN(".roothash") + 1);
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

        *ret = TAKE_PTR(k);
        *ret_size = l;

        return 1;
}

int dissected_image_acquire_metadata(DissectedImage *m) {

        enum {
                META_HOSTNAME,
                META_MACHINE_ID,
                META_MACHINE_INFO,
                META_OS_RELEASE,
                _META_MAX,
        };

        static const char *const paths[_META_MAX] = {
                [META_HOSTNAME]     = "/etc/hostname\0",
                [META_MACHINE_ID]   = "/etc/machine-id\0",
                [META_MACHINE_INFO] = "/etc/machine-info\0",
                [META_OS_RELEASE]   = "/etc/os-release\0/usr/lib/os-release\0",
        };

        _cleanup_strv_free_ char **machine_info = NULL, **os_release = NULL;
        _cleanup_(rmdir_and_freep) char *t = NULL;
        _cleanup_(sigkill_waitp) pid_t child = 0;
        sd_id128_t machine_id = SD_ID128_NULL;
        _cleanup_free_ char *hostname = NULL;
        unsigned n_meta_initialized = 0, k;
        int fds[2 * _META_MAX], r;

        BLOCK_SIGNALS(SIGCHLD);

        assert(m);

        for (; n_meta_initialized < _META_MAX; n_meta_initialized ++)
                if (pipe2(fds + 2*n_meta_initialized, O_CLOEXEC) < 0) {
                        r = -errno;
                        goto finish;
                }

        r = mkdtemp_malloc("/tmp/dissect-XXXXXX", &t);
        if (r < 0)
                goto finish;

        r = safe_fork("(sd-dissect)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, &child);
        if (r < 0)
                goto finish;
        if (r == 0) {
                r = dissected_image_mount(m, t, UID_INVALID, DISSECT_IMAGE_READ_ONLY|DISSECT_IMAGE_MOUNT_ROOT_ONLY|DISSECT_IMAGE_VALIDATE_OS);
                if (r < 0) {
                        log_debug_errno(r, "Failed to mount dissected image: %m");
                        _exit(EXIT_FAILURE);
                }

                for (k = 0; k < _META_MAX; k++) {
                        _cleanup_close_ int fd = -1;
                        const char *p;

                        fds[2*k] = safe_close(fds[2*k]);

                        NULSTR_FOREACH(p, paths[k]) {
                                fd = chase_symlinks_and_open(p, t, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
                                if (fd >= 0)
                                        break;
                        }
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to read %s file of image, ignoring: %m", paths[k]);
                                continue;
                        }

                        r = copy_bytes(fd, fds[2*k+1], (uint64_t) -1, 0);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        fds[2*k+1] = safe_close(fds[2*k+1]);
                }

                _exit(EXIT_SUCCESS);
        }

        for (k = 0; k < _META_MAX; k++) {
                _cleanup_fclose_ FILE *f = NULL;

                fds[2*k+1] = safe_close(fds[2*k+1]);

                f = fdopen(fds[2*k], "r");
                if (!f) {
                        r = -errno;
                        goto finish;
                }

                fds[2*k] = -1;

                switch (k) {

                case META_HOSTNAME:
                        r = read_etc_hostname_stream(f, &hostname);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read /etc/hostname: %m");

                        break;

                case META_MACHINE_ID: {
                        _cleanup_free_ char *line = NULL;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read /etc/machine-id: %m");
                        else if (r == 33) {
                                r = sd_id128_from_string(line, &machine_id);
                                if (r < 0)
                                        log_debug_errno(r, "Image contains invalid /etc/machine-id: %s", line);
                        } else if (r == 0)
                                log_debug("/etc/machine-id file is empty.");
                        else
                                log_debug("/etc/machine-id has unexpected length %i.", r);

                        break;
                }

                case META_MACHINE_INFO:
                        r = load_env_file_pairs(f, "machine-info", &machine_info);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read /etc/machine-info: %m");

                        break;

                case META_OS_RELEASE:
                        r = load_env_file_pairs(f, "os-release", &os_release);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read OS release file: %m");

                        break;
                }
        }

        r = wait_for_terminate_and_check("(sd-dissect)", child, 0);
        child = 0;
        if (r < 0)
                goto finish;
        if (r != EXIT_SUCCESS)
                return -EPROTO;

        free_and_replace(m->hostname, hostname);
        m->machine_id = machine_id;
        strv_free_and_replace(m->machine_info, machine_info);
        strv_free_and_replace(m->os_release, os_release);

finish:
        for (k = 0; k < n_meta_initialized; k++)
                safe_close_pair(fds + 2*k);

        return r;
}

int dissect_image_and_warn(
                int fd,
                const char *name,
                const void *root_hash,
                size_t root_hash_size,
                DissectImageFlags flags,
                DissectedImage **ret) {

        _cleanup_free_ char *buffer = NULL;
        int r;

        if (!name) {
                r = fd_get_path(fd, &buffer);
                if (r < 0)
                        return r;

                name = buffer;
        }

        r = dissect_image(fd, root_hash, root_hash_size, flags, ret);

        switch (r) {

        case -EOPNOTSUPP:
                return log_error_errno(r, "Dissecting images is not supported, compiled without blkid support.");

        case -ENOPKG:
                return log_error_errno(r, "Couldn't identify a suitable partition table or file system in '%s'.", name);

        case -EADDRNOTAVAIL:
                return log_error_errno(r, "No root partition for specified root hash found in '%s'.", name);

        case -ENOTUNIQ:
                return log_error_errno(r, "Multiple suitable root partitions found in image '%s'.", name);

        case -ENXIO:
                return log_error_errno(r, "No suitable root partition found in image '%s'.", name);

        case -EPROTONOSUPPORT:
                return log_error_errno(r, "Device '%s' is loopback block device with partition scanning turned off, please turn it on.", name);

        default:
                if (r < 0)
                        return log_error_errno(r, "Failed to dissect image '%s': %m", name);

                return r;
        }
}

static const char *const partition_designator_table[] = {
        [PARTITION_ROOT] = "root",
        [PARTITION_ROOT_SECONDARY] = "root-secondary",
        [PARTITION_HOME] = "home",
        [PARTITION_SRV] = "srv",
        [PARTITION_ESP] = "esp",
        [PARTITION_XBOOTLDR] = "xbootldr",
        [PARTITION_SWAP] = "swap",
        [PARTITION_ROOT_VERITY] = "root-verity",
        [PARTITION_ROOT_SECONDARY_VERITY] = "root-secondary-verity",
};

DEFINE_STRING_TABLE_LOOKUP(partition_designator, int);
