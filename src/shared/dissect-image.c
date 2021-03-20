/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <linux/dm-ioctl.h>
#include <linux/loop.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sysexits.h>

#include "sd-device.h"
#include "sd-id128.h"

#include "architecture.h"
#include "ask-password-api.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "copy.h"
#include "cryptsetup-util.h"
#include "def.h"
#include "device-nodes.h"
#include "device-util.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "dm-util.h"
#include "env-file.h"
#include "extension-release.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fsck-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "id128-util.h"
#include "import-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
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

/* how many times to wait for the device nodes to appear */
#define N_DEVICE_NODE_LIST_ATTEMPTS 10

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
        if (r == -2)
                return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Results ambiguous for partition %s", node);
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

static int device_is_partition(sd_device *d, blkid_partition pp) {
        blkid_loff_t bsize, bstart;
        uint64_t size, start;
        int partno, bpartno, r;
        const char *ss, *v;

        assert(d);
        assert(pp);

        r = sd_device_get_subsystem(d, &ss);
        if (r < 0)
                return r;
        if (!streq(ss, "block"))
                return false;

        r = sd_device_get_sysattr_value(d, "partition", &v);
        if (r == -ENOENT ||        /* Not a partition device */
            ERRNO_IS_PRIVILEGE(r)) /* Not ready to access? */
                return false;
        if (r < 0)
                return r;
        r = safe_atoi(v, &partno);
        if (r < 0)
                return r;

        errno = 0;
        bpartno = blkid_partition_get_partno(pp);
        if (bpartno < 0)
                return errno_or_else(EIO);

        if (partno != bpartno)
                return false;

        r = sd_device_get_sysattr_value(d, "start", &v);
        if (r < 0)
                return r;
        r = safe_atou64(v, &start);
        if (r < 0)
                return r;

        errno = 0;
        bstart = blkid_partition_get_start(pp);
        if (bstart < 0)
                return errno_or_else(EIO);

        if (start != (uint64_t) bstart)
                return false;

        r = sd_device_get_sysattr_value(d, "size", &v);
        if (r < 0)
                return r;
        r = safe_atou64(v, &size);
        if (r < 0)
                return r;

        errno = 0;
        bsize = blkid_partition_get_size(pp);
        if (bsize < 0)
                return errno_or_else(EIO);

        if (size != (uint64_t) bsize)
                return false;

        return true;
}

static int find_partition(
                sd_device *parent,
                blkid_partition pp,
                sd_device **ret) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *q;
        int r;

        assert(parent);
        assert(pp);
        assert(ret);

        r = enumerator_for_parent(parent, &e);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, q) {
                r = device_is_partition(q, pp);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *ret = sd_device_ref(q);
                        return 0;
                }
        }

        return -ENXIO;
}

struct wait_data {
        sd_device *parent_device;
        blkid_partition blkidp;
        sd_device *found;
};

static inline void wait_data_done(struct wait_data *d) {
        sd_device_unref(d->found);
}

static int device_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        const char *parent1_path, *parent2_path;
        struct wait_data *w = userdata;
        sd_device *pp;
        int r;

        assert(w);

        if (device_for_action(device, SD_DEVICE_REMOVE))
                return 0;

        r = sd_device_get_parent(device, &pp);
        if (r < 0)
                return 0; /* Doesn't have a parent? No relevant to us */

        r = sd_device_get_syspath(pp, &parent1_path); /* Check parent of device of this action */
        if (r < 0)
                goto finish;

        r = sd_device_get_syspath(w->parent_device, &parent2_path); /* Check parent of device we are looking for */
        if (r < 0)
                goto finish;

        if (!path_equal(parent1_path, parent2_path))
                return 0; /* Has a different parent than what we need, not interesting to us */

        r = device_is_partition(device, w->blkidp);
        if (r < 0)
                goto finish;
        if (r == 0) /* Not the one we need */
                return 0;

        /* It's the one we need! Yay! */
        assert(!w->found);
        w->found = sd_device_ref(device);
        r = 0;

finish:
        return sd_event_exit(sd_device_monitor_get_event(monitor), r);
}

static int wait_for_partition_device(
                sd_device *parent,
                blkid_partition pp,
                usec_t deadline,
                sd_device **ret) {

        _cleanup_(sd_event_source_unrefp) sd_event_source *timeout_source = NULL;
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        assert(parent);
        assert(pp);
        assert(ret);

        r = find_partition(parent, pp, ret);
        if (r != -ENXIO)
                return r;

        r = sd_event_new(&event);
        if (r < 0)
                return r;

        r = sd_device_monitor_new(&monitor);
        if (r < 0)
                return r;

        r = sd_device_monitor_filter_add_match_subsystem_devtype(monitor, "block", "partition");
        if (r < 0)
                return r;

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return r;

        _cleanup_(wait_data_done) struct wait_data w = {
                .parent_device = parent,
                .blkidp = pp,
        };

        r = sd_device_monitor_start(monitor, device_monitor_handler, &w);
        if (r < 0)
                return r;

        /* Check again, the partition might have appeared in the meantime */
        r = find_partition(parent, pp, ret);
        if (r != -ENXIO)
                return r;

        if (deadline != USEC_INFINITY) {
                r = sd_event_add_time(
                                event, &timeout_source,
                                CLOCK_MONOTONIC, deadline, 0,
                                NULL, INT_TO_PTR(-ETIMEDOUT));
                if (r < 0)
                        return r;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return r;

        assert(w.found);
        *ret = TAKE_PTR(w.found);
        return 0;
}

static void check_partition_flags(
                const char *node,
                unsigned long long pflags,
                unsigned long long supported) {

        assert(node);

        /* Mask away all flags supported by this partition's type and the three flags the UEFI spec defines generically */
        pflags &= ~(supported | GPT_FLAG_REQUIRED_PARTITION | GPT_FLAG_NO_BLOCK_IO_PROTOCOL | GPT_FLAG_LEGACY_BIOS_BOOTABLE);

        if (pflags == 0)
                return;

        /* If there are other bits set, then log about it, to make things discoverable */
        for (unsigned i = 0; i < sizeof(pflags) * 8; i++) {
                unsigned long long bit = 1ULL << i;
                if (!FLAGS_SET(pflags, bit))
                        continue;

                log_debug("Unexpected partition flag %llu set on %s!", bit, node);
        }
}

static int device_wait_for_initialization_harder(
                sd_device *device,
                const char *subsystem,
                usec_t deadline,
                sd_device **ret) {

        _cleanup_free_ char *uevent = NULL;
        usec_t start, left, retrigger_timeout;
        int r;

        start = now(CLOCK_MONOTONIC);
        left = usec_sub_unsigned(deadline, start);

        if (DEBUG_LOGGING) {
                char buf[FORMAT_TIMESPAN_MAX];
                const char *sn = NULL;

                (void) sd_device_get_sysname(device, &sn);
                log_debug("Waiting for device '%s' to initialize for %s.", strna(sn), format_timespan(buf, sizeof(buf), left, 0));
        }

        if (left != USEC_INFINITY)
                retrigger_timeout = CLAMP(left / 4, 1 * USEC_PER_SEC, 5 * USEC_PER_SEC); /* A fourth of the total timeout, but let's clamp to 1s…5s range */
        else
                retrigger_timeout = 2 * USEC_PER_SEC;

        for (;;) {
                usec_t local_deadline, n;
                bool last_try;

                n = now(CLOCK_MONOTONIC);
                assert(n >= start);

                /* Find next deadline, when we'll retrigger */
                local_deadline = start +
                        DIV_ROUND_UP(n - start, retrigger_timeout) * retrigger_timeout;

                if (deadline != USEC_INFINITY && deadline <= local_deadline) {
                        local_deadline = deadline;
                        last_try = true;
                } else
                        last_try = false;

                r = device_wait_for_initialization(device, subsystem, local_deadline, ret);
                if (r >= 0 && DEBUG_LOGGING) {
                        char buf[FORMAT_TIMESPAN_MAX];
                        const char *sn = NULL;

                        (void) sd_device_get_sysname(device, &sn);
                        log_debug("Successfully waited for device '%s' to initialize for %s.", strna(sn), format_timespan(buf, sizeof(buf), usec_sub_unsigned(now(CLOCK_MONOTONIC), start), 0));

                }
                if (r != -ETIMEDOUT || last_try)
                        return r;

                if (!uevent) {
                        const char *syspath;

                        r = sd_device_get_syspath(device, &syspath);
                        if (r < 0)
                                return r;

                        uevent = path_join(syspath, "uevent");
                        if (!uevent)
                                return -ENOMEM;
                }

                if (DEBUG_LOGGING) {
                        char buf[FORMAT_TIMESPAN_MAX];

                        log_debug("Device didn't initialize within %s, assuming lost event. Retriggering device through %s.",
                                  format_timespan(buf, sizeof(buf), usec_sub_unsigned(now(CLOCK_MONOTONIC), start), 0),
                                  uevent);
                }

                r = write_string_file(uevent, "change", WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return r;
        }
}
#endif

#define DEVICE_TIMEOUT_USEC (45 * USEC_PER_SEC)

int dissect_image(
                int fd,
                const VeritySettings *verity,
                const MountOptions *mount_options,
                DissectImageFlags flags,
                DissectedImage **ret) {

#if HAVE_BLKID
#ifdef GPT_ROOT_NATIVE
        sd_id128_t root_uuid = SD_ID128_NULL, root_verity_uuid = SD_ID128_NULL;
#endif
#ifdef GPT_USR_NATIVE
        sd_id128_t usr_uuid = SD_ID128_NULL, usr_verity_uuid = SD_ID128_NULL;
#endif
        bool is_gpt, is_mbr, generic_rw, multiple_generic = false;
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *generic_node = NULL;
        sd_id128_t generic_uuid = SD_ID128_NULL;
        const char *pttype = NULL, *sysname = NULL;
        blkid_partlist pl;
        int r, generic_nr, n_partitions;
        struct stat st;
        usec_t deadline;

        assert(fd >= 0);
        assert(ret);
        assert(!verity || verity->root_hash || verity->root_hash_size == 0);
        assert(!((flags & DISSECT_IMAGE_GPT_ONLY) && (flags & DISSECT_IMAGE_NO_PARTITION_TABLE)));

        /* Probes a disk image, and returns information about what it found in *ret.
         *
         * Returns -ENOPKG if no suitable partition table or file system could be found.
         * Returns -EADDRNOTAVAIL if a root hash was specified but no matching root/verity partitions found. */

        if (verity && verity->root_hash) {
                sd_id128_t fsuuid, vuuid;

                /* If a root hash is supplied, then we use the root partition that has a UUID that match the
                 * first 128bit of the root hash. And we use the verity partition that has a UUID that match
                 * the final 128bit. */

                if (verity->root_hash_size < sizeof(sd_id128_t))
                        return -EINVAL;

                memcpy(&fsuuid, verity->root_hash, sizeof(sd_id128_t));
                memcpy(&vuuid, (const uint8_t*) verity->root_hash + verity->root_hash_size - sizeof(sd_id128_t), sizeof(sd_id128_t));

                if (sd_id128_is_null(fsuuid))
                        return -EINVAL;
                if (sd_id128_is_null(vuuid))
                        return -EINVAL;

                /* If the verity data declares it's for the /usr partition, then search for that, in all
                 * other cases assume it's for the root partition. */
#ifdef GPT_USR_NATIVE
                if (verity->designator == PARTITION_USR) {
                        usr_uuid = fsuuid;
                        usr_verity_uuid = vuuid;
                } else {
#endif
#ifdef GPT_ROOT_NATIVE
                        root_uuid = fsuuid;
                        root_verity_uuid = vuuid;
#endif
#ifdef GPT_USR_NATIVE
                }
#endif
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        r = sd_device_new_from_stat_rdev(&d, &st);
        if (r < 0)
                return r;

        if (!FLAGS_SET(flags, DISSECT_IMAGE_NO_UDEV)) {
                _cleanup_(sd_device_unrefp) sd_device *initialized = NULL;

                /* If udev support is enabled, then let's wait for the device to be initialized before we doing anything. */

                r = device_wait_for_initialization_harder(
                                d,
                                "block",
                                usec_add(now(CLOCK_MONOTONIC), DEVICE_TIMEOUT_USEC),
                                &initialized);
                if (r < 0)
                        return r;

                sd_device_unref(d);
                d = TAKE_PTR(initialized);
        }

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

        r = sd_device_get_sysname(d, &sysname);
        if (r < 0)
                return log_debug_errno(r, "Failed to get device sysname: %m");
        if (startswith(sysname, "loop")) {
                _cleanup_free_ char *name_stripped = NULL;
                const char *full_path;

                r = sd_device_get_sysattr_value(d, "loop/backing_file", &full_path);
                if (r < 0)
                        log_debug_errno(r, "Failed to lookup image name via loop device backing file sysattr, ignoring: %m");
                else {
                        r = raw_strip_suffixes(basename(full_path), &name_stripped);
                        if (r < 0)
                                return r;
                }

                free_and_replace(m->image_name, name_stripped);
        } else {
                r = free_and_strdup(&m->image_name, sysname);
                if (r < 0)
                        return r;
        }

        if (!image_name_is_valid(m->image_name)) {
                log_debug("Image name %s is not valid, ignoring", strempty(m->image_name));
                m->image_name = mfree(m->image_name);
        }

        if ((!(flags & DISSECT_IMAGE_GPT_ONLY) &&
            (flags & DISSECT_IMAGE_REQUIRE_ROOT)) ||
            (flags & DISSECT_IMAGE_NO_PARTITION_TABLE)) {
                const char *usage = NULL;

                /* If flags permit this, also allow using non-partitioned single-filesystem images */

                (void) blkid_probe_lookup_value(b, "USAGE", &usage, NULL);
                if (STRPTR_IN_SET(usage, "filesystem", "crypto")) {
                        const char *fstype = NULL, *options = NULL, *devname = NULL;
                        _cleanup_free_ char *t = NULL, *n = NULL, *o = NULL;

                        /* OK, we have found a file system, that's our root partition then. */
                        (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);

                        if (fstype) {
                                t = strdup(fstype);
                                if (!t)
                                        return -ENOMEM;
                        }

                        r = sd_device_get_devname(d, &devname);
                        if (r < 0)
                                return r;

                        n = strdup(devname);
                        if (!n)
                                return -ENOMEM;

                        m->single_file_system = true;
                        m->verity = verity && verity->root_hash && verity->data_path && (verity->designator < 0 || verity->designator == PARTITION_ROOT);
                        m->can_verity = verity && verity->data_path;

                        options = mount_options_from_designator(mount_options, PARTITION_ROOT);
                        if (options) {
                                o = strdup(options);
                                if (!o)
                                        return -ENOMEM;
                        }

                        m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                .found = true,
                                .rw = !m->verity,
                                .partno = -1,
                                .architecture = _ARCHITECTURE_INVALID,
                                .fstype = TAKE_PTR(t),
                                .node = TAKE_PTR(n),
                                .mount_options = TAKE_PTR(o),
                        };

                        m->encrypted = streq_ptr(fstype, "crypto_LUKS");

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

        /* Safety check: refuse block devices that carry a partition table but for which the kernel doesn't
         * do partition scanning. */
        r = blockdev_partscan_enabled(fd);
        if (r < 0)
                return r;
        if (r == 0)
                return -EPROTONOSUPPORT;

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return errno_or_else(ENOMEM);

        errno = 0;
        n_partitions = blkid_partlist_numof_partitions(pl);
        if (n_partitions < 0)
                return errno_or_else(EIO);

        deadline = usec_add(now(CLOCK_MONOTONIC), DEVICE_TIMEOUT_USEC);
        for (int i = 0; i < n_partitions; i++) {
                _cleanup_(sd_device_unrefp) sd_device *q = NULL;
                unsigned long long pflags;
                blkid_partition pp;
                const char *node;
                int nr;

                errno = 0;
                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return errno_or_else(EIO);

                r = wait_for_partition_device(d, pp, deadline, &q);
                if (r < 0)
                        return r;

                r = sd_device_get_devname(q, &node);
                if (r < 0)
                        return r;

                pflags = blkid_partition_get_flags(pp);

                errno = 0;
                nr = blkid_partition_get_partno(pp);
                if (nr < 0)
                        return errno_or_else(EIO);

                if (is_gpt) {
                        PartitionDesignator designator = _PARTITION_DESIGNATOR_INVALID;
                        int architecture = _ARCHITECTURE_INVALID;
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

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_HOME;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);

                        } else if (sd_id128_equal(type_id, GPT_SRV)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_SRV;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);

                        } else if (sd_id128_equal(type_id, GPT_ESP)) {

                                /* Note that we don't check the GPT_FLAG_NO_AUTO flag for the ESP, as it is
                                 * not defined there. We instead check the GPT_FLAG_NO_BLOCK_IO_PROTOCOL, as
                                 * recommended by the UEFI spec (See "12.3.3 Number and Location of System
                                 * Partitions"). */

                                if (pflags & GPT_FLAG_NO_BLOCK_IO_PROTOCOL)
                                        continue;

                                designator = PARTITION_ESP;
                                fstype = "vfat";

                        } else if (sd_id128_equal(type_id, GPT_XBOOTLDR)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_XBOOTLDR;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);
                        }
#ifdef GPT_ROOT_NATIVE
                        else if (sd_id128_equal(type_id, GPT_ROOT_NATIVE)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a root ID is specified, ignore everything but the root id */
                                if (!sd_id128_is_null(root_uuid) && !sd_id128_equal(root_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT;
                                architecture = native_architecture();
                                rw = !(pflags & GPT_FLAG_READ_ONLY);

                        } else if (sd_id128_equal(type_id, GPT_ROOT_NATIVE_VERITY)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                m->can_verity = true;

                                /* Ignore verity unless a root hash is specified */
                                if (sd_id128_is_null(root_verity_uuid) || !sd_id128_equal(root_verity_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT_VERITY;
                                fstype = "DM_verity_hash";
                                architecture = native_architecture();
                                rw = false;
                        }
#endif
#ifdef GPT_ROOT_SECONDARY
                        else if (sd_id128_equal(type_id, GPT_ROOT_SECONDARY)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a root ID is specified, ignore everything but the root id */
                                if (!sd_id128_is_null(root_uuid) && !sd_id128_equal(root_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT_SECONDARY;
                                architecture = SECONDARY_ARCHITECTURE;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);

                        } else if (sd_id128_equal(type_id, GPT_ROOT_SECONDARY_VERITY)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                m->can_verity = true;

                                /* Ignore verity unless root has is specified */
                                if (sd_id128_is_null(root_verity_uuid) || !sd_id128_equal(root_verity_uuid, id))
                                        continue;

                                designator = PARTITION_ROOT_SECONDARY_VERITY;
                                fstype = "DM_verity_hash";
                                architecture = SECONDARY_ARCHITECTURE;
                                rw = false;
                        }
#endif
#ifdef GPT_USR_NATIVE
                        else if (sd_id128_equal(type_id, GPT_USR_NATIVE)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a usr ID is specified, ignore everything but the usr id */
                                if (!sd_id128_is_null(usr_uuid) && !sd_id128_equal(usr_uuid, id))
                                        continue;

                                designator = PARTITION_USR;
                                architecture = native_architecture();
                                rw = !(pflags & GPT_FLAG_READ_ONLY);

                        } else if (sd_id128_equal(type_id, GPT_USR_NATIVE_VERITY)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                m->can_verity = true;

                                /* Ignore verity unless a usr hash is specified */
                                if (sd_id128_is_null(usr_verity_uuid) || !sd_id128_equal(usr_verity_uuid, id))
                                        continue;

                                designator = PARTITION_USR_VERITY;
                                fstype = "DM_verity_hash";
                                architecture = native_architecture();
                                rw = false;
                        }
#endif
#ifdef GPT_USR_SECONDARY
                        else if (sd_id128_equal(type_id, GPT_USR_SECONDARY)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a usr ID is specified, ignore everything but the usr id */
                                if (!sd_id128_is_null(usr_uuid) && !sd_id128_equal(usr_uuid, id))
                                        continue;

                                designator = PARTITION_USR_SECONDARY;
                                architecture = SECONDARY_ARCHITECTURE;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);

                        } else if (sd_id128_equal(type_id, GPT_USR_SECONDARY_VERITY)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                m->can_verity = true;

                                /* Ignore verity unless usr has is specified */
                                if (sd_id128_is_null(usr_verity_uuid) || !sd_id128_equal(usr_verity_uuid, id))
                                        continue;

                                designator = PARTITION_USR_SECONDARY_VERITY;
                                fstype = "DM_verity_hash";
                                architecture = SECONDARY_ARCHITECTURE;
                                rw = false;
                        }
#endif
                        else if (sd_id128_equal(type_id, GPT_SWAP)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_SWAP;
                                fstype = "swap";

                        } else if (sd_id128_equal(type_id, GPT_LINUX_GENERIC)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

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

                        } else if (sd_id128_equal(type_id, GPT_TMP)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                designator = PARTITION_TMP;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);

                        } else if (sd_id128_equal(type_id, GPT_VAR)) {

                                check_partition_flags(node, pflags, GPT_FLAG_NO_AUTO|GPT_FLAG_READ_ONLY);

                                if (pflags & GPT_FLAG_NO_AUTO)
                                        continue;

                                if (!FLAGS_SET(flags, DISSECT_IMAGE_RELAX_VAR_CHECK)) {
                                        sd_id128_t var_uuid;

                                        /* For /var we insist that the uuid of the partition matches the
                                         * HMAC-SHA256 of the /var GPT partition type uuid, keyed by machine
                                         * ID. Why? Unlike the other partitions /var is inherently
                                         * installation specific, hence we need to be careful not to mount it
                                         * in the wrong installation. By hashing the partition UUID from
                                         * /etc/machine-id we can securely bind the partition to the
                                         * installation. */

                                        r = sd_id128_get_machine_app_specific(GPT_VAR, &var_uuid);
                                        if (r < 0)
                                                return r;

                                        if (!sd_id128_equal(var_uuid, id)) {
                                                log_debug("Found a /var/ partition, but its UUID didn't match our expectations, ignoring.");
                                                continue;
                                        }
                                }

                                designator = PARTITION_VAR;
                                rw = !(pflags & GPT_FLAG_READ_ONLY);
                        }

                        if (designator != _PARTITION_DESIGNATOR_INVALID) {
                                _cleanup_free_ char *t = NULL, *n = NULL, *o = NULL;
                                const char *options = NULL;

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

                                options = mount_options_from_designator(mount_options, designator);
                                if (options) {
                                        o = strdup(options);
                                        if (!o)
                                                return -ENOMEM;
                                }

                                m->partitions[designator] = (DissectedPartition) {
                                        .found = true,
                                        .partno = nr,
                                        .rw = rw,
                                        .architecture = architecture,
                                        .node = TAKE_PTR(n),
                                        .fstype = TAKE_PTR(t),
                                        .uuid = id,
                                        .mount_options = TAKE_PTR(o),
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
                                _cleanup_free_ char *n = NULL, *o = NULL;
                                sd_id128_t id = SD_ID128_NULL;
                                const char *sid, *options = NULL;

                                /* First one wins */
                                if (m->partitions[PARTITION_XBOOTLDR].found)
                                        continue;

                                sid = blkid_partition_get_uuid(pp);
                                if (sid)
                                        (void) sd_id128_from_string(sid, &id);

                                n = strdup(node);
                                if (!n)
                                        return -ENOMEM;

                                options = mount_options_from_designator(mount_options, PARTITION_XBOOTLDR);
                                if (options) {
                                        o = strdup(options);
                                        if (!o)
                                                return -ENOMEM;
                                }

                                m->partitions[PARTITION_XBOOTLDR] = (DissectedPartition) {
                                        .found = true,
                                        .partno = nr,
                                        .rw = true,
                                        .architecture = _ARCHITECTURE_INVALID,
                                        .node = TAKE_PTR(n),
                                        .uuid = id,
                                        .mount_options = TAKE_PTR(o),
                                };

                                break;
                        }}
                }
        }

        if (m->partitions[PARTITION_ROOT].found) {
                /* If we found the primary arch, then invalidate the secondary arch to avoid any ambiguities,
                 * since we never want to mount the secondary arch in this case. */
                m->partitions[PARTITION_ROOT_SECONDARY].found = false;
                m->partitions[PARTITION_ROOT_SECONDARY_VERITY].found = false;
                m->partitions[PARTITION_USR_SECONDARY].found = false;
                m->partitions[PARTITION_USR_SECONDARY_VERITY].found = false;
        } else {
                /* No root partition found? Then let's see if ther's one for the secondary architecture. And if not
                 * either, then check if there's a single generic one, and use that. */

                if (m->partitions[PARTITION_ROOT_VERITY].found)
                        return -EADDRNOTAVAIL;

                /* We didn't find a primary architecture root, but we found a primary architecture /usr? Refuse that for now. */
                if (m->partitions[PARTITION_USR].found || m->partitions[PARTITION_USR_VERITY].found)
                        return -EADDRNOTAVAIL;

                if (m->partitions[PARTITION_ROOT_SECONDARY].found) {
                        /* Upgrade secondary arch to first */
                        m->partitions[PARTITION_ROOT] = m->partitions[PARTITION_ROOT_SECONDARY];
                        zero(m->partitions[PARTITION_ROOT_SECONDARY]);
                        m->partitions[PARTITION_ROOT_VERITY] = m->partitions[PARTITION_ROOT_SECONDARY_VERITY];
                        zero(m->partitions[PARTITION_ROOT_SECONDARY_VERITY]);

                        m->partitions[PARTITION_USR] = m->partitions[PARTITION_USR_SECONDARY];
                        zero(m->partitions[PARTITION_USR_SECONDARY]);
                        m->partitions[PARTITION_USR_VERITY] = m->partitions[PARTITION_USR_SECONDARY_VERITY];
                        zero(m->partitions[PARTITION_USR_SECONDARY_VERITY]);

                } else if (flags & DISSECT_IMAGE_REQUIRE_ROOT) {
                        _cleanup_free_ char *o = NULL;
                        const char *options = NULL;

                        /* If the root hash was set, then we won't fall back to a generic node, because the
                         * root hash decides. */
                        if (verity && verity->root_hash)
                                return -EADDRNOTAVAIL;

                        /* If we didn't find a generic node, then we can't fix this up either */
                        if (!generic_node)
                                return -ENXIO;

                        /* If we didn't find a properly marked root partition, but we did find a single suitable
                         * generic Linux partition, then use this as root partition, if the caller asked for it. */
                        if (multiple_generic)
                                return -ENOTUNIQ;

                        options = mount_options_from_designator(mount_options, PARTITION_ROOT);
                        if (options) {
                                o = strdup(options);
                                if (!o)
                                        return -ENOMEM;
                        }

                        m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                .found = true,
                                .rw = generic_rw,
                                .partno = generic_nr,
                                .architecture = _ARCHITECTURE_INVALID,
                                .node = TAKE_PTR(generic_node),
                                .uuid = generic_uuid,
                                .mount_options = TAKE_PTR(o),
                        };
                }
        }

        /* Refuse if we found a verity partition for /usr but no matching file system partition */
        if (!m->partitions[PARTITION_USR].found && m->partitions[PARTITION_USR_VERITY].found)
                return -EADDRNOTAVAIL;

        /* Combinations of verity /usr with verity-less root is OK, but the reverse is not */
        if (m->partitions[PARTITION_ROOT_VERITY].found && m->partitions[PARTITION_USR].found && !m->partitions[PARTITION_USR_VERITY].found)
                return -EADDRNOTAVAIL;

        if (verity && verity->root_hash) {
                if (verity->designator < 0 || verity->designator == PARTITION_ROOT) {
                        if (!m->partitions[PARTITION_ROOT_VERITY].found || !m->partitions[PARTITION_ROOT].found)
                                return -EADDRNOTAVAIL;

                        /* If we found a verity setup, then the root partition is necessarily read-only. */
                        m->partitions[PARTITION_ROOT].rw = false;
                        m->verity = true;
                }

                if (verity->designator == PARTITION_USR) {
                        if (!m->partitions[PARTITION_USR_VERITY].found || !m->partitions[PARTITION_USR].found)
                                return -EADDRNOTAVAIL;

                        m->partitions[PARTITION_USR].rw = false;
                        m->verity = true;
                }
        }

        blkid_free_probe(b);
        b = NULL;

        /* Fill in file system types if we don't know them yet. */
        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
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
        if (!m)
                return NULL;

        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                free(m->partitions[i].fstype);
                free(m->partitions[i].node);
                free(m->partitions[i].decrypted_fstype);
                free(m->partitions[i].decrypted_node);
                free(m->partitions[i].mount_options);
        }

        free(m->image_name);
        free(m->hostname);
        strv_free(m->machine_info);
        strv_free(m->os_release);
        strv_free(m->extension_release);

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

static int run_fsck(const char *node, const char *fstype) {
        int r, exit_status;
        pid_t pid;

        assert(node);
        assert(fstype);

        r = fsck_exists(fstype);
        if (r < 0) {
                log_debug_errno(r, "Couldn't determine whether fsck for %s exists, proceeding anyway.", fstype);
                return 0;
        }
        if (r == 0) {
                log_debug("Not checking partition %s, as fsck for %s does not exist.", node, fstype);
                return 0;
        }

        r = safe_fork("(fsck)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_NULL_STDIO, &pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork off fsck: %m");
        if (r == 0) {
                /* Child */
                execl("/sbin/fsck", "/sbin/fsck", "-aT", node, NULL);
                log_open();
                log_debug_errno(errno, "Failed to execl() fsck: %m");
                _exit(FSCK_OPERATIONAL_ERROR);
        }

        exit_status = wait_for_terminate_and_check("fsck", pid, 0);
        if (exit_status < 0)
                return log_debug_errno(exit_status, "Failed to fork off /sbin/fsck: %m");

        if ((exit_status & ~FSCK_ERROR_CORRECTED) != FSCK_SUCCESS) {
                log_debug("fsck failed with exit status %i.", exit_status);

                if ((exit_status & (FSCK_SYSTEM_SHOULD_REBOOT|FSCK_ERRORS_LEFT_UNCORRECTED)) != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN), "File system is corrupted, refusing.");

                log_debug("Ignoring fsck error.");
        }

        return 0;
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

        /* Use decrypted node and matching fstype if available, otherwise use the original device */
        node = m->decrypted_node ?: m->node;
        fstype = m->decrypted_node ? m->decrypted_fstype: m->fstype;

        if (!m->found || !node)
                return 0;
        if (!fstype)
                return -EAFNOSUPPORT;

        /* We are looking at an encrypted partition? This either means stacked encryption, or the caller didn't call dissected_image_decrypt() beforehand. Let's return a recognizable error for this case. */
        if (streq(fstype, "crypto_LUKS"))
                return -EUNATCH;

        rw = m->rw && !(flags & DISSECT_IMAGE_READ_ONLY);

        if (FLAGS_SET(flags, DISSECT_IMAGE_FSCK) && rw) {
                r = run_fsck(node, fstype);
                if (r < 0)
                        return r;
        }

        if (directory) {
                /* Automatically create missing mount points inside the image, if necessary. */
                r = mkdir_p_root(where, directory, uid_shift, (gid_t) uid_shift, 0755);
                if (r < 0 && r != -EROFS)
                        return r;

                r = chase_symlinks(directory, where, CHASE_PREFIX_ROOT, &chased, NULL);
                if (r < 0)
                        return r;

                p = chased;
        } else {
                /* Create top-level mount if missing – but only if this is asked for. This won't modify the
                 * image (as the branch above does) but the host hierarchy, and the created directory might
                 * survive our mount in the host hierarchy hence. */
                if (FLAGS_SET(flags, DISSECT_IMAGE_MKDIR)) {
                        r = mkdir_p(where, 0755);
                        if (r < 0)
                                return r;
                }

                p = where;
        }

        /* If requested, turn on discard support. */
        if (fstype_can_discard(fstype) &&
            ((flags & DISSECT_IMAGE_DISCARD) ||
             ((flags & DISSECT_IMAGE_DISCARD_ON_LOOP) && is_loop_device(m->node) > 0))) {
                options = strdup("discard");
                if (!options)
                        return -ENOMEM;
        }

        if (uid_is_valid(uid_shift) && uid_shift != 0 && fstype_can_uid_gid(fstype)) {
                _cleanup_free_ char *uid_option = NULL;

                if (asprintf(&uid_option, "uid=" UID_FMT ",gid=" GID_FMT, uid_shift, (gid_t) uid_shift) < 0)
                        return -ENOMEM;

                if (!strextend_with_separator(&options, ",", uid_option))
                        return -ENOMEM;
        }

        if (!isempty(m->mount_options))
                if (!strextend_with_separator(&options, ",", m->mount_options))
                        return -ENOMEM;

        r = mount_nofollow_verbose(LOG_DEBUG, node, p, fstype, MS_NODEV|(rw ? 0 : MS_RDONLY), options);
        if (r < 0)
                return r;

        return 1;
}

int dissected_image_mount(DissectedImage *m, const char *where, uid_t uid_shift, DissectImageFlags flags) {
        int r, xbootldr_mounted;

        assert(m);
        assert(where);

        /* Returns:
         *
         *  -ENXIO        → No root partition found
         *  -EMEDIUMTYPE  → DISSECT_IMAGE_VALIDATE_OS set but no os-release/extension-release file found
         *  -EUNATCH      → Encrypted partition found for which no dm-crypt was set up yet
         *  -EUCLEAN      → fsck for file system failed
         *  -EBUSY        → File system already mounted/used elsewhere (kernel)
         *  -EAFNOSUPPORT → File system type not supported or not known
         */

        if (!m->partitions[PARTITION_ROOT].found)
                return -ENXIO;

        if ((flags & DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY) == 0) {
                r = mount_partition(m->partitions + PARTITION_ROOT, where, NULL, uid_shift, flags);
                if (r < 0)
                        return r;
        }

        if ((flags & DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY) == 0) {
                /* For us mounting root always means mounting /usr as well */
                r = mount_partition(m->partitions + PARTITION_USR, where, "/usr", uid_shift, flags);
                if (r < 0)
                        return r;

                if (flags & DISSECT_IMAGE_VALIDATE_OS) {
                        r = path_is_os_tree(where);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                r = path_is_extension_tree(where, m->image_name);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -EMEDIUMTYPE;
                        }
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

        r = mount_partition(m->partitions + PARTITION_VAR, where, "/var", uid_shift, flags);
        if (r < 0)
                return r;

        r = mount_partition(m->partitions + PARTITION_TMP, where, "/var/tmp", uid_shift, flags);
        if (r < 0)
                return r;

        xbootldr_mounted = mount_partition(m->partitions + PARTITION_XBOOTLDR, where, "/boot", uid_shift, flags);
        if (xbootldr_mounted < 0)
                return xbootldr_mounted;

        if (m->partitions[PARTITION_ESP].found) {
                int esp_done = false;

                /* Mount the ESP to /efi if it exists. If it doesn't exist, use /boot instead, but only if it
                 * exists and is empty, and we didn't already mount the XBOOTLDR partition into it. */

                r = chase_symlinks("/efi", where, CHASE_PREFIX_ROOT, NULL, NULL);
                if (r < 0) {
                        if (r != -ENOENT)
                                return r;

                        /* /efi doesn't exist. Let's see if /boot is suitable then */

                        if (!xbootldr_mounted) {
                                _cleanup_free_ char *p = NULL;

                                r = chase_symlinks("/boot", where, CHASE_PREFIX_ROOT, &p, NULL);
                                if (r < 0) {
                                        if (r != -ENOENT)
                                                return r;
                                } else if (dir_is_empty(p) > 0) {
                                        /* It exists and is an empty directory. Let's mount the ESP there. */
                                        r = mount_partition(m->partitions + PARTITION_ESP, where, "/boot", uid_shift, flags);
                                        if (r < 0)
                                                return r;

                                        esp_done = true;
                                }
                        }
                }

                if (!esp_done) {
                        /* OK, let's mount the ESP now to /efi (possibly creating the dir if missing) */

                        r = mount_partition(m->partitions + PARTITION_ESP, where, "/efi", uid_shift, flags);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int dissected_image_mount_and_warn(DissectedImage *m, const char *where, uid_t uid_shift, DissectImageFlags flags) {
        int r;

        assert(m);
        assert(where);

        r = dissected_image_mount(m, where, uid_shift, flags);
        if (r == -ENXIO)
                return log_error_errno(r, "Not root file system found in image.");
        if (r == -EMEDIUMTYPE)
                return log_error_errno(r, "No suitable os-release/extension-release file in image found.");
        if (r == -EUNATCH)
                return log_error_errno(r, "Encrypted file system discovered, but decryption not requested.");
        if (r == -EUCLEAN)
                return log_error_errno(r, "File system check on image failed.");
        if (r == -EBUSY)
                return log_error_errno(r, "File system already mounted elsewhere.");
        if (r == -EAFNOSUPPORT)
                return log_error_errno(r, "File system type not supported or not known.");
        if (r < 0)
                return log_error_errno(r, "Failed to mount image: %m");

        return r;
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
        int r;

        if (!d)
                return NULL;

        for (size_t i = 0; i < d->n_decrypted; i++) {
                DecryptedPartition *p = d->decrypted + i;

                if (p->device && p->name && !p->relinquished) {
                        r = sym_crypt_deactivate_by_name(p->device, p->name, 0);
                        if (r < 0)
                                log_debug_errno(r, "Failed to deactivate encrypted partition %s", p->name);
                }

                if (p->device)
                        sym_crypt_free(p->device);
                free(p->name);
        }

        free(d->decrypted);
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
                base = original_node;
        else
                base++;
        if (isempty(base))
                return -EINVAL;

        name = strjoin(base, suffix);
        if (!name)
                return -ENOMEM;
        if (!filename_is_valid(name))
                return -EINVAL;

        node = path_join(sym_crypt_get_dir(), name);
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
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        int r;

        assert(m);
        assert(d);

        if (!m->found || !m->node || !m->fstype)
                return 0;

        if (!streq(m->fstype, "crypto_LUKS"))
                return 0;

        if (!passphrase)
                return -ENOKEY;

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = make_dm_name_and_node(m->node, "-decrypted", &name, &node);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC0(d->decrypted, d->n_allocated, d->n_decrypted + 1))
                return -ENOMEM;

        r = sym_crypt_init(&cd, m->node);
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize dm-crypt: %m");

        cryptsetup_enable_logging(cd);

        r = sym_crypt_load(cd, CRYPT_LUKS, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load LUKS metadata: %m");

        r = sym_crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, passphrase, strlen(passphrase),
                                             ((flags & DISSECT_IMAGE_READ_ONLY) ? CRYPT_ACTIVATE_READONLY : 0) |
                                             ((flags & DISSECT_IMAGE_DISCARD_ON_CRYPTO) ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0));
        if (r < 0) {
                log_debug_errno(r, "Failed to activate LUKS device: %m");
                return r == -EPERM ? -EKEYREJECTED : r;
        }

        d->decrypted[d->n_decrypted++] = (DecryptedPartition) {
                .name = TAKE_PTR(name),
                .device = TAKE_PTR(cd),
        };

        m->decrypted_node = TAKE_PTR(node);

        return 0;
}

static int verity_can_reuse(
                const VeritySettings *verity,
                const char *name,
                struct crypt_device **ret_cd) {

        /* If the same volume was already open, check that the root hashes match, and reuse it if they do */
        _cleanup_free_ char *root_hash_existing = NULL;
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        struct crypt_params_verity crypt_params = {};
        size_t root_hash_existing_size;
        int r;

        assert(verity);
        assert(name);
        assert(ret_cd);

        r = sym_crypt_init_by_name(&cd, name);
        if (r < 0)
                return log_debug_errno(r, "Error opening verity device, crypt_init_by_name failed: %m");

        r = sym_crypt_get_verity_info(cd, &crypt_params);
        if (r < 0)
                return log_debug_errno(r, "Error opening verity device, crypt_get_verity_info failed: %m");

        root_hash_existing_size = verity->root_hash_size;
        root_hash_existing = malloc0(root_hash_existing_size);
        if (!root_hash_existing)
                return -ENOMEM;

        r = sym_crypt_volume_key_get(cd, CRYPT_ANY_SLOT, root_hash_existing, &root_hash_existing_size, NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Error opening verity device, crypt_volume_key_get failed: %m");
        if (verity->root_hash_size != root_hash_existing_size ||
            memcmp(root_hash_existing, verity->root_hash, verity->root_hash_size) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Error opening verity device, it already exists but root hashes are different.");

#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
        /* Ensure that, if signatures are supported, we only reuse the device if the previous mount used the
         * same settings, so that a previous unsigned mount will not be reused if the user asks to use
         * signing for the new one, and vice versa. */
        if (!!verity->root_hash_sig != !!(crypt_params.flags & CRYPT_VERITY_ROOT_HASH_SIGNATURE))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Error opening verity device, it already exists but signature settings are not the same.");
#endif

        *ret_cd = TAKE_PTR(cd);
        return 0;
}

static inline char* dm_deferred_remove_clean(char *name) {
        if (!name)
                return NULL;

        (void) sym_crypt_deactivate_by_name(NULL, name, CRYPT_DEACTIVATE_DEFERRED);
        return mfree(name);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char *, dm_deferred_remove_clean);

static int verity_partition(
                PartitionDesignator designator,
                DissectedPartition *m,
                DissectedPartition *v,
                const VeritySettings *verity,
                DissectImageFlags flags,
                DecryptedImage *d) {

        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(dm_deferred_remove_cleanp) char *restore_deferred_remove = NULL;
        _cleanup_free_ char *node = NULL, *name = NULL;
        int r;

        assert(m);
        assert(v || (verity && verity->data_path));

        if (!verity || !verity->root_hash)
                return 0;
        if (!((verity->designator < 0 && designator == PARTITION_ROOT) ||
              (verity->designator == designator)))
                return 0;

        if (!m->found || !m->node || !m->fstype)
                return 0;
        if (!verity->data_path) {
                if (!v->found || !v->node || !v->fstype)
                        return 0;

                if (!streq(v->fstype, "DM_verity_hash"))
                        return 0;
        }

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE)) {
                /* Use the roothash, which is unique per volume, as the device node name, so that it can be reused */
                _cleanup_free_ char *root_hash_encoded = NULL;

                root_hash_encoded = hexmem(verity->root_hash, verity->root_hash_size);
                if (!root_hash_encoded)
                        return -ENOMEM;

                r = make_dm_name_and_node(root_hash_encoded, "-verity", &name, &node);
        } else
                r = make_dm_name_and_node(m->node, "-verity", &name, &node);
        if (r < 0)
                return r;

        r = sym_crypt_init(&cd, verity->data_path ?: v->node);
        if (r < 0)
                return r;

        cryptsetup_enable_logging(cd);

        r = sym_crypt_load(cd, CRYPT_VERITY, NULL);
        if (r < 0)
                return r;

        r = sym_crypt_set_data_device(cd, m->node);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC0(d->decrypted, d->n_allocated, d->n_decrypted + 1))
                return -ENOMEM;

        /* If activating fails because the device already exists, check the metadata and reuse it if it matches.
         * In case of ENODEV/ENOENT, which can happen if another process is activating at the exact same time,
         * retry a few times before giving up. */
        for (unsigned i = 0; i < N_DEVICE_NODE_LIST_ATTEMPTS; i++) {
                if (verity->root_hash_sig) {
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        r = sym_crypt_activate_by_signed_key(
                                        cd,
                                        name,
                                        verity->root_hash,
                                        verity->root_hash_size,
                                        verity->root_hash_sig,
                                        verity->root_hash_sig_size,
                                        CRYPT_ACTIVATE_READONLY);
#else
                        r = log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "Activation of verity device with signature requested, but not supported by %s due to missing crypt_activate_by_signed_key().", program_invocation_short_name);
#endif
                } else
                        r = sym_crypt_activate_by_volume_key(
                                        cd,
                                        name,
                                        verity->root_hash,
                                        verity->root_hash_size,
                                        CRYPT_ACTIVATE_READONLY);
                /* libdevmapper can return EINVAL when the device is already in the activation stage.
                 * There's no way to distinguish this situation from a genuine error due to invalid
                 * parameters, so immediately fall back to activating the device with a unique name.
                 * Improvements in libcrypsetup can ensure this never happens:
                 * https://gitlab.com/cryptsetup/cryptsetup/-/merge_requests/96 */
                if (r == -EINVAL && FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE))
                        return verity_partition(designator, m, v, verity, flags & ~DISSECT_IMAGE_VERITY_SHARE, d);
                if (!IN_SET(r,
                            0,       /* Success */
                            -EEXIST, /* Volume is already open and ready to be used */
                            -EBUSY,  /* Volume is being opened but not ready, crypt_init_by_name can fetch details */
                            -ENODEV  /* Volume is being opened but not ready, crypt_init_by_name would fail, try to open again */))
                        return r;
                if (IN_SET(r, -EEXIST, -EBUSY)) {
                        struct crypt_device *existing_cd = NULL;

                        if (!restore_deferred_remove){
                                /* To avoid races, disable automatic removal on umount while setting up the new device. Restore it on failure. */
                                r = dm_deferred_remove_cancel(name);
                                /* If activation returns EBUSY there might be no deferred removal to cancel, that's fine */
                                if (r < 0 && r != -ENXIO)
                                        return log_debug_errno(r, "Disabling automated deferred removal for verity device %s failed: %m", node);
                                if (r == 0) {
                                        restore_deferred_remove = strdup(name);
                                        if (!restore_deferred_remove)
                                                return -ENOMEM;
                                }
                        }

                        r = verity_can_reuse(verity, name, &existing_cd);
                        /* Same as above, -EINVAL can randomly happen when it actually means -EEXIST */
                        if (r == -EINVAL && FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE))
                                return verity_partition(designator, m, v, verity, flags & ~DISSECT_IMAGE_VERITY_SHARE, d);
                        if (!IN_SET(r, 0, -ENODEV, -ENOENT, -EBUSY))
                                return log_debug_errno(r, "Checking whether existing verity device %s can be reused failed: %m", node);
                        if (r == 0) {
                                /* devmapper might say that the device exists, but the devlink might not yet have been
                                 * created. Check and wait for the udev event in that case. */
                                r = device_wait_for_devlink(node, "block", usec_add(now(CLOCK_MONOTONIC), 100 * USEC_PER_MSEC), NULL);
                                /* Fallback to activation with a unique device if it's taking too long */
                                if (r == -ETIMEDOUT)
                                        break;
                                if (r < 0)
                                        return r;

                                if (cd)
                                        sym_crypt_free(cd);
                                cd = existing_cd;
                        }
                }
                if (r == 0)
                        break;

                /* Device is being opened by another process, but it has not finished yet, yield for 2ms */
                (void) usleep(2 * USEC_PER_MSEC);
        }

        /* An existing verity device was reported by libcryptsetup/libdevmapper, but we can't use it at this time.
         * Fall back to activating it with a unique device name. */
        if (r != 0 && FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE))
                return verity_partition(designator, m, v, verity, flags & ~DISSECT_IMAGE_VERITY_SHARE, d);

        /* Everything looks good and we'll be able to mount the device, so deferred remove will be re-enabled at that point. */
        restore_deferred_remove = mfree(restore_deferred_remove);

        d->decrypted[d->n_decrypted++] = (DecryptedPartition) {
                .name = TAKE_PTR(name),
                .device = TAKE_PTR(cd),
        };

        m->decrypted_node = TAKE_PTR(node);

        return 0;
}
#endif

int dissected_image_decrypt(
                DissectedImage *m,
                const char *passphrase,
                const VeritySettings *verity,
                DissectImageFlags flags,
                DecryptedImage **ret) {

#if HAVE_LIBCRYPTSETUP
        _cleanup_(decrypted_image_unrefp) DecryptedImage *d = NULL;
        int r;
#endif

        assert(m);
        assert(!verity || verity->root_hash || verity->root_hash_size == 0);

        /* Returns:
         *
         *      = 0           → There was nothing to decrypt
         *      > 0           → Decrypted successfully
         *      -ENOKEY       → There's something to decrypt but no key was supplied
         *      -EKEYREJECTED → Passed key was not correct
         */

        if (verity && verity->root_hash && verity->root_hash_size < sizeof(sd_id128_t))
                return -EINVAL;

        if (!m->encrypted && !m->verity) {
                *ret = NULL;
                return 0;
        }

#if HAVE_LIBCRYPTSETUP
        d = new0(DecryptedImage, 1);
        if (!d)
                return -ENOMEM;

        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                DissectedPartition *p = m->partitions + i;
                PartitionDesignator k;

                if (!p->found)
                        continue;

                r = decrypt_partition(p, passphrase, flags, d);
                if (r < 0)
                        return r;

                k = PARTITION_VERITY_OF(i);
                if (k >= 0) {
                        r = verity_partition(i, p, m->partitions + k, verity, flags | DISSECT_IMAGE_VERITY_SHARE, d);
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
                const VeritySettings *verity,
                DissectImageFlags flags,
                DecryptedImage **ret) {

        _cleanup_strv_free_erase_ char **z = NULL;
        int n = 3, r;

        if (passphrase)
                n--;

        for (;;) {
                r = dissected_image_decrypt(m, passphrase, verity, flags, ret);
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
        assert(d);

        /* Turns on automatic removal after the last use ended for all DM devices of this image, and sets a
         * boolean so that we don't clean it up ourselves either anymore */

#if HAVE_LIBCRYPTSETUP
        int r;

        for (size_t i = 0; i < d->n_decrypted; i++) {
                DecryptedPartition *p = d->decrypted + i;

                if (p->relinquished)
                        continue;

                r = sym_crypt_deactivate_by_name(NULL, p->name, CRYPT_DEACTIVATE_DEFERRED);
                if (r < 0)
                        return log_debug_errno(r, "Failed to mark %s for auto-removal: %m", p->name);

                p->relinquished = true;
        }
#endif

        return 0;
}

static char *build_auxiliary_path(const char *image, const char *suffix) {
        const char *e;
        char *n;

        assert(image);
        assert(suffix);

        e = endswith(image, ".raw");
        if (!e)
                return strjoin(e, suffix);

        n = new(char, e - image + strlen(suffix) + 1);
        if (!n)
                return NULL;

        strcpy(mempcpy(n, image, e - image), suffix);
        return n;
}

void verity_settings_done(VeritySettings *v) {
        assert(v);

        v->root_hash = mfree(v->root_hash);
        v->root_hash_size = 0;

        v->root_hash_sig = mfree(v->root_hash_sig);
        v->root_hash_sig_size = 0;

        v->data_path = mfree(v->data_path);
}

int verity_settings_load(
                VeritySettings *verity,
                const char *image,
                const char *root_hash_path,
                const char *root_hash_sig_path) {

        _cleanup_free_ void *root_hash = NULL, *root_hash_sig = NULL;
        size_t root_hash_size = 0, root_hash_sig_size = 0;
        _cleanup_free_ char *verity_data_path = NULL;
        PartitionDesignator designator;
        int r;

        assert(verity);
        assert(image);
        assert(verity->designator < 0 || IN_SET(verity->designator, PARTITION_ROOT, PARTITION_USR));

        /* If we are asked to load the root hash for a device node, exit early */
        if (is_device_path(image))
                return 0;

        designator = verity->designator;

        /* We only fill in what isn't already filled in */

        if (!verity->root_hash) {
                _cleanup_free_ char *text = NULL;

                if (root_hash_path) {
                        /* If explicitly specified it takes precedence */
                        r = read_one_line_file(root_hash_path, &text);
                        if (r < 0)
                                return r;

                        if (designator < 0)
                                designator = PARTITION_ROOT;
                } else {
                        /* Otherwise look for xattr and separate file, and first for the data for root and if
                         * that doesn't exist for /usr */

                        if (designator < 0 || designator == PARTITION_ROOT) {
                                r = getxattr_malloc(image, "user.verity.roothash", &text, true);
                                if (r < 0) {
                                        _cleanup_free_ char *p = NULL;

                                        if (!IN_SET(r, -ENODATA, -ENOENT) && !ERRNO_IS_NOT_SUPPORTED(r))
                                                return r;

                                        p = build_auxiliary_path(image, ".roothash");
                                        if (!p)
                                                return -ENOMEM;

                                        r = read_one_line_file(p, &text);
                                        if (r < 0 && r != -ENOENT)
                                                return r;
                                }

                                if (text)
                                        designator = PARTITION_ROOT;
                        }

                        if (!text && (designator < 0 || designator == PARTITION_USR)) {
                                /* So in the "roothash" xattr/file name above the "root" of course primarily
                                 * refers to the root of the Verity Merkle tree. But coincidentally it also
                                 * is the hash for the *root* file system, i.e. the "root" neatly refers to
                                 * two distinct concepts called "root". Taking benefit of this happy
                                 * coincidence we call the file with the root hash for the /usr/ file system
                                 * `usrhash`, because `usrroothash` or `rootusrhash` would just be too
                                 * confusing. We thus drop the reference to the root of the Merkle tree, and
                                 * just indicate which file system it's about. */
                                r = getxattr_malloc(image, "user.verity.usrhash", &text, true);
                                if (r < 0) {
                                        _cleanup_free_ char *p = NULL;

                                        if (!IN_SET(r, -ENODATA, -ENOENT) && !ERRNO_IS_NOT_SUPPORTED(r))
                                                return r;

                                        p = build_auxiliary_path(image, ".usrhash");
                                        if (!p)
                                                return -ENOMEM;

                                        r = read_one_line_file(p, &text);
                                        if (r < 0 && r != -ENOENT)
                                                return r;
                                }

                                if (text)
                                        designator = PARTITION_USR;
                        }
                }

                if (text) {
                        r = unhexmem(text, strlen(text), &root_hash, &root_hash_size);
                        if (r < 0)
                                return r;
                        if (root_hash_size < sizeof(sd_id128_t))
                                return -EINVAL;
                }
        }

        if ((root_hash || verity->root_hash) && !verity->root_hash_sig) {
                if (root_hash_sig_path) {
                        r = read_full_file(root_hash_sig_path, (char**) &root_hash_sig, &root_hash_sig_size);
                        if (r < 0 && r != -ENOENT)
                                return r;

                        if (designator < 0)
                                designator = PARTITION_ROOT;
                } else {
                        if (designator < 0 || designator == PARTITION_ROOT) {
                                _cleanup_free_ char *p = NULL;

                                /* Follow naming convention recommended by the relevant RFC:
                                 * https://tools.ietf.org/html/rfc5751#section-3.2.1 */
                                p = build_auxiliary_path(image, ".roothash.p7s");
                                if (!p)
                                        return -ENOMEM;

                                r = read_full_file(p, (char**) &root_hash_sig, &root_hash_sig_size);
                                if (r < 0 && r != -ENOENT)
                                        return r;
                                if (r >= 0)
                                        designator = PARTITION_ROOT;
                        }

                        if (!root_hash_sig && (designator < 0 || designator == PARTITION_USR)) {
                                _cleanup_free_ char *p = NULL;

                                p = build_auxiliary_path(image, ".usrhash.p7s");
                                if (!p)
                                        return -ENOMEM;

                                r = read_full_file(p, (char**) &root_hash_sig, &root_hash_sig_size);
                                if (r < 0 && r != -ENOENT)
                                        return r;
                                if (r >= 0)
                                        designator = PARTITION_USR;
                        }
                }

                if (root_hash_sig && root_hash_sig_size == 0) /* refuse empty size signatures */
                        return -EINVAL;
        }

        if (!verity->data_path) {
                _cleanup_free_ char *p = NULL;

                p = build_auxiliary_path(image, ".verity");
                if (!p)
                        return -ENOMEM;

                if (access(p, F_OK) < 0) {
                        if (errno != ENOENT)
                                return -errno;
                } else
                        verity_data_path = TAKE_PTR(p);
        }

        if (root_hash) {
                verity->root_hash = TAKE_PTR(root_hash);
                verity->root_hash_size = root_hash_size;
        }

        if (root_hash_sig) {
                verity->root_hash_sig = TAKE_PTR(root_hash_sig);
                verity->root_hash_sig_size = root_hash_sig_size;
        }

        if (verity_data_path)
                verity->data_path = TAKE_PTR(verity_data_path);

        if (verity->designator < 0)
                verity->designator = designator;

        return 1;
}

int dissected_image_acquire_metadata(DissectedImage *m) {

        enum {
                META_HOSTNAME,
                META_MACHINE_ID,
                META_MACHINE_INFO,
                META_OS_RELEASE,
                META_EXTENSION_RELEASE,
                _META_MAX,
        };

        static const char *paths[_META_MAX] = {
                [META_HOSTNAME]          = "/etc/hostname\0",
                [META_MACHINE_ID]        = "/etc/machine-id\0",
                [META_MACHINE_INFO]      = "/etc/machine-info\0",
                [META_OS_RELEASE]        = "/etc/os-release\0"
                                           "/usr/lib/os-release\0",
                [META_EXTENSION_RELEASE] = NULL,
        };

        _cleanup_strv_free_ char **machine_info = NULL, **os_release = NULL, **extension_release = NULL;
        _cleanup_close_pair_ int error_pipe[2] = { -1, -1 };
        _cleanup_(rmdir_and_freep) char *t = NULL;
        _cleanup_(sigkill_waitp) pid_t child = 0;
        sd_id128_t machine_id = SD_ID128_NULL;
        _cleanup_free_ char *hostname = NULL;
        unsigned n_meta_initialized = 0;
        int fds[2 * _META_MAX], r, v;
        ssize_t n;

        BLOCK_SIGNALS(SIGCHLD);

        assert(m);

        /* As per the os-release spec, if the image is an extension it will have a file
         * named after the image name in extension-release.d/ */
        if (m->image_name) {
                char *ext;

                ext = strjoina("/usr/lib/extension-release.d/extension-release.", m->image_name, "0");
                ext[strlen(ext) - 1] = '\0'; /* Extra \0 for NULSTR_FOREACH using placeholder from above */
                paths[META_EXTENSION_RELEASE] = ext;
        } else
                log_debug("No image name available, will skip extension-release metadata");

        for (; n_meta_initialized < _META_MAX; n_meta_initialized ++) {
                if (!paths[n_meta_initialized]) {
                        fds[2*n_meta_initialized] = fds[2*n_meta_initialized+1] = -1;
                        continue;
                }

                if (pipe2(fds + 2*n_meta_initialized, O_CLOEXEC) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        r = mkdtemp_malloc("/tmp/dissect-XXXXXX", &t);
        if (r < 0)
                goto finish;

        if (pipe2(error_pipe, O_CLOEXEC) < 0) {
                r = -errno;
                goto finish;
        }

        r = safe_fork("(sd-dissect)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, &child);
        if (r < 0)
                goto finish;
        if (r == 0) {
                error_pipe[0] = safe_close(error_pipe[0]);

                r = dissected_image_mount(m, t, UID_INVALID, DISSECT_IMAGE_READ_ONLY|DISSECT_IMAGE_MOUNT_ROOT_ONLY|DISSECT_IMAGE_VALIDATE_OS);
                if (r < 0) {
                        /* Let parent know the error */
                        (void) write(error_pipe[1], &r, sizeof(r));

                        log_debug_errno(r, "Failed to mount dissected image: %m");
                        _exit(EXIT_FAILURE);
                }

                for (unsigned k = 0; k < _META_MAX; k++) {
                        _cleanup_close_ int fd = -ENOENT;
                        const char *p;

                        if (!paths[k])
                                continue;

                        fds[2*k] = safe_close(fds[2*k]);

                        NULSTR_FOREACH(p, paths[k]) {
                                fd = chase_symlinks_and_open(p, t, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
                                if (fd >= 0)
                                        break;
                        }
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to read %s file of image, ignoring: %m", paths[k]);
                                fds[2*k+1] = safe_close(fds[2*k+1]);
                                continue;
                        }

                        r = copy_bytes(fd, fds[2*k+1], UINT64_MAX, 0);
                        if (r < 0) {
                                (void) write(error_pipe[1], &r, sizeof(r));
                                _exit(EXIT_FAILURE);
                        }

                        fds[2*k+1] = safe_close(fds[2*k+1]);
                }

                _exit(EXIT_SUCCESS);
        }

        error_pipe[1] = safe_close(error_pipe[1]);

        for (unsigned k = 0; k < _META_MAX; k++) {
                _cleanup_fclose_ FILE *f = NULL;

                if (!paths[k])
                        continue;

                fds[2*k+1] = safe_close(fds[2*k+1]);

                f = take_fdopen(&fds[2*k], "r");
                if (!f) {
                        r = -errno;
                        goto finish;
                }

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
                        else if (streq(line, "uninitialized"))
                                log_debug("/etc/machine-id file is uninitialized (likely aborted first boot).");
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

                case META_EXTENSION_RELEASE:
                        r = load_env_file_pairs(f, "extension-release", &extension_release);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read extension release file: %m");

                        break;
                }
        }

        r = wait_for_terminate_and_check("(sd-dissect)", child, 0);
        child = 0;
        if (r < 0)
                return r;

        n = read(error_pipe[0], &v, sizeof(v));
        if (n < 0)
                return -errno;
        if (n == sizeof(v))
                return v; /* propagate error sent to us from child */
        if (n != 0)
                return -EIO;

        if (r != EXIT_SUCCESS)
                return -EPROTO;

        free_and_replace(m->hostname, hostname);
        m->machine_id = machine_id;
        strv_free_and_replace(m->machine_info, machine_info);
        strv_free_and_replace(m->os_release, os_release);
        strv_free_and_replace(m->extension_release, extension_release);

finish:
        for (unsigned k = 0; k < n_meta_initialized; k++)
                safe_close_pair(fds + 2*k);

        return r;
}

int dissect_image_and_warn(
                int fd,
                const char *name,
                const VeritySettings *verity,
                const MountOptions *mount_options,
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

        r = dissect_image(fd, verity, mount_options, flags, ret);
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

bool dissected_image_can_do_verity(const DissectedImage *image, PartitionDesignator partition_designator) {
        if (image->single_file_system)
                return partition_designator == PARTITION_ROOT && image->can_verity;

        return PARTITION_VERITY_OF(partition_designator) >= 0;
}

bool dissected_image_has_verity(const DissectedImage *image, PartitionDesignator partition_designator) {
        int k;

        if (image->single_file_system)
                return partition_designator == PARTITION_ROOT && image->verity;

        k = PARTITION_VERITY_OF(partition_designator);
        return k >= 0 && image->partitions[k].found;
}

MountOptions* mount_options_free_all(MountOptions *options) {
        MountOptions *m;

        while ((m = options)) {
                LIST_REMOVE(mount_options, options, m);
                free(m->options);
                free(m);
        }

        return NULL;
}

const char* mount_options_from_designator(const MountOptions *options, PartitionDesignator designator) {
        const MountOptions *m;

        LIST_FOREACH(mount_options, m, options)
                if (designator == m->partition_designator && !isempty(m->options))
                        return m->options;

        return NULL;
}

int mount_image_privately_interactively(
                const char *image,
                DissectImageFlags flags,
                char **ret_directory,
                LoopDevice **ret_loop_device,
                DecryptedImage **ret_decrypted_image) {

        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_(rmdir_and_freep) char *created_dir = NULL;
        _cleanup_free_ char *temp = NULL;
        int r;

        /* Mounts an OS image at a temporary place, inside a newly created mount namespace of our own. This
         * is used by tools such as systemd-tmpfiles or systemd-firstboot to operate on some disk image
         * easily. */

        assert(image);
        assert(ret_directory);
        assert(ret_loop_device);
        assert(ret_decrypted_image);

        r = tempfn_random_child(NULL, program_invocation_short_name, &temp);
        if (r < 0)
                return log_error_errno(r, "Failed to generate temporary mount directory: %m");

        r = loop_device_make_by_path(
                        image,
                        FLAGS_SET(flags, DISSECT_IMAGE_READ_ONLY) ? O_RDONLY : O_RDWR,
                        FLAGS_SET(flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                        &d);
        if (r < 0)
                return log_error_errno(r, "Failed to set up loopback device: %m");

        r = dissect_image_and_warn(d->fd, image, NULL, NULL, flags, &dissected_image);
        if (r < 0)
                return r;

        r = dissected_image_decrypt_interactively(dissected_image, NULL, NULL, flags, &decrypted_image);
        if (r < 0)
                return r;

        r = detach_mount_namespace();
        if (r < 0)
                return log_error_errno(r, "Failed to detach mount namespace: %m");

        r = mkdir_p(temp, 0700);
        if (r < 0)
                return log_error_errno(r, "Failed to create mount point: %m");

        created_dir = TAKE_PTR(temp);

        r = dissected_image_mount_and_warn(dissected_image, created_dir, UID_INVALID, flags);
        if (r < 0)
                return r;

        if (decrypted_image) {
                r = decrypted_image_relinquish(decrypted_image);
                if (r < 0)
                        return log_error_errno(r, "Failed to relinquish DM devices: %m");
        }

        loop_device_relinquish(d);

        *ret_directory = TAKE_PTR(created_dir);
        *ret_loop_device = TAKE_PTR(d);
        *ret_decrypted_image = TAKE_PTR(decrypted_image);

        return 0;
}

static const char *const partition_designator_table[] = {
        [PARTITION_ROOT] = "root",
        [PARTITION_ROOT_SECONDARY] = "root-secondary",
        [PARTITION_USR] = "usr",
        [PARTITION_USR_SECONDARY] = "usr-secondary",
        [PARTITION_HOME] = "home",
        [PARTITION_SRV] = "srv",
        [PARTITION_ESP] = "esp",
        [PARTITION_XBOOTLDR] = "xbootldr",
        [PARTITION_SWAP] = "swap",
        [PARTITION_ROOT_VERITY] = "root-verity",
        [PARTITION_ROOT_SECONDARY_VERITY] = "root-secondary-verity",
        [PARTITION_USR_VERITY] = "usr-verity",
        [PARTITION_USR_SECONDARY_VERITY] = "usr-secondary-verity",
        [PARTITION_TMP] = "tmp",
        [PARTITION_VAR] = "var",
};

int verity_dissect_and_mount(
                const char *src,
                const char *dest,
                const MountOptions *options,
                const char *required_host_os_release_id,
                const char *required_host_os_release_version_id,
                const char *required_host_os_release_sysext_level) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        DissectImageFlags dissect_image_flags;
        int r;

        assert(src);
        assert(dest);

        r = verity_settings_load(&verity, src, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load root hash: %m");

        dissect_image_flags = verity.data_path ? DISSECT_IMAGE_NO_PARTITION_TABLE : 0;

        r = loop_device_make_by_path(
                        src,
                        -1,
                        verity.data_path ? 0 : LO_FLAGS_PARTSCAN,
                        &loop_device);
        if (r < 0)
                return log_debug_errno(r, "Failed to create loop device for image: %m");

        r = dissect_image(
                        loop_device->fd,
                        &verity,
                        options,
                        dissect_image_flags,
                        &dissected_image);
        /* No partition table? Might be a single-filesystem image, try again */
        if (!verity.data_path && r == -ENOPKG)
                 r = dissect_image(
                                loop_device->fd,
                                &verity,
                                options,
                                dissect_image_flags|DISSECT_IMAGE_NO_PARTITION_TABLE,
                                &dissected_image);
        if (r < 0)
                return log_debug_errno(r, "Failed to dissect image: %m");

        r = dissected_image_decrypt(
                        dissected_image,
                        NULL,
                        &verity,
                        dissect_image_flags,
                        &decrypted_image);
        if (r < 0)
                return log_debug_errno(r, "Failed to decrypt dissected image: %m");

        r = mkdir_p_label(dest, 0755);
        if (r < 0)
                return log_debug_errno(r, "Failed to create destination directory %s: %m", dest);
        r = umount_recursive(dest, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to umount under destination directory %s: %m", dest);

        r = dissected_image_mount(dissected_image, dest, UID_INVALID, dissect_image_flags);
        if (r < 0)
                return log_debug_errno(r, "Failed to mount image: %m");

        /* If we got os-release values from the caller, then we need to match them with the image's
         * extension-release.d/ content. Return -EINVAL if there's any mismatch.
         * First, check the distro ID. If that matches, then check the new SYSEXT_LEVEL value if
         * available, or else fallback to VERSION_ID. */
        if (required_host_os_release_id &&
            (required_host_os_release_version_id || required_host_os_release_sysext_level)) {
                _cleanup_strv_free_ char **extension_release = NULL;

                r = load_extension_release_pairs(dest, dissected_image->image_name, &extension_release);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse image %s extension-release metadata: %m", dissected_image->image_name);

                r = extension_release_validate(
                        dissected_image->image_name,
                        required_host_os_release_id,
                        required_host_os_release_version_id,
                        required_host_os_release_sysext_level,
                        extension_release);
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Image %s extension-release metadata does not match the root's", dissected_image->image_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to compare image %s extension-release metadata with the root's os-release: %m", dissected_image->image_name);
        }

        if (decrypted_image) {
                r = decrypted_image_relinquish(decrypted_image);
                if (r < 0)
                        return log_debug_errno(r, "Failed to relinquish decrypted image: %m");
        }

        loop_device_relinquish(loop_device);

        return 0;
}

DEFINE_STRING_TABLE_LOOKUP(partition_designator, PartitionDesignator);
