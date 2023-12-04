/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <linux/dm-ioctl.h>
#include <linux/loop.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sysexits.h>

#if HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

#include "sd-device.h"
#include "sd-id128.h"

#include "architecture.h"
#include "ask-password-api.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "chase.h"
#include "conf-files.h"
#include "constants.h"
#include "copy.h"
#include "cryptsetup-util.h"
#include "device-nodes.h"
#include "device-util.h"
#include "devnum-util.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "dm-util.h"
#include "env-file.h"
#include "env-util.h"
#include "extension-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fsck-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "id128-util.h"
#include "import-util.h"
#include "io-util.h"
#include "missing_mount.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "nulstr-util.h"
#include "openssl-util.h"
#include "os-util.h"
#include "path-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "resize-fs.h"
#include "signal-util.h"
#include "sparse-endian.h"
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

int dissect_fstype_ok(const char *fstype) {
        const char *e;
        bool b;

        /* When we automatically mount file systems, be a bit conservative by default what we are willing to
         * mount, just as an extra safety net to not mount with badly maintained legacy file system
         * drivers. */

        e = secure_getenv("SYSTEMD_DISSECT_FILE_SYSTEMS");
        if (e) {
                _cleanup_strv_free_ char **l = NULL;

                l = strv_split(e, ":");
                if (!l)
                        return -ENOMEM;

                b = strv_contains(l, fstype);
        } else
                b = STR_IN_SET(fstype,
                               "btrfs",
                               "erofs",
                               "ext4",
                               "f2fs",
                               "squashfs",
                               "vfat",
                               "xfs");
        if (b)
                return true;

        log_debug("File system type '%s' is not allowed to be mounted as result of automatic dissection.", fstype);
        return false;
}

int probe_sector_size(int fd, uint32_t *ret) {

        /* Disk images might be for 512B or for 4096 sector sizes, let's try to auto-detect that by searching
         * for the GPT headers at the relevant byte offsets */

        assert_cc(sizeof(GptHeader) == 92);

        /* We expect a sector size in the range 512…4096. The GPT header is located in the second
         * sector. Hence it could be at byte 512 at the earliest, and at byte 4096 at the latest. And we must
         * read with granularity of the largest sector size we care about. Which means 8K. */
        uint8_t sectors[2 * 4096];
        uint32_t found = 0;
        ssize_t n;

        assert(fd >= 0);
        assert(ret);

        n = pread(fd, sectors, sizeof(sectors), 0);
        if (n < 0)
                return -errno;
        if (n != sizeof(sectors)) /* too short? */
                goto not_found;

        /* Let's see if we find the GPT partition header with various expected sector sizes */
        for (uint32_t sz = 512; sz <= 4096; sz <<= 1) {
                const GptHeader *p;

                assert(sizeof(sectors) >= sz * 2);
                p = (const GptHeader*) (sectors + sz);

                if (!gpt_header_has_signature(p))
                        continue;

                if (found != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                               "Detected valid partition table at offsets matching multiple sector sizes, refusing.");

                found = sz;
        }

        if (found != 0) {
                log_debug("Determined sector size %" PRIu32 " based on discovered partition table.", found);
                *ret = found;
                return 1; /* indicate we *did* find it */
        }

not_found:
        log_debug("Couldn't find any partition table to derive sector size of.");
        *ret = 512; /* pick the traditional default */
        return 0;   /* indicate we didn't find it */
}

int probe_sector_size_prefer_ioctl(int fd, uint32_t *ret) {
        struct stat st;

        assert(fd >= 0);
        assert(ret);

        /* Just like probe_sector_size(), but if we are looking at a block device, will use the already
         * configured sector size rather than probing by contents */

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISBLK(st.st_mode))
                return blockdev_get_sector_size(fd, ret);

        return probe_sector_size(fd, ret);
}

int probe_filesystem_full(
                int fd,
                const char *path,
                uint64_t offset,
                uint64_t size,
                char **ret_fstype) {

        /* Try to find device content type and return it in *ret_fstype. If nothing is found,
         * 0/NULL will be returned. -EUCLEAN will be returned for ambiguous results, and a
         * different error otherwise. */

#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *path_by_fd = NULL;
        _cleanup_close_ int fd_close = -EBADF;
        const char *fstype;
        int r;

        assert(fd >= 0 || path);
        assert(ret_fstype);

        if (fd < 0) {
                fd_close = open(path, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                if (fd_close < 0)
                        return -errno;

                fd = fd_close;
        }

        if (!path) {
                r = fd_get_path(fd, &path_by_fd);
                if (r < 0)
                        return r;

                path = path_by_fd;
        }

        if (size == 0) /* empty size? nothing found! */
                goto not_found;

        b = blkid_new_probe();
        if (!b)
                return -ENOMEM;

        /* The Linux kernel maintains separate block device caches for main ("whole") and partition block
         * devices, which means making a change to one might not be reflected immediately when reading via
         * the other. That's massively confusing when mixing accesses to such devices. Let's address this in
         * a limited way: when probing a file system that is not at the beginning of the block device we
         * apparently probe a partition via the main block device, and in that case let's first flush the
         * main block device cache, so that we get the data that the per-partition block device last
         * sync'ed on.
         *
         * This only works under the assumption that any tools that write to the partition block devices
         * issue an syncfs()/fsync() on the device after making changes. Typically file system formatting
         * tools that write a superblock onto a partition block device do that, however. */
        if (offset != 0)
                if (ioctl(fd, BLKFLSBUF, 0) < 0)
                        log_debug_errno(errno, "Failed to flush block device cache, ignoring: %m");

        errno = 0;
        r = blkid_probe_set_device(
                        b,
                        fd,
                        offset,
                        size == UINT64_MAX ? 0 : size); /* when blkid sees size=0 it understands "everything". We prefer using UINT64_MAX for that */
        if (r != 0)
                return errno_or_else(ENOMEM);

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_NOT_FOUND)
                goto not_found;
        if (r == _BLKID_SAFEPROBE_AMBIGUOUS)
                return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Results ambiguous for partition %s", path);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_debug_errno(errno_or_else(EIO), "Failed to probe partition %s: %m", path);

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);

        if (fstype) {
                char *t;

                log_debug("Probed fstype '%s' on partition %s.", fstype, path);

                t = strdup(fstype);
                if (!t)
                        return -ENOMEM;

                *ret_fstype = t;
                return 1;
        }

not_found:
        log_debug("No type detected on partition %s", path);
        *ret_fstype = NULL;
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

#if HAVE_BLKID
static int image_policy_may_use(
                const ImagePolicy *policy,
                PartitionDesignator designator) {

        PartitionPolicyFlags f;

        /* For each partition we find in the partition table do a first check if it may exist at all given
         * the policy, or if it shall be ignored. */

        f = image_policy_get_exhaustively(policy, designator);
        if (f < 0)
                return f;

        if ((f & _PARTITION_POLICY_USE_MASK) == PARTITION_POLICY_ABSENT)
                /* only flag set in policy is "absent"? then this partition may not exist at all */
                return log_debug_errno(
                                SYNTHETIC_ERRNO(ERFKILL),
                                "Partition of designator '%s' exists, but not allowed by policy, refusing.",
                                partition_designator_to_string(designator));
        if ((f & _PARTITION_POLICY_USE_MASK & ~PARTITION_POLICY_ABSENT) == PARTITION_POLICY_UNUSED) {
                /* only "unused" or "unused" + "absent" are set? then don't use it */
                log_debug("Partition of designator '%s' exists, and policy dictates to ignore it, doing so.",
                          partition_designator_to_string(designator));
                return false; /* ignore! */
        }

        return true; /* use! */
}

static int image_policy_check_protection(
                const ImagePolicy *policy,
                PartitionDesignator designator,
                PartitionPolicyFlags found_flags) {

        PartitionPolicyFlags policy_flags;

        /* Checks if the flags in the policy for the designated partition overlap the flags of what we found */

        if (found_flags < 0)
                return found_flags;

        policy_flags = image_policy_get_exhaustively(policy, designator);
        if (policy_flags < 0)
                return policy_flags;

        if ((found_flags & policy_flags) == 0) {
                _cleanup_free_ char *found_flags_string = NULL, *policy_flags_string = NULL;

                (void) partition_policy_flags_to_string(found_flags, /* simplify= */ true, &found_flags_string);
                (void) partition_policy_flags_to_string(policy_flags, /* simplify= */ true, &policy_flags_string);

                return log_debug_errno(SYNTHETIC_ERRNO(ERFKILL), "Partition %s discovered with policy '%s' but '%s' was required, refusing.",
                                       partition_designator_to_string(designator),
                                       strnull(found_flags_string), strnull(policy_flags_string));
        }

        return 0;
}

static int image_policy_check_partition_flags(
                const ImagePolicy *policy,
                PartitionDesignator designator,
                uint64_t gpt_flags) {

        PartitionPolicyFlags policy_flags;
        bool b;

        /* Checks if the partition flags in the policy match reality */

        policy_flags = image_policy_get_exhaustively(policy, designator);
        if (policy_flags < 0)
                return policy_flags;

        b = FLAGS_SET(gpt_flags, SD_GPT_FLAG_READ_ONLY);
        if ((policy_flags & _PARTITION_POLICY_READ_ONLY_MASK) == (b ? PARTITION_POLICY_READ_ONLY_OFF : PARTITION_POLICY_READ_ONLY_ON))
                return log_debug_errno(SYNTHETIC_ERRNO(ERFKILL), "Partition %s has 'read-only' flag incorrectly set (must be %s, is %s), refusing.",
                                       partition_designator_to_string(designator),
                                       one_zero(!b), one_zero(b));

        b = FLAGS_SET(gpt_flags, SD_GPT_FLAG_GROWFS);
        if ((policy_flags & _PARTITION_POLICY_GROWFS_MASK) == (b ? PARTITION_POLICY_GROWFS_OFF : PARTITION_POLICY_GROWFS_ON))
                return log_debug_errno(SYNTHETIC_ERRNO(ERFKILL), "Partition %s has 'growfs' flag incorrectly set (must be %s, is %s), refusing.",
                                       partition_designator_to_string(designator),
                                       one_zero(!b), one_zero(b));

        return 0;
}

static int dissected_image_probe_filesystems(
                DissectedImage *m,
                int fd,
                const ImagePolicy *policy) {

        int r;

        assert(m);

        /* Fill in file system types if we don't know them yet. */

        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                DissectedPartition *p = m->partitions + i;
                PartitionPolicyFlags found_flags;

                if (!p->found)
                        continue;

                if (!p->fstype) {
                        /* If we have an fd referring to the partition block device, use that. Otherwise go
                         * via the whole block device or backing regular file, and read via offset. */
                        if (p->mount_node_fd >= 0)
                                r = probe_filesystem_full(p->mount_node_fd, p->node, 0, UINT64_MAX, &p->fstype);
                        else
                                r = probe_filesystem_full(fd, p->node, p->offset, p->size, &p->fstype);
                        if (r < 0)
                                return r;
                }

                if (streq_ptr(p->fstype, "crypto_LUKS")) {
                        m->encrypted = true;
                        found_flags = PARTITION_POLICY_ENCRYPTED; /* found this one, and its definitely encrypted */
                } else
                        /* found it, but it's definitely not encrypted, hence mask the encrypted flag, but
                         * set all other ways that indicate "present". */
                        found_flags = PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED;

                if (p->fstype && fstype_is_ro(p->fstype))
                        p->rw = false;

                if (!p->rw)
                        p->growfs = false;

                /* We might have learnt more about the file system now (i.e. whether it is encrypted or not),
                 * hence we need to validate this against policy again, to see if the policy still matches
                 * with this new information. Note that image_policy_check_protection() will check for
                 * overlap between what's allowed in the policy and what we pass as 'found_policy' here. In
                 * the unencrypted case we thus might pass an overly unspecific mask here (i.e. unprotected
                 * OR verity OR signed), but that's fine since the earlier policy check already checked more
                 * specific which of those three cases where OK. Keep in mind that this function here only
                 * looks at specific partitions (and thus can only deduce encryption or not) but not the
                 * overall partition table (and thus cannot deduce verity or not). The earlier dissection
                 * checks already did the relevant checks that look at the whole partition table, and
                 * enforced policy there as needed. */
                r = image_policy_check_protection(policy, i, found_flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void check_partition_flags(
                const char *node,
                unsigned long long pflags,
                unsigned long long supported) {

        assert(node);

        /* Mask away all flags supported by this partition's type and the three flags the UEFI spec defines generically */
        pflags &= ~(supported |
                    SD_GPT_FLAG_REQUIRED_PARTITION |
                    SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL |
                    SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE);

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

static int dissected_image_new(const char *path, DissectedImage **ret) {
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_free_ char *name = NULL;
        int r;

        assert(ret);

        if (path) {
                _cleanup_free_ char *filename = NULL;

                r = path_extract_filename(path, &filename);
                if (r < 0)
                        return r;

                r = raw_strip_suffixes(filename, &name);
                if (r < 0)
                        return r;

                if (!image_name_is_valid(name)) {
                        log_debug("Image name %s is not valid, ignoring.", strna(name));
                        name = mfree(name);
                }
        }

        m = new(DissectedImage, 1);
        if (!m)
                return -ENOMEM;

        *m = (DissectedImage) {
                .has_init_system = -1,
                .image_name = TAKE_PTR(name),
        };

        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++)
                m->partitions[i] = DISSECTED_PARTITION_NULL;

        *ret = TAKE_PTR(m);
        return 0;
}
#endif

static void dissected_partition_done(DissectedPartition *p) {
        assert(p);

        free(p->fstype);
        free(p->node);
        free(p->label);
        free(p->decrypted_fstype);
        free(p->decrypted_node);
        free(p->mount_options);
        safe_close(p->mount_node_fd);
        safe_close(p->fsmount_fd);

        *p = DISSECTED_PARTITION_NULL;
}

#if HAVE_BLKID
static int make_partition_devname(
                const char *whole_devname,
                uint64_t diskseq,
                int nr,
                DissectImageFlags flags,
                char **ret) {

        _cleanup_free_ char *s = NULL;
        int r;

        assert(whole_devname);
        assert(nr != 0); /* zero is not a valid partition nr */
        assert(ret);

        if (!FLAGS_SET(flags, DISSECT_IMAGE_DISKSEQ_DEVNODE) || diskseq == 0) {

                /* Given a whole block device node name (e.g. /dev/sda or /dev/loop7) generate a partition
                 * device name (e.g. /dev/sda7 or /dev/loop7p5). The rule the kernel uses is simple: if whole
                 * block device node name ends in a digit, then suffix a 'p', followed by the partition
                 * number. Otherwise, just suffix the partition number without any 'p'. */

                if (nr < 0) { /* whole disk? */
                        s = strdup(whole_devname);
                        if (!s)
                                return -ENOMEM;
                } else {
                        size_t l = strlen(whole_devname);
                        if (l < 1) /* underflow check for the subtraction below */
                                return -EINVAL;

                        bool need_p = ascii_isdigit(whole_devname[l-1]); /* Last char a digit? */

                        if (asprintf(&s, "%s%s%i", whole_devname, need_p ? "p" : "", nr) < 0)
                                return -ENOMEM;
                }
        } else {
                if (nr < 0) /* whole disk? */
                        r = asprintf(&s, "/dev/disk/by-diskseq/%" PRIu64, diskseq);
                else
                        r = asprintf(&s, "/dev/disk/by-diskseq/%" PRIu64 "-part%i", diskseq, nr);
                if (r < 0)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

static int open_partition(
                const char *node,
                bool is_partition,
                const LoopDevice *loop) {

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_close_ int fd = -EBADF;
        dev_t devnum;
        int r;

        assert(node);
        assert(loop);

        fd = open(node, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        /* Check if the block device is a child of (or equivalent to) the originally provided one. */
        r = block_device_new_from_fd(fd, is_partition ? BLOCK_DEVICE_LOOKUP_WHOLE_DISK : 0, &dev);
        if (r < 0)
                return r;

        r = sd_device_get_devnum(dev, &devnum);
        if (r < 0)
                return r;

        if (loop->devno != devnum)
                return -ENXIO;

        /* Also check diskseq. */
        if (loop->diskseq != 0) {
                uint64_t diskseq;

                r = fd_get_diskseq(fd, &diskseq);
                if (r < 0)
                        return r;

                if (loop->diskseq != diskseq)
                        return -ENXIO;
        }

        log_debug("Opened %s (fd=%i, whole_block_devnum=" DEVNUM_FORMAT_STR ", diskseq=%" PRIu64 ").",
                  node, fd, DEVNUM_FORMAT_VAL(loop->devno), loop->diskseq);
        return TAKE_FD(fd);
}

static int compare_arch(Architecture a, Architecture b) {
        if (a == b)
                return 0;

        if (a == native_architecture())
                return 1;

        if (b == native_architecture())
                return -1;

#ifdef ARCHITECTURE_SECONDARY
        if (a == ARCHITECTURE_SECONDARY)
                return 1;

        if (b == ARCHITECTURE_SECONDARY)
                return -1;
#endif

        return 0;
}

static int dissect_image(
                DissectedImage *m,
                int fd,
                const char *devname,
                const VeritySettings *verity,
                const MountOptions *mount_options,
                const ImagePolicy *policy,
                DissectImageFlags flags) {

        sd_id128_t root_uuid = SD_ID128_NULL, root_verity_uuid = SD_ID128_NULL;
        sd_id128_t usr_uuid = SD_ID128_NULL, usr_verity_uuid = SD_ID128_NULL;
        bool is_gpt, is_mbr, multiple_generic = false,
                generic_rw = false,  /* initialize to appease gcc */
                generic_growfs = false;
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *generic_node = NULL;
        sd_id128_t generic_uuid = SD_ID128_NULL;
        const char *pttype = NULL, *sptuuid = NULL;
        blkid_partlist pl;
        int r, generic_nr = -1, n_partitions;

        assert(m);
        assert(fd >= 0);
        assert(devname);
        assert(!verity || verity->designator < 0 || IN_SET(verity->designator, PARTITION_ROOT, PARTITION_USR));
        assert(!verity || verity->root_hash || verity->root_hash_size == 0);
        assert(!verity || verity->root_hash_sig || verity->root_hash_sig_size == 0);
        assert(!verity || (verity->root_hash || !verity->root_hash_sig));
        assert(!((flags & DISSECT_IMAGE_GPT_ONLY) && (flags & DISSECT_IMAGE_NO_PARTITION_TABLE)));
        assert(m->sector_size > 0);

        /* Probes a disk image, and returns information about what it found in *ret.
         *
         * Returns -ENOPKG if no suitable partition table or file system could be found.
         * Returns -EADDRNOTAVAIL if a root hash was specified but no matching root/verity partitions found.
         * Returns -ENXIO if we couldn't find any partition suitable as root or /usr partition
         * Returns -ENOTUNIQ if we only found multiple generic partitions and thus don't know what to do with that
         * Returns -ERFKILL if image doesn't match image policy
         * Returns -EBADR if verity data was provided externally for an image that has a GPT partition table (i.e. is not just a naked fs)
         * Returns -EPROTONOSUPPORT if DISSECT_IMAGE_ADD_PARTITION_DEVICES is set but the block device does not have partition logic enabled
         * Returns -ENOMSG if we didn't find a single usable partition (and DISSECT_IMAGE_REFUSE_EMPTY is set) */

        uint64_t diskseq = m->loop ? m->loop->diskseq : 0;

        if (verity && verity->root_hash) {
                sd_id128_t fsuuid, vuuid;

                /* If a root hash is supplied, then we use the root partition that has a UUID that match the
                 * first 128-bit of the root hash. And we use the verity partition that has a UUID that match
                 * the final 128-bit. */

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
                if (verity->designator == PARTITION_USR) {
                        usr_uuid = fsuuid;
                        usr_verity_uuid = vuuid;
                } else {
                        root_uuid = fsuuid;
                        root_verity_uuid = vuuid;
                }
        }

        b = blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0)
                return errno_or_else(ENOMEM);

        errno = 0;
        r = blkid_probe_set_sectorsize(b, m->sector_size);
        if (r != 0)
                return errno_or_else(EIO);

        if ((flags & DISSECT_IMAGE_GPT_ONLY) == 0) {
                /* Look for file system superblocks, unless we only shall look for GPT partition tables */
                blkid_probe_enable_superblocks(b, 1);
                blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_USAGE|BLKID_SUBLKS_UUID);
        }

        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return errno_or_else(EIO);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOPKG), "Failed to identify any partition table.");

        assert(r == _BLKID_SAFEPROBE_FOUND);

        if ((!(flags & DISSECT_IMAGE_GPT_ONLY) &&
            (flags & DISSECT_IMAGE_GENERIC_ROOT)) ||
            (flags & DISSECT_IMAGE_NO_PARTITION_TABLE)) {
                const char *usage = NULL;

                /* If flags permit this, also allow using non-partitioned single-filesystem images */

                (void) blkid_probe_lookup_value(b, "USAGE", &usage, NULL);
                if (STRPTR_IN_SET(usage, "filesystem", "crypto")) {
                        _cleanup_free_ char *t = NULL, *n = NULL, *o = NULL;
                        const char *fstype = NULL, *options = NULL, *suuid = NULL;
                        _cleanup_close_ int mount_node_fd = -EBADF;
                        sd_id128_t uuid = SD_ID128_NULL;
                        PartitionPolicyFlags found_flags;
                        bool encrypted;

                        /* OK, we have found a file system, that's our root partition then. */

                        r = image_policy_may_use(policy, PARTITION_ROOT);
                        if (r < 0)
                                return r;
                        if (r == 0) /* policy says ignore this, so we ignore it */
                                return -ENOPKG;

                        (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);
                        (void) blkid_probe_lookup_value(b, "UUID", &suuid, NULL);

                        encrypted = streq_ptr(fstype, "crypto_LUKS");

                        if (verity_settings_data_covers(verity, PARTITION_ROOT))
                                found_flags = verity->root_hash_sig ? PARTITION_POLICY_SIGNED : PARTITION_POLICY_VERITY;
                        else
                                found_flags = encrypted ? PARTITION_POLICY_ENCRYPTED : PARTITION_POLICY_UNPROTECTED;

                        r = image_policy_check_protection(policy, PARTITION_ROOT, found_flags);
                        if (r < 0)
                                return r;

                        r = image_policy_check_partition_flags(policy, PARTITION_ROOT, 0); /* we have no gpt partition flags, hence check against all bits off */
                        if (r < 0)
                                return r;

                        if (FLAGS_SET(flags, DISSECT_IMAGE_PIN_PARTITION_DEVICES)) {
                                mount_node_fd = open_partition(devname, /* is_partition = */ false, m->loop);
                                if (mount_node_fd < 0)
                                        return mount_node_fd;
                        }

                        if (fstype) {
                                t = strdup(fstype);
                                if (!t)
                                        return -ENOMEM;
                        }

                        if (suuid) {
                                /* blkid will return FAT's serial number as UUID, hence it is quite possible
                                 * that parsing this will fail. We'll ignore the ID, since it's just too
                                 * short to be useful as tru identifier. */
                                r = sd_id128_from_string(suuid, &uuid);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to parse file system UUID '%s', ignoring: %m", suuid);
                        }

                        r = make_partition_devname(devname, diskseq, -1, flags, &n);
                        if (r < 0)
                                return r;

                        m->single_file_system = true;
                        m->encrypted = encrypted;

                        m->has_verity = verity && verity->data_path;
                        m->verity_ready = verity_settings_data_covers(verity, PARTITION_ROOT);

                        m->has_verity_sig = false; /* signature not embedded, must be specified */
                        m->verity_sig_ready = m->verity_ready && verity->root_hash_sig;

                        m->image_uuid = uuid;

                        options = mount_options_from_designator(mount_options, PARTITION_ROOT);
                        if (options) {
                                o = strdup(options);
                                if (!o)
                                        return -ENOMEM;
                        }

                        m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                .found = true,
                                .rw = !m->verity_ready && !fstype_is_ro(fstype),
                                .partno = -1,
                                .architecture = _ARCHITECTURE_INVALID,
                                .fstype = TAKE_PTR(t),
                                .node = TAKE_PTR(n),
                                .mount_options = TAKE_PTR(o),
                                .mount_node_fd = TAKE_FD(mount_node_fd),
                                .offset = 0,
                                .size = UINT64_MAX,
                                .fsmount_fd = -EBADF,
                        };

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

        /* We support external verity data partitions only if the image has no partition table */
        if (verity && verity->data_path)
                return -EBADR;

        if (FLAGS_SET(flags, DISSECT_IMAGE_ADD_PARTITION_DEVICES)) {
                /* Safety check: refuse block devices that carry a partition table but for which the kernel doesn't
                 * do partition scanning. */
                r = blockdev_partscan_enabled(fd);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EPROTONOSUPPORT;
        }

        (void) blkid_probe_lookup_value(b, "PTUUID", &sptuuid, NULL);
        if (sptuuid) {
                r = sd_id128_from_string(sptuuid, &m->image_uuid);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse partition table UUID '%s', ignoring: %m", sptuuid);
        }

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return errno_or_else(ENOMEM);

        errno = 0;
        n_partitions = blkid_partlist_numof_partitions(pl);
        if (n_partitions < 0)
                return errno_or_else(EIO);

        for (int i = 0; i < n_partitions; i++) {
                _cleanup_free_ char *node = NULL;
                unsigned long long pflags;
                blkid_loff_t start, size;
                blkid_partition pp;
                int nr;

                errno = 0;
                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return errno_or_else(EIO);

                pflags = blkid_partition_get_flags(pp);

                errno = 0;
                nr = blkid_partition_get_partno(pp);
                if (nr < 0)
                        return errno_or_else(EIO);

                errno = 0;
                start = blkid_partition_get_start(pp);
                if (start < 0)
                        return errno_or_else(EIO);

                assert((uint64_t) start < UINT64_MAX/512);

                errno = 0;
                size = blkid_partition_get_size(pp);
                if (size < 0)
                        return errno_or_else(EIO);

                assert((uint64_t) size < UINT64_MAX/512);

                /* While probing we need the non-diskseq device node name to access the thing, hence mask off
                 * DISSECT_IMAGE_DISKSEQ_DEVNODE. */
                r = make_partition_devname(devname, diskseq, nr, flags & ~DISSECT_IMAGE_DISKSEQ_DEVNODE, &node);
                if (r < 0)
                        return r;

                /* So here's the thing: after the main ("whole") block device popped up it might take a while
                 * before the kernel fully probed the partition table. Waiting for that to finish is icky in
                 * userspace. So here's what we do instead. We issue the BLKPG_ADD_PARTITION ioctl to add the
                 * partition ourselves, racing against the kernel. Good thing is: if this call fails with
                 * EBUSY then the kernel was quicker than us, and that's totally OK, the outcome is good for
                 * us: the device node will exist. If OTOH our call was successful we won the race. Which is
                 * also good as the outcome is the same: the partition block device exists, and we can use
                 * it.
                 *
                 * Kernel returns EBUSY if there's already a partition by that number or an overlapping
                 * partition already existent. */

                if (FLAGS_SET(flags, DISSECT_IMAGE_ADD_PARTITION_DEVICES)) {
                        r = block_device_add_partition(fd, node, nr, (uint64_t) start * 512, (uint64_t) size * 512);
                        if (r < 0) {
                                if (r != -EBUSY)
                                        return log_debug_errno(r, "BLKPG_ADD_PARTITION failed: %m");

                                log_debug_errno(r, "Kernel was quicker than us in adding partition %i.", nr);
                        } else
                                log_debug("We were quicker than kernel in adding partition %i.", nr);
                }

                if (is_gpt) {
                        const char *fstype = NULL, *label;
                        sd_id128_t type_id, id;
                        GptPartitionType type;
                        bool rw = true, growfs = false;

                        r = blkid_partition_get_uuid_id128(pp, &id);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to read partition UUID, ignoring: %m");
                                continue;
                        }

                        r = blkid_partition_get_type_id128(pp, &type_id);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to read partition type UUID, ignoring: %m");
                                continue;
                        }

                        type = gpt_partition_type_from_uuid(type_id);

                        label = blkid_partition_get_name(pp); /* libblkid returns NULL here if empty */

                        if (IN_SET(type.designator,
                                   PARTITION_HOME,
                                   PARTITION_SRV,
                                   PARTITION_XBOOTLDR,
                                   PARTITION_TMP)) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY | SD_GPT_FLAG_GROWFS);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                rw = !(pflags & SD_GPT_FLAG_READ_ONLY);
                                growfs = FLAGS_SET(pflags, SD_GPT_FLAG_GROWFS);

                        } else if (type.designator == PARTITION_ESP) {

                                /* Note that we don't check the SD_GPT_FLAG_NO_AUTO flag for the ESP, as it is
                                 * not defined there. We instead check the SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL, as
                                 * recommended by the UEFI spec (See "12.3.3 Number and Location of System
                                 * Partitions"). */

                                if (pflags & SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL)
                                        continue;

                                fstype = "vfat";

                        } else if (type.designator == PARTITION_ROOT) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY | SD_GPT_FLAG_GROWFS);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a root ID is specified, ignore everything but the root id */
                                if (!sd_id128_is_null(root_uuid) && !sd_id128_equal(root_uuid, id))
                                        continue;

                                rw = !(pflags & SD_GPT_FLAG_READ_ONLY);
                                growfs = FLAGS_SET(pflags, SD_GPT_FLAG_GROWFS);

                        } else if (type.designator == PARTITION_ROOT_VERITY) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                m->has_verity = true;

                                /* If no verity configuration is specified, then don't do verity */
                                if (!verity)
                                        continue;
                                if (verity->designator >= 0 && verity->designator != PARTITION_ROOT)
                                        continue;

                                /* If root hash is specified, then ignore everything but the root id */
                                if (!sd_id128_is_null(root_verity_uuid) && !sd_id128_equal(root_verity_uuid, id))
                                        continue;

                                fstype = "DM_verity_hash";
                                rw = false;

                        } else if (type.designator == PARTITION_ROOT_VERITY_SIG) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                m->has_verity_sig = true;

                                if (!verity)
                                        continue;
                                if (verity->designator >= 0 && verity->designator != PARTITION_ROOT)
                                        continue;

                                fstype = "verity_hash_signature";
                                rw = false;

                        } else if (type.designator == PARTITION_USR) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY | SD_GPT_FLAG_GROWFS);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                /* If a usr ID is specified, ignore everything but the usr id */
                                if (!sd_id128_is_null(usr_uuid) && !sd_id128_equal(usr_uuid, id))
                                        continue;

                                rw = !(pflags & SD_GPT_FLAG_READ_ONLY);
                                growfs = FLAGS_SET(pflags, SD_GPT_FLAG_GROWFS);

                        } else if (type.designator == PARTITION_USR_VERITY) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                m->has_verity = true;

                                if (!verity)
                                        continue;
                                if (verity->designator >= 0 && verity->designator != PARTITION_USR)
                                        continue;

                                /* If usr hash is specified, then ignore everything but the usr id */
                                if (!sd_id128_is_null(usr_verity_uuid) && !sd_id128_equal(usr_verity_uuid, id))
                                        continue;

                                fstype = "DM_verity_hash";
                                rw = false;

                        } else if (type.designator == PARTITION_USR_VERITY_SIG) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                m->has_verity_sig = true;

                                if (!verity)
                                        continue;
                                if (verity->designator >= 0 && verity->designator != PARTITION_USR)
                                        continue;

                                fstype = "verity_hash_signature";
                                rw = false;

                        } else if (type.designator == PARTITION_SWAP) {

                                check_partition_flags(node, pflags, SD_GPT_FLAG_NO_AUTO);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                /* Note: we don't set fstype = "swap" here, because we still need to probe if
                                 * it might be encrypted (i.e. fstype "crypt_LUKS") or unencrypted
                                 * (i.e. fstype "swap"), and the only way to figure that out is via fstype
                                 * probing. */

                        /* We don't have a designator for SD_GPT_LINUX_GENERIC so check the UUID instead. */
                        } else if (sd_id128_equal(type.uuid, SD_GPT_LINUX_GENERIC)) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY | SD_GPT_FLAG_GROWFS);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
                                        continue;

                                if (generic_node)
                                        multiple_generic = true;
                                else {
                                        generic_nr = nr;
                                        generic_rw = !(pflags & SD_GPT_FLAG_READ_ONLY);
                                        generic_growfs = FLAGS_SET(pflags, SD_GPT_FLAG_GROWFS);
                                        generic_uuid = id;
                                        generic_node = TAKE_PTR(node);
                                }

                        } else if (type.designator == PARTITION_VAR) {

                                check_partition_flags(node, pflags,
                                                      SD_GPT_FLAG_NO_AUTO | SD_GPT_FLAG_READ_ONLY | SD_GPT_FLAG_GROWFS);

                                if (pflags & SD_GPT_FLAG_NO_AUTO)
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

                                        r = sd_id128_get_machine_app_specific(SD_GPT_VAR, &var_uuid);
                                        if (r < 0)
                                                return r;

                                        if (!sd_id128_equal(var_uuid, id)) {
                                                log_debug("Found a /var/ partition, but its UUID didn't match our expectations "
                                                          "(found: " SD_ID128_UUID_FORMAT_STR ", expected: " SD_ID128_UUID_FORMAT_STR "), ignoring.",
                                                          SD_ID128_FORMAT_VAL(id), SD_ID128_FORMAT_VAL(var_uuid));
                                                continue;
                                        }
                                }

                                rw = !(pflags & SD_GPT_FLAG_READ_ONLY);
                                growfs = FLAGS_SET(pflags, SD_GPT_FLAG_GROWFS);
                        }

                        if (type.designator != _PARTITION_DESIGNATOR_INVALID) {
                                _cleanup_free_ char *t = NULL, *o = NULL, *l = NULL, *n = NULL;
                                _cleanup_close_ int mount_node_fd = -EBADF;
                                const char *options = NULL;

                                r = image_policy_may_use(policy, type.designator);
                                if (r < 0)
                                        return r;
                                if (r == 0) {
                                        /* Policy says: ignore; Remember this fact, so that we later can distinguish between "found but ignored" and "not found at all" */

                                        if (!m->partitions[type.designator].found)
                                                m->partitions[type.designator].ignored = true;

                                        continue;
                                }

                                if (m->partitions[type.designator].found) {
                                        int c;

                                        /* For most partition types the first one we see wins. Except for the
                                         * rootfs and /usr, where we do a version compare of the label, and
                                         * let the newest version win. This permits a simple A/B versioning
                                         * scheme in OS images. */

                                        c = compare_arch(type.arch, m->partitions[type.designator].architecture);
                                        if (c < 0) /* the arch we already found is better than the one we found now */
                                                continue;
                                        if (c == 0 && /* same arch? then go by version in label */
                                            (!partition_designator_is_versioned(type.designator) ||
                                             strverscmp_improved(label, m->partitions[type.designator].label) <= 0))
                                                continue;

                                        dissected_partition_done(m->partitions + type.designator);
                                }

                                if (FLAGS_SET(flags, DISSECT_IMAGE_PIN_PARTITION_DEVICES) &&
                                    type.designator != PARTITION_SWAP) {
                                        mount_node_fd = open_partition(node, /* is_partition = */ true, m->loop);
                                        if (mount_node_fd < 0)
                                                return mount_node_fd;
                                }

                                r = make_partition_devname(devname, diskseq, nr, flags, &n);
                                if (r < 0)
                                        return r;

                                if (fstype) {
                                        t = strdup(fstype);
                                        if (!t)
                                                return -ENOMEM;
                                }

                                if (label) {
                                        l = strdup(label);
                                        if (!l)
                                                return -ENOMEM;
                                }

                                options = mount_options_from_designator(mount_options, type.designator);
                                if (options) {
                                        o = strdup(options);
                                        if (!o)
                                                return -ENOMEM;
                                }

                                m->partitions[type.designator] = (DissectedPartition) {
                                        .found = true,
                                        .partno = nr,
                                        .rw = rw,
                                        .growfs = growfs,
                                        .architecture = type.arch,
                                        .node = TAKE_PTR(n),
                                        .fstype = TAKE_PTR(t),
                                        .label = TAKE_PTR(l),
                                        .uuid = id,
                                        .mount_options = TAKE_PTR(o),
                                        .mount_node_fd = TAKE_FD(mount_node_fd),
                                        .offset = (uint64_t) start * 512,
                                        .size = (uint64_t) size * 512,
                                        .gpt_flags = pflags,
                                        .fsmount_fd = -EBADF,
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
                                        generic_growfs = false;
                                        generic_node = TAKE_PTR(node);
                                }

                                break;

                        case 0xEA: { /* Boot Loader Spec extended $BOOT partition */
                                _cleanup_close_ int mount_node_fd = -EBADF;
                                _cleanup_free_ char *o = NULL, *n = NULL;
                                sd_id128_t id = SD_ID128_NULL;
                                const char *options = NULL;

                                r = image_policy_may_use(policy, PARTITION_XBOOTLDR);
                                if (r < 0)
                                        return r;
                                if (r == 0) { /* policy says: ignore */
                                        if (!m->partitions[PARTITION_XBOOTLDR].found)
                                                m->partitions[PARTITION_XBOOTLDR].ignored = true;

                                        continue;
                                }

                                /* First one wins */
                                if (m->partitions[PARTITION_XBOOTLDR].found)
                                        continue;

                                if (FLAGS_SET(flags, DISSECT_IMAGE_PIN_PARTITION_DEVICES)) {
                                        mount_node_fd = open_partition(node, /* is_partition = */ true, m->loop);
                                        if (mount_node_fd < 0)
                                                return mount_node_fd;
                                }

                                (void) blkid_partition_get_uuid_id128(pp, &id);

                                r = make_partition_devname(devname, diskseq, nr, flags, &n);
                                if (r < 0)
                                        return r;

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
                                        .growfs = false,
                                        .architecture = _ARCHITECTURE_INVALID,
                                        .node = TAKE_PTR(n),
                                        .uuid = id,
                                        .mount_options = TAKE_PTR(o),
                                        .mount_node_fd = TAKE_FD(mount_node_fd),
                                        .offset = (uint64_t) start * 512,
                                        .size = (uint64_t) size * 512,
                                        .fsmount_fd = -EBADF,
                                };

                                break;
                        }}
                }
        }

        if (!m->partitions[PARTITION_ROOT].found &&
                (m->partitions[PARTITION_ROOT_VERITY].found ||
                 m->partitions[PARTITION_ROOT_VERITY_SIG].found))
                        return -EADDRNOTAVAIL; /* Verity found but no matching rootfs? Something is off, refuse. */

        /* Hmm, we found a signature partition but no Verity data? Something is off. */
        if (m->partitions[PARTITION_ROOT_VERITY_SIG].found && !m->partitions[PARTITION_ROOT_VERITY].found)
                return -EADDRNOTAVAIL;

        if (!m->partitions[PARTITION_USR].found &&
                (m->partitions[PARTITION_USR_VERITY].found ||
                 m->partitions[PARTITION_USR_VERITY_SIG].found))
                        return -EADDRNOTAVAIL; /* as above */

        /* as above */
        if (m->partitions[PARTITION_USR_VERITY_SIG].found && !m->partitions[PARTITION_USR_VERITY].found)
                return -EADDRNOTAVAIL;

        /* If root and /usr are combined then insist that the architecture matches */
        if (m->partitions[PARTITION_ROOT].found &&
            m->partitions[PARTITION_USR].found &&
            (m->partitions[PARTITION_ROOT].architecture >= 0 &&
             m->partitions[PARTITION_USR].architecture >= 0 &&
             m->partitions[PARTITION_ROOT].architecture != m->partitions[PARTITION_USR].architecture))
                return -EADDRNOTAVAIL;

        if (!m->partitions[PARTITION_ROOT].found &&
            !m->partitions[PARTITION_USR].found &&
            (flags & DISSECT_IMAGE_GENERIC_ROOT) &&
            (!verity || !verity->root_hash || verity->designator != PARTITION_USR)) {

                /* OK, we found nothing usable, then check if there's a single generic partition, and use
                 * that. If the root hash was set however, then we won't fall back to a generic node, because
                 * the root hash decides. */

                /* If we didn't find a properly marked root partition, but we did find a single suitable
                 * generic Linux partition, then use this as root partition, if the caller asked for it. */
                if (multiple_generic)
                        return -ENOTUNIQ;

                /* If we didn't find a generic node, then we can't fix this up either */
                if (generic_node) {
                        r = image_policy_may_use(policy, PARTITION_ROOT);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                /* Policy says: ignore; remember that we did */
                                m->partitions[PARTITION_ROOT].ignored = true;
                        else {
                                _cleanup_close_ int mount_node_fd = -EBADF;
                                _cleanup_free_ char *o = NULL, *n = NULL;
                                const char *options;

                                if (FLAGS_SET(flags, DISSECT_IMAGE_PIN_PARTITION_DEVICES)) {
                                        mount_node_fd = open_partition(generic_node, /* is_partition = */ true, m->loop);
                                        if (mount_node_fd < 0)
                                                return mount_node_fd;
                                }

                                r = make_partition_devname(devname, diskseq, generic_nr, flags, &n);
                                if (r < 0)
                                        return r;

                                options = mount_options_from_designator(mount_options, PARTITION_ROOT);
                                if (options) {
                                        o = strdup(options);
                                        if (!o)
                                                return -ENOMEM;
                                }

                                assert(generic_nr >= 0);
                                m->partitions[PARTITION_ROOT] = (DissectedPartition) {
                                        .found = true,
                                        .rw = generic_rw,
                                        .growfs = generic_growfs,
                                        .partno = generic_nr,
                                        .architecture = _ARCHITECTURE_INVALID,
                                        .node = TAKE_PTR(n),
                                        .uuid = generic_uuid,
                                        .mount_options = TAKE_PTR(o),
                                        .mount_node_fd = TAKE_FD(mount_node_fd),
                                        .offset = UINT64_MAX,
                                        .size = UINT64_MAX,
                                        .fsmount_fd = -EBADF,
                                };
                        }
                }
        }

        /* Check if we have a root fs if we are told to do check. /usr alone is fine too, but only if appropriate flag for that is set too */
        if (FLAGS_SET(flags, DISSECT_IMAGE_REQUIRE_ROOT) &&
            !(m->partitions[PARTITION_ROOT].found || (m->partitions[PARTITION_USR].found && FLAGS_SET(flags, DISSECT_IMAGE_USR_NO_ROOT))))
                return -ENXIO;

        if (m->partitions[PARTITION_ROOT_VERITY].found) {
                /* We only support one verity partition per image, i.e. can't do for both /usr and root fs */
                if (m->partitions[PARTITION_USR_VERITY].found)
                        return -ENOTUNIQ;

                /* We don't support verity enabled root with a split out /usr. Neither with nor without
                 * verity there. (Note that we do support verity-less root with verity-full /usr, though.) */
                if (m->partitions[PARTITION_USR].found)
                        return -EADDRNOTAVAIL;
        }

        if (verity) {
                /* If a verity designator is specified, then insist that the matching partition exists */
                if (verity->designator >= 0 && !m->partitions[verity->designator].found)
                        return -EADDRNOTAVAIL;

                bool have_verity_sig_partition;
                if (verity->designator >= 0)
                        have_verity_sig_partition = m->partitions[verity->designator == PARTITION_USR ? PARTITION_USR_VERITY_SIG : PARTITION_ROOT_VERITY_SIG].found;
                else
                        have_verity_sig_partition = m->partitions[PARTITION_USR_VERITY_SIG].found || m->partitions[PARTITION_ROOT_VERITY_SIG].found;

                if (verity->root_hash) {
                        /* If we have an explicit root hash and found the partitions for it, then we are ready to use
                         * Verity, set things up for it */

                        if (verity->designator < 0 || verity->designator == PARTITION_ROOT) {
                                if (!m->partitions[PARTITION_ROOT_VERITY].found || !m->partitions[PARTITION_ROOT].found)
                                        return -EADDRNOTAVAIL;

                                /* If we found a verity setup, then the root partition is necessarily read-only. */
                                m->partitions[PARTITION_ROOT].rw = false;
                                m->verity_ready = true;

                        } else {
                                assert(verity->designator == PARTITION_USR);

                                if (!m->partitions[PARTITION_USR_VERITY].found || !m->partitions[PARTITION_USR].found)
                                        return -EADDRNOTAVAIL;

                                m->partitions[PARTITION_USR].rw = false;
                                m->verity_ready = true;
                        }

                        if (m->verity_ready)
                                m->verity_sig_ready = verity->root_hash_sig || have_verity_sig_partition;

                } else if (have_verity_sig_partition) {

                        /* If we found an embedded signature partition, we are ready, too. */

                        m->verity_ready = m->verity_sig_ready = true;
                        if (verity->designator >= 0)
                                m->partitions[verity->designator == PARTITION_USR ? PARTITION_USR : PARTITION_ROOT].rw = false;
                        else if (m->partitions[PARTITION_USR_VERITY_SIG].found)
                                m->partitions[PARTITION_USR].rw = false;
                        else if (m->partitions[PARTITION_ROOT_VERITY_SIG].found)
                                m->partitions[PARTITION_ROOT].rw = false;
                }
        }

        bool any = false;

        /* After we discovered all partitions let's see if the verity requirements match the policy. (Note:
         * we don't check encryption requirements here, because we haven't probed the file system yet, hence
         * don't know if this is encrypted or not) */
        for (PartitionDesignator di = 0; di < _PARTITION_DESIGNATOR_MAX; di++) {
                PartitionDesignator vi, si;
                PartitionPolicyFlags found_flags;

                any = any || m->partitions[di].found;

                vi = partition_verity_of(di);
                si = partition_verity_sig_of(di);

                /* Determine the verity protection level for this partition. */
                found_flags = m->partitions[di].found ?
                        (vi >= 0 && m->partitions[vi].found ?
                         (si >= 0 && m->partitions[si].found ? PARTITION_POLICY_SIGNED : PARTITION_POLICY_VERITY) :
                         PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED) :
                        (m->partitions[di].ignored ? PARTITION_POLICY_UNUSED : PARTITION_POLICY_ABSENT);

                r = image_policy_check_protection(policy, di, found_flags);
                if (r < 0)
                        return r;

                if (m->partitions[di].found) {
                        r = image_policy_check_partition_flags(policy, di, m->partitions[di].gpt_flags);
                        if (r < 0)
                                return r;
                }
        }

        if (!any && !FLAGS_SET(flags, DISSECT_IMAGE_ALLOW_EMPTY))
                return -ENOMSG;

        r = dissected_image_probe_filesystems(m, fd, policy);
        if (r < 0)
                return r;

        return 0;
}
#endif

int dissect_image_file(
                const char *path,
                const VeritySettings *verity,
                const MountOptions *mount_options,
                const ImagePolicy *image_policy,
                DissectImageFlags flags,
                DissectedImage **ret) {

#if HAVE_BLKID
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(path);

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        r = dissected_image_new(path, &m);
        if (r < 0)
                return r;

        m->image_size = st.st_size;

        r = probe_sector_size(fd, &m->sector_size);
        if (r < 0)
                return r;

        r = dissect_image(m, fd, path, verity, mount_options, image_policy, flags);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(m);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int dissect_log_error(int log_level, int r, const char *name, const VeritySettings *verity) {
        assert(log_level >= 0 && log_level <= LOG_DEBUG);
        assert(name);

        switch (r) {

        case 0 ... INT_MAX: /* success! */
                return r;

        case -EOPNOTSUPP:
                return log_full_errno(log_level, r, "Dissecting images is not supported, compiled without blkid support.");

        case -ENOPKG:
                return log_full_errno(log_level, r, "%s: Couldn't identify a suitable partition table or file system.", name);

        case -ENOMEDIUM:
                return log_full_errno(log_level, r, "%s: The image does not pass os-release/extension-release validation.", name);

        case -EADDRNOTAVAIL:
                return log_full_errno(log_level, r, "%s: No root partition for specified root hash found.", name);

        case -ENOTUNIQ:
                return log_full_errno(log_level, r, "%s: Multiple suitable root partitions found in image.", name);

        case -ENXIO:
                return log_full_errno(log_level, r, "%s: No suitable root partition found in image.", name);

        case -EPROTONOSUPPORT:
                return log_full_errno(log_level, r, "Device '%s' is a loopback block device with partition scanning turned off, please turn it on.", name);

        case -ENOTBLK:
                return log_full_errno(log_level, r, "%s: Image is not a block device.", name);

        case -EBADR:
                return log_full_errno(log_level, r,
                                      "Combining partitioned images (such as '%s') with external Verity data (such as '%s') not supported. "
                                      "(Consider setting $SYSTEMD_DISSECT_VERITY_SIDECAR=0 to disable automatic discovery of external Verity data.)",
                                      name, strna(verity ? verity->data_path : NULL));

        case -ERFKILL:
                return log_full_errno(log_level, r, "%s: image does not match image policy.", name);

        case -ENOMSG:
                return log_full_errno(log_level, r, "%s: no suitable partitions found.", name);

        default:
                return log_full_errno(log_level, r, "%s: cannot dissect image: %m", name);
        }
}

int dissect_image_file_and_warn(
                const char *path,
                const VeritySettings *verity,
                const MountOptions *mount_options,
                const ImagePolicy *image_policy,
                DissectImageFlags flags,
                DissectedImage **ret) {

        return dissect_log_error(
                        LOG_ERR,
                        dissect_image_file(path, verity, mount_options, image_policy, flags, ret),
                        path,
                        verity);
}

void dissected_image_close(DissectedImage *m) {
        if (!m)
                return;

        /* Closes all fds we keep open assocated with this, but nothing else */

        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                DissectedPartition* p = m->partitions + i;

                p->mount_node_fd = safe_close(p->mount_node_fd);
                p->fsmount_fd = safe_close(p->fsmount_fd);
        }

        m->loop = loop_device_unref(m->loop);
}

DissectedImage* dissected_image_unref(DissectedImage *m) {
        if (!m)
                return NULL;

        /* First, clear dissected partitions. */
        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++)
                dissected_partition_done(m->partitions + i);

        /* Second, free decrypted images. This must be after dissected_partition_done(), as freeing
         * DecryptedImage may try to deactivate partitions. */
        decrypted_image_unref(m->decrypted_image);

        /* Third, unref LoopDevice. This must be called after the above two, as freeing LoopDevice may try to
         * remove existing partitions on the loopback block device. */
        loop_device_unref(m->loop);

        free(m->image_name);
        free(m->hostname);
        strv_free(m->machine_info);
        strv_free(m->os_release);
        strv_free(m->initrd_release);
        strv_free(m->confext_release);
        strv_free(m->sysext_release);

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

static int run_fsck(int node_fd, const char *fstype) {
        int r, exit_status;
        pid_t pid;

        assert(node_fd >= 0);
        assert(fstype);

        r = fsck_exists_for_fstype(fstype);
        if (r < 0) {
                log_debug_errno(r, "Couldn't determine whether fsck for %s exists, proceeding anyway.", fstype);
                return 0;
        }
        if (r == 0) {
                log_debug("Not checking partition %s, as fsck for %s does not exist.", FORMAT_PROC_FD_PATH(node_fd), fstype);
                return 0;
        }

        r = safe_fork_full(
                        "(fsck)",
                        NULL,
                        &node_fd, 1, /* Leave the node fd open */
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_CLOEXEC_OFF,
                        &pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork off fsck: %m");
        if (r == 0) {
                /* Child */
                execlp("fsck", "fsck", "-aT", FORMAT_PROC_FD_PATH(node_fd), NULL);
                log_open();
                log_debug_errno(errno, "Failed to execl() fsck: %m");
                _exit(FSCK_OPERATIONAL_ERROR);
        }

        exit_status = wait_for_terminate_and_check("fsck", pid, 0);
        if (exit_status < 0)
                return log_debug_errno(exit_status, "Failed to fork off fsck: %m");

        if ((exit_status & ~FSCK_ERROR_CORRECTED) != FSCK_SUCCESS) {
                log_debug("fsck failed with exit status %i.", exit_status);

                if ((exit_status & (FSCK_SYSTEM_SHOULD_REBOOT|FSCK_ERRORS_LEFT_UNCORRECTED)) != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN), "File system is corrupted, refusing.");

                log_debug("Ignoring fsck error.");
        }

        return 0;
}

static int fs_grow(const char *node_path, int mount_fd, const char *mount_path) {
        _cleanup_close_ int _mount_fd = -EBADF, node_fd = -EBADF;
        uint64_t size, newsize;
        const char *id;
        int r;

        assert(node_path);
        assert(mount_fd >= 0 || mount_path);

        node_fd = open(node_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (node_fd < 0)
                return log_debug_errno(errno, "Failed to open node device %s: %m", node_path);

        if (ioctl(node_fd, BLKGETSIZE64, &size) != 0)
                return log_debug_errno(errno, "Failed to get block device size of %s: %m", node_path);

        if (mount_fd < 0) {
                assert(mount_path);

                _mount_fd = open(mount_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (_mount_fd < 0)
                        return log_debug_errno(errno, "Failed to open mounted file system %s: %m", mount_path);

                mount_fd = _mount_fd;
        } else {
                mount_fd = fd_reopen_condition(mount_fd, O_RDONLY|O_DIRECTORY|O_CLOEXEC, O_RDONLY|O_DIRECTORY|O_CLOEXEC, &_mount_fd);
                if (mount_fd < 0)
                        return log_debug_errno(errno, "Failed to reopen mount node: %m");
        }

        id = mount_path ?: node_path;

        log_debug("Resizing \"%s\" to %"PRIu64" bytes...", id, size);
        r = resize_fs(mount_fd, size, &newsize);
        if (r < 0)
                return log_debug_errno(r, "Failed to resize \"%s\" to %"PRIu64" bytes: %m", id, size);

        if (newsize == size)
                log_debug("Successfully resized \"%s\" to %s bytes.",
                          id, FORMAT_BYTES(newsize));
        else {
                assert(newsize < size);
                log_debug("Successfully resized \"%s\" to %s bytes (%"PRIu64" bytes lost due to blocksize).",
                          id, FORMAT_BYTES(newsize), size - newsize);
        }

        return 0;
}

int partition_pick_mount_options(
                PartitionDesignator d,
                const char *fstype,
                bool rw,
                bool discard,
                char **ret_options,
                unsigned long *ret_ms_flags) {

        _cleanup_free_ char *options = NULL;

        assert(ret_options);

        /* Selects a baseline of bind mount flags, that should always apply.
         *
         * Firstly, we set MS_NODEV universally on all mounts, since we don't want to allow device nodes outside of /dev/.
         *
         * On /var/tmp/ we'll also set MS_NOSUID, same as we set for /tmp/ on the host.
         *
         * On the ESP and XBOOTLDR partitions we'll also disable symlinks, and execution. These file systems
         * are generally untrusted (i.e. not encrypted or authenticated), and typically VFAT hence we should
         * be as restrictive as possible, and this shouldn't hurt, since the functionality is not available
         * there anyway. */

        unsigned long flags = MS_NODEV;

        if (!rw)
                flags |= MS_RDONLY;

        switch (d) {

        case PARTITION_ESP:
        case PARTITION_XBOOTLDR:
                flags |= MS_NOSUID|MS_NOEXEC|ms_nosymfollow_supported();

                /* The ESP might contain a pre-boot random seed. Let's make this unaccessible to regular
                 * userspace. ESP/XBOOTLDR is almost certainly VFAT, hence if we don't know assume it is. */
                if (!fstype || fstype_can_umask(fstype))
                        if (!strextend_with_separator(&options, ",", "umask=0077"))
                                return -ENOMEM;
                break;

        case PARTITION_TMP:
                flags |= MS_NOSUID;
                break;

        default:
                break;
        }

        /* So, when you request MS_RDONLY from ext4, then this means nothing. It happily still writes to the
         * backing storage. What's worse, the BLKRO[GS]ET flag and (in case of loopback devices)
         * LO_FLAGS_READ_ONLY don't mean anything, they affect userspace accesses only, and write accesses
         * from the upper file system still get propagated through to the underlying file system,
         * unrestricted. To actually get ext4/xfs/btrfs to stop writing to the device we need to specify
         * "norecovery" as mount option, in addition to MS_RDONLY. Yes, this sucks, since it means we need to
         * carry a per file system table here.
         *
         * Note that this means that we might not be able to mount corrupted file systems as read-only
         * anymore (since in some cases the kernel implementations will refuse mounting when corrupted,
         * read-only and "norecovery" is specified). But I think for the case of automatically determined
         * mount options for loopback devices this is the right choice, since otherwise using the same
         * loopback file twice even in read-only mode, is going to fail badly sooner or later. The use case of
         * making reuse of the immutable images "just work" is more relevant to us than having read-only
         * access that actually modifies stuff work on such image files. Or to say this differently: if
         * people want their file systems to be fixed up they should just open them in writable mode, where
         * all these problems don't exist. */
        if (!rw && fstype && fstype_can_norecovery(fstype))
                if (!strextend_with_separator(&options, ",", "norecovery"))
                        return -ENOMEM;

        if (discard && fstype && fstype_can_discard(fstype))
                if (!strextend_with_separator(&options, ",", "discard"))
                        return -ENOMEM;

        if (!ret_ms_flags) /* Fold flags into option string if ret_flags specified as NULL */
                if (!strextend_with_separator(&options, ",",
                                              FLAGS_SET(flags, MS_RDONLY) ? "ro" : "rw",
                                              FLAGS_SET(flags, MS_NODEV) ? "nodev" : "dev",
                                              FLAGS_SET(flags, MS_NOSUID) ? "nosuid" : "suid",
                                              FLAGS_SET(flags, MS_NOEXEC) ? "noexec" : "exec",
                                              FLAGS_SET(flags, MS_NOSYMFOLLOW) ? "nosymfollow" : NULL))
                        /* NB: we suppress 'symfollow' here, since it's the default, and old /bin/mount might not know it */
                        return -ENOMEM;

        if (ret_ms_flags)
                *ret_ms_flags = flags;

        *ret_options = TAKE_PTR(options);
        return 0;
}

static bool need_user_mapping(uid_t uid_shift, uid_t uid_range) {

        if (!uid_is_valid(uid_shift))
                return false;

        return uid_shift != 0 || uid_range != UINT32_MAX;
}

static int mount_partition(
                PartitionDesignator d,
                DissectedPartition *m,
                const char *where,
                const char *directory,
                uid_t uid_shift,
                uid_t uid_range,
                int userns_fd,
                DissectImageFlags flags) {

        _cleanup_free_ char *chased = NULL, *options = NULL;
        const char *p = NULL, *node, *fstype = NULL;
        bool rw, discard, grow;
        unsigned long ms_flags;
        int r;

        assert(m);

        if (!m->found)
                return 0;

        /* Check the various combinations when we can't do anything anymore */
        if (m->fsmount_fd < 0 && m->mount_node_fd < 0)
                return 0;
        if (m->fsmount_fd >= 0 && !where)
                return 0;
        if (!where && m->mount_node_fd < 0)
                return 0;

        if (m->fsmount_fd < 0) {
                fstype = dissected_partition_fstype(m);
                if (!fstype)
                        return -EAFNOSUPPORT;

                /* We are looking at an encrypted partition? This either means stacked encryption, or the
                 * caller didn't call dissected_image_decrypt() beforehand. Let's return a recognizable error
                 * for this case. */
                if (streq(fstype, "crypto_LUKS"))
                        return -EUNATCH;

                r = dissect_fstype_ok(fstype);
                if (r < 0)
                        return r;
                if (!r)
                        return -EIDRM; /* Recognizable error */
        }

        node = m->mount_node_fd < 0 ? NULL : FORMAT_PROC_FD_PATH(m->mount_node_fd);
        rw = m->rw && !(flags & DISSECT_IMAGE_MOUNT_READ_ONLY);

        discard = ((flags & DISSECT_IMAGE_DISCARD) ||
                   ((flags & DISSECT_IMAGE_DISCARD_ON_LOOP) && (m->node && is_loop_device(m->node) > 0)));

        grow = rw && m->growfs && FLAGS_SET(flags, DISSECT_IMAGE_GROWFS);

        if (FLAGS_SET(flags, DISSECT_IMAGE_FSCK) && rw && m->mount_node_fd >= 0 && m->fsmount_fd < 0) {
                r = run_fsck(m->mount_node_fd, fstype);
                if (r < 0)
                        return r;
        }

        if (where) {
                if (directory) {
                        /* Automatically create missing mount points inside the image, if necessary. */
                        r = mkdir_p_root(where, directory, uid_shift, (gid_t) uid_shift, 0755, NULL);
                        if (r < 0 && r != -EROFS)
                                return r;

                        r = chase(directory, where, CHASE_PREFIX_ROOT, &chased, NULL);
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
        }

        if (m->fsmount_fd < 0) {
                r = partition_pick_mount_options(d, fstype, rw, discard, &options, &ms_flags);
                if (r < 0)
                        return r;

                if (need_user_mapping(uid_shift, uid_range) && fstype_can_uid_gid(fstype)) {
                        _cleanup_free_ char *uid_option = NULL;

                        if (asprintf(&uid_option, "uid=" UID_FMT ",gid=" GID_FMT, uid_shift, (gid_t) uid_shift) < 0)
                                return -ENOMEM;

                        if (!strextend_with_separator(&options, ",", uid_option))
                                return -ENOMEM;

                        userns_fd = -EBADF; /* Not needed */
                }

                if (!isempty(m->mount_options))
                        if (!strextend_with_separator(&options, ",", m->mount_options))
                                return -ENOMEM;
        }

        if (p) {
                if (m->fsmount_fd >= 0) {
                        /* Case #1: Attach existing fsmount fd to the file system */

                        r = mount_exchange_graceful(
                                        m->fsmount_fd,
                                        p,
                                        FLAGS_SET(flags, DISSECT_IMAGE_TRY_ATOMIC_MOUNT_EXCHANGE));
                        if (r < 0)
                                return log_debug_errno(r, "Failed to mount image on '%s': %m", p);

                } else {
                        assert(node);

                        /* Case #2: Mount directly into place */
                        r = mount_nofollow_verbose(LOG_DEBUG, node, p, fstype, ms_flags, options);
                        if (r < 0)
                                return r;

                        if (grow)
                                (void) fs_grow(node, -EBADF, p);

                        if (userns_fd >= 0) {
                                r = remount_idmap_fd(STRV_MAKE(p), userns_fd);
                                if (r < 0)
                                        return r;
                        }
                }
        } else {
                assert(node);

                /* Case #3: Create fsmount fd */

                m->fsmount_fd = make_fsmount(LOG_DEBUG, node, fstype, ms_flags, options, userns_fd);
                if (m->fsmount_fd < 0)
                        return m->fsmount_fd;

                if (grow)
                        (void) fs_grow(node, m->fsmount_fd, NULL);
        }

        return 1;
}

static int mount_root_tmpfs(const char *where, uid_t uid_shift, uid_t uid_range, DissectImageFlags flags) {
        _cleanup_free_ char *options = NULL;
        int r;

        assert(where);

        /* For images that contain /usr/ but no rootfs, let's mount rootfs as tmpfs */

        if (FLAGS_SET(flags, DISSECT_IMAGE_MKDIR)) {
                r = mkdir_p(where, 0755);
                if (r < 0)
                        return r;
        }

        if (need_user_mapping(uid_shift, uid_range)) {
                if (asprintf(&options, "uid=" UID_FMT ",gid=" GID_FMT, uid_shift, (gid_t) uid_shift) < 0)
                        return -ENOMEM;
        }

        r = mount_nofollow_verbose(LOG_DEBUG, "rootfs", where, "tmpfs", MS_NODEV, options);
        if (r < 0)
                return r;

        return 1;
}

static int mount_point_is_available(const char *where, const char *path, bool missing_ok) {
        _cleanup_free_ char *p = NULL;
        int r;

        /* Check whether <path> is suitable as a mountpoint, i.e. is an empty directory
         * or does not exist at all (when missing_ok). */

        r = chase(path, where, CHASE_PREFIX_ROOT, &p, NULL);
        if (r == -ENOENT)
                return missing_ok;
        if (r < 0)
                return log_debug_errno(r, "Failed to chase \"%s\": %m", path);

        r = dir_is_empty(p, /* ignore_hidden_or_backup= */ false);
        if (r == -ENOTDIR)
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to check directory \"%s\": %m", p);
        return r > 0;
}

int dissected_image_mount(
                DissectedImage *m,
                const char *where,
                uid_t uid_shift,
                uid_t uid_range,
                int userns_fd,
                DissectImageFlags flags) {

        _cleanup_close_ int my_userns_fd = -EBADF;
        int r;

        assert(m);

        /* If 'where' is NULL then we'll use the new mount API to create fsmount() fds for the mounts and
         * store them in DissectedPartition.fsmount_fd.
         *
         * If 'where' is not NULL then we'll either mount the partitions to the right places ourselves,
         * or use DissectedPartition.fsmount_fd and bind it to the right places.
         *
         * This allows splitting the setting up up the superblocks and the binding to file systems paths into
         * two distinct and differently privileged components: one that gets the fsmount fds, and the other
         * that then applies them.
         *
         * Returns:
         *
         *  -ENXIO        → No root partition found
         *  -EMEDIUMTYPE  → DISSECT_IMAGE_VALIDATE_OS set but no os-release/extension-release file found
         *  -EUNATCH      → Encrypted partition found for which no dm-crypt was set up yet
         *  -EUCLEAN      → fsck for file system failed
         *  -EBUSY        → File system already mounted/used elsewhere (kernel)
         *  -EAFNOSUPPORT → File system type not supported or not known
         *  -EIDRM        → File system is not among allowlisted "common" file systems
         */

        if (!where && (flags & (DISSECT_IMAGE_VALIDATE_OS|DISSECT_IMAGE_VALIDATE_OS_EXT)) != 0)
                return -EOPNOTSUPP; /* for now, not supported */

        if (!(m->partitions[PARTITION_ROOT].found ||
              (m->partitions[PARTITION_USR].found && FLAGS_SET(flags, DISSECT_IMAGE_USR_NO_ROOT))))
                return -ENXIO; /* Require a root fs or at least a /usr/ fs (the latter is subject to a flag of its own) */

        if (userns_fd < 0 && need_user_mapping(uid_shift, uid_range) && FLAGS_SET(flags, DISSECT_IMAGE_MOUNT_IDMAPPED)) {

                my_userns_fd = make_userns(uid_shift, uid_range, UID_INVALID, REMOUNT_IDMAPPING_HOST_ROOT);
                if (my_userns_fd < 0)
                        return my_userns_fd;

                userns_fd = my_userns_fd;
        }

        if ((flags & DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY) == 0) {

                /* First mount the root fs. If there's none we use a tmpfs. */
                if (m->partitions[PARTITION_ROOT].found) {
                        r = mount_partition(PARTITION_ROOT, m->partitions + PARTITION_ROOT, where, NULL, uid_shift, uid_range, userns_fd, flags);
                        if (r < 0)
                                return r;

                } else if (where) {
                        r = mount_root_tmpfs(where, uid_shift, uid_range, flags);
                        if (r < 0)
                                return r;
                }

                /* For us mounting root always means mounting /usr as well */
                r = mount_partition(PARTITION_USR, m->partitions + PARTITION_USR, where, "/usr", uid_shift, uid_range, userns_fd, flags);
                if (r < 0)
                        return r;
        }

        if ((flags & DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY) == 0 &&
            (flags & (DISSECT_IMAGE_VALIDATE_OS|DISSECT_IMAGE_VALIDATE_OS_EXT)) != 0) {
                /* If either one of the validation flags are set, ensure that the image qualifies as
                 * one or the other (or both). */
                bool ok = false;

                assert(where);

                if (FLAGS_SET(flags, DISSECT_IMAGE_VALIDATE_OS)) {
                        r = path_is_os_tree(where);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                ok = true;
                }
                if (!ok && FLAGS_SET(flags, DISSECT_IMAGE_VALIDATE_OS_EXT) && m->image_name) {
                        r = extension_has_forbidden_content(where);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                r = path_is_extension_tree(IMAGE_SYSEXT, where, m->image_name, FLAGS_SET(flags, DISSECT_IMAGE_RELAX_EXTENSION_CHECK));
                                if (r == 0)
                                        r = path_is_extension_tree(IMAGE_CONFEXT, where, m->image_name, FLAGS_SET(flags, DISSECT_IMAGE_RELAX_EXTENSION_CHECK));
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        ok = true;
                        }
                }

                if (!ok)
                        return -ENOMEDIUM;
        }

        if (flags & DISSECT_IMAGE_MOUNT_ROOT_ONLY)
                return 0;

        r = mount_partition(PARTITION_HOME, m->partitions + PARTITION_HOME, where, "/home", uid_shift, uid_range, userns_fd, flags);
        if (r < 0)
                return r;

        r = mount_partition(PARTITION_SRV, m->partitions + PARTITION_SRV, where, "/srv", uid_shift, uid_range, userns_fd, flags);
        if (r < 0)
                return r;

        r = mount_partition(PARTITION_VAR, m->partitions + PARTITION_VAR, where, "/var", uid_shift, uid_range, userns_fd, flags);
        if (r < 0)
                return r;

        r = mount_partition(PARTITION_TMP, m->partitions + PARTITION_TMP, where, "/var/tmp", uid_shift, uid_range, userns_fd, flags);
        if (r < 0)
                return r;

        int slash_boot_is_available = 0;
        if (where) {
                r = slash_boot_is_available = mount_point_is_available(where, "/boot", /* missing_ok = */ true);
                if (r < 0)
                        return r;
        }
        if (!where || slash_boot_is_available) {
                r = mount_partition(PARTITION_XBOOTLDR, m->partitions + PARTITION_XBOOTLDR, where, "/boot", uid_shift, uid_range, userns_fd, flags);
                if (r < 0)
                        return r;
                slash_boot_is_available = !r;
        }

        if (m->partitions[PARTITION_ESP].found) {
                const char *esp_path = NULL;

                if (where) {
                        /* Mount the ESP to /boot/ if it exists and is empty and we didn't already mount the
                         * XBOOTLDR partition into it. Otherwise, use /efi instead, but only if it exists
                         * and is empty. */

                        if (slash_boot_is_available) {
                                r = mount_point_is_available(where, "/boot", /* missing_ok = */ false);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        esp_path = "/boot";
                        }

                        if (!esp_path) {
                                r = mount_point_is_available(where, "/efi", /* missing_ok = */ true);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        esp_path = "/efi";
                        }
                }

                /* OK, let's mount the ESP now (possibly creating the dir if missing) */
                r = mount_partition(PARTITION_ESP, m->partitions + PARTITION_ESP, where, esp_path, uid_shift, uid_range, userns_fd, flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dissected_image_mount_and_warn(
                DissectedImage *m,
                const char *where,
                uid_t uid_shift,
                uid_t uid_range,
                int userns_fd,
                DissectImageFlags flags) {

        int r;

        assert(m);

        r = dissected_image_mount(m, where, uid_shift, uid_range, userns_fd, flags);
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
        if (r == -EIDRM)
                return log_error_errno(r, "File system is too uncommon, refused.");
        if (r < 0)
                return log_error_errno(r, "Failed to mount image: %m");

        return r;
}

#if HAVE_LIBCRYPTSETUP
struct DecryptedPartition {
        struct crypt_device *device;
        char *name;
        bool relinquished;
};
#endif

typedef struct DecryptedPartition DecryptedPartition;

struct DecryptedImage {
        unsigned n_ref;
        DecryptedPartition *decrypted;
        size_t n_decrypted;
};

static DecryptedImage* decrypted_image_free(DecryptedImage *d) {
#if HAVE_LIBCRYPTSETUP
        int r;

        if (!d)
                return NULL;

        for (size_t i = 0; i < d->n_decrypted; i++) {
                DecryptedPartition *p = d->decrypted + i;

                if (p->device && p->name && !p->relinquished) {
                        _cleanup_free_ char *node = NULL;

                        node = path_join("/dev/mapper", p->name);
                        if (node) {
                                r = btrfs_forget_device(node);
                                if (r < 0 && r != -ENOENT)
                                        log_debug_errno(r, "Failed to forget btrfs device %s, ignoring: %m", node);
                        } else
                                log_oom_debug();

                        /* Let's deactivate lazily, as the dm volume may be already/still used by other processes. */
                        r = sym_crypt_deactivate_by_name(p->device, p->name, CRYPT_DEACTIVATE_DEFERRED);
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

DEFINE_TRIVIAL_REF_UNREF_FUNC(DecryptedImage, decrypted_image, decrypted_image_free);

#if HAVE_LIBCRYPTSETUP
static int decrypted_image_new(DecryptedImage **ret) {
        _cleanup_(decrypted_image_unrefp) DecryptedImage *d = NULL;

        assert(ret);

        d = new(DecryptedImage, 1);
        if (!d)
                return -ENOMEM;

        *d = (DecryptedImage) {
                .n_ref = 1,
        };

        *ret = TAKE_PTR(d);
        return 0;
}

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
        _cleanup_close_ int fd = -EBADF;
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

        if (!GREEDY_REALLOC0(d->decrypted, d->n_decrypted + 1))
                return -ENOMEM;

        r = sym_crypt_init(&cd, m->node);
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize dm-crypt: %m");

        cryptsetup_enable_logging(cd);

        r = sym_crypt_load(cd, CRYPT_LUKS, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load LUKS metadata: %m");

        r = sym_crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, passphrase, strlen(passphrase),
                                             ((flags & DISSECT_IMAGE_DEVICE_READ_ONLY) ? CRYPT_ACTIVATE_READONLY : 0) |
                                             ((flags & DISSECT_IMAGE_DISCARD_ON_CRYPTO) ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0));
        if (r < 0) {
                log_debug_errno(r, "Failed to activate LUKS device: %m");
                return r == -EPERM ? -EKEYREJECTED : r;
        }

        fd = open(node, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open %s: %m", node);

        d->decrypted[d->n_decrypted++] = (DecryptedPartition) {
                .name = TAKE_PTR(name),
                .device = TAKE_PTR(cd),
        };

        m->decrypted_node = TAKE_PTR(node);
        close_and_replace(m->mount_node_fd, fd);

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

        cryptsetup_enable_logging(cd);

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

static char* dm_deferred_remove_clean(char *name) {
        if (!name)
                return NULL;

        (void) sym_crypt_deactivate_by_name(NULL, name, CRYPT_DEACTIVATE_DEFERRED);
        return mfree(name);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char *, dm_deferred_remove_clean);

static int validate_signature_userspace(const VeritySettings *verity) {
#if HAVE_OPENSSL
        _cleanup_(sk_X509_free_allp) STACK_OF(X509) *sk = NULL;
        _cleanup_strv_free_ char **certs = NULL;
        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        _cleanup_free_ char *s = NULL;
        _cleanup_(BIO_freep) BIO *bio = NULL; /* 'bio' must be freed first, 's' second, hence keep this order
                                               * of declaration in place, please */
        const unsigned char *d;
        int r;

        assert(verity);
        assert(verity->root_hash);
        assert(verity->root_hash_sig);

        /* Because installing a signature certificate into the kernel chain is so messy, let's optionally do
         * userspace validation. */

        r = conf_files_list_nulstr(&certs, ".crt", NULL, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, CONF_PATHS_NULSTR("verity.d"));
        if (r < 0)
                return log_debug_errno(r, "Failed to enumerate certificates: %m");
        if (strv_isempty(certs)) {
                log_debug("No userspace dm-verity certificates found.");
                return 0;
        }

        d = verity->root_hash_sig;
        p7 = d2i_PKCS7(NULL, &d, (long) verity->root_hash_sig_size);
        if (!p7)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse PKCS7 DER signature data.");

        s = hexmem(verity->root_hash, verity->root_hash_size);
        if (!s)
                return log_oom_debug();

        bio = BIO_new_mem_buf(s, strlen(s));
        if (!bio)
                return log_oom_debug();

        sk = sk_X509_new_null();
        if (!sk)
                return log_oom_debug();

        STRV_FOREACH(i, certs) {
                _cleanup_(X509_freep) X509 *c = NULL;
                _cleanup_fclose_ FILE *f = NULL;

                f = fopen(*i, "re");
                if (!f) {
                        log_debug_errno(errno, "Failed to open '%s', ignoring: %m", *i);
                        continue;
                }

                c = PEM_read_X509(f, NULL, NULL, NULL);
                if (!c) {
                        log_debug("Failed to load X509 certificate '%s', ignoring.", *i);
                        continue;
                }

                if (sk_X509_push(sk, c) == 0)
                        return log_oom_debug();

                TAKE_PTR(c);
        }

        r = PKCS7_verify(p7, sk, NULL, bio, NULL, PKCS7_NOINTERN|PKCS7_NOVERIFY);
        if (r)
                log_debug("Userspace PKCS#7 validation succeeded.");
        else
                log_debug("Userspace PKCS#7 validation failed: %s", ERR_error_string(ERR_get_error(), NULL));

        return r;
#else
        log_debug("Not doing client-side validation of dm-verity root hash signatures, OpenSSL support disabled.");
        return 0;
#endif
}

static int do_crypt_activate_verity(
                struct crypt_device *cd,
                const char *name,
                const VeritySettings *verity) {

        bool check_signature;
        int r, k;

        assert(cd);
        assert(name);
        assert(verity);

        if (verity->root_hash_sig) {
                r = getenv_bool_secure("SYSTEMD_DISSECT_VERITY_SIGNATURE");
                if (r < 0 && r != -ENXIO)
                        log_debug_errno(r, "Failed to parse $SYSTEMD_DISSECT_VERITY_SIGNATURE");

                check_signature = r != 0;
        } else
                check_signature = false;

        if (check_signature) {

#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                /* First, if we have support for signed keys in the kernel, then try that first. */
                r = sym_crypt_activate_by_signed_key(
                                cd,
                                name,
                                verity->root_hash,
                                verity->root_hash_size,
                                verity->root_hash_sig,
                                verity->root_hash_sig_size,
                                CRYPT_ACTIVATE_READONLY);
                if (r >= 0)
                        return r;

                log_debug_errno(r, "Validation of dm-verity signature failed via the kernel, trying userspace validation instead: %m");
#else
                log_debug("Activation of verity device with signature requested, but not supported via the kernel by %s due to missing crypt_activate_by_signed_key(), trying userspace validation instead.",
                          program_invocation_short_name);
                r = 0; /* Set for the propagation below */
#endif

                /* So this didn't work via the kernel, then let's try userspace validation instead. If that
                 * works we'll try to activate without telling the kernel the signature. */

                /* Preferably propagate the original kernel error, so that the fallback logic can work,
                 * as the device-mapper is finicky around concurrent activations of the same volume */
                k = validate_signature_userspace(verity);
                if (k < 0)
                        return r < 0 ? r : k;
                if (k == 0)
                        return log_debug_errno(r < 0 ? r : SYNTHETIC_ERRNO(ENOKEY),
                                               "Activation of signed Verity volume worked neither via the kernel nor in userspace, can't activate.");
        }

        return sym_crypt_activate_by_volume_key(
                        cd,
                        name,
                        verity->root_hash,
                        verity->root_hash_size,
                        CRYPT_ACTIVATE_READONLY);
}

static usec_t verity_timeout(void) {
        usec_t t = 100 * USEC_PER_MSEC;
        const char *e;
        int r;

        /* On slower machines, like non-KVM vm, setting up device may take a long time.
         * Let's make the timeout configurable. */

        e = getenv("SYSTEMD_DISSECT_VERITY_TIMEOUT_SEC");
        if (!e)
                return t;

        r = parse_sec(e, &t);
        if (r < 0)
                log_debug_errno(r,
                                "Failed to parse timeout specified in $SYSTEMD_DISSECT_VERITY_TIMEOUT_SEC, "
                                "using the default timeout (%s).",
                                FORMAT_TIMESPAN(t, USEC_PER_MSEC));

        return t;
}

static int verity_partition(
                PartitionDesignator designator,
                DissectedPartition *m,
                DissectedPartition *v,
                const VeritySettings *verity,
                DissectImageFlags flags,
                DecryptedImage *d) {

        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_free_ char *node = NULL, *name = NULL;
        _cleanup_close_ int mount_node_fd = -EBADF;
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

        if (!GREEDY_REALLOC0(d->decrypted, d->n_decrypted + 1))
                return -ENOMEM;

        /* If activating fails because the device already exists, check the metadata and reuse it if it matches.
         * In case of ENODEV/ENOENT, which can happen if another process is activating at the exact same time,
         * retry a few times before giving up. */
        for (unsigned i = 0; i < N_DEVICE_NODE_LIST_ATTEMPTS; i++) {
                _cleanup_(dm_deferred_remove_cleanp) char *restore_deferred_remove = NULL;
                _cleanup_(sym_crypt_freep) struct crypt_device *existing_cd = NULL;
                _cleanup_close_ int fd = -EBADF;

                /* First, check if the device already exists. */
                fd = open(node, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                if (fd < 0 && !ERRNO_IS_DEVICE_ABSENT(errno))
                        return log_debug_errno(errno, "Failed to open verity device %s: %m", node);
                if (fd >= 0)
                        goto check; /* The device already exists. Let's check it. */

                /* The symlink to the device node does not exist yet. Assume not activated, and let's activate it. */
                r = do_crypt_activate_verity(cd, name, verity);
                if (r >= 0)
                        goto try_open; /* The device is activated. Let's open it. */
                /* libdevmapper can return EINVAL when the device is already in the activation stage.
                 * There's no way to distinguish this situation from a genuine error due to invalid
                 * parameters, so immediately fall back to activating the device with a unique name.
                 * Improvements in libcrypsetup can ensure this never happens:
                 * https://gitlab.com/cryptsetup/cryptsetup/-/merge_requests/96 */
                if (r == -EINVAL && FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE))
                        break;
                if (r == -ENODEV) /* Volume is being opened but not ready, crypt_init_by_name would fail, try to open again */
                        goto try_again;
                if (!IN_SET(r,
                            -EEXIST, /* Volume has already been opened and ready to be used. */
                            -EBUSY   /* Volume is being opened but not ready, crypt_init_by_name() can fetch details. */))
                        return log_debug_errno(r, "Failed to activate verity device %s: %m", node);

        check:
                /* To avoid races, disable automatic removal on umount while setting up the new device. Restore it on failure. */
                r = dm_deferred_remove_cancel(name);
                /* -EBUSY and -ENXIO: the device has already been removed or being removed. We cannot
                 * use the device, try to open again. See target_message() in drivers/md/dm-ioctl.c
                 * and dm_cancel_deferred_remove() in drivers/md/dm.c */
                if (IN_SET(r, -EBUSY, -ENXIO))
                        goto try_again;
                if (r < 0)
                        return log_debug_errno(r, "Failed to disable automated deferred removal for verity device %s: %m", node);

                restore_deferred_remove = strdup(name);
                if (!restore_deferred_remove)
                        return log_oom_debug();

                r = verity_can_reuse(verity, name, &existing_cd);
                /* Same as above, -EINVAL can randomly happen when it actually means -EEXIST */
                if (r == -EINVAL && FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE))
                        break;
                if (IN_SET(r,
                           -ENOENT, /* Removed?? */
                           -EBUSY,  /* Volume is being opened but not ready, crypt_init_by_name() can fetch details. */
                           -ENODEV  /* Volume is being opened but not ready, crypt_init_by_name() would fail, try to open again. */ ))
                        goto try_again;
                if (r < 0)
                        return log_debug_errno(r, "Failed to check if existing verity device %s can be reused: %m", node);

                if (fd < 0) {
                        /* devmapper might say that the device exists, but the devlink might not yet have been
                         * created. Check and wait for the udev event in that case. */
                        r = device_wait_for_devlink(node, "block", verity_timeout(), NULL);
                        /* Fallback to activation with a unique device if it's taking too long */
                        if (r == -ETIMEDOUT && FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE))
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to wait device node symlink %s: %m", node);
                }

        try_open:
                if (fd < 0) {
                        /* Now, the device is activated and devlink is created. Let's open it. */
                        fd = open(node, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                        if (fd < 0) {
                                if (!ERRNO_IS_DEVICE_ABSENT(errno))
                                        return log_debug_errno(errno, "Failed to open verity device %s: %m", node);

                                /* The device has already been removed?? */
                                goto try_again;
                        }
                }

                /* Everything looks good and we'll be able to mount the device, so deferred remove will be re-enabled at that point. */
                restore_deferred_remove = mfree(restore_deferred_remove);

                mount_node_fd = TAKE_FD(fd);
                if (existing_cd)
                        crypt_free_and_replace(cd, existing_cd);

                goto success;

        try_again:
                /* Device is being removed by another process. Let's wait for a while. */
                (void) usleep_safe(2 * USEC_PER_MSEC);
        }

        /* All trials failed or a conflicting verity device exists. Let's try to activate with a unique name. */
        if (FLAGS_SET(flags, DISSECT_IMAGE_VERITY_SHARE)) {
                /* Before trying to activate with unique name, we need to free crypt_device object.
                 * Otherwise, we get error from libcryptsetup like the following:
                 * ------
                 * systemd[1234]: Cannot use device /dev/loop5 which is in use (already mapped or mounted).
                 * ------
                 */
                sym_crypt_free(cd);
                cd = NULL;
                return verity_partition(designator, m, v, verity, flags & ~DISSECT_IMAGE_VERITY_SHARE, d);
        }

        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "All attempts to activate verity device %s failed.", name);

success:
        d->decrypted[d->n_decrypted++] = (DecryptedPartition) {
                .name = TAKE_PTR(name),
                .device = TAKE_PTR(cd),
        };

        m->decrypted_node = TAKE_PTR(node);
        close_and_replace(m->mount_node_fd, mount_node_fd);

        return 0;
}
#endif

int dissected_image_decrypt(
                DissectedImage *m,
                const char *passphrase,
                const VeritySettings *verity,
                DissectImageFlags flags) {

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

        if (!m->encrypted && !m->verity_ready)
                return 0;

#if HAVE_LIBCRYPTSETUP
        r = decrypted_image_new(&d);
        if (r < 0)
                return r;

        for (PartitionDesignator i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                DissectedPartition *p = m->partitions + i;
                PartitionDesignator k;

                if (!p->found)
                        continue;

                r = decrypt_partition(p, passphrase, flags, d);
                if (r < 0)
                        return r;

                k = partition_verity_of(i);
                if (k >= 0) {
                        r = verity_partition(i, p, m->partitions + k, verity, flags | DISSECT_IMAGE_VERITY_SHARE, d);
                        if (r < 0)
                                return r;
                }

                if (!p->decrypted_fstype && p->mount_node_fd >= 0 && p->decrypted_node) {
                        r = probe_filesystem_full(p->mount_node_fd, p->decrypted_node, 0, UINT64_MAX, &p->decrypted_fstype);
                        if (r < 0 && r != -EUCLEAN)
                                return r;
                }
        }

        m->decrypted_image = TAKE_PTR(d);

        return 1;
#else
        return -EOPNOTSUPP;
#endif
}

int dissected_image_decrypt_interactively(
                DissectedImage *m,
                const char *passphrase,
                const VeritySettings *verity,
                DissectImageFlags flags) {

        _cleanup_strv_free_erase_ char **z = NULL;
        int n = 3, r;

        if (passphrase)
                n--;

        for (;;) {
                r = dissected_image_decrypt(m, passphrase, verity, flags);
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

                r = ask_password_auto("Please enter image passphrase:", NULL, "dissect", "dissect", "dissect.passphrase", USEC_INFINITY, 0, &z);
                if (r < 0)
                        return log_error_errno(r, "Failed to query for passphrase: %m");

                passphrase = z[0];
        }
}

static int decrypted_image_relinquish(DecryptedImage *d) {
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

int dissected_image_relinquish(DissectedImage *m) {
        int r;

        assert(m);

        if (m->decrypted_image) {
                r = decrypted_image_relinquish(m->decrypted_image);
                if (r < 0)
                        return r;
        }

        if (m->loop)
                loop_device_relinquish(m->loop);

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

        r = getenv_bool_secure("SYSTEMD_DISSECT_VERITY_SIDECAR");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_DISSECT_VERITY_SIDECAR, ignoring: %m");
        if (r == 0)
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
                                r = getxattr_malloc(image, "user.verity.roothash", &text);
                                if (r < 0) {
                                        _cleanup_free_ char *p = NULL;

                                        if (r != -ENOENT && !ERRNO_IS_XATTR_ABSENT(r))
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
                                r = getxattr_malloc(image, "user.verity.usrhash", &text);
                                if (r < 0) {
                                        _cleanup_free_ char *p = NULL;

                                        if (r != -ENOENT && !ERRNO_IS_XATTR_ABSENT(r))
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

int dissected_image_load_verity_sig_partition(
                DissectedImage *m,
                int fd,
                VeritySettings *verity) {

        _cleanup_free_ void *root_hash = NULL, *root_hash_sig = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        size_t root_hash_size, root_hash_sig_size;
        _cleanup_free_ char *buf = NULL;
        PartitionDesignator d;
        DissectedPartition *p;
        JsonVariant *rh, *sig;
        ssize_t n;
        char *e;
        int r;

        assert(m);
        assert(fd >= 0);
        assert(verity);

        if (verity->root_hash && verity->root_hash_sig) /* Already loaded? */
                return 0;

        r = getenv_bool_secure("SYSTEMD_DISSECT_VERITY_EMBEDDED");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_DISSECT_VERITY_EMBEDDED, ignoring: %m");
        if (r == 0)
                return 0;

        d = partition_verity_sig_of(verity->designator < 0 ? PARTITION_ROOT : verity->designator);
        assert(d >= 0);

        p = m->partitions + d;
        if (!p->found)
                return 0;
        if (p->offset == UINT64_MAX || p->size == UINT64_MAX)
                return -EINVAL;

        if (p->size > 4*1024*1024) /* Signature data cannot possible be larger than 4M, refuse that */
                return log_debug_errno(SYNTHETIC_ERRNO(EFBIG), "Verity signature partition is larger than 4M, refusing.");

        buf = new(char, p->size+1);
        if (!buf)
                return -ENOMEM;

        n = pread(fd, buf, p->size, p->offset);
        if (n < 0)
                return -ENOMEM;
        if ((uint64_t) n != p->size)
                return -EIO;

        e = memchr(buf, 0, p->size);
        if (e) {
                /* If we found a NUL byte then the rest of the data must be NUL too */
                if (!memeqzero(e, p->size - (e - buf)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Signature data contains embedded NUL byte.");
        } else
                buf[p->size] = 0;

        r = json_parse(buf, 0, &v, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse signature JSON data: %m");

        rh = json_variant_by_key(v, "rootHash");
        if (!rh)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Signature JSON object lacks 'rootHash' field.");
        if (!json_variant_is_string(rh))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'rootHash' field of signature JSON object is not a string.");

        r = unhexmem(json_variant_string(rh), SIZE_MAX, &root_hash, &root_hash_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse root hash field: %m");

        /* Check if specified root hash matches if it is specified */
        if (verity->root_hash &&
            memcmp_nn(verity->root_hash, verity->root_hash_size, root_hash, root_hash_size) != 0) {
                _cleanup_free_ char *a = NULL, *b = NULL;

                a = hexmem(root_hash, root_hash_size);
                b = hexmem(verity->root_hash, verity->root_hash_size);

                return log_debug_errno(r, "Root hash in signature JSON data (%s) doesn't match configured hash (%s).", strna(a), strna(b));
        }

        sig = json_variant_by_key(v, "signature");
        if (!sig)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Signature JSON object lacks 'signature' field.");
        if (!json_variant_is_string(sig))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'signature' field of signature JSON object is not a string.");

        r = unbase64mem(json_variant_string(sig), SIZE_MAX, &root_hash_sig, &root_hash_sig_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse signature field: %m");

        free_and_replace(verity->root_hash, root_hash);
        verity->root_hash_size = root_hash_size;

        free_and_replace(verity->root_hash_sig, root_hash_sig);
        verity->root_hash_sig_size = root_hash_sig_size;

        return 1;
}

int dissected_image_acquire_metadata(
                DissectedImage *m,
                int userns_fd,
                DissectImageFlags extra_flags) {

        enum {
                META_HOSTNAME,
                META_MACHINE_ID,
                META_MACHINE_INFO,
                META_OS_RELEASE,
                META_INITRD_RELEASE,
                META_SYSEXT_RELEASE,
                META_CONFEXT_RELEASE,
                META_HAS_INIT_SYSTEM,
                _META_MAX,
        };

        static const char *const paths[_META_MAX] = {
                [META_HOSTNAME]          = "/etc/hostname\0",
                [META_MACHINE_ID]        = "/etc/machine-id\0",
                [META_MACHINE_INFO]      = "/etc/machine-info\0",
                [META_OS_RELEASE]        = "/etc/os-release\0"
                                           "/usr/lib/os-release\0",
                [META_INITRD_RELEASE]    = "/etc/initrd-release\0"
                                           "/usr/lib/initrd-release\0",
                [META_SYSEXT_RELEASE]    = "sysext-release\0",       /* String used only for logging. */
                [META_CONFEXT_RELEASE]   = "confext-release\0",      /* ditto */
                [META_HAS_INIT_SYSTEM]   = "has-init-system\0",      /* ditto */
        };

        _cleanup_strv_free_ char **machine_info = NULL, **os_release = NULL, **initrd_release = NULL, **sysext_release = NULL, **confext_release = NULL;
        _cleanup_free_ char *hostname = NULL, *t = NULL;
        _cleanup_close_pair_ int error_pipe[2] = EBADF_PAIR;
        _cleanup_(sigkill_waitp) pid_t child = 0;
        sd_id128_t machine_id = SD_ID128_NULL;
        unsigned n_meta_initialized = 0;
        int fds[2 * _META_MAX], r, v;
        int has_init_system = -1;
        ssize_t n;

        BLOCK_SIGNALS(SIGCHLD);

        assert(m);

        for (; n_meta_initialized < _META_MAX; n_meta_initialized ++) {
                assert(paths[n_meta_initialized]);

                if (pipe2(fds + 2*n_meta_initialized, O_CLOEXEC) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        r = get_common_dissect_directory(&t);
        if (r < 0)
                goto finish;

        if (pipe2(error_pipe, O_CLOEXEC) < 0) {
                r = -errno;
                goto finish;
        }

        r = safe_fork("(sd-dissect)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM, &child);
        if (r < 0)
                goto finish;
        if (r == 0) {
                /* Child */
                error_pipe[0] = safe_close(error_pipe[0]);

                if (userns_fd < 0)
                        r = detach_mount_namespace_harder(0, 0);
                else
                        r = detach_mount_namespace_userns(userns_fd);
                if (r < 0) {
                        log_debug_errno(r, "Failed to detach mount namespace: %m");
                        goto inner_fail;
                }

                r = dissected_image_mount(
                                m,
                                t,
                                /* uid_shift= */ UID_INVALID,
                                /* uid_range= */ UID_INVALID,
                                /* userns_fd= */ -EBADF,
                                extra_flags |
                                DISSECT_IMAGE_READ_ONLY |
                                DISSECT_IMAGE_MOUNT_ROOT_ONLY |
                                DISSECT_IMAGE_USR_NO_ROOT);
                if (r < 0) {
                        log_debug_errno(r, "Failed to mount dissected image: %m");
                        goto inner_fail;
                }

                for (unsigned k = 0; k < _META_MAX; k++) {
                        _cleanup_close_ int fd = -ENOENT;

                        assert(paths[k]);

                        fds[2*k] = safe_close(fds[2*k]);

                        switch (k) {

                        case META_SYSEXT_RELEASE:
                                if (!m->image_name)
                                        goto next;

                                /* As per the os-release spec, if the image is an extension it will have a
                                 * file named after the image name in extension-release.d/ - we use the image
                                 * name and try to resolve it with the extension-release helpers, as
                                 * sometimes the image names are mangled on deployment and do not match
                                 * anymore.  Unlike other paths this is not fixed, and the image name can be
                                 * mangled on deployment, so by calling into the helper we allow a fallback
                                 * that matches on the first extension-release file found in the directory,
                                 * if one named after the image cannot be found first. */
                                r = open_extension_release(
                                                t,
                                                IMAGE_SYSEXT,
                                                m->image_name,
                                                /* relax_extension_release_check= */ false,
                                                /* ret_path= */ NULL,
                                                &fd);
                                if (r < 0)
                                        fd = r;
                                break;

                        case META_CONFEXT_RELEASE:
                                if (!m->image_name)
                                        goto next;

                                /* As above */
                                r = open_extension_release(
                                                t,
                                                IMAGE_CONFEXT,
                                                m->image_name,
                                                /* relax_extension_release_check= */ false,
                                                /* ret_path= */ NULL,
                                                &fd);
                                if (r < 0)
                                        fd = r;

                                break;

                        case META_HAS_INIT_SYSTEM: {
                                bool found = false;

                                FOREACH_STRING(init,
                                               "/usr/lib/systemd/systemd",  /* systemd on /usr/ merged system */
                                               "/lib/systemd/systemd",      /* systemd on /usr/ non-merged systems */
                                               "/sbin/init") {              /* traditional path the Linux kernel invokes */

                                        r = chase(init, t, CHASE_PREFIX_ROOT, NULL, NULL);
                                        if (r < 0) {
                                                if (r != -ENOENT)
                                                        log_debug_errno(r, "Failed to resolve %s, ignoring: %m", init);
                                        } else {
                                                found = true;
                                                break;
                                        }
                                }

                                r = loop_write(fds[2*k+1], &found, sizeof(found));
                                if (r < 0)
                                        goto inner_fail;

                                goto next;
                        }

                        default:
                                NULSTR_FOREACH(p, paths[k]) {
                                        fd = chase_and_open(p, t, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
                                        if (fd >= 0)
                                                break;
                                }
                        }

                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to read %s file of image, ignoring: %m", paths[k]);
                                goto next;
                        }

                        r = copy_bytes(fd, fds[2*k+1], UINT64_MAX, 0);
                        if (r < 0)
                                goto inner_fail;

                next:
                        fds[2*k+1] = safe_close(fds[2*k+1]);
                }

                _exit(EXIT_SUCCESS);

        inner_fail:
                /* Let parent know the error */
                (void) write(error_pipe[1], &r, sizeof(r));
                _exit(EXIT_FAILURE);
        }

        error_pipe[1] = safe_close(error_pipe[1]);

        for (unsigned k = 0; k < _META_MAX; k++) {
                _cleanup_fclose_ FILE *f = NULL;

                assert(paths[k]);

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
                                log_debug_errno(r, "Failed to read /etc/hostname of image: %m");

                        break;

                case META_MACHINE_ID: {
                        _cleanup_free_ char *line = NULL;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read /etc/machine-id of image: %m");
                        else if (r == 33) {
                                r = sd_id128_from_string(line, &machine_id);
                                if (r < 0)
                                        log_debug_errno(r, "Image contains invalid /etc/machine-id: %s", line);
                        } else if (r == 0)
                                log_debug("/etc/machine-id file of image is empty.");
                        else if (streq(line, "uninitialized"))
                                log_debug("/etc/machine-id file of image is uninitialized (likely aborted first boot).");
                        else
                                log_debug("/etc/machine-id file of image has unexpected length %i.", r);

                        break;
                }

                case META_MACHINE_INFO:
                        r = load_env_file_pairs(f, "machine-info", &machine_info);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read /etc/machine-info of image: %m");

                        break;

                case META_OS_RELEASE:
                        r = load_env_file_pairs(f, "os-release", &os_release);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read OS release file of image: %m");

                        break;

                case META_INITRD_RELEASE:
                        r = load_env_file_pairs(f, "initrd-release", &initrd_release);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read initrd release file of image: %m");

                        break;

                case META_SYSEXT_RELEASE:
                        r = load_env_file_pairs(f, "sysext-release", &sysext_release);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read sysext release file of image: %m");

                        break;

                case META_CONFEXT_RELEASE:
                        r = load_env_file_pairs(f, "confext-release", &confext_release);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read confext release file of image: %m");

                        break;

                case META_HAS_INIT_SYSTEM: {
                        bool b = false;
                        size_t nr;

                        errno = 0;
                        nr = fread(&b, 1, sizeof(b), f);
                        if (nr != sizeof(b))
                                log_debug_errno(errno_or_else(EIO), "Failed to read has-init-system boolean: %m");
                        else
                                has_init_system = b;

                        break;
                }}
        }

        r = wait_for_terminate_and_check("(sd-dissect)", child, 0);
        child = 0;
        if (r < 0)
                goto finish;

        n = read(error_pipe[0], &v, sizeof(v));
        if (n < 0) {
                r = -errno;
                goto finish;
        }
        if (n == sizeof(v)) {
                r = v; /* propagate error sent to us from child */
                goto finish;
        }
        if (n != 0) {
                r = -EIO;
                goto finish;
        }
        if (r != EXIT_SUCCESS) {
                r = -EPROTO;
                goto finish;
        }

        free_and_replace(m->hostname, hostname);
        m->machine_id = machine_id;
        strv_free_and_replace(m->machine_info, machine_info);
        strv_free_and_replace(m->os_release, os_release);
        strv_free_and_replace(m->initrd_release, initrd_release);
        strv_free_and_replace(m->sysext_release, sysext_release);
        strv_free_and_replace(m->confext_release, confext_release);
        m->has_init_system = has_init_system;

finish:
        for (unsigned k = 0; k < n_meta_initialized; k++)
                safe_close_pair(fds + 2*k);

        return r;
}

Architecture dissected_image_architecture(DissectedImage *img) {
        assert(img);

        if (img->partitions[PARTITION_ROOT].found &&
            img->partitions[PARTITION_ROOT].architecture >= 0)
                return img->partitions[PARTITION_ROOT].architecture;

        if (img->partitions[PARTITION_USR].found &&
            img->partitions[PARTITION_USR].architecture >= 0)
                return img->partitions[PARTITION_USR].architecture;

        return _ARCHITECTURE_INVALID;
}

int dissect_loop_device(
                LoopDevice *loop,
                const VeritySettings *verity,
                const MountOptions *mount_options,
                const ImagePolicy *image_policy,
                DissectImageFlags flags,
                DissectedImage **ret) {

#if HAVE_BLKID
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        int r;

        assert(loop);

        r = dissected_image_new(loop->backing_file ?: loop->node, &m);
        if (r < 0)
                return r;

        m->loop = loop_device_ref(loop);
        m->image_size = m->loop->device_size;
        m->sector_size = m->loop->sector_size;

        r = dissect_image(m, loop->fd, loop->node, verity, mount_options, image_policy, flags);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(m);

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int dissect_loop_device_and_warn(
                LoopDevice *loop,
                const VeritySettings *verity,
                const MountOptions *mount_options,
                const ImagePolicy *image_policy,
                DissectImageFlags flags,
                DissectedImage **ret) {

        assert(loop);

        return dissect_log_error(
                        LOG_ERR,
                        dissect_loop_device(loop, verity, mount_options, image_policy, flags, ret),
                        loop->backing_file ?: loop->node,
                        verity);

}

bool dissected_image_verity_candidate(const DissectedImage *image, PartitionDesignator partition_designator) {
        assert(image);

        /* Checks if this partition could theoretically do Verity. For non-partitioned images this only works
         * if there's an external verity file supplied, for which we can consult .has_verity. For partitioned
         * images we only check the partition type.
         *
         * This call is used to decide whether to suppress or show a verity column in tabular output of the
         * image. */

        if (image->single_file_system)
                return partition_designator == PARTITION_ROOT && image->has_verity;

        return partition_verity_of(partition_designator) >= 0;
}

bool dissected_image_verity_ready(const DissectedImage *image, PartitionDesignator partition_designator) {
        PartitionDesignator k;

        assert(image);

        /* Checks if this partition has verity data available that we can activate. For non-partitioned this
         * works for the root partition, for others only if the associated verity partition was found. */

        if (!image->verity_ready)
                return false;

        if (image->single_file_system)
                return partition_designator == PARTITION_ROOT;

        k = partition_verity_of(partition_designator);
        return k >= 0 && image->partitions[k].found;
}

bool dissected_image_verity_sig_ready(const DissectedImage *image, PartitionDesignator partition_designator) {
        PartitionDesignator k;

        assert(image);

        /* Checks if this partition has verity signature data available that we can use. */

        if (!image->verity_sig_ready)
                return false;

        if (image->single_file_system)
                return partition_designator == PARTITION_ROOT;

        k = partition_verity_sig_of(partition_designator);
        return k >= 0 && image->partitions[k].found;
}

MountOptions* mount_options_free_all(MountOptions *options) {
        MountOptions *m;

        while ((m = LIST_POP(mount_options, options))) {
                free(m->options);
                free(m);
        }

        return NULL;
}

const char* mount_options_from_designator(const MountOptions *options, PartitionDesignator designator) {
        LIST_FOREACH(mount_options, m, options)
                if (designator == m->partition_designator && !isempty(m->options))
                        return m->options;

        return NULL;
}

int mount_image_privately_interactively(
                const char *image,
                const ImagePolicy *image_policy,
                DissectImageFlags flags,
                char **ret_directory,
                int *ret_dir_fd,
                LoopDevice **ret_loop_device) {

        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_free_ char *dir = NULL;
        int r;

        /* Mounts an OS image at a temporary place, inside a newly created mount namespace of our own. This
         * is used by tools such as systemd-tmpfiles or systemd-firstboot to operate on some disk image
         * easily. */

        assert(image);
        assert(ret_loop_device);

        /* We intend to mount this right-away, hence add the partitions if needed and pin them. */
        flags |= DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                DISSECT_IMAGE_PIN_PARTITION_DEVICES;

        r = verity_settings_load(&verity, image, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load root hash data: %m");

        r = loop_device_make_by_path(
                        image,
                        FLAGS_SET(flags, DISSECT_IMAGE_DEVICE_READ_ONLY) ? O_RDONLY : O_RDWR,
                        /* sector_size= */ UINT32_MAX,
                        FLAGS_SET(flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                        LOCK_SH,
                        &d);
        if (r < 0)
                return log_error_errno(r, "Failed to set up loopback device for %s: %m", image);

        r = dissect_loop_device_and_warn(
                        d,
                        &verity,
                        /* mount_options= */ NULL,
                        image_policy,
                        flags,
                        &dissected_image);
        if (r < 0)
                return r;

        r = dissected_image_load_verity_sig_partition(dissected_image, d->fd, &verity);
        if (r < 0)
                return r;

        r = dissected_image_decrypt_interactively(dissected_image, NULL, &verity, flags);
        if (r < 0)
                return r;

        r = detach_mount_namespace();
        if (r < 0)
                return log_error_errno(r, "Failed to detach mount namespace: %m");

        r = mkdir_p("/run/systemd/mount-rootfs", 0555);
        if (r < 0)
                return log_error_errno(r, "Failed to create mount point: %m");

        r = dissected_image_mount_and_warn(
                        dissected_image,
                        "/run/systemd/mount-rootfs",
                        /* uid_shift= */ UID_INVALID,
                        /* uid_range= */ UID_INVALID,
                        /* userns_fd= */ -EBADF,
                        flags);
        if (r < 0)
                return r;

        r = loop_device_flock(d, LOCK_UN);
        if (r < 0)
                return r;

        r = dissected_image_relinquish(dissected_image);
        if (r < 0)
                return log_error_errno(r, "Failed to relinquish DM and loopback block devices: %m");

        if (ret_directory) {
                dir = strdup("/run/systemd/mount-rootfs");
                if (!dir)
                        return log_oom();
        }

        if (ret_dir_fd) {
                _cleanup_close_ int dir_fd = -EBADF;

                dir_fd = open("/run/systemd/mount-rootfs", O_CLOEXEC|O_DIRECTORY);
                if (dir_fd < 0)
                        return log_error_errno(errno, "Failed to open mount point directory: %m");

                *ret_dir_fd = TAKE_FD(dir_fd);
        }

        if (ret_directory)
                *ret_directory = TAKE_PTR(dir);

        *ret_loop_device = TAKE_PTR(d);
        return 0;
}

static bool mount_options_relax_extension_release_checks(const MountOptions *options) {
        if (!options)
                return false;

        return string_contains_word(mount_options_from_designator(options, PARTITION_ROOT), ",", "x-systemd.relax-extension-release-check") ||
                        string_contains_word(mount_options_from_designator(options, PARTITION_USR), ",", "x-systemd.relax-extension-release-check") ||
                        string_contains_word(options->options, ",", "x-systemd.relax-extension-release-check");
}

int verity_dissect_and_mount(
                int src_fd,
                const char *src,
                const char *dest,
                const MountOptions *options,
                const ImagePolicy *image_policy,
                const char *required_host_os_release_id,
                const char *required_host_os_release_version_id,
                const char *required_host_os_release_sysext_level,
                const char *required_host_os_release_confext_level,
                const char *required_sysext_scope,
                DissectedImage **ret_image) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        DissectImageFlags dissect_image_flags;
        bool relax_extension_release_check;
        int r;

        assert(src);
        /* Verifying release metadata requires mounted image for now, so ensure the check is skipped when
         * opening an image without mounting it immediately (i.e.: 'dest' is NULL). */
        assert(!required_host_os_release_id || dest);

        relax_extension_release_check = mount_options_relax_extension_release_checks(options);

        /* We might get an FD for the image, but we use the original path to look for the dm-verity files */
        r = verity_settings_load(&verity, src, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load root hash: %m");

        dissect_image_flags = (verity.data_path ? DISSECT_IMAGE_NO_PARTITION_TABLE : 0) |
                (relax_extension_release_check ? DISSECT_IMAGE_RELAX_EXTENSION_CHECK : 0) |
                DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                DISSECT_IMAGE_PIN_PARTITION_DEVICES;

        /* Note that we don't use loop_device_make here, as the FD is most likely O_PATH which would not be
         * accepted by LOOP_CONFIGURE, so just let loop_device_make_by_path reopen it as a regular FD. */
        r = loop_device_make_by_path(
                        src_fd >= 0 ? FORMAT_PROC_FD_PATH(src_fd) : src,
                        /* open_flags= */ -1,
                        /* sector_size= */ UINT32_MAX,
                        verity.data_path ? 0 : LO_FLAGS_PARTSCAN,
                        LOCK_SH,
                        &loop_device);
        if (r < 0)
                return log_debug_errno(r, "Failed to create loop device for image: %m");

        r = dissect_loop_device(
                        loop_device,
                        &verity,
                        options,
                        image_policy,
                        dissect_image_flags,
                        &dissected_image);
        /* No partition table? Might be a single-filesystem image, try again */
        if (!verity.data_path && r == -ENOPKG)
                 r = dissect_loop_device(
                                loop_device,
                                &verity,
                                options,
                                image_policy,
                                dissect_image_flags | DISSECT_IMAGE_NO_PARTITION_TABLE,
                                &dissected_image);
        if (r < 0)
                return log_debug_errno(r, "Failed to dissect image: %m");

        r = dissected_image_load_verity_sig_partition(dissected_image, loop_device->fd, &verity);
        if (r < 0)
                return r;

        r = dissected_image_decrypt(
                        dissected_image,
                        NULL,
                        &verity,
                        dissect_image_flags);
        if (r < 0)
                return log_debug_errno(r, "Failed to decrypt dissected image: %m");

        if (dest) {
                r = mkdir_p_label(dest, 0755);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create destination directory %s: %m", dest);
                r = umount_recursive(dest, 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to umount under destination directory %s: %m", dest);
        }

        r = dissected_image_mount(
                        dissected_image,
                        dest,
                        /* uid_shift= */ UID_INVALID,
                        /* uid_range= */ UID_INVALID,
                        /* userns_fd= */ -EBADF,
                        dissect_image_flags);
        if (r < 0)
                return log_debug_errno(r, "Failed to mount image: %m");

        r = loop_device_flock(loop_device, LOCK_UN);
        if (r < 0)
                return log_debug_errno(r, "Failed to unlock loopback device: %m");

        /* If we got os-release values from the caller, then we need to match them with the image's
         * extension-release.d/ content. Return -EINVAL if there's any mismatch.
         * First, check the distro ID. If that matches, then check the new SYSEXT_LEVEL value if
         * available, or else fallback to VERSION_ID. If neither is present (eg: rolling release),
         * then a simple match on the ID will be performed. */
        if (required_host_os_release_id) {
                _cleanup_strv_free_ char **extension_release = NULL;
                ImageClass class = IMAGE_SYSEXT;

                assert(!isempty(required_host_os_release_id));

                r = load_extension_release_pairs(dest, IMAGE_SYSEXT, dissected_image->image_name, relax_extension_release_check, &extension_release);
                if (r == -ENOENT) {
                        r = load_extension_release_pairs(dest, IMAGE_CONFEXT, dissected_image->image_name, relax_extension_release_check, &extension_release);
                        if (r >= 0)
                                class = IMAGE_CONFEXT;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse image %s extension-release metadata: %m", dissected_image->image_name);

                r = extension_release_validate(
                                dissected_image->image_name,
                                required_host_os_release_id,
                                required_host_os_release_version_id,
                                class == IMAGE_SYSEXT ? required_host_os_release_sysext_level : required_host_os_release_confext_level,
                                required_sysext_scope,
                                extension_release,
                                class);
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Image %s extension-release metadata does not match the root's", dissected_image->image_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to compare image %s extension-release metadata with the root's os-release: %m", dissected_image->image_name);
        }

        r = dissected_image_relinquish(dissected_image);
        if (r < 0)
                return log_debug_errno(r, "Failed to relinquish dissected image: %m");

        if (ret_image)
                *ret_image = TAKE_PTR(dissected_image);

        return 0;
}

int get_common_dissect_directory(char **ret) {
        _cleanup_free_ char *t = NULL;
        int r;

        /* A common location we mount dissected images to. The assumption is that everyone who uses this
         * function runs in their own private mount namespace (with mount propagation off on /run/systemd/,
         * and thus can mount something here without affecting anyone else. */

        t = strdup("/run/systemd/dissect-root");
        if (!t)
                return -ENOMEM;

        r = mkdir_p(t, 0000); /* It's supposed to be overmounted, hence let's make this unnaccessible */
        if (r < 0)
                return log_error_errno(r, "Failed to create mount point '%s': %m", t);

        if (ret)
                *ret = TAKE_PTR(t);

        return 0;
}
