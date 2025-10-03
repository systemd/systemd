/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <stdlib.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-gpt.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "btrfs-util.h"
#include "chase.h"
#include "device-util.h"
#include "devnum-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "find-esp.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

typedef enum VerifyESPFlags {
        VERIFY_ESP_SEARCHING         = 1 << 0, /* Downgrade various "not found" logs to debug level */
        VERIFY_ESP_UNPRIVILEGED_MODE = 1 << 1, /* Call into udev rather than blkid */
        VERIFY_ESP_SKIP_FSTYPE_CHECK = 1 << 2, /* Skip filesystem check */
        VERIFY_ESP_SKIP_DEVICE_CHECK = 1 << 3, /* Skip device node check  */
} VerifyESPFlags;

static VerifyESPFlags verify_esp_flags_init(int unprivileged_mode, const char *env_name_for_relaxing) {
        VerifyESPFlags flags = 0;
        int r;

        assert(env_name_for_relaxing);

        if (unprivileged_mode < 0)
                unprivileged_mode = geteuid() != 0;
        if (unprivileged_mode)
                flags |= VERIFY_ESP_UNPRIVILEGED_MODE;

        r = getenv_bool(env_name_for_relaxing);
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $%s environment variable, assuming false.", env_name_for_relaxing);
        else if (r > 0)
                flags |= VERIFY_ESP_SKIP_FSTYPE_CHECK | VERIFY_ESP_SKIP_DEVICE_CHECK;

        if (detect_container() > 0)
                flags |= VERIFY_ESP_SKIP_DEVICE_CHECK;

        return flags;
}

static int verify_esp_blkid(
                dev_t devid,
                VerifyESPFlags flags,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;

#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *node = NULL;
        bool searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING);
        const char *v;
        int r;

        r = dlopen_libblkid();
        if (r < 0)
                return log_debug_errno(r, "No libblkid support: %m");

        r = devname_from_devnum(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to get device path for " DEVNUM_FORMAT_STR ": %m", DEVNUM_FORMAT_VAL(devid));

        errno = 0;
        b = sym_blkid_new_probe_from_filename(node);
        if (!b)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(ENOMEM), "Failed to open file system \"%s\": %m", node);

        sym_blkid_probe_enable_superblocks(b, 1);
        sym_blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        sym_blkid_probe_enable_partitions(b, 1);
        sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == -2)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" is ambiguous.", node);
        if (r == 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" does not contain a label.", node);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe file system \"%s\": %m", node);

        r = sym_blkid_probe_lookup_value(b, "TYPE", &v, NULL);
        if (r != 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "No filesystem found on \"%s\".", node);
        if (!streq(v, "vfat"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not FAT.", node);

        r = sym_blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not located on a partitioned block device.", node);
        if (!streq(v, "gpt"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not on a GPT partition table.", node);

        errno = 0;
        r = sym_blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition type UUID of \"%s\": %m", node);
        if (sd_id128_string_equal(v, SD_GPT_ESP) <= 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                       SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                       "File system \"%s\" has wrong type for an EFI System Partition (ESP).", node);

        r = blkid_probe_lookup_value_id128(b, "PART_ENTRY_UUID", &uuid);
        if (r < 0)
                return log_error_errno(r, "Failed to probe partition entry UUID of \"%s\": %m", node);

        errno = 0;
        r = sym_blkid_probe_lookup_value(b, "PART_ENTRY_NUMBER", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition number of \"%s\": %m", node);
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_NUMBER field.");

        r = blkid_probe_lookup_value_u64(b, "PART_ENTRY_OFFSET", &pstart);
        if (r < 0)
                return log_error_errno(r, "Failed to probe partition offset of \"%s\": %m", node);

        r = blkid_probe_lookup_value_u64(b, "PART_ENTRY_SIZE", &psize);
        if (r < 0)
                return log_error_errno(r, "Failed to probe partition size of \"%s\": %m", node);
#endif

        if (ret_part)
                *ret_part = part;
        if (ret_pstart)
                *ret_pstart = pstart;
        if (ret_psize)
                *ret_psize = psize;
        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_esp_udev(
                dev_t devid,
                VerifyESPFlags flags,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        bool searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING);
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;
        const char *node, *v;
        int r;

        r = sd_device_new_from_devnum(&d, 'b', devid);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from device number: %m");

        r = sd_device_get_devname(d, &node);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device node: %m");

        r = sd_device_get_property_value(d, "ID_FS_TYPE", &v);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device property: %m");
        if (!streq(v, "vfat"))
                return log_device_full_errno(d,
                                             searching ? LOG_DEBUG : LOG_ERR,
                                             SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                             "File system \"%s\" is not FAT.", node );

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SCHEME", &v);
        if (r < 0)
                return log_device_full_errno(d,
                                             searching && r == -ENOENT ? LOG_DEBUG : LOG_ERR,
                                             searching && r == -ENOENT ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : r,
                                             "Failed to get device property: %m");
        if (!streq(v, "gpt"))
                return log_device_full_errno(d,
                                             searching ? LOG_DEBUG : LOG_ERR,
                                             SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                             "File system \"%s\" is not on a GPT partition table.", node);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &v);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device property: %m");
        if (sd_id128_string_equal(v, SD_GPT_ESP) <= 0)
                return log_device_full_errno(d,
                                             searching ? LOG_DEBUG : LOG_ERR,
                                             SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                             "File system \"%s\" has wrong type for an EFI System Partition (ESP).", node);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_UUID", &v);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device property: %m");
        r = sd_id128_from_string(v, &uuid);
        if (r < 0)
                return log_device_error_errno(d, r, "Partition \"%s\" has invalid UUID \"%s\".", node, v);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_NUMBER", &v);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device property: %m");
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to parse PART_ENTRY_NUMBER field.");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_OFFSET", &v);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device property: %m");
        r = safe_atou64(v, &pstart);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to parse PART_ENTRY_OFFSET field.");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SIZE", &v);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device property: %m");
        r = safe_atou64(v, &psize);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to parse PART_ENTRY_SIZE field.");

        if (ret_part)
                *ret_part = part;
        if (ret_pstart)
                *ret_pstart = pstart;
        if (ret_psize)
                *ret_psize = psize;
        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_fsroot_dir(
                int dir_fd,
                const char *path,
                VerifyESPFlags flags,
                dev_t *ret_dev) {

        bool searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING),
                unprivileged_mode = FLAGS_SET(flags, VERIFY_ESP_UNPRIVILEGED_MODE);
        _cleanup_free_ char *f = NULL;
        struct statx sx;
        int r;

        /* Checks if the specified directory is at the root of its file system, and returns device
         * major/minor of the device, if it is. */

        assert(dir_fd >= 0);
        assert(path);

        /* We pass the full path from the root directory file descriptor so we can use it for logging, but
         * dir_fd points to the parent directory of the final component of the given path, so we extract the
         * filename and operate on that. */

        r = path_extract_filename(path, &f);
        if (r < 0 && r != -EADDRNOTAVAIL)
                return log_error_errno(r, "Failed to extract filename of %s: %m", path);

        if (statx(dir_fd, strempty(f),
                  AT_SYMLINK_NOFOLLOW|(isempty(f) ? AT_EMPTY_PATH : 0),
                  STATX_TYPE|STATX_INO|STATX_MNT_ID, &sx) < 0)
                return log_full_errno((searching && errno == ENOENT) ||
                                      (unprivileged_mode && ERRNO_IS_PRIVILEGE(errno)) ? LOG_DEBUG : LOG_ERR, errno,
                                      "Failed to determine block device node of \"%s\": %m", path);

        assert(S_ISDIR(sx.stx_mode)); /* We used O_DIRECTORY above, when opening, so this must hold */

        if (!FLAGS_SET(sx.stx_attributes_mask, STATX_ATTR_MOUNT_ROOT))
                return log_error_errno(SYNTHETIC_ERRNO(ENOSYS), "statx() does not provides STATX_ATTR_MOUNT_ROOT, running on an old kernel?");

        if (!FLAGS_SET(sx.stx_attributes, STATX_ATTR_MOUNT_ROOT))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "Directory \"%s\" is not the root of the file system.", path);

        if (!ret_dev)
                return 0;

        if (sx.stx_dev_major == 0) /* Hmm, maybe a btrfs device, and the caller asked for the backing device? Then let's try to get it. */
                return btrfs_get_block_device_at(dir_fd, strempty(f), ret_dev);

        *ret_dev = makedev(sx.stx_dev_major, sx.stx_dev_minor);
        return 0;
}

static int verify_esp(
                int rfd,
                const char *path,
                char **ret_path,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid,
                VerifyESPFlags flags) {

        bool searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING),
                unprivileged_mode = FLAGS_SET(flags, VERIFY_ESP_UNPRIVILEGED_MODE);
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int pfd = -EBADF;
        dev_t devid = 0;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(path);

        /* This logs about all errors, except:
         *
         *  -ENOENT        → if 'searching' is set, and the dir doesn't exist
         *  -EADDRNOTAVAIL → if 'searching' is set, and the dir doesn't look like an ESP
         *  -EACESS        → if 'unprivileged_mode' is set, and we have trouble accessing the thing
         */

        /* Non-root user can only check the status, so if an error occurred in the following, it does not cause any
         * issues. Let's also, silence the error messages. */

        r = chaseat(rfd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_TRIGGER_AUTOFS, &p, &pfd);
        if (r < 0)
                return log_full_errno((searching && r == -ENOENT) ||
                                      (unprivileged_mode && ERRNO_IS_PRIVILEGE(r)) ? LOG_DEBUG : LOG_ERR,
                                      r, "Failed to open parent directory of \"%s\": %m", path);

        if (!FLAGS_SET(flags, VERIFY_ESP_SKIP_FSTYPE_CHECK)) {
                _cleanup_free_ char *f = NULL;
                struct statfs sfs;

                r = path_extract_filename(p, &f);
                if (r < 0 && r != -EADDRNOTAVAIL)
                        return log_error_errno(r, "Failed to extract filename of %s: %m", p);

                /* Trigger any automounts so that xstatfsat() operates on the mount instead of the mountpoint
                 * directory. */
                r = trigger_automount_at(pfd, f);
                if (r < 0)
                        return log_error_errno(r, "Failed to trigger automount at %s: %m", p);

                r = xstatfsat(pfd, strempty(f), &sfs);
                if (r < 0)
                        /* If we are searching for the mount point, don't generate a log message if we can't find the path */
                        return log_full_errno((searching && r == -ENOENT) ||
                                              (unprivileged_mode && r == -EACCES) ? LOG_DEBUG : LOG_ERR, r,
                                              "Failed to check file system type of \"%s\": %m", p);

                if (!F_TYPE_EQUAL(sfs.f_type, MSDOS_SUPER_MAGIC))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                              "File system \"%s\" is not a FAT EFI System Partition (ESP) file system.", p);
        }

        r = verify_fsroot_dir(pfd, p, flags, FLAGS_SET(flags, VERIFY_ESP_SKIP_DEVICE_CHECK) ? NULL : &devid);
        if (r < 0)
                return r;

        /* In a container we don't have access to block devices, skip this part of the verification, we trust
         * the container manager set everything up correctly on its own. */
        if (FLAGS_SET(flags, VERIFY_ESP_SKIP_DEVICE_CHECK))
                goto finish;

        if (devnum_is_zero(devid))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "Could not determine backing block device of directory \"%s\" (btrfs RAID?).", p);

        /* If we are unprivileged we ask udev for the metadata about the partition. If we are privileged we
         * use blkid instead. Why? Because this code is called from 'bootctl' which is pretty much an
         * emergency recovery tool that should also work when udev isn't up (i.e. from the emergency shell),
         * however blkid can't work if we have no privileges to access block devices directly, which is why
         * we use udev in that case. */
        if (unprivileged_mode)
                r = verify_esp_udev(devid, flags, ret_part, ret_pstart, ret_psize, ret_uuid);
        else
                r = verify_esp_blkid(devid, flags, ret_part, ret_pstart, ret_psize, ret_uuid);
        if (r < 0)
                return r;

        if (ret_path)
                *ret_path = TAKE_PTR(p);
        if (ret_devid)
                *ret_devid = devid;

        return 0;

finish:
        if (ret_path)
                *ret_path = TAKE_PTR(p);
        if (ret_part)
                *ret_part = 0;
        if (ret_pstart)
                *ret_pstart = 0;
        if (ret_psize)
                *ret_psize = 0;
        if (ret_uuid)
                *ret_uuid = SD_ID128_NULL;
        if (ret_devid)
                *ret_devid = 0;

        return 0;
}

int find_esp_and_warn_at(
                int rfd,
                const char *path,
                int unprivileged_mode,
                char **ret_path,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        VerifyESPFlags flags;
        int r;

        /* This logs about all errors except:
         *
         *    -ENOKEY → when we can't find the partition
         *   -EACCESS → when unprivileged_mode is true, and we can't access something
         */

        assert(rfd >= 0 || rfd == AT_FDCWD);

        flags = verify_esp_flags_init(unprivileged_mode, "SYSTEMD_RELAX_ESP_CHECKS");

        if (path)
                return verify_esp(rfd, path, ret_path, ret_part, ret_pstart, ret_psize, ret_uuid, ret_devid, flags);

        path = getenv("SYSTEMD_ESP_PATH");
        if (path) {
                _cleanup_free_ char *p = NULL;
                _cleanup_close_ int fd = -EBADF;
                struct stat st;

                if (!path_is_valid(path) || !path_is_absolute(path))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "$SYSTEMD_ESP_PATH does not refer to an absolute path, refusing to use it: %s",
                                               path);

                r = chaseat(rfd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_TRIGGER_AUTOFS, &p, &fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path %s: %m", path);

                /* Note: when the user explicitly configured things with an env var we won't validate the
                 * path beyond checking it refers to a directory. After all we want this to be useful for
                 * testing. */

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", p);
                if (!S_ISDIR(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "ESP path '%s' is not a directory.", p);

                if (ret_path)
                        *ret_path = TAKE_PTR(p);
                if (ret_part)
                        *ret_part = 0;
                if (ret_pstart)
                        *ret_pstart = 0;
                if (ret_psize)
                        *ret_psize = 0;
                if (ret_uuid)
                        *ret_uuid = SD_ID128_NULL;
                if (ret_devid)
                        *ret_devid = st.st_dev;

                return 0;
        }

        FOREACH_STRING(dir, "/efi", "/boot", "/boot/efi") {
                r = verify_esp(rfd, dir, ret_path, ret_part, ret_pstart, ret_psize, ret_uuid, ret_devid,
                               flags | VERIFY_ESP_SEARCHING);
                if (r >= 0)
                        return 0;
                if (!IN_SET(r, -ENOENT, -EADDRNOTAVAIL, -ENOTDIR, -ENOTTY)) /* This one is not it */
                        return r;
        }

        /* No logging here */
        return -ENOKEY;
}

int find_esp_and_warn(
                const char *root,
                const char *path,
                int unprivileged_mode,
                char **ret_path,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        _cleanup_close_ int rfd = -EBADF;
        _cleanup_free_ char *p = NULL;
        uint32_t part;
        uint64_t pstart, psize;
        sd_id128_t uuid;
        dev_t devid;
        int r;

        rfd = open(empty_to_root(root), O_PATH|O_DIRECTORY|O_CLOEXEC);
        if (rfd < 0)
                return -errno;

        r = find_esp_and_warn_at(
                        rfd,
                        path,
                        unprivileged_mode,
                        ret_path ? &p : NULL,
                        ret_part ? &part : NULL,
                        ret_pstart ? &pstart : NULL,
                        ret_psize ? &psize : NULL,
                        ret_uuid ? &uuid : NULL,
                        ret_devid ? &devid : NULL);
        if (r < 0)
                return r;

        if (ret_path) {
                r = chaseat_prefix_root(p, root, ret_path);
                if (r < 0)
                        return r;
        }
        if (ret_part)
                *ret_part = part;
        if (ret_pstart)
                *ret_pstart = pstart;
        if (ret_psize)
                *ret_psize = psize;
        if (ret_uuid)
                *ret_uuid = uuid;
        if (ret_devid)
                *ret_devid = devid;

        return 0;
}

static int verify_xbootldr_blkid(
                dev_t devid,
                VerifyESPFlags flags,
                sd_id128_t *ret_uuid) {

        sd_id128_t uuid = SD_ID128_NULL;

#if HAVE_BLKID
        bool searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING);
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *node = NULL;
        const char *type, *v;
        int r;

        r = dlopen_libblkid();
        if (r < 0)
                return log_debug_errno(r, "No libblkid support: %m");

        r = devname_from_devnum(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to get block device path for " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devid));

        errno = 0;
        b = sym_blkid_new_probe_from_filename(node);
        if (!b)
                return log_error_errno(errno_or_else(ENOMEM), "%s: Failed to create blkid probe: %m", node);

        sym_blkid_probe_enable_partitions(b, 1);
        sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_AMBIGUOUS)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "%s: File system is ambiguous.", node);
        if (r == _BLKID_SAFEPROBE_NOT_FOUND)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "%s: File system does not contain a label.", node);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return log_error_errno(errno_or_else(EIO), "%s: Failed to probe file system: %m", node);

        assert(r == _BLKID_SAFEPROBE_FOUND);

        r = sym_blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &type, NULL);
        if (r != 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(EIO),
                                      "%s: Failed to probe PART_ENTRY_SCHEME.", node);
        if (streq(type, "gpt")) {

                errno = 0;
                r = sym_blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno_or_else(EIO), "%s: Failed to probe PART_ENTRY_TYPE: %m", node);
                if (sd_id128_string_equal(v, SD_GPT_XBOOTLDR) <= 0)
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                              "%s: Partition has wrong PART_ENTRY_TYPE=%s for XBOOTLDR partition.", node, v);

                r = blkid_probe_lookup_value_id128(b, "PART_ENTRY_UUID", &uuid);
                if (r < 0)
                        return log_error_errno(r, "%s: Failed to probe PART_ENTRY_UUID: %m", node);

        } else if (streq(type, "dos")) {

                errno = 0;
                r = sym_blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno_or_else(EIO), "%s: Failed to probe PART_ENTRY_TYPE: %m", node);
                if (!streq(v, "0xea"))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                              "%s: Wrong PART_ENTRY_TYPE=%s for XBOOTLDR partition.", node, v);

        } else
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                      "%s: Not on a GPT or DOS partition table (PART_ENTRY_SCHEME=%s).", node, type);
#endif

        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_xbootldr_udev(
                dev_t devid,
                VerifyESPFlags flags,
                sd_id128_t *ret_uuid) {

        bool searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING);
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        sd_id128_t uuid = SD_ID128_NULL;
        const char *node, *type, *v;
        int r;

        r = sd_device_new_from_devnum(&d, 'b', devid);
        if (r < 0)
                return log_error_errno(r, "Failed to get block device for " DEVNUM_FORMAT_STR ": %m", DEVNUM_FORMAT_VAL(devid));

        r = sd_device_get_devname(d, &node);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device node: %m");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SCHEME", &type);
        if (r < 0)
                return log_device_full_errno(d,
                                             searching && r == -ENOENT ? LOG_DEBUG : LOG_ERR,
                                             searching && r == -ENOENT ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : r,
                                             "Failed to query ID_PART_ENTRY_SCHEME: %m");

        if (streq(type, "gpt")) {

                r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &v);
                if (r < 0)
                        return log_device_error_errno(d, r, "Failed to query ID_PART_ENTRY_TYPE: %m");

                r = sd_id128_string_equal(v, SD_GPT_XBOOTLDR);
                if (r < 0)
                        return log_device_error_errno(d, r, "Failed to parse ID_PART_ENTRY_TYPE=%s: %m", v);
                if (r == 0)
                        return log_device_full_errno(
                                        d,
                                        searching ? LOG_DEBUG : LOG_ERR,
                                        searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                        "Partition has wrong ID_PART_ENTRY_TYPE=%s for XBOOTLDR partition.", v);

                r = sd_device_get_property_value(d, "ID_PART_ENTRY_UUID", &v);
                if (r < 0)
                        return log_device_error_errno(d, r, "Failed to query ID_PART_ENTRY_UUID: %m");
                r = sd_id128_from_string(v, &uuid);
                if (r < 0)
                        return log_device_error_errno(d, r, "Partition has invalid UUID ID_PART_ENTRY_TYPE=%s: %m", v);

        } else if (streq(type, "dos")) {

                r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &v);
                if (r < 0)
                        return log_device_error_errno(d, r, "Failed to query ID_PART_ENTRY_TYPE: %m");
                if (!streq(v, "0xea"))
                        return log_device_full_errno(
                                        d,
                                        searching ? LOG_DEBUG : LOG_ERR,
                                        searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                        "Wrong ID_PART_ENTRY_TYPE=%s for XBOOTLDR partition.", v);

        } else
                return log_device_full_errno(
                                d,
                                searching ? LOG_DEBUG : LOG_ERR,
                                searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                "Not on a GPT or DOS partition table (ID_PART_ENTRY_SCHEME=%s).", type);

        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_xbootldr(
                int rfd,
                const char *path,
                VerifyESPFlags flags,
                char **ret_path,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int pfd = -EBADF;
        bool searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING),
                unprivileged_mode = FLAGS_SET(flags, VERIFY_ESP_UNPRIVILEGED_MODE);
        dev_t devid = 0;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(path);

        r = chaseat(rfd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_TRIGGER_AUTOFS, &p, &pfd);
        if (r < 0)
                return log_full_errno((searching && r == -ENOENT) ||
                                      (unprivileged_mode && ERRNO_IS_PRIVILEGE(r)) ? LOG_DEBUG : LOG_ERR,
                                      r, "Failed to open parent directory of \"%s\": %m", path);

        r = verify_fsroot_dir(pfd, p, flags, FLAGS_SET(flags, VERIFY_ESP_SKIP_DEVICE_CHECK) ? NULL : &devid);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, VERIFY_ESP_SKIP_DEVICE_CHECK))
                goto finish;

        if (devnum_is_zero(devid))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "Could not determine backing block device of directory \"%s\" (btrfs RAID?).%s",
                                      p,
                                      searching ? "" :
                                      "\nHint: set $SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes environment variable "
                                      "to bypass this and further verifications for the directory.");

        if (unprivileged_mode)
                r = verify_xbootldr_udev(devid, flags, ret_uuid);
        else
                r = verify_xbootldr_blkid(devid, flags, ret_uuid);
        if (r < 0)
                return r;

        if (ret_path)
                *ret_path = TAKE_PTR(p);
        if (ret_devid)
                *ret_devid = devid;

        return 0;

finish:
        if (ret_path)
                *ret_path = TAKE_PTR(p);
        if (ret_uuid)
                *ret_uuid = SD_ID128_NULL;
        if (ret_devid)
                *ret_devid = 0;

        return 0;
}

int find_xbootldr_and_warn_at(
                int rfd,
                const char *path,
                int unprivileged_mode,
                char **ret_path,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        VerifyESPFlags flags;
        int r;

        /* Similar to find_esp_and_warn(), but finds the XBOOTLDR partition. Returns the same errors. */

        assert(rfd >= 0 || rfd == AT_FDCWD);

        flags = verify_esp_flags_init(unprivileged_mode, "SYSTEMD_RELAX_XBOOTLDR_CHECKS");

        if (path)
                return verify_xbootldr(rfd, path, flags, ret_path, ret_uuid, ret_devid);

        path = getenv("SYSTEMD_XBOOTLDR_PATH");
        if (path) {
                _cleanup_free_ char *p = NULL;
                _cleanup_close_ int fd = -EBADF;
                struct stat st;

                if (!path_is_valid(path) || !path_is_absolute(path))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "$SYSTEMD_XBOOTLDR_PATH does not refer to an absolute path, refusing to use it: %s",
                                               path);

                r = chaseat(rfd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_TRIGGER_AUTOFS, &p, &fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path %s: %m", p);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", p);
                if (!S_ISDIR(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "XBOOTLDR path '%s' is not a directory.", p);

                if (ret_path)
                        *ret_path = TAKE_PTR(p);
                if (ret_uuid)
                        *ret_uuid = SD_ID128_NULL;
                if (ret_devid)
                        *ret_devid = st.st_dev;

                return 0;
        }

        r = verify_xbootldr(rfd, "/boot", flags | VERIFY_ESP_SEARCHING, ret_path, ret_uuid, ret_devid);
        if (r < 0) {
                if (!IN_SET(r, -ENOENT, -EADDRNOTAVAIL, -ENOTDIR, -ENOTTY)) /* This one is not it */
                        return r;

                return -ENOKEY;
        }

        return 0;
}

int find_xbootldr_and_warn(
                const char *root,
                const char *path,
                int unprivileged_mode,
                char **ret_path,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        _cleanup_close_ int rfd = -EBADF;
        _cleanup_free_ char *p = NULL;
        sd_id128_t uuid;
        dev_t devid;
        int r;

        rfd = open(empty_to_root(root), O_PATH|O_DIRECTORY|O_CLOEXEC);
        if (rfd < 0)
                return -errno;

        r = find_xbootldr_and_warn_at(
                        rfd,
                        path,
                        unprivileged_mode,
                        ret_path ? &p : NULL,
                        ret_uuid ? &uuid : NULL,
                        ret_devid ? &devid : NULL);
        if (r < 0)
                return r;

        if (ret_path) {
                r = chaseat_prefix_root(p, root, ret_path);
                if (r < 0)
                        return r;
        }
        if (ret_uuid)
                *ret_uuid = uuid;
        if (ret_devid)
                *ret_devid = devid;

        return 0;
}
