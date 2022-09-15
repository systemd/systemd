/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <sys/vfs.h>

#include "sd-device.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "chase-symlinks.h"
#include "device-util.h"
#include "devnum-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "find-esp.h"
#include "gpt.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "virt.h"

typedef enum VerifyESPFlags {
        VERIFY_ESP_SEARCHING         = 1 << 0, /* Downgrade various "not found" logs to debug level */
        VERIFY_ESP_UNPRIVILEGED_MODE = 1 << 1, /* Call into udev rather than blkid */
        VERIFY_ESP_RELAX_CHECKS      = 1 << 2, /* Do not validate ESP partition */
} VerifyESPFlags;

static int verify_esp_blkid(
                dev_t devid,
                bool searching,
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
        const char *v;
        int r;

        r = devname_from_devnum(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to get device path for " DEVNUM_FORMAT_STR ": %m", DEVNUM_FORMAT_VAL(devid));

        errno = 0;
        b = blkid_new_probe_from_filename(node);
        if (!b)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(ENOMEM), "Failed to open file system \"%s\": %m", node);

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" is ambiguous.", node);
        else if (r == 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" does not contain a label.", node);
        else if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe file system \"%s\": %m", node);

        r = blkid_probe_lookup_value(b, "TYPE", &v, NULL);
        if (r != 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "No filesystem found on \"%s\": %m", node);
        if (!streq(v, "vfat"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not FAT.", node);

        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not located on a partitioned block device.", node);
        if (!streq(v, "gpt"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not on a GPT partition table.", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition type UUID of \"%s\": %m", node);
        if (sd_id128_string_equal(v, SD_GPT_ESP) <= 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                       SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                       "File system \"%s\" has wrong type for an EFI System Partition (ESP).", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition entry UUID of \"%s\": %m", node);
        r = sd_id128_from_string(v, &uuid);
        if (r < 0)
                return log_error_errno(r, "Partition \"%s\" has invalid UUID \"%s\".", node, v);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_NUMBER", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition number of \"%s\": %m", node);
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_NUMBER field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_OFFSET", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition offset of \"%s\": %m", node);
        r = safe_atou64(v, &pstart);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_OFFSET field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SIZE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition size of \"%s\": %m", node);
        r = safe_atou64(v, &psize);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_SIZE field.");
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
                bool searching,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

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
                return log_error_errno(r, "Failed to get device node: %m");

        r = sd_device_get_property_value(d, "ID_FS_TYPE", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        if (!streq(v, "vfat"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not FAT.", node );

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SCHEME", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        if (!streq(v, "gpt"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not on a GPT partition table.", node);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        if (sd_id128_string_equal(v, SD_GPT_ESP) <= 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                       SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                       "File system \"%s\" has wrong type for an EFI System Partition (ESP).", node);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_UUID", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = sd_id128_from_string(v, &uuid);
        if (r < 0)
                return log_error_errno(r, "Partition \"%s\" has invalid UUID \"%s\".", node, v);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_NUMBER", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_NUMBER field.");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_OFFSET", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = safe_atou64(v, &pstart);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_OFFSET field.");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SIZE", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = safe_atou64(v, &psize);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_SIZE field.");

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
                const char *path,
                bool searching,
                bool unprivileged_mode,
                dev_t *ret_dev) {

        struct stat st, st2;
        const char *t2, *trigger;
        int r;

        assert(path);
        assert(ret_dev);

        /* So, the ESP and XBOOTLDR partition are commonly located on an autofs mount. stat() on the
         * directory won't trigger it, if it is not mounted yet. Let's hence explicitly trigger it here,
         * before stat()ing */
        trigger = strjoina(path, "/trigger"); /* Filename doesn't matter... */
        (void) access(trigger, F_OK);

        if (stat(path, &st) < 0)
                return log_full_errno((searching && errno == ENOENT) ||
                                      (unprivileged_mode && errno == EACCES) ? LOG_DEBUG : LOG_ERR, errno,
                                      "Failed to determine block device node of \"%s\": %m", path);

        if (major(st.st_dev) == 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "Block device node of \"%s\" is invalid.", path);

        if (path_equal(path, "/")) {
                /* Let's assume that the root directory of the OS is always the root of its file system
                 * (which technically doesn't have to be the case, but it's close enough, and it's not easy
                 * to be fully correct for it, since we can't look further up than the root dir easily.) */
                if (ret_dev)
                        *ret_dev = st.st_dev;

                return 0;
        }

        t2 = strjoina(path, "/..");
        if (stat(t2, &st2) < 0) {
                if (errno != EACCES)
                        r = -errno;
                else {
                        _cleanup_free_ char *parent = NULL;

                        /* If going via ".." didn't work due to EACCESS, then let's determine the parent path
                         * directly instead. It's not as good, due to symlinks and such, but we can't do
                         * anything better here. */

                        r = path_extract_directory(path, &parent);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract parent path from '%s': %m", path);

                        r = RET_NERRNO(stat(parent, &st2));
                }

                if (r < 0)
                        return log_full_errno(unprivileged_mode && r == -EACCES ? LOG_DEBUG : LOG_ERR, r,
                                              "Failed to determine block device node of parent of \"%s\": %m", path);
        }

        if (st.st_dev == st2.st_dev)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "Directory \"%s\" is not the root of the file system.", path);

        if (ret_dev)
                *ret_dev = st.st_dev;

        return 0;
}

static int verify_esp(
                const char *p,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid,
                VerifyESPFlags flags) {

        bool relax_checks, searching = FLAGS_SET(flags, VERIFY_ESP_SEARCHING),
             unprivileged_mode = FLAGS_SET(flags, VERIFY_ESP_UNPRIVILEGED_MODE);
        dev_t devid;
        int r;

        assert(p);

        /* This logs about all errors, except:
         *
         *  -ENOENT        → if 'searching' is set, and the dir doesn't exist
         *  -EADDRNOTAVAIL → if 'searching' is set, and the dir doesn't look like an ESP
         *  -EACESS        → if 'unprivileged_mode' is set, and we have trouble accessing the thing
         */

        relax_checks = getenv_bool("SYSTEMD_RELAX_ESP_CHECKS") > 0 || FLAGS_SET(flags, VERIFY_ESP_RELAX_CHECKS);

        /* Non-root user can only check the status, so if an error occurred in the following, it does not cause any
         * issues. Let's also, silence the error messages. */

        if (!relax_checks) {
                struct statfs sfs;

                if (statfs(p, &sfs) < 0)
                        /* If we are searching for the mount point, don't generate a log message if we can't find the path */
                        return log_full_errno((searching && errno == ENOENT) ||
                                              (unprivileged_mode && errno == EACCES) ? LOG_DEBUG : LOG_ERR, errno,
                                              "Failed to check file system type of \"%s\": %m", p);

                if (!F_TYPE_EQUAL(sfs.f_type, MSDOS_SUPER_MAGIC))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                              "File system \"%s\" is not a FAT EFI System Partition (ESP) file system.", p);
        }

        r = verify_fsroot_dir(p, searching, unprivileged_mode, &devid);
        if (r < 0)
                return r;

        /* In a container we don't have access to block devices, skip this part of the verification, we trust
         * the container manager set everything up correctly on its own. */
        if (detect_container() > 0 || relax_checks)
                goto finish;

        /* If we are unprivileged we ask udev for the metadata about the partition. If we are privileged we
         * use blkid instead. Why? Because this code is called from 'bootctl' which is pretty much an
         * emergency recovery tool that should also work when udev isn't up (i.e. from the emergency shell),
         * however blkid can't work if we have no privileges to access block devices directly, which is why
         * we use udev in that case. */
        if (unprivileged_mode)
                r = verify_esp_udev(devid, searching, ret_part, ret_pstart, ret_psize, ret_uuid);
        else
                r = verify_esp_blkid(devid, searching, ret_part, ret_pstart, ret_psize, ret_uuid);
        if (r < 0)
                return r;

        if (ret_devid)
                *ret_devid = devid;

        return 0;

finish:
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

int find_esp_and_warn(
                const char *root,
                const char *path,
                bool unprivileged_mode,
                char **ret_path,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        VerifyESPFlags flags = (unprivileged_mode ? VERIFY_ESP_UNPRIVILEGED_MODE : 0) |
                               (root ? VERIFY_ESP_RELAX_CHECKS : 0);
        _cleanup_free_ char *p = NULL;
        int r;

        /* This logs about all errors except:
         *
         *    -ENOKEY → when we can't find the partition
         *   -EACCESS → when unprivileged_mode is true, and we can't access something
         */

        if (path) {
                r = chase_symlinks(path, root, CHASE_PREFIX_ROOT, &p, NULL);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to resolve path %s%s%s: %m",
                                               path,
                                               root ? " under directory " : "",
                                               strempty(root));

                r = verify_esp(p, ret_part, ret_pstart, ret_psize, ret_uuid, ret_devid, flags);
                if (r < 0)
                        return r;

                goto found;
        }

        path = getenv("SYSTEMD_ESP_PATH");
        if (path) {
                struct stat st;

                r = chase_symlinks(path, root, CHASE_PREFIX_ROOT, &p, NULL);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to resolve path %s%s%s: %m",
                                               path,
                                               root ? " under directory " : "",
                                               strempty(root));

                if (!path_is_valid(p) || !path_is_absolute(p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "$SYSTEMD_ESP_PATH does not refer to absolute path, refusing to use it: %s",
                                               p);

                /* Note: when the user explicitly configured things with an env var we won't validate the
                 * path beyond checking it refers to a directory. After all we want this to be useful for
                 * testing. */

                if (stat(p, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", p);
                if (!S_ISDIR(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "ESP path '%s' is not a directory.", p);

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

                goto found;
        }

        FOREACH_STRING(dir, "/efi", "/boot", "/boot/efi") {
                r = chase_symlinks(dir, root, CHASE_PREFIX_ROOT, &p, NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to resolve path %s%s%s: %m",
                                               dir,
                                               root ? " under directory " : "",
                                               strempty(root));

                r = verify_esp(p, ret_part, ret_pstart, ret_psize, ret_uuid, ret_devid,
                               flags | VERIFY_ESP_SEARCHING);
                if (r >= 0)
                        goto found;
                if (!IN_SET(r, -ENOENT, -EADDRNOTAVAIL)) /* This one is not it */
                        return r;

                p = mfree(p);
        }

        /* No logging here */
        return -ENOKEY;

found:
        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return 0;
}

static int verify_xbootldr_blkid(
                dev_t devid,
                bool searching,
                sd_id128_t *ret_uuid) {

        sd_id128_t uuid = SD_ID128_NULL;

#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *node = NULL;
        const char *type, *v;
        int r;

        r = devname_from_devnum(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to get block device path for " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devid));

        errno = 0;
        b = blkid_new_probe_from_filename(node);
        if (!b)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(ENOMEM), "%s: Failed to create blkid probe: %m", node);

        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "%s: File system is ambiguous.", node);
        else if (r == 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "%s: File system does not contain a label.", node);
        else if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "%s: Failed to probe file system: %m", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &type, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "%s: Failed to probe PART_ENTRY_SCHEME: %m", node);
        if (streq(type, "gpt")) {

                errno = 0;
                r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "%s: Failed to probe PART_ENTRY_TYPE: %m", node);
                if (sd_id128_string_equal(v, SD_GPT_XBOOTLDR) <= 0)
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                              "%s: Partitition has wrong PART_ENTRY_TYPE=%s for XBOOTLDR partition.", node, v);

                errno = 0;
                r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "%s: Failed to probe PART_ENTRY_UUID: %m", node);
                r = sd_id128_from_string(v, &uuid);
                if (r < 0)
                        return log_error_errno(r, "%s: Partition has invalid UUID PART_ENTRY_TYPE=%s: %m", node, v);

        } else if (streq(type, "dos")) {

                errno = 0;
                r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "%s: Failed to probe PART_ENTRY_TYPE: %m", node);
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
                bool searching,
                sd_id128_t *ret_uuid) {

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        sd_id128_t uuid = SD_ID128_NULL;
        const char *node, *type, *v;
        int r;

        r = sd_device_new_from_devnum(&d, 'b', devid);
        if (r < 0)
                return log_error_errno(r, "Failed to get block device for " DEVNUM_FORMAT_STR ": %m", DEVNUM_FORMAT_VAL(devid));

        r = sd_device_get_devname(d, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to get device node: %m");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SCHEME", &type);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to query ID_PART_ENTRY_SCHEME: %m");

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
                const char *p,
                bool searching,
                bool unprivileged_mode,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        bool relax_checks;
        dev_t devid;
        int r;

        assert(p);

        relax_checks = getenv_bool("SYSTEMD_RELAX_XBOOTLDR_CHECKS") > 0;

        r = verify_fsroot_dir(p, searching, unprivileged_mode, &devid);
        if (r < 0)
                return r;

        if (detect_container() > 0 || relax_checks)
                goto finish;

        if (unprivileged_mode)
                r = verify_xbootldr_udev(devid, searching, ret_uuid);
        else
                r = verify_xbootldr_blkid(devid, searching, ret_uuid);
        if (r < 0)
                return r;

        if (ret_devid)
                *ret_devid = devid;

        return 0;

finish:
        if (ret_uuid)
                *ret_uuid = SD_ID128_NULL;
        if (ret_devid)
                *ret_devid = 0;

        return 0;
}

int find_xbootldr_and_warn(
                const char *root,
                const char *path,
                bool unprivileged_mode,
                char **ret_path,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        _cleanup_free_ char *p = NULL;
        int r;

        /* Similar to find_esp_and_warn(), but finds the XBOOTLDR partition. Returns the same errors. */

        if (path) {
                r = chase_symlinks(path, root, CHASE_PREFIX_ROOT, &p, NULL);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to resolve path %s%s%s: %m",
                                               path,
                                               root ? " under directory " : "",
                                               strempty(root));

                r = verify_xbootldr(p, /* searching= */ false, unprivileged_mode, ret_uuid, ret_devid);
                if (r < 0)
                        return r;

                goto found;
        }

        path = getenv("SYSTEMD_XBOOTLDR_PATH");
        if (path) {
                struct stat st;

                r = chase_symlinks(path, root, CHASE_PREFIX_ROOT, &p, NULL);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to resolve path %s%s%s: %m",
                                               path,
                                               root ? " under directory " : "",
                                               strempty(root));

                if (!path_is_valid(p) || !path_is_absolute(p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "$SYSTEMD_XBOOTLDR_PATH does not refer to absolute path, refusing to use it: %s",
                                               p);

                if (stat(p, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", p);
                if (!S_ISDIR(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "XBOOTLDR path '%s' is not a directory.", p);

                if (ret_uuid)
                        *ret_uuid = SD_ID128_NULL;
                if (ret_devid)
                        *ret_devid = st.st_dev;

                goto found;
        }

        r = chase_symlinks("/boot", root, CHASE_PREFIX_ROOT, &p, NULL);
        if (r == -ENOENT)
                return -ENOKEY;
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to resolve path /boot%s%s: %m",
                                       root ? " under directory " : "",
                                       strempty(root));

        r = verify_xbootldr(p, true, unprivileged_mode, ret_uuid, ret_devid);
        if (r >= 0)
                goto found;
        if (!IN_SET(r, -ENOENT, -EADDRNOTAVAIL)) /* This one is not it */
                return r;

        return -ENOKEY;

found:
        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return 0;
}
