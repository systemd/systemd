/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include "sd-daemon.h"
#include "sd-device.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "blkid-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "chattr-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dm-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fdisk-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "fs-util.h"
#include "fsck-util.h"
#include "glyph-util.h"
#include "gpt.h"
#include "home-util.h"
#include "homework-luks.h"
#include "homework-mount.h"
#include "io-util.h"
#include "keyring-util.h"
#include "memory-util.h"
#include "missing_magic.h"
#include "mkdir.h"
#include "mkfs-util.h"
#include "mount-util.h"
#include "openssl-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "resize-fs.h"
#include "strv.h"
#include "sync-util.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "user-util.h"

/* Round down to the nearest 4K size. Given that newer hardware generally prefers 4K sectors, let's align our
 * partitions to that too. In the worst case we'll waste 3.5K per partition that way, but I think I can live
 * with that. */
#define DISK_SIZE_ROUND_DOWN(x) ((x) & ~UINT64_C(4095))

/* Rounds up to the nearest 4K boundary. Returns UINT64_MAX on overflow */
#define DISK_SIZE_ROUND_UP(x)                                           \
        ({                                                              \
                uint64_t _x = (x);                                      \
                _x > UINT64_MAX - 4095U ? UINT64_MAX : (_x + 4095U) & ~UINT64_C(4095); \
        })

/* How much larger will the image on disk be than the fs inside it, i.e. the space we pay for the GPT and
 * LUKS2 envelope. (As measured on cryptsetup 2.4.1) */
#define GPT_LUKS2_OVERHEAD UINT64_C(18874368)

static int resize_image_loop(UserRecord *h, HomeSetup *setup, uint64_t old_image_size, uint64_t new_image_size, uint64_t *ret_image_size);

int run_mark_dirty(int fd, bool b) {
        char x = '1';
        int r, ret;

        /* Sets or removes the 'user.home-dirty' xattr on the specified file. We use this to detect when a
         * home directory was not properly unmounted. */

        assert(fd >= 0);

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        if (b) {
                ret = fsetxattr(fd, "user.home-dirty", &x, 1, XATTR_CREATE);
                if (ret < 0 && errno != EEXIST)
                        return log_debug_errno(errno, "Could not mark home directory as dirty: %m");

        } else {
                r = fsync_full(fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to synchronize image before marking it clean: %m");

                ret = fremovexattr(fd, "user.home-dirty");
                if (ret < 0 && !ERRNO_IS_XATTR_ABSENT(errno))
                        return log_debug_errno(errno, "Could not mark home directory as clean: %m");
        }

        r = fsync_full(fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to synchronize dirty flag to disk: %m");

        return ret >= 0;
}

int run_mark_dirty_by_path(const char *path, bool b) {
        _cleanup_close_ int fd = -EBADF;

        assert(path);

        fd = open(path, O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open %s to mark dirty or clean: %m", path);

        return run_mark_dirty(fd, b);
}

static int probe_file_system_by_fd(
                int fd,
                char **ret_fstype,
                sd_id128_t *ret_uuid) {

        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *s = NULL;
        const char *fstype = NULL, *uuid = NULL;
        sd_id128_t id;
        int r;

        assert(fd >= 0);
        assert(ret_fstype);
        assert(ret_uuid);

        b = blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0)
                return errno_or_else(ENOMEM);

        (void) blkid_probe_enable_superblocks(b, 1);
        (void) blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_UUID);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return errno_or_else(EIO);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND))
                return -ENOPKG;

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);
        if (!fstype)
                return -ENOPKG;

        (void) blkid_probe_lookup_value(b, "UUID", &uuid, NULL);
        if (!uuid)
                return -ENOPKG;

        r = sd_id128_from_string(uuid, &id);
        if (r < 0)
                return r;

        s = strdup(fstype);
        if (!s)
                return -ENOMEM;

        *ret_fstype = TAKE_PTR(s);
        *ret_uuid = id;

        return 0;
}

static int probe_file_system_by_path(const char *path, char **ret_fstype, sd_id128_t *ret_uuid) {
        _cleanup_close_ int fd = -EBADF;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (fd < 0)
                return negative_errno();

        return probe_file_system_by_fd(fd, ret_fstype, ret_uuid);
}

static int block_get_size_by_fd(int fd, uint64_t *ret) {
        struct stat st;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        return blockdev_get_device_size(fd, ret);
}

static int block_get_size_by_path(const char *path, uint64_t *ret) {
        _cleanup_close_ int fd = -EBADF;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        return block_get_size_by_fd(fd, ret);
}

static int run_fsck(const char *node, const char *fstype) {
        int r, exit_status;
        pid_t fsck_pid;

        assert(node);
        assert(fstype);

        r = fsck_exists_for_fstype(fstype);
        if (r < 0)
                return log_error_errno(r, "Failed to check if fsck for file system %s exists: %m", fstype);
        if (r == 0) {
                log_warning("No fsck for file system %s installed, ignoring.", fstype);
                return 0;
        }

        r = safe_fork("(fsck)",
                      FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS,
                      &fsck_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execlp("fsck", "fsck", "-aTl", node, NULL);
                log_open();
                log_error_errno(errno, "Failed to execute fsck: %m");
                _exit(FSCK_OPERATIONAL_ERROR);
        }

        exit_status = wait_for_terminate_and_check("fsck", fsck_pid, WAIT_LOG_ABNORMAL);
        if (exit_status < 0)
                return exit_status;
        if ((exit_status & ~FSCK_ERROR_CORRECTED) != 0) {
                log_warning("fsck failed with exit status %i.", exit_status);

                if ((exit_status & (FSCK_SYSTEM_SHOULD_REBOOT|FSCK_ERRORS_LEFT_UNCORRECTED)) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "File system is corrupted, refusing.");

                log_warning("Ignoring fsck error.");
        }

        log_info("File system check completed.");

        return 1;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(key_serial_t, keyring_unlink, -1);

static int upload_to_keyring(
                UserRecord *h,
                const char *password,
                key_serial_t *ret_key_serial) {

        _cleanup_free_ char *name = NULL;
        key_serial_t serial;

        assert(h);
        assert(password);

        /* If auto-shrink-on-logout is turned on, we need to keep the key we used to unlock the LUKS volume
         * around, since we'll need it when automatically resizing (since we can't ask the user there
         * again). We do this by uploading it into the kernel keyring, specifically the "session" one. This
         * is done under the assumption systemd-homed gets its private per-session keyring (i.e. default
         * service behaviour, given that KeyringMode=private is the default). It will survive between our
         * systemd-homework invocations that way.
         *
         * If auto-shrink-on-logout is disabled we'll skip this step, to be frugal with sensitive data. */

        if (user_record_auto_resize_mode(h) != AUTO_RESIZE_SHRINK_AND_GROW) {  /* Won't need it */
                if (ret_key_serial)
                        *ret_key_serial = -1;
                return 0;
        }

        name = strjoin("homework-user-", h->user_name);
        if (!name)
                return -ENOMEM;

        serial = add_key("user", name, password, strlen(password), KEY_SPEC_SESSION_KEYRING);
        if (serial == -1)
                return -errno;

        if (ret_key_serial)
                *ret_key_serial = serial;

        return 1;
}

static int luks_try_passwords(
                UserRecord *h,
                struct crypt_device *cd,
                char **passwords,
                void *volume_key,
                size_t *volume_key_size,
                key_serial_t *ret_key_serial) {

        int r;

        assert(h);
        assert(cd);

        STRV_FOREACH(pp, passwords) {
                size_t vks = *volume_key_size;

                r = sym_crypt_volume_key_get(
                                cd,
                                CRYPT_ANY_SLOT,
                                volume_key,
                                &vks,
                                *pp,
                                strlen(*pp));
                if (r >= 0) {
                        if (ret_key_serial) {
                                /* If ret_key_serial is non-NULL, let's try to upload the password that
                                 * worked, and return its serial. */
                                r = upload_to_keyring(h, *pp, ret_key_serial);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to upload LUKS password to kernel keyring, ignoring: %m");
                                        *ret_key_serial = -1;
                                }
                        }

                        *volume_key_size = vks;
                        return 0;
                }

                log_debug_errno(r, "Password %zu didn't work for unlocking LUKS superblock: %m", (size_t) (pp - passwords));
        }

        return -ENOKEY;
}

static int luks_setup(
                UserRecord *h,
                const char *node,
                const char *dm_name,
                sd_id128_t uuid,
                const char *cipher,
                const char *cipher_mode,
                uint64_t volume_key_size,
                char **passwords,
                const PasswordCache *cache,
                bool discard,
                struct crypt_device **ret,
                sd_id128_t *ret_found_uuid,
                void **ret_volume_key,
                size_t *ret_volume_key_size,
                key_serial_t *ret_key_serial) {

        _cleanup_(keyring_unlinkp) key_serial_t key_serial = -1;
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        sd_id128_t p;
        size_t vks;
        char **list;
        int r;

        assert(h);
        assert(node);
        assert(dm_name);
        assert(ret);

        r = sym_crypt_init(&cd, node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        r = sym_crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS superblock: %m");

        r = sym_crypt_get_volume_key_size(cd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine LUKS volume key size");
        vks = (size_t) r;

        if (!sd_id128_is_null(uuid) || ret_found_uuid) {
                const char *s;

                s = sym_crypt_get_uuid(cd);
                if (!s)
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock has no UUID.");

                r = sd_id128_from_string(s, &p);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock has invalid UUID.");

                /* Check that the UUID matches, if specified */
                if (!sd_id128_is_null(uuid) &&
                    !sd_id128_equal(uuid, p))
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock has wrong UUID.");
        }

        if (cipher && !streq_ptr(cipher, sym_crypt_get_cipher(cd)))
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock declares wrong cipher.");

        if (cipher_mode && !streq_ptr(cipher_mode, sym_crypt_get_cipher_mode(cd)))
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock declares wrong cipher mode.");

        if (volume_key_size != UINT64_MAX && vks != volume_key_size)
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock declares wrong volume key size.");

        vk = malloc(vks);
        if (!vk)
                return log_oom();

        r = -ENOKEY;
        FOREACH_POINTER(list,
                        cache ? cache->keyring_passswords : NULL,
                        cache ? cache->pkcs11_passwords : NULL,
                        cache ? cache->fido2_passwords : NULL,
                        passwords) {
                r = luks_try_passwords(h, cd, list, vk, &vks, ret_key_serial ? &key_serial : NULL);
                if (r != -ENOKEY)
                        break;
        }
        if (r == -ENOKEY)
                return log_error_errno(r, "No valid password for LUKS superblock.");
        if (r < 0)
                return log_error_errno(r, "Failed to unlock LUKS superblock: %m");

        r = sym_crypt_activate_by_volume_key(
                        cd,
                        dm_name,
                        vk, vks,
                        discard ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0);
        if (r < 0)
                return log_error_errno(r, "Failed to unlock LUKS superblock: %m");

        log_info("Setting up LUKS device /dev/mapper/%s completed.", dm_name);

        *ret = TAKE_PTR(cd);

        if (ret_found_uuid) /* Return the UUID actually found if the caller wants to know */
                *ret_found_uuid = p;
        if (ret_volume_key)
                *ret_volume_key = TAKE_PTR(vk);
        if (ret_volume_key_size)
                *ret_volume_key_size = vks;
        if (ret_key_serial)
                *ret_key_serial = TAKE_KEY_SERIAL(key_serial);

        return 0;
}

static int make_dm_names(UserRecord *h, HomeSetup *setup) {
        assert(h);
        assert(h->user_name);
        assert(setup);

        if (!setup->dm_name) {
                setup->dm_name = strjoin("home-", h->user_name);
                if (!setup->dm_name)
                        return log_oom();
        }

        if (!setup->dm_node) {
                setup->dm_node = path_join("/dev/mapper/", setup->dm_name);
                if (!setup->dm_node)
                        return log_oom();
        }

        return 0;
}

static int acquire_open_luks_device(
                UserRecord *h,
                HomeSetup *setup,
                bool graceful) {

        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        int r;

        assert(h);
        assert(setup);
        assert(!setup->crypt_device);

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = make_dm_names(h, setup);
        if (r < 0)
                return r;

        r = sym_crypt_init_by_name(&cd, setup->dm_name);
        if ((ERRNO_IS_NEG_DEVICE_ABSENT(r) || r == -EINVAL) && graceful)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to initialize cryptsetup context for %s: %m", setup->dm_name);

        cryptsetup_enable_logging(cd);

        setup->crypt_device = TAKE_PTR(cd);
        return 1;
}

static int luks_open(
                UserRecord *h,
                HomeSetup *setup,
                const PasswordCache *cache,
                sd_id128_t *ret_found_uuid,
                void **ret_volume_key,
                size_t *ret_volume_key_size) {

        _cleanup_(erase_and_freep) void *vk = NULL;
        sd_id128_t p;
        char **list;
        size_t vks;
        int r;

        assert(h);
        assert(setup);
        assert(!setup->crypt_device);

        /* Opens a LUKS device that is already set up. Re-validates the password while doing so (which also
         * provides us with the volume key, which we want). */

        r = acquire_open_luks_device(h, setup, /* graceful= */ false);
        if (r < 0)
                return r;

        r = sym_crypt_load(setup->crypt_device, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS superblock: %m");

        r = sym_crypt_get_volume_key_size(setup->crypt_device);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine LUKS volume key size");
        vks = (size_t) r;

        if (ret_found_uuid) {
                const char *s;

                s = sym_crypt_get_uuid(setup->crypt_device);
                if (!s)
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock has no UUID.");

                r = sd_id128_from_string(s, &p);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock has invalid UUID.");
        }

        vk = malloc(vks);
        if (!vk)
                return log_oom();

        r = -ENOKEY;
        FOREACH_POINTER(list,
                        cache ? cache->keyring_passswords : NULL,
                        cache ? cache->pkcs11_passwords : NULL,
                        cache ? cache->fido2_passwords : NULL,
                        h->password) {
                r = luks_try_passwords(h, setup->crypt_device, list, vk, &vks, NULL);
                if (r != -ENOKEY)
                        break;
        }
        if (r == -ENOKEY)
                return log_error_errno(r, "No valid password for LUKS superblock.");
        if (r < 0)
                return log_error_errno(r, "Failed to unlock LUKS superblock: %m");

        log_info("Discovered used LUKS device /dev/mapper/%s, and validated password.", setup->dm_name);

        /* This is needed so that crypt_resize() can operate correctly for pre-existing LUKS devices. We need
         * to tell libcryptsetup the volume key explicitly, so that it is in the kernel keyring. */
        r = sym_crypt_activate_by_volume_key(setup->crypt_device, NULL, vk, vks, CRYPT_ACTIVATE_KEYRING_KEY);
        if (r < 0)
                return log_error_errno(r, "Failed to upload volume key again: %m");

        log_info("Successfully re-activated LUKS device.");

        if (ret_found_uuid)
                *ret_found_uuid = p;
        if (ret_volume_key)
                *ret_volume_key = TAKE_PTR(vk);
        if (ret_volume_key_size)
                *ret_volume_key_size = vks;

        return 0;
}

static int fs_validate(
                const char *dm_node,
                sd_id128_t uuid,
                char **ret_fstype,
                sd_id128_t *ret_found_uuid) {

        _cleanup_free_ char *fstype = NULL;
        sd_id128_t u = SD_ID128_NULL; /* avoid false maybe-unitialized warning */
        int r;

        assert(dm_node);
        assert(ret_fstype);

        r = probe_file_system_by_path(dm_node, &fstype, &u);
        if (r < 0)
                return log_error_errno(r, "Failed to probe file system: %m");

        /* Limit the set of supported file systems a bit, as protection against little tested kernel file
         * systems. Also, we only support the resize ioctls for these file systems. */
        if (!supported_fstype(fstype))
                return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "Image contains unsupported file system: %s", strna(fstype));

        if (!sd_id128_is_null(uuid) &&
            !sd_id128_equal(uuid, u))
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "File system has wrong UUID.");

        log_info("Probing file system completed (found %s).", fstype);

        *ret_fstype = TAKE_PTR(fstype);

        if (ret_found_uuid) /* Return the UUID actually found if the caller wants to know */
                *ret_found_uuid = u;

        return 0;
}

static int luks_validate(
                int fd,
                const char *label,
                sd_id128_t partition_uuid,
                sd_id128_t *ret_partition_uuid,
                uint64_t *ret_offset,
                uint64_t *ret_size) {

        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        sd_id128_t found_partition_uuid = SD_ID128_NULL;
        const char *fstype = NULL, *pttype = NULL;
        blkid_loff_t offset = 0, size = 0;
        blkid_partlist pl;
        bool found = false;
        int r, n;

        assert(fd >= 0);
        assert(label);
        assert(ret_offset);
        assert(ret_size);

        b = blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0)
                return errno_or_else(ENOMEM);

        (void) blkid_probe_enable_superblocks(b, 1);
        (void) blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        (void) blkid_probe_enable_partitions(b, 1);
        (void) blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return errno_or_else(EIO);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND))
                return -ENOPKG;

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) blkid_probe_lookup_value(b, "TYPE", &fstype, NULL);
        if (streq_ptr(fstype, "crypto_LUKS")) {
                /* Directly a LUKS image */
                *ret_offset = 0;
                *ret_size = UINT64_MAX; /* full disk */
                *ret_partition_uuid = SD_ID128_NULL;
                return 0;
        } else if (fstype)
                return -ENOPKG;

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt"))
                return -ENOPKG;

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl)
                return errno_or_else(ENOMEM);

        errno = 0;
        n = blkid_partlist_numof_partitions(pl);
        if (n < 0)
                return errno_or_else(EIO);

        for (int i = 0; i < n; i++) {
                sd_id128_t id = SD_ID128_NULL;
                blkid_partition pp;

                errno = 0;
                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return errno_or_else(EIO);

                if (sd_id128_string_equal(blkid_partition_get_type_string(pp), SD_GPT_USER_HOME) <= 0)
                        continue;

                if (!streq_ptr(blkid_partition_get_name(pp), label))
                        continue;


                r = blkid_partition_get_uuid_id128(pp, &id);
                if (r < 0)
                        log_debug_errno(r, "Failed to read partition UUID, ignoring: %m");
                else if (!sd_id128_is_null(partition_uuid) && !sd_id128_equal(id, partition_uuid))
                        continue;

                if (found)
                        return -ENOPKG;

                offset = blkid_partition_get_start(pp);
                size = blkid_partition_get_size(pp);
                found_partition_uuid = id;

                found = true;
        }

        if (!found)
                return -ENOPKG;

        if (offset < 0)
                return -EINVAL;
        if ((uint64_t) offset > UINT64_MAX / 512U)
                return -EINVAL;
        if (size <= 0)
                return -EINVAL;
        if ((uint64_t) size > UINT64_MAX / 512U)
                return -EINVAL;

        *ret_offset = offset * 512U;
        *ret_size = size * 512U;
        *ret_partition_uuid = found_partition_uuid;

        return 0;
}

static int crypt_device_to_evp_cipher(struct crypt_device *cd, const EVP_CIPHER **ret) {
        _cleanup_free_ char *cipher_name = NULL;
        const char *cipher, *cipher_mode, *e;
        size_t key_size, key_bits;
        const EVP_CIPHER *cc;
        int r;

        assert(cd);

        /* Let's find the right OpenSSL EVP_CIPHER object that matches the encryption settings of the LUKS
         * device */

        cipher = sym_crypt_get_cipher(cd);
        if (!cipher)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot get cipher from LUKS device.");

        cipher_mode = sym_crypt_get_cipher_mode(cd);
        if (!cipher_mode)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot get cipher mode from LUKS device.");

        e = strchr(cipher_mode, '-');
        if (e)
                cipher_mode = strndupa_safe(cipher_mode, e - cipher_mode);

        r = sym_crypt_get_volume_key_size(cd);
        if (r <= 0)
                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Cannot get volume key size from LUKS device.");

        key_size = r;
        key_bits = key_size * 8;
        if (streq(cipher_mode, "xts"))
                key_bits /= 2;

        if (asprintf(&cipher_name, "%s-%zu-%s", cipher, key_bits, cipher_mode) < 0)
                return log_oom();

        cc = EVP_get_cipherbyname(cipher_name);
        if (!cc)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Selected cipher mode '%s' not supported, can't encrypt JSON record.", cipher_name);

        /* Verify that our key length calculations match what OpenSSL thinks */
        r = EVP_CIPHER_key_length(cc);
        if (r < 0 || (uint64_t) r != key_size)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key size of selected cipher doesn't meet our expectations.");

        *ret = cc;
        return 0;
}

static int luks_validate_home_record(
                struct crypt_device *cd,
                UserRecord *h,
                const void *volume_key,
                PasswordCache *cache,
                UserRecord **ret_luks_home_record) {

        int r;

        assert(cd);
        assert(h);

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *rr = NULL;
                _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
                _cleanup_(user_record_unrefp) UserRecord *lhr = NULL;
                _cleanup_free_ void *encrypted = NULL, *iv = NULL;
                size_t decrypted_size, encrypted_size, iv_size;
                int decrypted_size_out1, decrypted_size_out2;
                _cleanup_free_ char *decrypted = NULL;
                const char *text, *type;
                crypt_token_info state;
                JsonVariant *jr, *jiv;
                unsigned line, column;
                const EVP_CIPHER *cc;

                state = sym_crypt_token_status(cd, token, &type);
                if (state == CRYPT_TOKEN_INACTIVE) /* First unconfigured token, give up */
                        break;
                if (IN_SET(state, CRYPT_TOKEN_INTERNAL, CRYPT_TOKEN_INTERNAL_UNKNOWN, CRYPT_TOKEN_EXTERNAL))
                        continue;
                if (state != CRYPT_TOKEN_EXTERNAL_UNKNOWN)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected token state of token %i: %i", token, (int) state);

                if (!streq(type, "systemd-homed"))
                        continue;

                r = sym_crypt_token_json_get(cd, token, &text);
                if (r < 0)
                        return log_error_errno(r, "Failed to read LUKS token %i: %m", token);

                r = json_parse(text, JSON_PARSE_SENSITIVE, &v, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse LUKS token JSON data %u:%u: %m", line, column);

                jr = json_variant_by_key(v, "record");
                if (!jr)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "LUKS token lacks 'record' field.");
                jiv = json_variant_by_key(v, "iv");
                if (!jiv)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "LUKS token lacks 'iv' field.");

                r = json_variant_unbase64(jr, &encrypted, &encrypted_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to base64 decode record: %m");

                r = json_variant_unbase64(jiv, &iv, &iv_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to base64 decode IV: %m");

                r = crypt_device_to_evp_cipher(cd, &cc);
                if (r < 0)
                        return r;
                if (iv_size > INT_MAX || EVP_CIPHER_iv_length(cc) != (int) iv_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "IV size doesn't match.");

                context = EVP_CIPHER_CTX_new();
                if (!context)
                        return log_oom();

                if (EVP_DecryptInit_ex(context, cc, NULL, volume_key, iv) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize decryption context.");

                decrypted_size = encrypted_size + EVP_CIPHER_key_length(cc) * 2;
                decrypted = new(char, decrypted_size);
                if (!decrypted)
                        return log_oom();

                if (EVP_DecryptUpdate(context, (uint8_t*) decrypted, &decrypted_size_out1, encrypted, encrypted_size) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decrypt JSON record.");

                assert((size_t) decrypted_size_out1 <= decrypted_size);

                if (EVP_DecryptFinal_ex(context, (uint8_t*) decrypted + decrypted_size_out1, &decrypted_size_out2) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finish decryption of JSON record.");

                assert((size_t) decrypted_size_out1 + (size_t) decrypted_size_out2 < decrypted_size);
                decrypted_size = (size_t) decrypted_size_out1 + (size_t) decrypted_size_out2;

                if (memchr(decrypted, 0, decrypted_size))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Inner NUL byte in JSON record, refusing.");

                decrypted[decrypted_size] = 0;

                r = json_parse(decrypted, JSON_PARSE_SENSITIVE, &rr, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse decrypted JSON record, refusing.");

                lhr = user_record_new();
                if (!lhr)
                        return log_oom();

                r = user_record_load(lhr, rr, USER_RECORD_LOAD_EMBEDDED|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse user record: %m");

                if (!user_record_compatible(h, lhr))
                        return log_error_errno(SYNTHETIC_ERRNO(EREMCHG), "LUKS home record not compatible with host record, refusing.");

                r = user_record_authenticate(lhr, h, cache, /* strict_verify= */ true);
                if (r < 0)
                        return r;
                assert(r > 0); /* Insist that a password was verified */

                *ret_luks_home_record = TAKE_PTR(lhr);
                return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Couldn't find home record in LUKS2 header, refusing.");
}

static int format_luks_token_text(
                struct crypt_device *cd,
                UserRecord *hr,
                const void *volume_key,
                char **ret) {

        int r, encrypted_size_out1 = 0, encrypted_size_out2 = 0, iv_size, key_size;
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ void *iv = NULL, *encrypted = NULL;
        size_t text_length, encrypted_size;
        _cleanup_free_ char *text = NULL;
        const EVP_CIPHER *cc;

        assert(cd);
        assert(hr);
        assert(volume_key);
        assert(ret);

        r = crypt_device_to_evp_cipher(cd, &cc);
        if (r < 0)
                return r;

        key_size = EVP_CIPHER_key_length(cc);
        iv_size = EVP_CIPHER_iv_length(cc);

        if (iv_size > 0) {
                iv = malloc(iv_size);
                if (!iv)
                        return log_oom();

                r = crypto_random_bytes(iv, iv_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate IV: %m");
        }

        context = EVP_CIPHER_CTX_new();
        if (!context)
                return log_oom();

        if (EVP_EncryptInit_ex(context, cc, NULL, volume_key, iv) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize encryption context.");

        r = json_variant_format(hr->json, 0, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format user record for LUKS: %m");

        text_length = strlen(text);
        encrypted_size = text_length + 2*key_size - 1;

        encrypted = malloc(encrypted_size);
        if (!encrypted)
                return log_oom();

        if (EVP_EncryptUpdate(context, encrypted, &encrypted_size_out1, (uint8_t*) text, text_length) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to encrypt JSON record.");

        assert((size_t) encrypted_size_out1 <= encrypted_size);

        if (EVP_EncryptFinal_ex(context, (uint8_t*) encrypted + encrypted_size_out1, &encrypted_size_out2) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finish encryption of JSON record. ");

        assert((size_t) encrypted_size_out1 + (size_t) encrypted_size_out2 <= encrypted_size);

        r = json_build(&v,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-homed")),
                                       JSON_BUILD_PAIR("keyslots", JSON_BUILD_EMPTY_ARRAY),
                                       JSON_BUILD_PAIR("record", JSON_BUILD_BASE64(encrypted, encrypted_size_out1 + encrypted_size_out2)),
                                       JSON_BUILD_PAIR("iv", JSON_BUILD_BASE64(iv, iv_size))));
        if (r < 0)
                return log_error_errno(r, "Failed to prepare LUKS JSON token object: %m");

        r = json_variant_format(v, 0, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to format encrypted user record for LUKS: %m");

        return 0;
}

int home_store_header_identity_luks(
                UserRecord *h,
                HomeSetup *setup,
                UserRecord *old_home) {

        _cleanup_(user_record_unrefp) UserRecord *header_home = NULL;
        _cleanup_free_ char *text = NULL;
        int r;

        assert(h);

        if (!setup->crypt_device)
                return 0;

        assert(setup->volume_key);

        /* Let's store the user's identity record in the LUKS2 "token" header data fields, in an encrypted
         * fashion. Why that? If we'd rely on the record being embedded in the payload file system itself we
         * would have to mount the file system before we can validate the JSON record, its signatures and
         * whether it matches what we are looking for. However, kernel file system implementations are
         * generally not ready to be used on untrusted media. Hence let's store the record independently of
         * the file system, so that we can validate it first, and only then mount the file system. To keep
         * things simple we use the same encryption settings for this record as for the file system itself. */

        r = user_record_clone(h, USER_RECORD_EXTRACT_EMBEDDED|USER_RECORD_PERMISSIVE, &header_home);
        if (r < 0)
                return log_error_errno(r, "Failed to determine new header record: %m");

        if (old_home && user_record_equal(old_home, header_home)) {
                log_debug("Not updating header home record.");
                return 0;
        }

        r = format_luks_token_text(setup->crypt_device, header_home, setup->volume_key, &text);
        if (r < 0)
                return r;

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                crypt_token_info state;
                const char *type;

                state = sym_crypt_token_status(setup->crypt_device, token, &type);
                if (state == CRYPT_TOKEN_INACTIVE) /* First unconfigured token, we are done */
                        break;
                if (IN_SET(state, CRYPT_TOKEN_INTERNAL, CRYPT_TOKEN_INTERNAL_UNKNOWN, CRYPT_TOKEN_EXTERNAL))
                        continue; /* Not ours */
                if (state != CRYPT_TOKEN_EXTERNAL_UNKNOWN)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected token state of token %i: %i", token, (int) state);

                if (!streq(type, "systemd-homed"))
                        continue;

                r = sym_crypt_token_json_set(setup->crypt_device, token, text);
                if (r < 0)
                        return log_error_errno(r, "Failed to set JSON token for slot %i: %m", token);

                /* Now, let's free the text so that for all further matching tokens we all crypt_json_token_set()
                 * with a NULL text in order to invalidate the tokens. */
                text = mfree(text);
        }

        if (text)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Didn't find any record token to update.");

        log_info("Wrote LUKS header user record.");

        return 1;
}

int run_fitrim(int root_fd) {
        struct fstrim_range range = {
                .len = UINT64_MAX,
        };

        /* If discarding is on, discard everything right after mounting, so that the discard setting takes
         * effect on activation. (Also, optionally, trim on logout) */

        assert(root_fd >= 0);

        if (ioctl(root_fd, FITRIM, &range) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno) || errno == EBADF) {
                        log_debug_errno(errno, "File system does not support FITRIM, not trimming.");
                        return 0;
                }

                return log_warning_errno(errno, "Failed to invoke FITRIM, ignoring: %m");
        }

        log_info("Discarded unused %s.", FORMAT_BYTES(range.len));
        return 1;
}

int run_fallocate(int backing_fd, const struct stat *st) {
        struct stat stbuf;

        assert(backing_fd >= 0);

        /* If discarding is off, let's allocate the whole image before mounting, so that the setting takes
         * effect on activation */

        if (!st) {
                if (fstat(backing_fd, &stbuf) < 0)
                        return log_error_errno(errno, "Failed to fstat(): %m");

                st = &stbuf;
        }

        if (!S_ISREG(st->st_mode))
                return 0;

        if (st->st_blocks >= DIV_ROUND_UP(st->st_size, 512)) {
                log_info("Backing file is fully allocated already.");
                return 0;
        }

        if (fallocate(backing_fd, FALLOC_FL_KEEP_SIZE, 0, st->st_size) < 0) {

                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        log_debug_errno(errno, "fallocate() not supported on file system, ignoring.");
                        return 0;
                }

                if (ERRNO_IS_DISK_SPACE(errno)) {
                        log_debug_errno(errno, "Not enough disk space to fully allocate home.");
                        return -ENOSPC; /* make recognizable */
                }

                return log_error_errno(errno, "Failed to allocate backing file blocks: %m");
        }

        log_info("Allocated additional %s.",
                 FORMAT_BYTES((DIV_ROUND_UP(st->st_size, 512) - st->st_blocks) * 512));
        return 1;
}

int run_fallocate_by_path(const char *backing_path) {
        _cleanup_close_ int backing_fd = -EBADF;

        backing_fd = open(backing_path, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (backing_fd < 0)
                return log_error_errno(errno, "Failed to open '%s' for fallocate(): %m", backing_path);

        return run_fallocate(backing_fd, NULL);
}

static int lock_image_fd(int image_fd, const char *ip) {
        int r;

        /* If the $SYSTEMD_LUKS_LOCK environment variable is set we'll take an exclusive BSD lock on the
         * image file, and send it to our parent. homed will keep it open to ensure no other instance of
         * homed (across the network or such) will also mount the file. */

        assert(image_fd >= 0);
        assert(ip);

        r = getenv_bool("SYSTEMD_LUKS_LOCK");
        if (r == -ENXIO)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse $SYSTEMD_LUKS_LOCK environment variable: %m");
        if (r == 0)
                return 0;

        if (flock(image_fd, LOCK_EX|LOCK_NB) < 0) {

                if (errno == EAGAIN)
                        log_error_errno(errno, "Image file '%s' already locked, can't use.", ip);
                else
                        log_error_errno(errno, "Failed to lock image file '%s': %m", ip);

                return errno != EAGAIN ? -errno : -EADDRINUSE; /* Make error recognizable */
        }

        log_info("Successfully locked image file '%s'.", ip);

        /* Now send it to our parent to keep safe while the home dir is active */
        r = sd_pid_notify_with_fds(0, false, "SYSTEMD_LUKS_LOCK_FD=1", &image_fd, 1);
        if (r < 0)
                log_warning_errno(r, "Failed to send LUKS lock fd to parent, ignoring: %m");

        return 0;
}

static int open_image_file(
                UserRecord *h,
                const char *force_image_path,
                struct stat *ret_stat) {

        _cleanup_close_ int image_fd = -EBADF;
        struct stat st;
        const char *ip;
        int r;

        assert(h || force_image_path);

        ip = force_image_path ?: user_record_image_path(h);

        image_fd = open(ip, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (image_fd < 0)
                return log_error_errno(errno, "Failed to open image file %s: %m", ip);

        if (fstat(image_fd, &st) < 0)
                return log_error_errno(errno, "Failed to fstat() image file: %m");
        if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))
                return log_error_errno(
                                S_ISDIR(st.st_mode) ? SYNTHETIC_ERRNO(EISDIR) : SYNTHETIC_ERRNO(EBADFD),
                                "Image file %s is not a regular file or block device: %m", ip);

        /* Locking block devices doesn't really make sense, as this might interfere with
         * udev's workings, and these locks aren't network propagated anyway, hence not what
         * we are after here. */
        if (S_ISREG(st.st_mode)) {
                r = lock_image_fd(image_fd, ip);
                if (r < 0)
                        return r;
        }

        if (ret_stat)
                *ret_stat = st;

        return TAKE_FD(image_fd);
}

int home_setup_luks(
                UserRecord *h,
                HomeSetupFlags flags,
                const char *force_image_path,
                HomeSetup *setup,
                PasswordCache *cache,
                UserRecord **ret_luks_home) {

        sd_id128_t found_partition_uuid, found_fs_uuid = SD_ID128_NULL, found_luks_uuid = SD_ID128_NULL;
        _cleanup_(user_record_unrefp) UserRecord *luks_home = NULL;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        size_t volume_key_size = 0;
        uint64_t offset, size;
        struct stat st;
        int r;

        assert(h);
        assert(setup);
        assert(user_record_storage(h) == USER_LUKS);

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = make_dm_names(h, setup);
        if (r < 0)
                return r;

        /* Reuse the image fd if it has already been opened by an earlier step */
        if (setup->image_fd < 0) {
                setup->image_fd = open_image_file(h, force_image_path, &st);
                if (setup->image_fd < 0)
                        return setup->image_fd;
        } else if (fstat(setup->image_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat image: %m");

        if (FLAGS_SET(flags, HOME_SETUP_ALREADY_ACTIVATED)) {
                struct loop_info64 info;
                const char *n;

                if (!setup->crypt_device) {
                        r = luks_open(h,
                                      setup,
                                      cache,
                                      &found_luks_uuid,
                                      &volume_key,
                                      &volume_key_size);
                        if (r < 0)
                                return r;
                }

                if (ret_luks_home) {
                        r = luks_validate_home_record(setup->crypt_device, h, volume_key, cache, &luks_home);
                        if (r < 0)
                                return r;
                }

                n = sym_crypt_get_device_name(setup->crypt_device);
                if (!n)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine backing device for DM %s.", setup->dm_name);

                if (!setup->loop) {
                        r = loop_device_open_from_path(n, O_RDWR, LOCK_UN, &setup->loop);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open loopback device %s: %m", n);
                }

                if (ioctl(setup->loop->fd, LOOP_GET_STATUS64, &info) < 0) {
                        _cleanup_free_ char *sysfs = NULL;

                        if (!IN_SET(errno, ENOTTY, EINVAL))
                                return log_error_errno(errno, "Failed to get block device metrics of %s: %m", n);

                        if (fstat(setup->loop->fd, &st) < 0)
                                return log_error_errno(r, "Failed to stat block device %s: %m", n);
                        assert(S_ISBLK(st.st_mode));

                        if (asprintf(&sysfs, "/sys/dev/block/" DEVNUM_FORMAT_STR "/partition", DEVNUM_FORMAT_VAL(st.st_rdev)) < 0)
                                return log_oom();

                        if (access(sysfs, F_OK) < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to determine whether %s exists: %m", sysfs);

                                offset = 0;
                        } else {
                                _cleanup_free_ char *buffer = NULL;

                                if (asprintf(&sysfs, "/sys/dev/block/" DEVNUM_FORMAT_STR "/start", DEVNUM_FORMAT_VAL(st.st_rdev)) < 0)
                                        return log_oom();

                                r = read_one_line_file(sysfs, &buffer);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to read partition start offset: %m");

                                r = safe_atou64(buffer, &offset);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse partition start offset: %m");

                                if (offset > UINT64_MAX / 512U)
                                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Offset too large for 64 byte range, refusing.");

                                offset *= 512U;
                        }

                        size = setup->loop->device_size;
                } else {
#if HAVE_VALGRIND_MEMCHECK_H
                        VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

                        offset = info.lo_offset;
                        size = info.lo_sizelimit;
                }

                found_partition_uuid = found_fs_uuid = SD_ID128_NULL;

                log_info("Discovered used loopback device %s.", setup->loop->node);

                if (setup->root_fd < 0) {
                        setup->root_fd = open(user_record_home_directory(h), O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                        if (setup->root_fd < 0)
                                return log_error_errno(errno, "Failed to open home directory: %m");
                }
        } else {
                _cleanup_free_ char *fstype = NULL, *subdir = NULL;
                const char *ip;

                /* When we aren't reopening the home directory we are allocating it fresh, hence the relevant
                 * objects can't be allocated yet. */
                assert(setup->root_fd < 0);
                assert(!setup->crypt_device);
                assert(!setup->loop);

                ip = force_image_path ?: user_record_image_path(h);

                subdir = path_join(HOME_RUNTIME_WORK_DIR, user_record_user_name_and_realm(h));
                if (!subdir)
                        return log_oom();

                r = luks_validate(setup->image_fd, user_record_user_name_and_realm(h), h->partition_uuid, &found_partition_uuid, &offset, &size);
                if (r < 0)
                        return log_error_errno(r, "Failed to validate disk label: %m");

                /* Everything before this point left the image untouched. We are now starting to make
                 * changes, hence mark the image dirty */
                if (run_mark_dirty(setup->image_fd, true) > 0)
                        setup->do_mark_clean = true;

                if (!user_record_luks_discard(h)) {
                        r = run_fallocate(setup->image_fd, &st);
                        if (r < 0)
                                return r;
                }

                r = loop_device_make(
                                setup->image_fd,
                                O_RDWR,
                                offset,
                                size,
                                h->luks_sector_size == UINT64_MAX ? UINT32_MAX : user_record_luks_sector_size(h), /* if sector size is not specified, select UINT32_MAX, i.e. auto-probe */
                                /* loop_flags= */ 0,
                                LOCK_UN,
                                &setup->loop);
                if (r == -ENOENT) {
                        log_error_errno(r, "Loopback block device support is not available on this system.");
                        return -ENOLINK; /* make recognizable */
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate loopback context: %m");

                log_info("Setting up loopback device %s completed.", setup->loop->node ?: ip);

                r = luks_setup(h,
                               setup->loop->node ?: ip,
                               setup->dm_name,
                               h->luks_uuid,
                               h->luks_cipher,
                               h->luks_cipher_mode,
                               h->luks_volume_key_size,
                               h->password,
                               cache,
                               user_record_luks_discard(h) || user_record_luks_offline_discard(h),
                               &setup->crypt_device,
                               &found_luks_uuid,
                               &volume_key,
                               &volume_key_size,
                               &setup->key_serial);
                if (r < 0)
                        return r;

                setup->undo_dm = true;

                if (ret_luks_home) {
                        r = luks_validate_home_record(setup->crypt_device, h, volume_key, cache, &luks_home);
                        if (r < 0)
                                return r;
                }

                r = fs_validate(setup->dm_node, h->file_system_uuid, &fstype, &found_fs_uuid);
                if (r < 0)
                        return r;

                r = run_fsck(setup->dm_node, fstype);
                if (r < 0)
                        return r;

                r = home_unshare_and_mount(setup->dm_node, fstype, user_record_luks_discard(h), user_record_mount_flags(h), h->luks_extra_mount_options);
                if (r < 0)
                        return r;

                setup->undo_mount = true;

                setup->root_fd = open(subdir, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (setup->root_fd < 0)
                        return log_error_errno(errno, "Failed to open home directory: %m");

                if (user_record_luks_discard(h))
                        (void) run_fitrim(setup->root_fd);

                setup->do_offline_fallocate = !(setup->do_offline_fitrim = user_record_luks_offline_discard(h));
        }

        if (!sd_id128_is_null(found_partition_uuid))
                setup->found_partition_uuid = found_partition_uuid;
        if (!sd_id128_is_null(found_luks_uuid))
                setup->found_luks_uuid = found_luks_uuid;
        if (!sd_id128_is_null(found_fs_uuid))
                setup->found_fs_uuid = found_fs_uuid;

        setup->partition_offset = offset;
        setup->partition_size = size;

        if (volume_key) {
                erase_and_free(setup->volume_key);
                setup->volume_key = TAKE_PTR(volume_key);
                setup->volume_key_size = volume_key_size;
        }

        if (ret_luks_home)
                *ret_luks_home = TAKE_PTR(luks_home);

        return 0;
}

static void print_size_summary(uint64_t host_size, uint64_t encrypted_size, const struct statfs *sfs) {
        assert(sfs);

        log_info("Image size is %s, file system size is %s, file system payload size is %s, file system free is %s.",
                 FORMAT_BYTES(host_size),
                 FORMAT_BYTES(encrypted_size),
                 FORMAT_BYTES((uint64_t) sfs->f_blocks * (uint64_t) sfs->f_frsize),
                 FORMAT_BYTES((uint64_t) sfs->f_bfree * (uint64_t) sfs->f_frsize));
}

static int home_auto_grow_luks(
                UserRecord *h,
                HomeSetup *setup,
                PasswordCache *cache) {

        struct statfs sfs;

        assert(h);
        assert(setup);

        if (!IN_SET(user_record_auto_resize_mode(h), AUTO_RESIZE_GROW, AUTO_RESIZE_SHRINK_AND_GROW))
                return 0;

        assert(setup->root_fd >= 0);

        if (fstatfs(setup->root_fd, &sfs) < 0)
                return log_error_errno(errno, "Failed to statfs home directory: %m");

        if (!fs_can_online_shrink_and_grow(sfs.f_type)) {
                log_debug("Not auto-grow file system, since selected file system cannot do both online shrink and grow.");
                return 0;
        }

        log_debug("Initiating auto-grow...");

        return home_resize_luks(
                        h,
                        HOME_SETUP_ALREADY_ACTIVATED|
                        HOME_SETUP_RESIZE_DONT_SYNC_IDENTITIES|
                        HOME_SETUP_RESIZE_DONT_SHRINK|
                        HOME_SETUP_RESIZE_DONT_UNDO,
                        setup,
                        cache,
                        NULL);
}

int home_activate_luks(
                UserRecord *h,
                HomeSetupFlags flags,
                HomeSetup *setup,
                PasswordCache *cache,
                UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL, *luks_home_record = NULL;
        uint64_t host_size, encrypted_size;
        const char *hdo, *hd;
        struct statfs sfs;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_LUKS);
        assert(setup);
        assert(ret_home);

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        assert_se(hdo = user_record_home_directory(h));
        hd = strdupa_safe(hdo); /* copy the string out, since it might change later in the home record object */

        r = home_get_state_luks(h, setup);
        if (r < 0)
                return r;
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Device mapper device %s already exists, refusing.", setup->dm_node);

        r = home_setup_luks(
                        h,
                        0,
                        NULL,
                        setup,
                        cache,
                        &luks_home_record);
        if (r < 0)
                return r;

        r = home_auto_grow_luks(h, setup, cache);
        if (r < 0)
                return r;

        r = block_get_size_by_fd(setup->loop->fd, &host_size);
        if (r < 0)
                return log_error_errno(r, "Failed to get loopback block device size: %m");

        r = block_get_size_by_path(setup->dm_node, &encrypted_size);
        if (r < 0)
                return log_error_errno(r, "Failed to get LUKS block device size: %m");

        r = home_refresh(
                        h,
                        flags,
                        setup,
                        luks_home_record,
                        cache,
                        &sfs,
                        &new_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, setup);
        if (r < 0)
                return r;

        setup->root_fd = safe_close(setup->root_fd);

        r = home_move_mount(user_record_user_name_and_realm(h), hd);
        if (r < 0)
                return r;

        setup->undo_mount = false;
        setup->do_offline_fitrim = false;

        loop_device_relinquish(setup->loop);

        r = sym_crypt_deactivate_by_name(NULL, setup->dm_name, CRYPT_DEACTIVATE_DEFERRED);
        if (r < 0)
                log_warning_errno(r, "Failed to relinquish DM device, ignoring: %m");

        setup->undo_dm = false;
        setup->do_offline_fallocate = false;
        setup->do_mark_clean = false;
        setup->do_drop_caches = false;
        TAKE_KEY_SERIAL(setup->key_serial); /* Leave key in kernel keyring */

        log_info("Activation completed.");

        print_size_summary(host_size, encrypted_size, &sfs);

        *ret_home = TAKE_PTR(new_home);
        return 1;
}

int home_deactivate_luks(UserRecord *h, HomeSetup *setup) {
        bool we_detached = false;
        int r;

        assert(h);
        assert(setup);

        /* Note that the DM device and loopback device are set to auto-detach, hence strictly speaking we
         * don't have to explicitly have to detach them. However, we do that nonetheless (in case of the DM
         * device), to avoid races: by explicitly detaching them we know when the detaching is complete. We
         * don't bother about the loopback device because unlike the DM device it doesn't have a fixed
         * name. */

        if (!setup->crypt_device) {
                r = acquire_open_luks_device(h, setup, /* graceful= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to initialize cryptsetup context for %s: %m", setup->dm_name);
                if (r == 0)
                        log_debug("LUKS device %s has already been detached.", setup->dm_name);
        }

        if (setup->crypt_device) {
                log_info("Discovered used LUKS device %s.", setup->dm_node);

                cryptsetup_enable_logging(setup->crypt_device);

                r = sym_crypt_deactivate_by_name(setup->crypt_device, setup->dm_name, 0);
                if (ERRNO_IS_NEG_DEVICE_ABSENT(r) || r == -EINVAL)
                        log_debug_errno(r, "LUKS device %s is already detached.", setup->dm_node);
                else if (r < 0)
                        return log_info_errno(r, "LUKS device %s couldn't be deactivated: %m", setup->dm_node);
                else {
                        log_info("LUKS device detaching completed.");
                        we_detached = true;
                }
        }

        (void) wait_for_block_device_gone(setup, USEC_PER_SEC * 30);
        setup->undo_dm = false;

        if (user_record_luks_offline_discard(h))
                log_debug("Not allocating on logout.");
        else
                (void) run_fallocate_by_path(user_record_image_path(h));

        run_mark_dirty_by_path(user_record_image_path(h), false);
        return we_detached;
}

int home_trim_luks(UserRecord *h, HomeSetup *setup) {
        assert(h);
        assert(setup);
        assert(setup->root_fd >= 0);

        if (!user_record_luks_offline_discard(h)) {
                log_debug("Not trimming on logout.");
                return 0;
        }

        (void) run_fitrim(setup->root_fd);
        return 0;
}

static struct crypt_pbkdf_type* build_good_pbkdf(struct crypt_pbkdf_type *buffer, UserRecord *hr) {
        assert(buffer);
        assert(hr);

        bool benchmark = user_record_luks_pbkdf_force_iterations(hr) == UINT64_MAX;

        *buffer = (struct crypt_pbkdf_type) {
                .hash = user_record_luks_pbkdf_hash_algorithm(hr),
                .type = user_record_luks_pbkdf_type(hr),
                .time_ms = benchmark ? user_record_luks_pbkdf_time_cost_usec(hr) / USEC_PER_MSEC : 0,
                .iterations = benchmark ? 0 : user_record_luks_pbkdf_force_iterations(hr),
                .max_memory_kb = user_record_luks_pbkdf_memory_cost(hr) / 1024,
                .parallel_threads = user_record_luks_pbkdf_parallel_threads(hr),
                .flags = benchmark ? 0 : CRYPT_PBKDF_NO_BENCHMARK,
        };

        return buffer;
}

static struct crypt_pbkdf_type* build_minimal_pbkdf(struct crypt_pbkdf_type *buffer, UserRecord *hr) {
        assert(buffer);
        assert(hr);

        /* For PKCS#11 derived keys (which are generated randomly and are of high quality already) we use a
         * minimal PBKDF */
        *buffer = (struct crypt_pbkdf_type) {
                .hash = user_record_luks_pbkdf_hash_algorithm(hr),
                .type = CRYPT_KDF_PBKDF2,
                .iterations = 1,
                .time_ms = 1,
        };

        return buffer;
}

static int luks_format(
                const char *node,
                const char *dm_name,
                sd_id128_t uuid,
                const char *label,
                const PasswordCache *cache,
                char **effective_passwords,
                bool discard,
                UserRecord *hr,
                struct crypt_device **ret) {

        _cleanup_(user_record_unrefp) UserRecord *reduced = NULL;
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        struct crypt_pbkdf_type good_pbkdf, minimal_pbkdf;
        _cleanup_free_ char *text = NULL;
        size_t volume_key_size;
        int slot = 0, r;

        assert(node);
        assert(dm_name);
        assert(hr);
        assert(ret);

        r = sym_crypt_init(&cd, node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        /* Normally we'd, just leave volume key generation to libcryptsetup. However, we can't, since we
         * can't extract the volume key from the library again, but we need it in order to encrypt the JSON
         * record. Hence, let's generate it on our own, so that we can keep track of it. */

        volume_key_size = user_record_luks_volume_key_size(hr);
        volume_key = malloc(volume_key_size);
        if (!volume_key)
                return log_oom();

        r = crypto_random_bytes(volume_key, volume_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to generate volume key: %m");

#if HAVE_CRYPT_SET_METADATA_SIZE
        /* Increase the metadata space to 4M, the largest LUKS2 supports */
        r = sym_crypt_set_metadata_size(cd, 4096U*1024U, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to change LUKS2 metadata size: %m");
#endif

        build_good_pbkdf(&good_pbkdf, hr);
        build_minimal_pbkdf(&minimal_pbkdf, hr);

        r = sym_crypt_format(
                        cd,
                        CRYPT_LUKS2,
                        user_record_luks_cipher(hr),
                        user_record_luks_cipher_mode(hr),
                        SD_ID128_TO_UUID_STRING(uuid),
                        volume_key,
                        volume_key_size,
                        &(struct crypt_params_luks2) {
                                .label = label,
                                .subsystem = "systemd-home",
                                .sector_size = user_record_luks_sector_size(hr),
                                .pbkdf = &good_pbkdf,
                        });
        if (r < 0)
                return log_error_errno(r, "Failed to format LUKS image: %m");

        log_info("LUKS formatting completed.");

        STRV_FOREACH(pp, effective_passwords) {

                if (password_cache_contains(cache, *pp)) { /* is this a fido2 or pkcs11 password? */
                        log_debug("Using minimal PBKDF for slot %i", slot);
                        r = sym_crypt_set_pbkdf_type(cd, &minimal_pbkdf);
                } else {
                        log_debug("Using good PBKDF for slot %i", slot);
                        r = sym_crypt_set_pbkdf_type(cd, &good_pbkdf);
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to tweak PBKDF for slot %i: %m", slot);

                r = sym_crypt_keyslot_add_by_volume_key(
                                cd,
                                slot,
                                volume_key,
                                volume_key_size,
                                *pp,
                                strlen(*pp));
                if (r < 0)
                        return log_error_errno(r, "Failed to set up LUKS password for slot %i: %m", slot);

                log_info("Writing password to LUKS keyslot %i completed.", slot);
                slot++;
        }

        r = sym_crypt_activate_by_volume_key(
                        cd,
                        dm_name,
                        volume_key,
                        volume_key_size,
                        discard ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0);
        if (r < 0)
                return log_error_errno(r, "Failed to activate LUKS superblock: %m");

        log_info("LUKS activation by volume key succeeded.");

        r = user_record_clone(hr, USER_RECORD_EXTRACT_EMBEDDED|USER_RECORD_PERMISSIVE, &reduced);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare home record for LUKS: %m");

        r = format_luks_token_text(cd, reduced, volume_key, &text);
        if (r < 0)
                return r;

        r = sym_crypt_token_json_set(cd, CRYPT_ANY_TOKEN, text);
        if (r < 0)
                return log_error_errno(r, "Failed to set LUKS JSON token: %m");

        log_info("Writing user record as LUKS token completed.");

        if (ret)
                *ret = TAKE_PTR(cd);

        return 0;
}

static int make_partition_table(
                int fd,
                uint32_t sector_size,
                const char *label,
                sd_id128_t uuid,
                uint64_t *ret_offset,
                uint64_t *ret_size,
                sd_id128_t *ret_disk_uuid) {

        _cleanup_(fdisk_unref_partitionp) struct fdisk_partition *p = NULL, *q = NULL;
        _cleanup_(fdisk_unref_parttypep) struct fdisk_parttype *t = NULL;
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_free_ char *disk_uuid_as_string = NULL;
        uint64_t offset, size, first_lba, start, last_lba, end;
        sd_id128_t disk_uuid;
        int r;

        assert(fd >= 0);
        assert(label);
        assert(ret_offset);
        assert(ret_size);

        t = fdisk_new_parttype();
        if (!t)
                return log_oom();

        r = fdisk_parttype_set_typestr(t, SD_GPT_USER_HOME_STR);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize partition type: %m");

        r = fdisk_new_context_at(fd, /* path= */ NULL, /* read_only= */ false, sector_size, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to open device: %m");

        r = fdisk_create_disklabel(c, "gpt");
        if (r < 0)
                return log_error_errno(r, "Failed to create GPT disk label: %m");

        p = fdisk_new_partition();
        if (!p)
                return log_oom();

        r = fdisk_partition_set_type(p, t);
        if (r < 0)
                return log_error_errno(r, "Failed to set partition type: %m");

        r = fdisk_partition_partno_follow_default(p, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to place partition at first free partition index: %m");

        first_lba = fdisk_get_first_lba(c); /* Boundary where usable space starts */
        assert(first_lba <= UINT64_MAX/512);
        start = DISK_SIZE_ROUND_UP(first_lba * 512); /* Round up to multiple of 4K */

        log_debug("Starting partition at offset %" PRIu64, start);

        if (start == UINT64_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Overflow while rounding up start LBA.");

        last_lba = fdisk_get_last_lba(c); /* One sector before boundary where usable space ends */
        assert(last_lba < UINT64_MAX/512);
        end = DISK_SIZE_ROUND_DOWN((last_lba + 1) * 512); /* Round down to multiple of 4K */

        if (end <= start)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Resulting partition size zero or negative.");

        r = fdisk_partition_set_start(p, start / 512);
        if (r < 0)
                return log_error_errno(r, "Failed to place partition at offset %" PRIu64 ": %m", start);

        r = fdisk_partition_set_size(p, (end - start) / 512);
        if (r < 0)
                return log_error_errno(r, "Failed to end partition at offset %" PRIu64 ": %m", end);

        r = fdisk_partition_set_name(p, label);
        if (r < 0)
                return log_error_errno(r, "Failed to set partition name: %m");

        r = fdisk_partition_set_uuid(p, SD_ID128_TO_UUID_STRING(uuid));
        if (r < 0)
                return log_error_errno(r, "Failed to set partition UUID: %m");

        r = fdisk_add_partition(c, p, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add partition: %m");

        r = fdisk_write_disklabel(c);
        if (r < 0)
                return log_error_errno(r, "Failed to write disk label: %m");

        r = fdisk_get_disklabel_id(c, &disk_uuid_as_string);
        if (r < 0)
                return log_error_errno(r, "Failed to determine disk label UUID: %m");

        r = sd_id128_from_string(disk_uuid_as_string, &disk_uuid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse disk label UUID: %m");

        r = fdisk_get_partition(c, 0, &q);
        if (r < 0)
                return log_error_errno(r, "Failed to read created partition metadata: %m");

        assert(fdisk_partition_has_start(q));
        offset = fdisk_partition_get_start(q);
        if (offset > UINT64_MAX / 512U)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Partition offset too large.");

        assert(fdisk_partition_has_size(q));
        size = fdisk_partition_get_size(q);
        if (size > UINT64_MAX / 512U)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Partition size too large.");

        *ret_offset = offset * 512U;
        *ret_size = size * 512U;
        *ret_disk_uuid = disk_uuid;

        return 0;
}

static bool supported_fs_size(const char *fstype, uint64_t host_size) {
        uint64_t m;

        m = minimal_size_by_fs_name(fstype);
        if (m == UINT64_MAX)
                return false;

        return host_size >= m;
}

static int wait_for_devlink(const char *path) {
        _cleanup_close_ int inotify_fd = -EBADF;
        usec_t until;
        int r;

        /* let's wait for a device link to show up in /dev, with a timeout. This is good to do since we
         * return a /dev/disk/by-uuid/… link to our callers and they likely want to access it right-away,
         * hence let's wait until udev has caught up with our changes, and wait for the symlink to be
         * created. */

        until = usec_add(now(CLOCK_MONOTONIC), 45 * USEC_PER_SEC);

        for (;;) {
                _cleanup_free_ char *dn = NULL;
                usec_t w;

                if (laccess(path, F_OK) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to determine whether %s exists: %m", path);
                } else
                        return 0; /* Found it */

                if (inotify_fd < 0) {
                        /* We need to wait for the device symlink to show up, let's create an inotify watch for it */
                        inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                        if (inotify_fd < 0)
                                return log_error_errno(errno, "Failed to allocate inotify fd: %m");
                }

                r = path_extract_directory(path, &dn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract directory from device node path '%s': %m", path);
                for (;;) {
                        _cleanup_free_ char *ndn = NULL;

                        log_info("Watching %s", dn);

                        if (inotify_add_watch(inotify_fd, dn, IN_CREATE|IN_MOVED_TO|IN_ONLYDIR|IN_DELETE_SELF|IN_MOVE_SELF) < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to add watch on %s: %m", dn);
                        } else
                                break;

                        r = path_extract_directory(dn, &ndn);
                        if (r == -EADDRNOTAVAIL) /* Arrived at the top? */
                                break;
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract directory from device node path '%s': %m", dn);

                        free_and_replace(dn, ndn);
                }

                w = now(CLOCK_MONOTONIC);
                if (w >= until)
                        return log_error_errno(SYNTHETIC_ERRNO(ETIMEDOUT), "Device link %s still hasn't shown up, giving up.", path);

                r = fd_wait_for_event(inotify_fd, POLLIN, until - w);
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to watch inotify: %m");

                (void) flush_fd(inotify_fd);
        }
}

static int calculate_initial_image_size(UserRecord *h, int image_fd, const char *fstype, uint64_t *ret) {
        uint64_t upper_boundary, lower_boundary;
        struct statfs sfs;

        assert(h);
        assert(image_fd >= 0);
        assert(ret);

        if (fstatfs(image_fd, &sfs) < 0)
                return log_error_errno(errno, "statfs() on image failed: %m");

        upper_boundary = DISK_SIZE_ROUND_DOWN((uint64_t) sfs.f_bsize * sfs.f_bavail);

        if (h->disk_size != UINT64_MAX)
                *ret = MIN(DISK_SIZE_ROUND_DOWN(h->disk_size), upper_boundary);
        else if (h->disk_size_relative == UINT64_MAX) {

                if (upper_boundary > UINT64_MAX / USER_DISK_SIZE_DEFAULT_PERCENT)
                        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Disk size too large.");

                *ret = DISK_SIZE_ROUND_DOWN(upper_boundary * USER_DISK_SIZE_DEFAULT_PERCENT / 100);

                log_info("Sizing home to %u%% of available disk space, which is %s.",
                         USER_DISK_SIZE_DEFAULT_PERCENT,
                         FORMAT_BYTES(*ret));
        } else {
                *ret = DISK_SIZE_ROUND_DOWN((uint64_t) ((double) upper_boundary * (double) CLAMP(h->disk_size_relative, 0U, UINT32_MAX) / (double) UINT32_MAX));

                log_info("Sizing home to %" PRIu64 ".%01" PRIu64 "%% of available disk space, which is %s.",
                         (h->disk_size_relative * 100) / UINT32_MAX,
                         ((h->disk_size_relative * 1000) / UINT32_MAX) % 10,
                         FORMAT_BYTES(*ret));
        }

        lower_boundary = minimal_size_by_fs_name(fstype);
        if (lower_boundary != UINT64_MAX) {
                assert(GPT_LUKS2_OVERHEAD < UINT64_MAX - lower_boundary);
                lower_boundary += GPT_LUKS2_OVERHEAD;
        }
        if (lower_boundary == UINT64_MAX || lower_boundary < USER_DISK_SIZE_MIN)
                lower_boundary = USER_DISK_SIZE_MIN;

        if (*ret < lower_boundary)
                *ret = lower_boundary;

        return 0;
}

static int home_truncate(
                UserRecord *h,
                int fd,
                uint64_t size) {

        bool trunc;
        int r;

        assert(h);
        assert(fd >= 0);

        trunc = user_record_luks_discard(h);
        if (!trunc) {
                r = fallocate(fd, 0, 0, size);
                if (r < 0 && ERRNO_IS_NOT_SUPPORTED(errno)) {
                        /* Some file systems do not support fallocate(), let's gracefully degrade
                         * (ZFS, reiserfs, …) and fall back to truncation */
                        log_notice_errno(errno, "Backing file system does not support fallocate(), falling back to ftruncate(), i.e. implicitly using non-discard mode.");
                        trunc = true;
                }
        }

        if (trunc)
                r = ftruncate(fd, size);

        if (r < 0) {
                if (ERRNO_IS_DISK_SPACE(errno)) {
                        log_debug_errno(errno, "Not enough disk space to allocate home of size %s.", FORMAT_BYTES(size));
                        return -ENOSPC; /* make recognizable */
                }

                return log_error_errno(errno, "Failed to truncate home image: %m");
        }

        return !trunc; /* Return == 0 if we managed to truncate, > 0 if we managed to allocate */
}

int home_create_luks(
                UserRecord *h,
                HomeSetup *setup,
                const PasswordCache *cache,
                char **effective_passwords,
                UserRecord **ret_home) {

        _cleanup_free_ char *subdir = NULL, *disk_uuid_path = NULL;
        uint64_t encrypted_size,
                host_size = 0, partition_offset = 0, partition_size = 0; /* Unnecessary initialization to appease gcc */
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        sd_id128_t partition_uuid, fs_uuid, luks_uuid, disk_uuid;
        _cleanup_close_ int mount_fd = -EBADF;
        const char *fstype, *ip;
        struct statfs sfs;
        int r;
        _cleanup_strv_free_ char **extra_mkfs_options = NULL;

        assert(h);
        assert(h->storage < 0 || h->storage == USER_LUKS);
        assert(setup);
        assert(!setup->temporary_image_path);
        assert(setup->image_fd < 0);
        assert(ret_home);

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        assert_se(ip = user_record_image_path(h));

        fstype = user_record_file_system_type(h);
        if (!supported_fstype(fstype))
                return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "Unsupported file system type: %s", fstype);

        r = mkfs_exists(fstype);
        if (r < 0)
                return log_error_errno(r, "Failed to check if mkfs binary for %s exists: %m", fstype);
        if (r == 0) {
                if (h->file_system_type || streq(fstype, "ext4") || !supported_fstype("ext4"))
                        return log_error_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "mkfs binary for file system type %s does not exist.", fstype);

                /* If the record does not explicitly declare a file system to use, and the compiled-in
                 * default does not actually exist, than do an automatic fallback onto ext4, as the baseline
                 * fs of Linux. We won't search for a working fs type here beyond ext4, i.e. nothing fancier
                 * than a single, conservative fallback to baseline. This should be useful in minimal
                 * environments where mkfs.btrfs or so are not made available, but mkfs.ext4 as Linux' most
                 * boring, most basic fs is. */
                log_info("Formatting tool for compiled-in default file system %s not available, falling back to ext4 instead.", fstype);
                fstype = "ext4";
        }

        if (sd_id128_is_null(h->partition_uuid)) {
                r = sd_id128_randomize(&partition_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire partition UUID: %m");
        } else
                partition_uuid = h->partition_uuid;

        if (sd_id128_is_null(h->luks_uuid)) {
                r = sd_id128_randomize(&luks_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire LUKS UUID: %m");
        } else
                luks_uuid = h->luks_uuid;

        if (sd_id128_is_null(h->file_system_uuid)) {
                r = sd_id128_randomize(&fs_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire file system UUID: %m");
        } else
                fs_uuid = h->file_system_uuid;

        r = make_dm_names(h, setup);
        if (r < 0)
                return r;

        r = access(setup->dm_node, F_OK);
        if (r < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to determine whether %s exists: %m", setup->dm_node);
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Device mapper device %s already exists, refusing.", setup->dm_node);

        if (path_startswith(ip, "/dev/")) {
                _cleanup_free_ char *sysfs = NULL;
                uint64_t block_device_size;
                struct stat st;

                /* Let's place the home directory on a real device, i.e. a USB stick or such */

                setup->image_fd = open_image_file(h, ip, &st);
                if (setup->image_fd < 0)
                        return setup->image_fd;

                if (!S_ISBLK(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Device is not a block device, refusing.");

                if (asprintf(&sysfs, "/sys/dev/block/" DEVNUM_FORMAT_STR "/partition", DEVNUM_FORMAT_VAL(st.st_rdev)) < 0)
                        return log_oom();
                if (access(sysfs, F_OK) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to check whether %s exists: %m", sysfs);
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Operating on partitions is currently not supported, sorry. Please specify a top-level block device.");

                if (flock(setup->image_fd, LOCK_EX) < 0) /* make sure udev doesn't read from it while we operate on the device */
                        return log_error_errno(errno, "Failed to lock block device %s: %m", ip);

                r = blockdev_get_device_size(setup->image_fd, &block_device_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to read block device size: %m");

                if (h->disk_size == UINT64_MAX) {

                        /* If a relative disk size is requested, apply it relative to the block device size */
                        if (h->disk_size_relative < UINT32_MAX)
                                host_size = CLAMP(DISK_SIZE_ROUND_DOWN(block_device_size * h->disk_size_relative / UINT32_MAX),
                                                  USER_DISK_SIZE_MIN, USER_DISK_SIZE_MAX);
                        else
                                host_size = block_device_size; /* Otherwise, take the full device */

                } else if (h->disk_size > block_device_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EMSGSIZE), "Selected disk size larger than backing block device, refusing.");
                else
                        host_size = DISK_SIZE_ROUND_DOWN(h->disk_size);

                if (!supported_fs_size(fstype, LESS_BY(host_size, GPT_LUKS2_OVERHEAD)))
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                               "Selected file system size too small for %s.", fstype);

                /* After creation we should reference this partition by its UUID instead of the block
                 * device. That's preferable since the user might have specified a device node such as
                 * /dev/sdb to us, which might look very different when replugged. */
                if (asprintf(&disk_uuid_path, "/dev/disk/by-uuid/" SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(luks_uuid)) < 0)
                        return log_oom();

                if (user_record_luks_discard(h) || user_record_luks_offline_discard(h)) {
                        /* If we want online or offline discard, discard once before we start using things. */

                        if (ioctl(setup->image_fd, BLKDISCARD, (uint64_t[]) { 0, block_device_size }) < 0)
                                log_full_errno(errno == EOPNOTSUPP ? LOG_DEBUG : LOG_WARNING, errno,
                                               "Failed to issue full-device BLKDISCARD on device, ignoring: %m");
                        else
                                log_info("Full device discard completed.");
                }
        } else {
                _cleanup_free_ char *t = NULL;

                r = mkdir_parents(ip, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create parent directory of %s: %m", ip);

                r = tempfn_random(ip, "homework", &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive temporary file name for %s: %m", ip);

                setup->image_fd = open(t, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
                if (setup->image_fd < 0)
                        return log_error_errno(errno, "Failed to create home image %s: %m", t);

                setup->temporary_image_path = TAKE_PTR(t);

                r = chattr_full(setup->image_fd, NULL, FS_NOCOW_FL|FS_NOCOMP_FL, FS_NOCOW_FL|FS_NOCOMP_FL, NULL, NULL, CHATTR_FALLBACK_BITWISE);
                if (r < 0 && r != -ENOANO) /* ENOANO → some bits didn't work; which we skip logging about because chattr_full() already debug logs about those flags */
                        log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to set file attributes on %s, ignoring: %m", setup->temporary_image_path);

                r = calculate_initial_image_size(h, setup->image_fd, fstype, &host_size);
                if (r < 0)
                        return r;

                r = resize_image_loop(h, setup, 0, host_size, &host_size);
                if (r < 0)
                        return r;

                log_info("Allocating image file completed.");
        }

        r = make_partition_table(
                        setup->image_fd,
                        user_record_luks_sector_size(h),
                        user_record_user_name_and_realm(h),
                        partition_uuid,
                        &partition_offset,
                        &partition_size,
                        &disk_uuid);
        if (r < 0)
                return r;

        log_info("Writing of partition table completed.");

        r = loop_device_make(
                        setup->image_fd,
                        O_RDWR,
                        partition_offset,
                        partition_size,
                        user_record_luks_sector_size(h),
                        0,
                        LOCK_EX,
                        &setup->loop);
        if (r < 0) {
                if (r == -ENOENT) { /* this means /dev/loop-control doesn't exist, i.e. we are in a container
                                     * or similar and loopback bock devices are not available, return a
                                     * recognizable error in this case. */
                        log_error_errno(r, "Loopback block device support is not available on this system.");
                        return -ENOLINK; /* Make recognizable */
                }

                return log_error_errno(r, "Failed to set up loopback device for %s: %m", setup->temporary_image_path);
        }

        log_info("Setting up loopback device %s completed.", setup->loop->node ?: ip);

        r = luks_format(setup->loop->node,
                        setup->dm_name,
                        luks_uuid,
                        user_record_user_name_and_realm(h),
                        cache,
                        effective_passwords,
                        user_record_luks_discard(h) || user_record_luks_offline_discard(h),
                        h,
                        &setup->crypt_device);
        if (r < 0)
                return r;

        setup->undo_dm = true;

        r = block_get_size_by_path(setup->dm_node, &encrypted_size);
        if (r < 0)
                return log_error_errno(r, "Failed to get encrypted block device size: %m");

        log_info("Setting up LUKS device %s completed.", setup->dm_node);

        r = mkfs_options_from_env("HOME", fstype, &extra_mkfs_options);
        if (r < 0)
                return log_error_errno(r, "Failed to determine mkfs command line options for '%s': %m", fstype);

        r = make_filesystem(setup->dm_node,
                            fstype,
                            user_record_user_name_and_realm(h),
                            /* root = */ NULL,
                            fs_uuid,
                            user_record_luks_discard(h),
                            /* quiet = */ true,
                            /* sector_size = */ 0,
                            extra_mkfs_options);
        if (r < 0)
                return r;

        log_info("Formatting file system completed.");

        r = home_unshare_and_mount(setup->dm_node, fstype, user_record_luks_discard(h), user_record_mount_flags(h), h->luks_extra_mount_options);
        if (r < 0)
                return r;

        setup->undo_mount = true;

        subdir = path_join(HOME_RUNTIME_WORK_DIR, user_record_user_name_and_realm(h));
        if (!subdir)
                return log_oom();

        /* Prefer using a btrfs subvolume if we can, fall back to directory otherwise */
        r = btrfs_subvol_make_fallback(AT_FDCWD, subdir, 0700);
        if (r < 0)
                return log_error_errno(r, "Failed to create user directory in mounted image file: %m");

        setup->root_fd = open(subdir, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open user directory in mounted image file: %m");

        (void) home_shift_uid(setup->root_fd, NULL, UID_NOBODY, h->uid, &mount_fd);

        if (mount_fd >= 0) {
                /* If we have established a new mount, then we can use that as new root fd to our home directory. */
                safe_close(setup->root_fd);

                setup->root_fd = fd_reopen(mount_fd, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (setup->root_fd < 0)
                        return log_error_errno(setup->root_fd, "Unable to convert mount fd into proper directory fd: %m");

                mount_fd = safe_close(mount_fd);
        }

        r = home_populate(h, setup->root_fd);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup->root_fd, &sfs);
        if (r < 0)
                return r;

        r = user_record_clone(h, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_LOG|USER_RECORD_PERMISSIVE, &new_home);
        if (r < 0)
                return log_error_errno(r, "Failed to clone record: %m");

        r = user_record_add_binding(
                        new_home,
                        USER_LUKS,
                        disk_uuid_path ?: ip,
                        partition_uuid,
                        luks_uuid,
                        fs_uuid,
                        sym_crypt_get_cipher(setup->crypt_device),
                        sym_crypt_get_cipher_mode(setup->crypt_device),
                        luks_volume_key_size_convert(setup->crypt_device),
                        fstype,
                        NULL,
                        h->uid,
                        (gid_t) h->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to add binding to record: %m");

        if (user_record_luks_offline_discard(h)) {
                r = run_fitrim(setup->root_fd);
                if (r < 0)
                        return r;
        }

        setup->root_fd = safe_close(setup->root_fd);

        r = home_setup_undo_mount(setup, LOG_ERR);
        if (r < 0)
                return r;

        r = home_setup_undo_dm(setup, LOG_ERR);
        if (r < 0)
                return r;

        setup->loop = loop_device_unref(setup->loop);

        if (!user_record_luks_offline_discard(h)) {
                r= run_fallocate(setup->image_fd, NULL /* refresh stat() data */);
                if (r < 0)
                        return r;
        }

        /* Sync everything to disk before we move things into place under the final name. */
        if (fsync(setup->image_fd) < 0)
                return log_error_errno(r, "Failed to synchronize image to disk: %m");

        if (disk_uuid_path)
                /* Reread partition table if this is a block device */
                (void) ioctl(setup->image_fd, BLKRRPART, 0);
        else {
                assert(setup->temporary_image_path);

                if (rename(setup->temporary_image_path, ip) < 0)
                        return log_error_errno(errno, "Failed to rename image file: %m");

                setup->temporary_image_path = mfree(setup->temporary_image_path);

                /* If we operate on a file, sync the containing directory too. */
                r = fsync_directory_of_file(setup->image_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to synchronize directory of image file to disk: %m");

                log_info("Moved image file into place.");
        }

        /* Let's close the image fd now. If we are operating on a real block device this will release the BSD
         * lock that ensures udev doesn't interfere with what we are doing */
        setup->image_fd = safe_close(setup->image_fd);

        if (disk_uuid_path)
                (void) wait_for_devlink(disk_uuid_path);

        log_info("Creation completed.");

        print_size_summary(host_size, encrypted_size, &sfs);

        log_debug("GPT + LUKS2 overhead is %" PRIu64 " (expected %" PRIu64 ")", host_size - encrypted_size, GPT_LUKS2_OVERHEAD);

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_get_state_luks(UserRecord *h, HomeSetup *setup) {
        int r;

        assert(h);
        assert(setup);

        r = make_dm_names(h, setup);
        if (r < 0)
                return r;

        r = access(setup->dm_node, F_OK);
        if (r < 0 && errno != ENOENT)
                return log_error_errno(errno, "Failed to determine whether %s exists: %m", setup->dm_node);

        return r >= 0;
}

enum {
        CAN_RESIZE_ONLINE,
        CAN_RESIZE_OFFLINE,
};

static int can_resize_fs(int fd, uint64_t old_size, uint64_t new_size) {
        struct statfs sfs;

        assert(fd >= 0);

        /* Filter out bogus requests early */
        if (old_size == 0 || old_size == UINT64_MAX ||
            new_size == 0 || new_size == UINT64_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid resize parameters.");

        if ((old_size & 511) != 0 || (new_size & 511) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Resize parameters not multiple of 512.");

        if (fstatfs(fd, &sfs) < 0)
                return log_error_errno(errno, "Failed to fstatfs() file system: %m");

        if (is_fs_type(&sfs, BTRFS_SUPER_MAGIC)) {

                if (new_size < BTRFS_MINIMAL_SIZE)
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "New file system size too small for btrfs (needs to be 256M at least.");

                /* btrfs can grow and shrink online */

        } else if (is_fs_type(&sfs, XFS_SB_MAGIC)) {

                if (new_size < XFS_MINIMAL_SIZE)
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "New file system size too small for xfs (needs to be 14M at least).");

                /* XFS can grow, but not shrink */
                if (new_size < old_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EMSGSIZE), "Shrinking this type of file system is not supported.");

        } else if (is_fs_type(&sfs, EXT4_SUPER_MAGIC)) {

                if (new_size < EXT4_MINIMAL_SIZE)
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "New file system size too small for ext4 (needs to be 1M at least).");

                /* ext4 can grow online, and shrink offline */
                if (new_size < old_size)
                        return CAN_RESIZE_OFFLINE;

        } else
                return log_error_errno(SYNTHETIC_ERRNO(ESOCKTNOSUPPORT), "Resizing this type of file system is not supported.");

        return CAN_RESIZE_ONLINE;
}

static int ext4_offline_resize_fs(
                HomeSetup *setup,
                uint64_t new_size,
                bool discard,
                unsigned long flags,
                const char *extra_mount_options) {

        _cleanup_free_ char *size_str = NULL;
        bool re_open = false, re_mount = false;
        pid_t resize_pid, fsck_pid;
        int r, exit_status;

        assert(setup);
        assert(setup->dm_node);

        /* First, unmount the file system */
        if (setup->root_fd >= 0) {
                setup->root_fd = safe_close(setup->root_fd);
                re_open = true;
        }

        if (setup->undo_mount) {
                r = home_setup_undo_mount(setup, LOG_ERR);
                if (r < 0)
                        return r;

                re_mount = true;
        }

        log_info("Temporary unmounting of file system completed.");

        /* resize2fs requires that the file system is force checked first, do so. */
        r = safe_fork("(e2fsck)",
                      FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS,
                      &fsck_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execlp("e2fsck" ,"e2fsck", "-fp", setup->dm_node, NULL);
                log_open();
                log_error_errno(errno, "Failed to execute e2fsck: %m");
                _exit(EXIT_FAILURE);
        }

        exit_status = wait_for_terminate_and_check("e2fsck", fsck_pid, WAIT_LOG_ABNORMAL);
        if (exit_status < 0)
                return exit_status;
        if ((exit_status & ~FSCK_ERROR_CORRECTED) != 0) {
                log_warning("e2fsck failed with exit status %i.", exit_status);

                if ((exit_status & (FSCK_SYSTEM_SHOULD_REBOOT|FSCK_ERRORS_LEFT_UNCORRECTED)) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "File system is corrupted, refusing.");

                log_warning("Ignoring fsck error.");
        }

        log_info("Forced file system check completed.");

        /* We use 512 sectors here, because resize2fs doesn't do byte sizes */
        if (asprintf(&size_str, "%" PRIu64 "s", new_size / 512) < 0)
                return log_oom();

        /* Resize the thing */
        r = safe_fork("(e2resize)",
                      FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS,
                      &resize_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execlp("resize2fs" ,"resize2fs", setup->dm_node, size_str, NULL);
                log_open();
                log_error_errno(errno, "Failed to execute resize2fs: %m");
                _exit(EXIT_FAILURE);
        }

        log_info("Offline file system resize completed.");

        /* Re-establish mounts and reopen the directory */
        if (re_mount) {
                r = home_mount_node(setup->dm_node, "ext4", discard, flags, extra_mount_options);
                if (r < 0)
                        return r;

                setup->undo_mount = true;
        }

        if (re_open) {
                setup->root_fd = open(HOME_RUNTIME_WORK_DIR, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (setup->root_fd < 0)
                        return log_error_errno(errno, "Failed to reopen file system: %m");
        }

        log_info("File system mounted again.");

        return 0;
}

static int prepare_resize_partition(
                int fd,
                uint64_t partition_offset,
                uint64_t old_partition_size,
                sd_id128_t *ret_disk_uuid,
                struct fdisk_table **ret_table,
                struct fdisk_partition **ret_partition) {

        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        _cleanup_free_ char *disk_uuid_as_string = NULL;
        struct fdisk_partition *found = NULL;
        sd_id128_t disk_uuid;
        size_t n_partitions;
        int r;

        assert(fd >= 0);
        assert(ret_disk_uuid);
        assert(ret_table);

        assert((partition_offset & 511) == 0);
        assert((old_partition_size & 511) == 0);
        assert(UINT64_MAX - old_partition_size >= partition_offset);

        if (partition_offset == 0) {
                /* If the offset is at the beginning we assume no partition table, let's exit early. */
                log_debug("Not rewriting partition table, operating on naked device.");
                *ret_disk_uuid = SD_ID128_NULL;
                *ret_table = NULL;
                *ret_partition = NULL;
                return 0;
        }

        r = fdisk_new_context_at(fd, /* path= */ NULL, /* read_only= */ false, UINT32_MAX, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to open device: %m");

        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEDIUM), "Disk has no GPT partition table.");

        r = fdisk_get_disklabel_id(c, &disk_uuid_as_string);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire disk UUID: %m");

        r = sd_id128_from_string(disk_uuid_as_string, &disk_uuid);
        if (r < 0)
                return log_error_errno(r, "Failed parse disk UUID: %m");

        r = fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++)  {
                struct fdisk_partition *p;

                p = fdisk_table_get_partition(t, i);
                if (!p)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata: %m");

                if (fdisk_partition_is_used(p) <= 0)
                        continue;
                if (fdisk_partition_has_start(p) <= 0 || fdisk_partition_has_size(p) <= 0 || fdisk_partition_has_end(p) <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Found partition without a size.");

                if (fdisk_partition_get_start(p) == partition_offset / 512U &&
                    fdisk_partition_get_size(p) == old_partition_size / 512U) {

                        if (found)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Partition found twice, refusing.");

                        found = p;
                } else if (fdisk_partition_get_end(p) > partition_offset / 512U)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't extend, not last partition in image.");
        }

        if (!found)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "Failed to find matching partition to resize.");

        *ret_disk_uuid = disk_uuid;
        *ret_table = TAKE_PTR(t);
        *ret_partition = found;

        return 1;
}

static int get_maximum_partition_size(
                int fd,
                struct fdisk_partition *p,
                uint64_t *ret_maximum_partition_size) {

        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        uint64_t start_lba, start, last_lba, end;
        int r;

        assert(fd >= 0);
        assert(p);
        assert(ret_maximum_partition_size);

        r = fdisk_new_context_at(fd, /* path= */ NULL, /* read_only= */ true, /* sector_size= */ UINT32_MAX, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to create fdisk context: %m");

        start_lba = fdisk_partition_get_start(p);
        assert(start_lba <= UINT64_MAX/512);
        start = start_lba * 512;

        last_lba = fdisk_get_last_lba(c); /* One sector before boundary where usable space ends */
        assert(last_lba < UINT64_MAX/512);
        end = DISK_SIZE_ROUND_DOWN((last_lba + 1) * 512); /* Round down to multiple of 4K */

        if (start > end)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Last LBA is before partition start.");

        *ret_maximum_partition_size = DISK_SIZE_ROUND_DOWN(end - start);

        return 1;
}

static int ask_cb(struct fdisk_context *c, struct fdisk_ask *ask, void *userdata) {
        char *result;

        assert(c);

        switch (fdisk_ask_get_type(ask)) {

        case FDISK_ASKTYPE_STRING:
                result = new(char, 37);
                if (!result)
                        return log_oom();

                fdisk_ask_string_set_result(ask, sd_id128_to_uuid_string(*(sd_id128_t*) userdata, result));
                break;

        default:
                log_debug("Unexpected question from libfdisk, ignoring.");
        }

        return 0;
}

static int apply_resize_partition(
                int fd,
                sd_id128_t disk_uuids,
                struct fdisk_table *t,
                struct fdisk_partition *p,
                size_t new_partition_size) {

        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_free_ void *two_zero_lbas = NULL;
        uint32_t ssz;
        ssize_t n;
        int r;

        assert(fd >= 0);
        assert(!t == !p);

        if (!t) /* no partition table to apply, exit early */
                return 0;

        assert(p);

        /* Before writing our partition patch the final size in */
        r = fdisk_partition_size_explicit(p, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to enable explicit partition size: %m");

        r = fdisk_partition_set_size(p, new_partition_size / 512U);
        if (r < 0)
                return log_error_errno(r, "Failed to change partition size: %m");

        r = probe_sector_size(fd, &ssz);
        if (r < 0)
                return log_error_errno(r, "Failed to determine current sector size: %m");

        two_zero_lbas = malloc0(ssz * 2);
        if (!two_zero_lbas)
                return log_oom();

        /* libfdisk appears to get confused by the existing PMBR. Let's explicitly flush it out. */
        n = pwrite(fd, two_zero_lbas, ssz * 2, 0);
        if (n < 0)
                return log_error_errno(errno, "Failed to wipe partition table: %m");
        if ((size_t) n != ssz * 2)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while wiping partition table.");

        r = fdisk_new_context_at(fd, /* path= */ NULL, /* read_only= */ false, ssz, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to open device: %m");

        r = fdisk_create_disklabel(c, "gpt");
        if (r < 0)
                return log_error_errno(r, "Failed to create GPT disk label: %m");

        r = fdisk_apply_table(c, t);
        if (r < 0)
                return log_error_errno(r, "Failed to apply partition table: %m");

        r = fdisk_set_ask(c, ask_cb, &disk_uuids);
        if (r < 0)
                return log_error_errno(r, "Failed to set libfdisk query function: %m");

        r = fdisk_set_disklabel_id(c);
        if (r < 0)
                return log_error_errno(r, "Failed to change disklabel ID: %m");

        r = fdisk_write_disklabel(c);
        if (r < 0)
                return log_error_errno(r, "Failed to write disk label: %m");

        return 1;
}

/* Always keep at least 16M free, so that we can safely log in and update the user record while doing so */
#define HOME_MIN_FREE (16U*1024U*1024U)

static int get_smallest_fs_size(int fd, uint64_t *ret) {
        uint64_t minsz, needed;
        struct statfs sfs;

        assert(fd >= 0);
        assert(ret);

        /* Determines the minimal disk size we might be able to shrink the file system referenced by the fd to. */

        if (syncfs(fd) < 0) /* let's sync before we query the size, so that the values returned are accurate */
                return log_error_errno(errno, "Failed to synchronize home file system: %m");

        if (fstatfs(fd, &sfs) < 0)
                return log_error_errno(errno, "Failed to statfs() home file system: %m");

        /* Let's determine the minimal file system size of the used fstype */
        minsz = minimal_size_by_fs_magic(sfs.f_type);
        if (minsz == UINT64_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Don't know minimum file system size of file system type '%s' of home directory.", fs_type_to_string(sfs.f_type));

        if (minsz < USER_DISK_SIZE_MIN)
                minsz = USER_DISK_SIZE_MIN;

        if (sfs.f_bfree > sfs.f_blocks)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Detected amount of free blocks is greater than the total amount of file system blocks. Refusing.");

        /* Calculate how much disk space is currently in use. */
        needed = sfs.f_blocks - sfs.f_bfree;
        if (needed > UINT64_MAX / sfs.f_bsize)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File system size out of range.");

        needed *= sfs.f_bsize;

        /* Add some safety margin of free space we'll always keep */
        if (needed > UINT64_MAX - HOME_MIN_FREE) /* Check for overflow */
                needed = UINT64_MAX;
        else
                needed += HOME_MIN_FREE;

        *ret = DISK_SIZE_ROUND_UP(MAX(needed, minsz));
        return 0;
}

static int get_largest_image_size(int fd, const struct stat *st, uint64_t *ret) {
        uint64_t used, avail, sum;
        struct statfs sfs;
        int r;

        assert(fd >= 0);
        assert(st);
        assert(ret);

        /* Determines the maximum file size we might be able to grow the image file referenced by the fd to. */

        r = stat_verify_regular(st);
        if (r < 0)
                return log_error_errno(r, "Image file is not a regular file, refusing: %m");

        if (syncfs(fd) < 0)
                return log_error_errno(errno, "Failed to synchronize file system backing image file: %m");

        if (fstatfs(fd, &sfs) < 0)
                return log_error_errno(errno, "Failed to statfs() image file: %m");

        used = (uint64_t) st->st_blocks * 512;
        avail = (uint64_t) sfs.f_bsize * sfs.f_bavail;

        if (avail > UINT64_MAX - used)
                sum = UINT64_MAX;
        else
                sum = avail + used;

        *ret = DISK_SIZE_ROUND_DOWN(MIN(sum, USER_DISK_SIZE_MAX));
        return 0;
}

static int resize_fs_loop(
                UserRecord *h,
                HomeSetup *setup,
                int resize_type,
                uint64_t old_fs_size,
                uint64_t new_fs_size,
                uint64_t *ret_fs_size) {

        uint64_t current_fs_size;
        unsigned n_iterations = 0;
        int r;

        assert(h);
        assert(setup);
        assert(setup->root_fd >= 0);

        /* A bisection loop trying to find the closest size to what the user asked for. (Well, we bisect like
         * this only when we *shrink* the fs — if we grow the fs there's no need to bisect.) */

        current_fs_size = old_fs_size;
        for (uint64_t lower_boundary = new_fs_size, upper_boundary = old_fs_size, try_fs_size = new_fs_size;;) {
                bool worked;

                n_iterations++;

                /* Now resize the file system */
                if (resize_type == CAN_RESIZE_ONLINE) {
                        r = resize_fs(setup->root_fd, try_fs_size, NULL);
                        if (r < 0) {
                                if (!ERRNO_IS_DISK_SPACE(r) || new_fs_size > old_fs_size) /* Not a disk space issue? Not trying to shrink? */
                                        return log_error_errno(r, "Failed to resize file system: %m");

                                log_debug_errno(r, "Shrinking from %s to %s didn't work, not enough space for contained data.", FORMAT_BYTES(current_fs_size), FORMAT_BYTES(try_fs_size));
                                worked = false;
                        } else {
                                log_debug("Successfully resized from %s to %s.", FORMAT_BYTES(current_fs_size), FORMAT_BYTES(try_fs_size));
                                current_fs_size = try_fs_size;
                                worked = true;
                        }

                        /* If we hit a disk space issue and are shrinking the fs, then maybe it helps to
                         * increase the image size. */
                } else {
                        r = ext4_offline_resize_fs(setup, try_fs_size, user_record_luks_discard(h), user_record_mount_flags(h), h->luks_extra_mount_options);
                        if (r < 0)
                                return r;

                        /* For now, when we fail to shrink an ext4 image we'll not try again via the
                         * bisection logic. We might add that later, but given this involves shelling out
                         * multiple programs, it's a bit too cumbersome for my taste. */

                        worked = true;
                        current_fs_size = try_fs_size;
                }

                if (new_fs_size > old_fs_size) /* If we are growing we are done after one iteration */
                        break;

                /* If we are shrinking then let's adjust our bisection boundaries and try again. */
                if (worked)
                        upper_boundary = MIN(upper_boundary, try_fs_size);
                else
                        lower_boundary = MAX(lower_boundary, try_fs_size);

                /* OK, this attempt to shrink didn't work. Let's try between the old size and what worked. */
                if (lower_boundary >= upper_boundary) {
                        log_debug("Image can't be shrunk further (range to try is empty).");
                        break;
                }

                /* Let's find a new value to try half-way between the lower boundary and the upper boundary
                 * to try now. */
                try_fs_size = DISK_SIZE_ROUND_DOWN(lower_boundary + (upper_boundary - lower_boundary) / 2);
                if (try_fs_size <= lower_boundary || try_fs_size >= upper_boundary) {
                        log_debug("Image can't be shrunk further (remaining range to try too small).");
                        break;
                }
        }

        log_debug("Bisection loop completed after %u iterations.", n_iterations);

        if (ret_fs_size)
                *ret_fs_size = current_fs_size;

        return 0;
}

static int resize_image_loop(
                UserRecord *h,
                HomeSetup *setup,
                uint64_t old_image_size,
                uint64_t new_image_size,
                uint64_t *ret_image_size) {

        uint64_t current_image_size;
        unsigned n_iterations = 0;
        int r;

        assert(h);
        assert(setup);
        assert(setup->image_fd >= 0);

        /* A bisection loop trying to find the closest size to what the user asked for. (Well, we bisect like
         * this only when we *grow* the image — if we shrink the image then there's no need to bisect.) */

        current_image_size = old_image_size;
        for (uint64_t lower_boundary = old_image_size, upper_boundary = new_image_size, try_image_size = new_image_size;;) {
                bool worked;

                n_iterations++;

                r = home_truncate(h, setup->image_fd, try_image_size);
                if (r < 0) {
                        if (!ERRNO_IS_DISK_SPACE(r) || new_image_size < old_image_size) /* Not a disk space issue? Not trying to grow? */
                                return r;

                        log_debug_errno(r, "Growing from %s to %s didn't work, not enough space on backing disk.", FORMAT_BYTES(current_image_size), FORMAT_BYTES(try_image_size));
                        worked = false;
                } else if (r > 0) { /* Success: allocation worked */
                        log_debug("Resizing from %s to %s via allocation worked successfully.", FORMAT_BYTES(current_image_size), FORMAT_BYTES(try_image_size));
                        current_image_size = try_image_size;
                        worked = true;
                } else { /* Success, but through truncation, not allocation. */
                        log_debug("Resizing from %s to %s via truncation worked successfully.", FORMAT_BYTES(old_image_size), FORMAT_BYTES(try_image_size));
                        current_image_size = try_image_size;
                        break; /* there's no point in the bisection logic if this was plain truncation and
                                * not allocation, let's exit immediately. */
                }

                if (new_image_size < old_image_size) /* If we are shrinking we are done after one iteration */
                        break;

                /* If we are growing then let's adjust our bisection boundaries and try again */
                if (worked)
                        lower_boundary = MAX(lower_boundary, try_image_size);
                else
                        upper_boundary = MIN(upper_boundary, try_image_size);

                if (lower_boundary >= upper_boundary) {
                        log_debug("Image can't be grown further (range to try is empty).");
                        break;
                }

                try_image_size = DISK_SIZE_ROUND_DOWN(lower_boundary + (upper_boundary - lower_boundary) / 2);
                if (try_image_size <= lower_boundary || try_image_size >= upper_boundary) {
                        log_debug("Image can't be grown further (remaining range to try too small).");
                        break;
                }
        }

        log_debug("Bisection loop completed after %u iterations.", n_iterations);

        if (ret_image_size)
                *ret_image_size = current_image_size;

        return 0;
}

int home_resize_luks(
                UserRecord *h,
                HomeSetupFlags flags,
                HomeSetup *setup,
                PasswordCache *cache,
                UserRecord **ret_home) {

        uint64_t old_image_size, new_image_size, old_fs_size, new_fs_size, crypto_offset, crypto_offset_bytes,
                new_partition_size, smallest_fs_size, resized_fs_size;
        _cleanup_(user_record_unrefp) UserRecord *header_home = NULL, *embedded_home = NULL, *new_home = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *table = NULL;
        struct fdisk_partition *partition = NULL;
        _cleanup_close_ int opened_image_fd = -EBADF;
        _cleanup_free_ char *whole_disk = NULL;
        int r, resize_type, image_fd = -EBADF;
        sd_id128_t disk_uuid;
        const char *ip, *ipo;
        struct statfs sfs;
        struct stat st;
        enum {
                INTENTION_DONT_KNOW = 0,    /* These happen to match the return codes of CMP() */
                INTENTION_SHRINK = -1,
                INTENTION_GROW = 1,
        } intention = INTENTION_DONT_KNOW;

        assert(h);
        assert(user_record_storage(h) == USER_LUKS);
        assert(setup);

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        assert_se(ipo = user_record_image_path(h));
        ip = strdupa_safe(ipo); /* copy out since original might change later in home record object */

        if (setup->image_fd < 0) {
                setup->image_fd = open_image_file(h, NULL, &st);
                if (setup->image_fd < 0)
                        return setup->image_fd;
        } else {
                if (fstat(setup->image_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat image file %s: %m", ip);
        }

        image_fd = setup->image_fd;

        if (S_ISBLK(st.st_mode)) {
                dev_t parent;

                r = block_get_whole_disk(st.st_rdev, &parent);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire whole block device for %s: %m", ip);
                if (r > 0) {
                        /* If we shall resize a file system on a partition device, then let's figure out the
                         * whole disk device and operate on that instead, since we need to rewrite the
                         * partition table to resize the partition. */

                        log_info("Operating on partition device %s, using parent device.", ip);

                        opened_image_fd = r = device_open_from_devnum(S_IFBLK, parent, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK, &whole_disk);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open whole block device for %s: %m", ip);

                        image_fd = opened_image_fd;

                        if (fstat(image_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat whole block device %s: %m", whole_disk);
                } else
                        log_info("Operating on whole block device %s.", ip);

                r = blockdev_get_device_size(image_fd, &old_image_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine size of original block device: %m");

                if (flock(image_fd, LOCK_EX) < 0) /* make sure udev doesn't read from it while we operate on the device */
                        return log_error_errno(errno, "Failed to lock block device %s: %m", ip);

                new_image_size = old_image_size; /* we can't resize physical block devices */
        } else {
                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Image %s is not a block device nor regular file: %m", ip);

                old_image_size = st.st_size;

                /* Note an asymmetry here: when we operate on loopback files the specified disk size we get we
                 * apply onto the loopback file as a whole. When we operate on block devices we instead apply
                 * to the partition itself only. */

                if (FLAGS_SET(flags, HOME_SETUP_RESIZE_MINIMIZE)) {
                        new_image_size = 0;
                        intention = INTENTION_SHRINK;
                } else {
                        uint64_t new_image_size_rounded;

                        new_image_size_rounded = DISK_SIZE_ROUND_DOWN(h->disk_size);

                        if (old_image_size >= new_image_size_rounded && old_image_size <= h->disk_size) {
                                /* If exact match, or a match after we rounded down, don't do a thing */
                                log_info("Image size already matching, skipping operation.");
                                return 0;
                        }

                        new_image_size = new_image_size_rounded;
                        intention = CMP(new_image_size, old_image_size); /* Is this a shrink */
                }
        }

        r = home_setup_luks(
                        h,
                        flags,
                        whole_disk,
                        setup,
                        cache,
                        FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_SYNC_IDENTITIES) ? NULL : &header_home);
        if (r < 0)
                return r;

        if (!FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_SYNC_IDENTITIES)) {
                r = home_load_embedded_identity(h, setup->root_fd, header_home, USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL, cache, &embedded_home, &new_home);
                if (r < 0)
                        return r;
        }

        r = home_maybe_shift_uid(h, flags, setup);
        if (r < 0)
                return r;

        log_info("offset = %" PRIu64 ", size = %" PRIu64 ", image = %" PRIu64, setup->partition_offset, setup->partition_size, old_image_size);

        if ((UINT64_MAX - setup->partition_offset) < setup->partition_size ||
            setup->partition_offset + setup->partition_size > old_image_size)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Old partition doesn't fit in backing storage, refusing.");

        /* Get target partition information in here for new_partition_size calculation */
        r = prepare_resize_partition(
                        image_fd,
                        setup->partition_offset,
                        setup->partition_size,
                        &disk_uuid,
                        &table,
                        &partition);
        if (r < 0)
                return r;

        if (S_ISREG(st.st_mode)) {
                uint64_t partition_table_extra, largest_size;

                partition_table_extra = old_image_size - setup->partition_size;

                r = get_largest_image_size(setup->image_fd, &st, &largest_size);
                if (r < 0)
                        return r;
                if (new_image_size > largest_size)
                        new_image_size = largest_size;

                if (new_image_size < partition_table_extra)
                        new_image_size = partition_table_extra;

                new_partition_size = DISK_SIZE_ROUND_DOWN(new_image_size - partition_table_extra);
        } else {
                assert(S_ISBLK(st.st_mode));

                if (FLAGS_SET(flags, HOME_SETUP_RESIZE_MINIMIZE)) {
                        new_partition_size = 0;
                        intention = INTENTION_SHRINK;
                } else {
                        uint64_t new_partition_size_rounded = DISK_SIZE_ROUND_DOWN(h->disk_size);

                        if (h->disk_size == UINT64_MAX && partition) {
                                r = get_maximum_partition_size(image_fd, partition, &new_partition_size_rounded);
                                if (r < 0)
                                        return r;
                        }

                        if (setup->partition_size >= new_partition_size_rounded &&
                            setup->partition_size <= h->disk_size) {
                                log_info("Partition size already matching, skipping operation.");
                                return 0;
                        }

                        new_partition_size = new_partition_size_rounded;
                        intention = CMP(new_partition_size, setup->partition_size);
                }
        }

        if ((UINT64_MAX - setup->partition_offset) < new_partition_size ||
            setup->partition_offset + new_partition_size > new_image_size)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "New partition doesn't fit into backing storage, refusing.");

        crypto_offset = sym_crypt_get_data_offset(setup->crypt_device);
        if (crypto_offset > UINT64_MAX/512U)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "LUKS2 data offset out of range, refusing.");
        crypto_offset_bytes = (uint64_t) crypto_offset * 512U;
        if (setup->partition_size <= crypto_offset_bytes)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Weird, old crypto payload offset doesn't actually fit in partition size?");

        /* Make sure at least the LUKS header fit in */
        if (new_partition_size <= crypto_offset_bytes) {
                uint64_t add;

                add = DISK_SIZE_ROUND_UP(crypto_offset_bytes) - new_partition_size;
                new_partition_size += add;
                if (S_ISREG(st.st_mode))
                        new_image_size += add;
        }

        old_fs_size = setup->partition_size - crypto_offset_bytes;
        new_fs_size = DISK_SIZE_ROUND_DOWN(new_partition_size - crypto_offset_bytes);

        r = get_smallest_fs_size(setup->root_fd, &smallest_fs_size);
        if (r < 0)
                return r;

        if (new_fs_size < smallest_fs_size) {
                uint64_t add;

                add = DISK_SIZE_ROUND_UP(smallest_fs_size) - new_fs_size;
                new_fs_size += add;
                new_partition_size += add;
                if (S_ISREG(st.st_mode))
                        new_image_size += add;
        }

        if (new_fs_size == old_fs_size) {
                log_info("New file system size identical to old file system size, skipping operation.");
                return 0;
        }

        if (FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_GROW) && new_fs_size > old_fs_size) {
                log_info("New file system size would be larger than old, but shrinking requested, skipping operation.");
                return 0;
        }

        if (FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_SHRINK) && new_fs_size < old_fs_size) {
                log_info("New file system size would be smaller than old, but growing requested, skipping operation.");
                return 0;
        }

        if (CMP(new_fs_size, old_fs_size) != intention) {
                if (intention < 0)
                        log_info("Shrink operation would enlarge file system, skipping operation.");
                else {
                        assert(intention > 0);
                        log_info("Grow operation would shrink file system, skipping operation.");
                }
                return 0;
        }

        /* Before we start doing anything, let's figure out if we actually can */
        resize_type = can_resize_fs(setup->root_fd, old_fs_size, new_fs_size);
        if (resize_type < 0)
                return resize_type;
        if (resize_type == CAN_RESIZE_OFFLINE && FLAGS_SET(flags, HOME_SETUP_ALREADY_ACTIVATED))
                return log_error_errno(SYNTHETIC_ERRNO(ETXTBSY), "File systems of this type can only be resized offline, but is currently online.");

        log_info("Ready to resize image size %s %s %s, partition size %s %s %s, file system size %s %s %s.",
                 FORMAT_BYTES(old_image_size),
                 special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                 FORMAT_BYTES(new_image_size),
                 FORMAT_BYTES(setup->partition_size),
                 special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                 FORMAT_BYTES(new_partition_size),
                 FORMAT_BYTES(old_fs_size),
                 special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                 FORMAT_BYTES(new_fs_size));

        if (new_fs_size > old_fs_size) { /* → Grow */

                if (S_ISREG(st.st_mode)) {
                        uint64_t resized_image_size;

                        /* Grow file size */
                        r = resize_image_loop(h, setup, old_image_size, new_image_size, &resized_image_size);
                        if (r < 0)
                                return r;

                        if (resized_image_size == old_image_size) {
                                log_info("Couldn't change image size.");
                                return 0;
                        }

                        assert(resized_image_size > old_image_size);

                        log_info("Growing of image file from %s to %s completed.", FORMAT_BYTES(old_image_size), FORMAT_BYTES(resized_image_size));

                        if (resized_image_size < new_image_size) {
                                uint64_t sub;

                                /* If the growing we managed to do is smaller than what we wanted we need to
                                 * adjust the partition/file system sizes we are going for, too */
                                sub = new_image_size - resized_image_size;
                                assert(new_partition_size >= sub);
                                new_partition_size -= sub;
                                assert(new_fs_size >= sub);
                                new_fs_size -= sub;
                        }

                        new_image_size = resized_image_size;
                } else {
                        assert(S_ISBLK(st.st_mode));
                        assert(new_image_size == old_image_size);
                }

                /* Make sure loopback device sees the new bigger size */
                r = loop_device_refresh_size(setup->loop, UINT64_MAX, new_partition_size);
                if (r == -ENOTTY)
                        log_debug_errno(r, "Device is not a loopback device, not refreshing size.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to refresh loopback device size: %m");
                else
                        log_info("Refreshing loop device size completed.");

                r = apply_resize_partition(image_fd, disk_uuid, table, partition, new_partition_size);
                if (r < 0)
                        return r;
                if (r > 0)
                        log_info("Growing of partition completed.");

                if (S_ISBLK(st.st_mode) && ioctl(image_fd, BLKRRPART, 0) < 0)
                        log_debug_errno(errno, "BLKRRPART failed on block device, ignoring: %m");

                /* Tell LUKS about the new bigger size too */
                r = sym_crypt_resize(setup->crypt_device, setup->dm_name, new_fs_size / 512U);
                if (r < 0)
                        return log_error_errno(r, "Failed to grow LUKS device: %m");

                log_info("LUKS device growing completed.");
        } else {
                /* → Shrink */

                if (!FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_SYNC_IDENTITIES)) {
                        r = home_store_embedded_identity(new_home, setup->root_fd, h->uid, embedded_home);
                        if (r < 0)
                                return r;
                }

                if (S_ISREG(st.st_mode)) {
                        if (user_record_luks_discard(h))
                                /* Before we shrink, let's trim the file system, so that we need less space on disk during the shrinking */
                                (void) run_fitrim(setup->root_fd);
                        else {
                                /* If discard is off, let's ensure all backing blocks are allocated, so that our resize operation doesn't fail half-way */
                                r = run_fallocate(image_fd, &st);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        /* Now try to resize the file system. The requested size might not always be possible, in which case
         * we'll try to get as close as we can get. The result is returned in 'resized_fs_size' */
        r = resize_fs_loop(h, setup, resize_type, old_fs_size, new_fs_size, &resized_fs_size);
        if (r < 0)
                return r;

        if (resized_fs_size == old_fs_size) {
                log_info("Couldn't change file system size.");
                return 0;
        }

        log_info("File system resizing from %s to %s completed.", FORMAT_BYTES(old_fs_size), FORMAT_BYTES(resized_fs_size));

        if (resized_fs_size > new_fs_size) {
                uint64_t add;

                /* If the shrinking we managed to do is larger than what we wanted we need to adjust the partition/image sizes. */
                add = resized_fs_size - new_fs_size;
                new_partition_size += add;
                if (S_ISREG(st.st_mode))
                        new_image_size += add;
        }

        new_fs_size = resized_fs_size;

        /* Immediately sync afterwards */
        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        if (new_fs_size < old_fs_size) { /* → Shrink */

                /* Shrink the LUKS device now, matching the new file system size */
                r = sym_crypt_resize(setup->crypt_device, setup->dm_name, new_fs_size / 512);
                if (r < 0)
                        return log_error_errno(r, "Failed to shrink LUKS device: %m");

                log_info("LUKS device shrinking completed.");

                /* Refresh the loop devices size */
                r = loop_device_refresh_size(setup->loop, UINT64_MAX, new_partition_size);
                if (r == -ENOTTY)
                        log_debug_errno(r, "Device is not a loopback device, not refreshing size.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to refresh loopback device size: %m");
                else
                        log_info("Refreshing loop device size completed.");

                if (S_ISREG(st.st_mode)) {
                        /* Shrink the image file */
                        if (ftruncate(image_fd, new_image_size) < 0)
                                return log_error_errno(errno, "Failed to shrink image file %s: %m", ip);

                        log_info("Shrinking of image file completed.");
                } else {
                        assert(S_ISBLK(st.st_mode));
                        assert(new_image_size == old_image_size);
                }

                r = apply_resize_partition(image_fd, disk_uuid, table, partition, new_partition_size);
                if (r < 0)
                        return r;
                if (r > 0)
                        log_info("Shrinking of partition completed.");

                if (S_ISBLK(st.st_mode) && ioctl(image_fd, BLKRRPART, 0) < 0)
                        log_debug_errno(errno, "BLKRRPART failed on block device, ignoring: %m");

        } else { /* → Grow */
                if (!FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_SYNC_IDENTITIES)) {
                        r = home_store_embedded_identity(new_home, setup->root_fd, h->uid, embedded_home);
                        if (r < 0)
                                return r;
                }
        }

        if (!FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_SYNC_IDENTITIES)) {
                r = home_store_header_identity_luks(new_home, setup, header_home);
                if (r < 0)
                        return r;

                r = home_extend_embedded_identity(new_home, h, setup);
                if (r < 0)
                        return r;
        }

        if (user_record_luks_discard(h))
                (void) run_fitrim(setup->root_fd);

        r = home_sync_and_statfs(setup->root_fd, &sfs);
        if (r < 0)
                return r;

        if (!FLAGS_SET(flags, HOME_SETUP_RESIZE_DONT_UNDO)) {
                r = home_setup_done(setup);
                if (r < 0)
                        return r;
        }

        log_info("Resizing completed.");

        print_size_summary(new_image_size, new_fs_size, &sfs);

        if (ret_home)
                *ret_home = TAKE_PTR(new_home);

        return 0;
}

int home_passwd_luks(
                UserRecord *h,
                HomeSetupFlags flags,
                HomeSetup *setup,
                const PasswordCache *cache, /* the passwords acquired via PKCS#11/FIDO2 security tokens */
                char **effective_passwords  /* new passwords */) {

        size_t volume_key_size, max_key_slots, n_effective;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        struct crypt_pbkdf_type good_pbkdf, minimal_pbkdf;
        const char *type;
        char **list;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_LUKS);
        assert(setup);

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        type = sym_crypt_get_type(setup->crypt_device);
        if (!type)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine crypto device type.");

        r = sym_crypt_keyslot_max(type);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine number of key slots.");
        max_key_slots = r;

        r = sym_crypt_get_volume_key_size(setup->crypt_device);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine volume key size.");
        volume_key_size = (size_t) r;

        volume_key = malloc(volume_key_size);
        if (!volume_key)
                return log_oom();

        r = -ENOKEY;
        FOREACH_POINTER(list,
                        cache ? cache->keyring_passswords : NULL,
                        cache ? cache->pkcs11_passwords : NULL,
                        cache ? cache->fido2_passwords : NULL,
                        h->password) {

                r = luks_try_passwords(h, setup->crypt_device, list, volume_key, &volume_key_size, NULL);
                if (r != -ENOKEY)
                        break;
        }
        if (r == -ENOKEY)
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Failed to unlock LUKS superblock with supplied passwords.");
        if (r < 0)
                return log_error_errno(r, "Failed to unlock LUKS superblock: %m");

        n_effective = strv_length(effective_passwords);

        build_good_pbkdf(&good_pbkdf, h);
        build_minimal_pbkdf(&minimal_pbkdf, h);

        for (size_t i = 0; i < max_key_slots; i++) {
                r = sym_crypt_keyslot_destroy(setup->crypt_device, i);
                if (r < 0 && !IN_SET(r, -ENOENT, -EINVAL)) /* Returns EINVAL or ENOENT if there's no key in this slot already */
                        return log_error_errno(r, "Failed to destroy LUKS password: %m");

                if (i >= n_effective) {
                        if (r >= 0)
                                log_info("Destroyed LUKS key slot %zu.", i);
                        continue;
                }

                if (password_cache_contains(cache, effective_passwords[i])) { /* Is this a FIDO2 or PKCS#11 password? */
                        log_debug("Using minimal PBKDF for slot %zu", i);
                        r = sym_crypt_set_pbkdf_type(setup->crypt_device, &minimal_pbkdf);
                } else {
                        log_debug("Using good PBKDF for slot %zu", i);
                        r = sym_crypt_set_pbkdf_type(setup->crypt_device, &good_pbkdf);
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to tweak PBKDF for slot %zu: %m", i);

                r = sym_crypt_keyslot_add_by_volume_key(
                                setup->crypt_device,
                                i,
                                volume_key,
                                volume_key_size,
                                effective_passwords[i],
                                strlen(effective_passwords[i]));
                if (r < 0)
                        return log_error_errno(r, "Failed to set up LUKS password: %m");

                log_info("Updated LUKS key slot %zu.", i);

                /* If we changed the password, then make sure to update the copy in the keyring, so that
                 * auto-rebalance continues to work. We only do this if we operate on an active home dir. */
                if (i == 0 && FLAGS_SET(flags, HOME_SETUP_ALREADY_ACTIVATED))
                        upload_to_keyring(h, effective_passwords[i], NULL);
        }

        return 1;
}

int home_lock_luks(UserRecord *h, HomeSetup *setup) {
        const char *p;
        int r;

        assert(h);
        assert(setup);
        assert(setup->root_fd < 0);
        assert(!setup->crypt_device);

        r = acquire_open_luks_device(h, setup, /* graceful= */ false);
        if (r < 0)
                return r;

        log_info("Discovered used LUKS device %s.", setup->dm_node);

        assert_se(p = user_record_home_directory(h));
        r = syncfs_path(AT_FDCWD, p);
        if (r < 0) /* Snake oil, but let's better be safe than sorry */
                return log_error_errno(r, "Failed to synchronize file system %s: %m", p);

        log_info("File system synchronized.");

        /* Note that we don't invoke FIFREEZE here, it appears libcryptsetup/device-mapper already does that on its own for us */

        r = sym_crypt_suspend(setup->crypt_device, setup->dm_name);
        if (r < 0)
                return log_error_errno(r, "Failed to suspend cryptsetup device: %s: %m", setup->dm_node);

        log_info("LUKS device suspended.");
        return 0;
}

static int luks_try_resume(
                struct crypt_device *cd,
                const char *dm_name,
                char **password) {

        int r;

        assert(cd);
        assert(dm_name);

        STRV_FOREACH(pp, password) {
                r = sym_crypt_resume_by_passphrase(
                                cd,
                                dm_name,
                                CRYPT_ANY_SLOT,
                                *pp,
                                strlen(*pp));
                if (r >= 0) {
                        log_info("Resumed LUKS device %s.", dm_name);
                        return 0;
                }

                log_debug_errno(r, "Password %zu didn't work for resuming device: %m", (size_t) (pp - password));
        }

        return -ENOKEY;
}

int home_unlock_luks(UserRecord *h, HomeSetup *setup, const PasswordCache *cache) {
        char **list;
        int r;

        assert(h);
        assert(setup);
        assert(!setup->crypt_device);

        r = acquire_open_luks_device(h, setup, /* graceful= */ false);
        if (r < 0)
                return r;

        log_info("Discovered used LUKS device %s.", setup->dm_node);

        r = -ENOKEY;
        FOREACH_POINTER(list,
                        cache ? cache->pkcs11_passwords : NULL,
                        cache ? cache->fido2_passwords : NULL,
                        h->password) {
                r = luks_try_resume(setup->crypt_device, setup->dm_name, list);
                if (r != -ENOKEY)
                        break;
        }
        if (r == -ENOKEY)
                return log_error_errno(r, "No valid password for LUKS superblock.");
        if (r < 0)
                return log_error_errno(r, "Failed to resume LUKS superblock: %m");

        log_info("LUKS device resumed.");
        return 0;
}

static int device_is_gone(HomeSetup *setup) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        struct stat st;
        int r;

        assert(setup);

        if (!setup->dm_node)
                return true;

        if (stat(setup->dm_node, &st) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to stat block device node %s: %m", setup->dm_node);

                return true;
        }

        r = sd_device_new_from_stat_rdev(&d, &st);
        if (r < 0) {
                if (r != -ENODEV)
                        return log_error_errno(errno, "Failed to allocate device object from block device node %s: %m", setup->dm_node);

                return true;
        }

        return false;
}

static int device_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        HomeSetup *setup = ASSERT_PTR(userdata);
        int r;

        if (!device_for_action(device, SD_DEVICE_REMOVE))
                return 0;

        /* We don't really care for the device object passed to us, we just check if the device node still
         * exists */

        r = device_is_gone(setup);
        if (r < 0)
                return r;
        if (r > 0) /* Yay! we are done! */
                (void) sd_event_exit(sd_device_monitor_get_event(monitor), 0);

        return 0;
}

int wait_for_block_device_gone(HomeSetup *setup, usec_t timeout_usec) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        assert(setup);

        /* So here's the thing: we enable "deferred deactivation" on our dm-crypt volumes. This means they
         * are automatically torn down once not used anymore (i.e. once unmounted). Which is great. It also
         * means that when we deactivate a home directory and try to tear down the volume that backs it, it
         * possibly is already torn down or in the process of being torn down, since we race against the
         * automatic tearing down. Which is fine, we handle errors from that. However, we lose the ability to
         * naturally wait for the tear down operation to complete: if we are not the ones who tear down the
         * device we are also not the ones who naturally block on that operation. Hence let's add some code
         * to actively wait for the device to go away, via sd-device. We'll call this whenever tearing down a
         * LUKS device, to ensure the device is really really gone before we proceed. Net effect: "homectl
         * deactivate foo && homectl activate foo" will work reliably, i.e. deactivation immediately followed
         * by activation will work. Also, by the time deactivation completes we can guarantee that all data
         * is sync'ed down to the lowest block layer as all higher levels are fully and entirely
         * destructed. */

        if (!setup->dm_name)
                return 0;

        assert(setup->dm_node);
        log_debug("Waiting until %s disappears.", setup->dm_node);

        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_device_monitor_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device monitor: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(m, "block", "disk");
        if (r < 0)
                return log_error_errno(r, "Failed to configure device monitor match: %m");

        r = sd_device_monitor_attach_event(m, event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach device monitor to event loop: %m");

        r = sd_device_monitor_start(m, device_monitor_handler, setup);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        r = device_is_gone(setup);
        if (r < 0)
                return r;
        if (r > 0) {
                log_debug("%s has already disappeared before entering wait loop.", setup->dm_node);
                return 0; /* gone already */
        }

        if (timeout_usec != USEC_INFINITY) {
                r = sd_event_add_time_relative(event, NULL, CLOCK_MONOTONIC, timeout_usec, 0, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add timer event: %m");
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        r = device_is_gone(setup);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(r, "Device %s still around.", setup->dm_node);

        log_debug("Successfully waited until device %s disappeared.", setup->dm_node);
        return 0;
}

int home_auto_shrink_luks(UserRecord *h, HomeSetup *setup, PasswordCache *cache) {
        struct statfs sfs;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_LUKS);
        assert(setup);
        assert(setup->root_fd >= 0);

        if (user_record_auto_resize_mode(h) != AUTO_RESIZE_SHRINK_AND_GROW)
                return 0;

        if (fstatfs(setup->root_fd, &sfs) < 0)
                return log_error_errno(errno, "Failed to statfs home directory: %m");

        if (!fs_can_online_shrink_and_grow(sfs.f_type)) {
                log_debug("Not auto-shrinking file system, since selected file system cannot do both online shrink and grow.");
                return 0;
        }

        r = home_resize_luks(
                        h,
                        HOME_SETUP_ALREADY_ACTIVATED|
                        HOME_SETUP_RESIZE_DONT_SYNC_IDENTITIES|
                        HOME_SETUP_RESIZE_MINIMIZE|
                        HOME_SETUP_RESIZE_DONT_GROW|
                        HOME_SETUP_RESIZE_DONT_UNDO,
                        setup,
                        cache,
                        NULL);
        if (r < 0)
                return r;

        return 1;
}
