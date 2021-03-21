/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <libfdisk.h>
#include <linux/loop.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/xattr.h>

#include "blkid-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "chattr-util.h"
#include "dm-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fsck-util.h"
#include "home-util.h"
#include "homework-luks.h"
#include "homework-mount.h"
#include "id128-util.h"
#include "io-util.h"
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
#include "stat-util.h"
#include "strv.h"
#include "tmpfile-util.h"

/* Round down to the nearest 1K size. Note that Linux generally handles block devices with 512 blocks only,
 * but actually doesn't accept uneven numbers in many cases. To avoid any confusion around this we'll
 * strictly round disk sizes down to the next 1K boundary.*/
#define DISK_SIZE_ROUND_DOWN(x) ((x) & ~UINT64_C(1023))

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
                if (ret < 0 && errno != ENODATA)
                        return log_debug_errno(errno, "Could not mark home directory as clean: %m");
        }

        r = fsync_full(fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to synchronize dirty flag to disk: %m");

        return ret >= 0;
}

int run_mark_dirty_by_path(const char *path, bool b) {
        _cleanup_close_ int fd = -1;

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
                return errno > 0 ? -errno : -ENOMEM;

        (void) blkid_probe_enable_superblocks(b, 1);
        (void) blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE|BLKID_SUBLKS_UUID);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (IN_SET(r, -2, 1)) /* nothing found or ambiguous result */
                return -ENOPKG;
        if (r != 0)
                return errno > 0 ? -errno : -EIO;

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
        _cleanup_close_ int fd = -1;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (fd < 0)
                return -errno;

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

        if (ioctl(fd, BLKGETSIZE64, ret) < 0)
                return -errno;

        return 0;
}

static int block_get_size_by_path(const char *path, uint64_t *ret) {
        _cleanup_close_ int fd = -1;

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

        r = fsck_exists(fstype);
        if (r < 0)
                return log_error_errno(r, "Failed to check if fsck for file system %s exists: %m", fstype);
        if (r == 0) {
                log_warning("No fsck for file system %s installed, ignoring.", fstype);
                return 0;
        }

        r = safe_fork("(fsck)",
                      FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_LOG|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS,
                      &fsck_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execl("/sbin/fsck", "/sbin/fsck", "-aTl", node, NULL);
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

static int luks_try_passwords(
                struct crypt_device *cd,
                char **passwords,
                void *volume_key,
                size_t *volume_key_size) {

        char **pp;
        int r;

        assert(cd);

        STRV_FOREACH(pp, passwords) {
                size_t vks = *volume_key_size;

                r = crypt_volume_key_get(
                                cd,
                                CRYPT_ANY_SLOT,
                                volume_key,
                                &vks,
                                *pp,
                                strlen(*pp));
                if (r >= 0) {
                        *volume_key_size = vks;
                        return 0;
                }

                log_debug_errno(r, "Password %zu didn't work for unlocking LUKS superblock: %m", (size_t) (pp - passwords));
        }

        return -ENOKEY;
}

static int luks_setup(
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
                size_t *ret_volume_key_size) {

        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        sd_id128_t p;
        size_t vks;
        char **list;
        int r;

        assert(node);
        assert(dm_name);
        assert(ret);

        r = crypt_init(&cd, node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        r = crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS superblock: %m");

        r = crypt_get_volume_key_size(cd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine LUKS volume key size");
        vks = (size_t) r;

        if (!sd_id128_is_null(uuid) || ret_found_uuid) {
                const char *s;

                s = crypt_get_uuid(cd);
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

        if (cipher && !streq_ptr(cipher, crypt_get_cipher(cd)))
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock declares wrong cipher.");

        if (cipher_mode && !streq_ptr(cipher_mode, crypt_get_cipher_mode(cd)))
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock declares wrong cipher mode.");

        if (volume_key_size != UINT64_MAX && vks != volume_key_size)
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "LUKS superblock declares wrong volume key size.");

        vk = malloc(vks);
        if (!vk)
                return log_oom();

        r = -ENOKEY;
        FOREACH_POINTER(list, cache->pkcs11_passwords, cache->fido2_passwords, passwords) {
                r = luks_try_passwords(cd, list, vk, &vks);
                if (r != -ENOKEY)
                        break;
        }
        if (r == -ENOKEY)
                return log_error_errno(r, "No valid password for LUKS superblock.");
        if (r < 0)
                return log_error_errno(r, "Failed to unlocks LUKS superblock: %m");

        r = crypt_activate_by_volume_key(
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

        return 0;
}

static int luks_open(
                const char *dm_name,
                char **passwords,
                PasswordCache *cache,
                struct crypt_device **ret,
                sd_id128_t *ret_found_uuid,
                void **ret_volume_key,
                size_t *ret_volume_key_size) {

        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        sd_id128_t p;
        char **list;
        size_t vks;
        int r;

        assert(dm_name);
        assert(ret);

        /* Opens a LUKS device that is already set up. Re-validates the password while doing so (which also
         * provides us with the volume key, which we want). */

        r = crypt_init_by_name(&cd, dm_name);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize cryptsetup context for %s: %m", dm_name);

        cryptsetup_enable_logging(cd);

        r = crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS superblock: %m");

        r = crypt_get_volume_key_size(cd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine LUKS volume key size");
        vks = (size_t) r;

        if (ret_found_uuid) {
                const char *s;

                s = crypt_get_uuid(cd);
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
        FOREACH_POINTER(list, cache->pkcs11_passwords, cache->fido2_passwords, passwords) {
                r = luks_try_passwords(cd, list, vk, &vks);
                if (r != -ENOKEY)
                        break;
        }
        if (r == -ENOKEY)
                return log_error_errno(r, "No valid password for LUKS superblock.");
        if (r < 0)
                return log_error_errno(r, "Failed to unlocks LUKS superblock: %m");

        log_info("Discovered used LUKS device /dev/mapper/%s, and validated password.", dm_name);

        /* This is needed so that crypt_resize() can operate correctly for pre-existing LUKS devices. We need
         * to tell libcryptsetup the volume key explicitly, so that it is in the kernel keyring. */
        r = crypt_activate_by_volume_key(cd, NULL, vk, vks, CRYPT_ACTIVATE_KEYRING_KEY);
        if (r < 0)
                return log_error_errno(r, "Failed to upload volume key again: %m");

        log_info("Successfully re-activated LUKS device.");

        *ret = TAKE_PTR(cd);

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
        sd_id128_t u;
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

static int make_dm_names(const char *user_name, char **ret_dm_name, char **ret_dm_node) {
        _cleanup_free_ char *name = NULL, *node = NULL;

        assert(user_name);
        assert(ret_dm_name);
        assert(ret_dm_node);

        name = strjoin("home-", user_name);
        if (!name)
                return log_oom();

        node = path_join("/dev/mapper/", name);
        if (!node)
                return log_oom();

        *ret_dm_name = TAKE_PTR(name);
        *ret_dm_node = TAKE_PTR(node);
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
                return errno > 0 ? -errno : -ENOMEM;

        (void) blkid_probe_enable_superblocks(b, 1);
        (void) blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        (void) blkid_probe_enable_partitions(b, 1);
        (void) blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (IN_SET(r, -2, 1)) /* nothing found or ambiguous result */
                return -ENOPKG;
        if (r != 0)
                return errno > 0 ? -errno : -EIO;

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
                return errno > 0 ? -errno : -ENOMEM;

        errno = 0;
        n = blkid_partlist_numof_partitions(pl);
        if (n < 0)
                return errno > 0 ? -errno : -EIO;

        for (int i = 0; i < n; i++) {
                blkid_partition pp;
                sd_id128_t id = SD_ID128_NULL;
                const char *sid;

                errno = 0;
                pp = blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return errno > 0 ? -errno : -EIO;

                if (!streq_ptr(blkid_partition_get_type_string(pp), "773f91ef-66d4-49b5-bd83-d683bf40ad16"))
                        continue;

                if (!streq_ptr(blkid_partition_get_name(pp), label))
                        continue;

                sid = blkid_partition_get_uuid(pp);
                if (sid) {
                        r = sd_id128_from_string(sid, &id);
                        if (r < 0)
                                log_debug_errno(r, "Couldn't parse partition UUID %s, weird: %m", sid);

                        if (!sd_id128_is_null(partition_uuid) && !sd_id128_equal(id, partition_uuid))
                                continue;
                }

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

        cipher = crypt_get_cipher(cd);
        if (!cipher)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot get cipher from LUKS device.");

        cipher_mode = crypt_get_cipher_mode(cd);
        if (!cipher_mode)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot get cipher mode from LUKS device.");

        e = strchr(cipher_mode, '-');
        if (e)
                cipher_mode = strndupa(cipher_mode, e - cipher_mode);

        r = crypt_get_volume_key_size(cd);
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

        for (int token = 0;; token++) {
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

                state = crypt_token_status(cd, token, &type);
                if (state == CRYPT_TOKEN_INACTIVE) /* First unconfigured token, give up */
                        break;
                if (IN_SET(state, CRYPT_TOKEN_INTERNAL, CRYPT_TOKEN_INTERNAL_UNKNOWN, CRYPT_TOKEN_EXTERNAL))
                        continue;
                if (state != CRYPT_TOKEN_EXTERNAL_UNKNOWN)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected token state of token %i: %i", token, (int) state);

                if (!streq(type, "systemd-homed"))
                        continue;

                r = crypt_token_json_get(cd, token, &text);
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

                r = user_record_load(lhr, rr, USER_RECORD_LOAD_EMBEDDED);
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

                r = genuine_random_bytes(iv, iv_size, RANDOM_BLOCK);
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
                                       JSON_BUILD_PAIR("type", JSON_BUILD_STRING("systemd-homed")),
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
        int token = 0, r;

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

        r = user_record_clone(h, USER_RECORD_EXTRACT_EMBEDDED, &header_home);
        if (r < 0)
                return log_error_errno(r, "Failed to determine new header record: %m");

        if (old_home && user_record_equal(old_home, header_home)) {
                log_debug("Not updating header home record.");
                return 0;
        }

        r = format_luks_token_text(setup->crypt_device, header_home, setup->volume_key, &text);
        if (r < 0)
                return r;

        for (;; token++) {
                crypt_token_info state;
                const char *type;

                state = crypt_token_status(setup->crypt_device, token, &type);
                if (state == CRYPT_TOKEN_INACTIVE) /* First unconfigured token, we are done */
                        break;
                if (IN_SET(state, CRYPT_TOKEN_INTERNAL, CRYPT_TOKEN_INTERNAL_UNKNOWN, CRYPT_TOKEN_EXTERNAL))
                        continue; /* Not ours */
                if (state != CRYPT_TOKEN_EXTERNAL_UNKNOWN)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected token state of token %i: %i", token, (int) state);

                if (!streq(type, "systemd-homed"))
                        continue;

                r = crypt_token_json_set(setup->crypt_device, token, text);
                if (r < 0)
                        return log_error_errno(r, "Failed to set JSON token for slot %i: %m", token);

                /* Now, let's free the text so that for all further matching tokens we all crypt_json_token_set()
                 * with a NULL text in order to invalidate the tokens. */
                text = mfree(text);
                token++;
        }

        if (text)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Didn't find any record token to update.");

        log_info("Wrote LUKS header user record.");

        return 1;
}

int run_fitrim(int root_fd) {
        char buf[FORMAT_BYTES_MAX];
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

        log_info("Discarded unused %s.",
                 format_bytes(buf, sizeof(buf), range.len));
        return 1;
}

int run_fitrim_by_path(const char *root_path) {
        _cleanup_close_ int root_fd = -1;

        root_fd = open(root_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (root_fd < 0)
                return log_error_errno(errno, "Failed to open file system '%s' for trimming: %m", root_path);

        return run_fitrim(root_fd);
}

int run_fallocate(int backing_fd, const struct stat *st) {
        char buf[FORMAT_BYTES_MAX];
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
                 format_bytes(buf, sizeof(buf), (DIV_ROUND_UP(st->st_size, 512) - st->st_blocks) * 512));
        return 1;
}

int run_fallocate_by_path(const char *backing_path) {
        _cleanup_close_ int backing_fd = -1;

        backing_fd = open(backing_path, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (backing_fd < 0)
                return log_error_errno(errno, "Failed to open '%s' for fallocate(): %m", backing_path);

        return run_fallocate(backing_fd, NULL);
}

int home_prepare_luks(
                UserRecord *h,
                bool already_activated,
                const char *force_image_path,
                PasswordCache *cache,
                HomeSetup *setup,
                UserRecord **ret_luks_home) {

        sd_id128_t found_partition_uuid, found_luks_uuid, found_fs_uuid;
        _cleanup_(user_record_unrefp) UserRecord *luks_home = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        _cleanup_close_ int root_fd = -1, image_fd = -1;
        bool dm_activated = false, mounted = false;
        size_t volume_key_size = 0;
        bool marked_dirty = false;
        uint64_t offset, size;
        int r;

        assert(h);
        assert(setup);
        assert(setup->dm_name);
        assert(setup->dm_node);

        assert(user_record_storage(h) == USER_LUKS);

        if (already_activated) {
                struct loop_info64 info;
                const char *n;

                r = luks_open(setup->dm_name,
                              h->password,
                              cache,
                              &cd,
                              &found_luks_uuid,
                              &volume_key,
                              &volume_key_size);
                if (r < 0)
                        return r;

                r = luks_validate_home_record(cd, h, volume_key, cache, &luks_home);
                if (r < 0)
                        return r;

                n = crypt_get_device_name(cd);
                if (!n)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine backing device for DM %s.", setup->dm_name);

                r = loop_device_open(n, O_RDWR, &loop);
                if (r < 0)
                        return log_error_errno(r, "Failed to open loopback device %s: %m", n);

                if (ioctl(loop->fd, LOOP_GET_STATUS64, &info) < 0) {
                        _cleanup_free_ char *sysfs = NULL;
                        struct stat st;

                        if (!IN_SET(errno, ENOTTY, EINVAL))
                                return log_error_errno(errno, "Failed to get block device metrics of %s: %m", n);

                        if (ioctl(loop->fd, BLKGETSIZE64, &size) < 0)
                                return log_error_errno(r, "Failed to read block device size of %s: %m", n);

                        if (fstat(loop->fd, &st) < 0)
                                return log_error_errno(r, "Failed to stat block device %s: %m", n);
                        assert(S_ISBLK(st.st_mode));

                        if (asprintf(&sysfs, "/sys/dev/block/%u:%u/partition", major(st.st_rdev), minor(st.st_rdev)) < 0)
                                return log_oom();

                        if (access(sysfs, F_OK) < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to determine whether %s exists: %m", sysfs);

                                offset = 0;
                        } else {
                                _cleanup_free_ char *buffer = NULL;

                                if (asprintf(&sysfs, "/sys/dev/block/%u:%u/start", major(st.st_rdev), minor(st.st_rdev)) < 0)
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
                } else {
                        offset = info.lo_offset;
                        size = info.lo_sizelimit;
                }

                found_partition_uuid = found_fs_uuid = SD_ID128_NULL;

                log_info("Discovered used loopback device %s.", loop->node);

                root_fd = open(user_record_home_directory(h), O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (root_fd < 0) {
                        r = log_error_errno(r, "Failed to open home directory: %m");
                        goto fail;
                }
        } else {
                _cleanup_free_ char *fstype = NULL, *subdir = NULL;
                const char *ip;
                struct stat st;

                ip = force_image_path ?: user_record_image_path(h);

                subdir = path_join("/run/systemd/user-home-mount/", user_record_user_name_and_realm(h));
                if (!subdir)
                        return log_oom();

                image_fd = open(ip, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (image_fd < 0)
                        return log_error_errno(errno, "Failed to open image file %s: %m", ip);

                if (fstat(image_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to fstat() image file: %m");
                if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))
                        return log_error_errno(
                                        S_ISDIR(st.st_mode) ? SYNTHETIC_ERRNO(EISDIR) : SYNTHETIC_ERRNO(EBADFD),
                                        "Image file %s is not a regular file or block device: %m", ip);

                r = luks_validate(image_fd, user_record_user_name_and_realm(h), h->partition_uuid, &found_partition_uuid, &offset, &size);
                if (r < 0)
                        return log_error_errno(r, "Failed to validate disk label: %m");

                /* Everything before this point left the image untouched. We are now starting to make
                 * changes, hence mark the image dirty */
                marked_dirty = run_mark_dirty(image_fd, true) > 0;

                if (!user_record_luks_discard(h)) {
                        r = run_fallocate(image_fd, &st);
                        if (r < 0)
                                return r;
                }

                r = loop_device_make(image_fd, O_RDWR, offset, size, 0, &loop);
                if (r == -ENOENT) {
                        log_error_errno(r, "Loopback block device support is not available on this system.");
                        return -ENOLINK; /* make recognizable */
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate loopback context: %m");

                log_info("Setting up loopback device %s completed.", loop->node ?: ip);

                r = luks_setup(loop->node ?: ip,
                               setup->dm_name,
                               h->luks_uuid,
                               h->luks_cipher,
                               h->luks_cipher_mode,
                               h->luks_volume_key_size,
                               h->password,
                               cache,
                               user_record_luks_discard(h) || user_record_luks_offline_discard(h),
                               &cd,
                               &found_luks_uuid,
                               &volume_key,
                               &volume_key_size);
                if (r < 0)
                        return r;

                dm_activated = true;

                r = luks_validate_home_record(cd, h, volume_key, cache, &luks_home);
                if (r < 0)
                        goto fail;

                r = fs_validate(setup->dm_node, h->file_system_uuid, &fstype, &found_fs_uuid);
                if (r < 0)
                        goto fail;

                r = run_fsck(setup->dm_node, fstype);
                if (r < 0)
                        goto fail;

                r = home_unshare_and_mount(setup->dm_node, fstype, user_record_luks_discard(h), user_record_mount_flags(h));
                if (r < 0)
                        goto fail;

                mounted = true;

                root_fd = open(subdir, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (root_fd < 0) {
                        r = log_error_errno(r, "Failed to open home directory: %m");
                        goto fail;
                }

                if (user_record_luks_discard(h))
                        (void) run_fitrim(root_fd);

                setup->image_fd = TAKE_FD(image_fd);
                setup->do_offline_fallocate = !(setup->do_offline_fitrim = user_record_luks_offline_discard(h));
                setup->do_mark_clean = marked_dirty;
        }

        setup->loop = TAKE_PTR(loop);
        setup->crypt_device = TAKE_PTR(cd);
        setup->root_fd = TAKE_FD(root_fd);
        setup->found_partition_uuid = found_partition_uuid;
        setup->found_luks_uuid = found_luks_uuid;
        setup->found_fs_uuid = found_fs_uuid;
        setup->partition_offset = offset;
        setup->partition_size = size;
        setup->volume_key = TAKE_PTR(volume_key);
        setup->volume_key_size = volume_key_size;

        setup->undo_mount = mounted;
        setup->undo_dm = dm_activated;

        if (ret_luks_home)
                *ret_luks_home = TAKE_PTR(luks_home);

        return 0;

fail:
        if (mounted)
                (void) umount_verbose(LOG_ERR, "/run/systemd/user-home-mount", UMOUNT_NOFOLLOW);

        if (dm_activated)
                (void) crypt_deactivate(cd, setup->dm_name);

        if (image_fd >= 0 && marked_dirty)
                (void) run_mark_dirty(image_fd, false);

        return r;
}

static void print_size_summary(uint64_t host_size, uint64_t encrypted_size, struct statfs *sfs) {
        char buffer1[FORMAT_BYTES_MAX], buffer2[FORMAT_BYTES_MAX], buffer3[FORMAT_BYTES_MAX], buffer4[FORMAT_BYTES_MAX];

        assert(sfs);

        log_info("Image size is %s, file system size is %s, file system payload size is %s, file system free is %s.",
                 format_bytes(buffer1, sizeof(buffer1), host_size),
                 format_bytes(buffer2, sizeof(buffer2), encrypted_size),
                 format_bytes(buffer3, sizeof(buffer3), (uint64_t) sfs->f_blocks * (uint64_t) sfs->f_frsize),
                 format_bytes(buffer4, sizeof(buffer4), (uint64_t) sfs->f_bfree * (uint64_t) sfs->f_frsize));
}

int home_activate_luks(
                UserRecord *h,
                PasswordCache *cache,
                UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL, *luks_home_record = NULL;
        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        uint64_t host_size, encrypted_size;
        const char *hdo, *hd;
        struct statfs sfs;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_LUKS);
        assert(ret_home);

        assert_se(hdo = user_record_home_directory(h));
        hd = strdupa(hdo); /* copy the string out, since it might change later in the home record object */

        r = make_dm_names(h->user_name, &setup.dm_name, &setup.dm_node);
        if (r < 0)
                return r;

        r = access(setup.dm_node, F_OK);
        if (r < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to determine whether %s exists: %m", setup.dm_node);
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Device mapper device %s already exists, refusing.", setup.dm_node);

        r = home_prepare_luks(
                        h,
                        false,
                        NULL,
                        cache,
                        &setup,
                        &luks_home_record);
        if (r < 0)
                return r;

        r = block_get_size_by_fd(setup.loop->fd, &host_size);
        if (r < 0)
                return log_error_errno(r, "Failed to get loopback block device size: %m");

        r = block_get_size_by_path(setup.dm_node, &encrypted_size);
        if (r < 0)
                return log_error_errno(r, "Failed to get LUKS block device size: %m");

        r = home_refresh(
                        h,
                        &setup,
                        luks_home_record,
                        cache,
                        &sfs,
                        &new_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, &setup);
        if (r < 0)
                return r;

        setup.root_fd = safe_close(setup.root_fd);

        r = home_move_mount(user_record_user_name_and_realm(h), hd);
        if (r < 0)
                return r;

        setup.undo_mount = false;
        setup.do_offline_fitrim = false;

        loop_device_relinquish(setup.loop);

        r = crypt_deactivate_by_name(NULL, setup.dm_name, CRYPT_DEACTIVATE_DEFERRED);
        if (r < 0)
                log_warning_errno(r, "Failed to relinquish DM device, ignoring: %m");

        setup.undo_dm = false;
        setup.do_offline_fallocate = false;
        setup.do_mark_clean = false;

        log_info("Everything completed.");

        print_size_summary(host_size, encrypted_size, &sfs);

        *ret_home = TAKE_PTR(new_home);
        return 1;
}

int home_deactivate_luks(UserRecord *h) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_free_ char *dm_name = NULL, *dm_node = NULL;
        bool we_detached;
        int r;

        /* Note that the DM device and loopback device are set to auto-detach, hence strictly speaking we
         * don't have to explicitly have to detach them. However, we do that nonetheless (in case of the DM
         * device), to avoid races: by explicitly detaching them we know when the detaching is complete. We
         * don't bother about the loopback device because unlike the DM device it doesn't have a fixed
         * name. */

        r = make_dm_names(h->user_name, &dm_name, &dm_node);
        if (r < 0)
                return r;

        r = crypt_init_by_name(&cd, dm_name);
        if (IN_SET(r, -ENODEV, -EINVAL, -ENOENT)) {
                log_debug_errno(r, "LUKS device %s has already been detached.", dm_name);
                we_detached = false;
        } else if (r < 0)
                return log_error_errno(r, "Failed to initialize cryptsetup context for %s: %m", dm_name);
        else {
                log_info("Discovered used LUKS device %s.", dm_node);

                cryptsetup_enable_logging(cd);

                r = crypt_deactivate(cd, dm_name);
                if (IN_SET(r, -ENODEV, -EINVAL, -ENOENT)) {
                        log_debug_errno(r, "LUKS device %s is already detached.", dm_node);
                        we_detached = false;
                } else if (r < 0)
                        return log_info_errno(r, "LUKS device %s couldn't be deactivated: %m", dm_node);
                else {
                        log_info("LUKS device detaching completed.");
                        we_detached = true;
                }
        }

        if (user_record_luks_offline_discard(h))
                log_debug("Not allocating on logout.");
        else
                (void) run_fallocate_by_path(user_record_image_path(h));

        run_mark_dirty_by_path(user_record_image_path(h), false);
        return we_detached;
}

int home_trim_luks(UserRecord *h) {
        assert(h);

        if (!user_record_luks_offline_discard(h)) {
                log_debug("Not trimming on logout.");
                return 0;
        }

        (void) run_fitrim_by_path(user_record_home_directory(h));
        return 0;
}

static struct crypt_pbkdf_type* build_good_pbkdf(struct crypt_pbkdf_type *buffer, UserRecord *hr) {
        assert(buffer);
        assert(hr);

        *buffer = (struct crypt_pbkdf_type) {
                .hash = user_record_luks_pbkdf_hash_algorithm(hr),
                .type = user_record_luks_pbkdf_type(hr),
                .time_ms = user_record_luks_pbkdf_time_cost_usec(hr) / USEC_PER_MSEC,
                .max_memory_kb = user_record_luks_pbkdf_memory_cost(hr) / 1024,
                .parallel_threads = user_record_luks_pbkdf_parallel_threads(hr),
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
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        struct crypt_pbkdf_type good_pbkdf, minimal_pbkdf;
        char suuid[ID128_UUID_STRING_MAX], **pp;
        _cleanup_free_ char *text = NULL;
        size_t volume_key_size;
        int slot = 0, r;

        assert(node);
        assert(dm_name);
        assert(hr);
        assert(ret);

        r = crypt_init(&cd, node);
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

        r = genuine_random_bytes(volume_key, volume_key_size, RANDOM_BLOCK);
        if (r < 0)
                return log_error_errno(r, "Failed to generate volume key: %m");

#if HAVE_CRYPT_SET_METADATA_SIZE
        /* Increase the metadata space to 4M, the largest LUKS2 supports */
        r = crypt_set_metadata_size(cd, 4096U*1024U, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to change LUKS2 metadata size: %m");
#endif

        build_good_pbkdf(&good_pbkdf, hr);
        build_minimal_pbkdf(&minimal_pbkdf, hr);

        r = crypt_format(cd,
                         CRYPT_LUKS2,
                         user_record_luks_cipher(hr),
                         user_record_luks_cipher_mode(hr),
                         id128_to_uuid_string(uuid, suuid),
                         volume_key,
                         volume_key_size,
                         &(struct crypt_params_luks2) {
                                 .label = label,
                                 .subsystem = "systemd-home",
                                 .sector_size = 512U,
                                 .pbkdf = &good_pbkdf,
                         });
        if (r < 0)
                return log_error_errno(r, "Failed to format LUKS image: %m");

        log_info("LUKS formatting completed.");

        STRV_FOREACH(pp, effective_passwords) {

                if (strv_contains(cache->pkcs11_passwords, *pp) ||
                    strv_contains(cache->fido2_passwords, *pp)) {
                        log_debug("Using minimal PBKDF for slot %i", slot);
                        r = crypt_set_pbkdf_type(cd, &minimal_pbkdf);
                } else {
                        log_debug("Using good PBKDF for slot %i", slot);
                        r = crypt_set_pbkdf_type(cd, &good_pbkdf);
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to tweak PBKDF for slot %i: %m", slot);

                r = crypt_keyslot_add_by_volume_key(
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

        r = crypt_activate_by_volume_key(
                        cd,
                        dm_name,
                        volume_key,
                        volume_key_size,
                        discard ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0);
        if (r < 0)
                return log_error_errno(r, "Failed to activate LUKS superblock: %m");

        log_info("LUKS activation by volume key succeeded.");

        r = user_record_clone(hr, USER_RECORD_EXTRACT_EMBEDDED, &reduced);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare home record for LUKS: %m");

        r = format_luks_token_text(cd, reduced, volume_key, &text);
        if (r < 0)
                return r;

        r = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, text);
        if (r < 0)
                return log_error_errno(r, "Failed to set LUKS JSON token: %m");

        log_info("Writing user record as LUKS token completed.");

        if (ret)
                *ret = TAKE_PTR(cd);

        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_context*, fdisk_unref_context, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_partition*, fdisk_unref_partition, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_parttype*, fdisk_unref_parttype, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_table*, fdisk_unref_table, NULL);

static int make_partition_table(
                int fd,
                const char *label,
                sd_id128_t uuid,
                uint64_t *ret_offset,
                uint64_t *ret_size,
                sd_id128_t *ret_disk_uuid) {

        _cleanup_(fdisk_unref_partitionp) struct fdisk_partition *p = NULL, *q = NULL;
        _cleanup_(fdisk_unref_parttypep) struct fdisk_parttype *t = NULL;
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_free_ char *path = NULL, *disk_uuid_as_string = NULL;
        uint64_t offset, size;
        sd_id128_t disk_uuid;
        char uuids[ID128_UUID_STRING_MAX];
        int r;

        assert(fd >= 0);
        assert(label);
        assert(ret_offset);
        assert(ret_size);

        t = fdisk_new_parttype();
        if (!t)
                return log_oom();

        r = fdisk_parttype_set_typestr(t, "773f91ef-66d4-49b5-bd83-d683bf40ad16");
        if (r < 0)
                return log_error_errno(r, "Failed to initialize partition type: %m");

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        if (asprintf(&path, "/proc/self/fd/%i", fd) < 0)
                return log_oom();

        r = fdisk_assign_device(c, path, 0);
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

        r = fdisk_partition_start_follow_default(p, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to place partition at beginning of space: %m");

        r = fdisk_partition_partno_follow_default(p, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to place partition at first free partition index: %m");

        r = fdisk_partition_end_follow_default(p, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to make partition cover all free space: %m");

        r = fdisk_partition_set_name(p, label);
        if (r < 0)
                return log_error_errno(r, "Failed to set partition name: %m");

        r = fdisk_partition_set_uuid(p, id128_to_uuid_string(uuid, uuids));
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
        _cleanup_close_ int inotify_fd = -1;
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

                dn = dirname_malloc(path);
                for (;;) {
                        if (!dn)
                                return log_oom();

                        log_info("Watching %s", dn);

                        if (inotify_add_watch(inotify_fd, dn, IN_CREATE|IN_MOVED_TO|IN_ONLYDIR|IN_DELETE_SELF|IN_MOVE_SELF) < 0) {
                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to add watch on %s: %m", dn);
                        } else
                                break;

                        if (empty_or_root(dn))
                                break;

                        dn = dirname_malloc(dn);
                }

                w = now(CLOCK_MONOTONIC);
                if (w >= until)
                        return log_error_errno(SYNTHETIC_ERRNO(ETIMEDOUT), "Device link %s still hasn't shown up, giving up.", path);

                r = fd_wait_for_event(inotify_fd, POLLIN, usec_sub_unsigned(until, w));
                if (r < 0)
                        return log_error_errno(r, "Failed to watch inotify: %m");

                (void) flush_fd(inotify_fd);
        }
}

static int calculate_disk_size(UserRecord *h, const char *parent_dir, uint64_t *ret) {
        char buf[FORMAT_BYTES_MAX];
        struct statfs sfs;
        uint64_t m;

        assert(h);
        assert(parent_dir);
        assert(ret);

        if (h->disk_size != UINT64_MAX) {
                *ret = DISK_SIZE_ROUND_DOWN(h->disk_size);
                return 0;
        }

        if (statfs(parent_dir, &sfs) < 0)
                return log_error_errno(errno, "statfs() on %s failed: %m", parent_dir);

        m = sfs.f_bsize * sfs.f_bavail;

        if (h->disk_size_relative == UINT64_MAX) {

                if (m > UINT64_MAX / USER_DISK_SIZE_DEFAULT_PERCENT)
                        return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Disk size too large.");

                *ret = DISK_SIZE_ROUND_DOWN(m * USER_DISK_SIZE_DEFAULT_PERCENT / 100);

                log_info("Sizing home to %u%% of available disk space, which is %s.",
                         USER_DISK_SIZE_DEFAULT_PERCENT,
                         format_bytes(buf, sizeof(buf), *ret));
        } else {
                *ret = DISK_SIZE_ROUND_DOWN((uint64_t) ((double) m * (double) h->disk_size_relative / (double) UINT32_MAX));

                log_info("Sizing home to %" PRIu64 ".%01" PRIu64 "%% of available disk space, which is %s.",
                         (h->disk_size_relative * 100) / UINT32_MAX,
                         ((h->disk_size_relative * 1000) / UINT32_MAX) % 10,
                         format_bytes(buf, sizeof(buf), *ret));
        }

        if (*ret < USER_DISK_SIZE_MIN)
                *ret = USER_DISK_SIZE_MIN;

        return 0;
}

static int home_truncate(
                UserRecord *h,
                int fd,
                const char *path,
                uint64_t size) {

        bool trunc;
        int r;

        assert(h);
        assert(fd >= 0);
        assert(path);

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
                        log_error_errno(errno, "Not enough disk space to allocate home.");
                        return -ENOSPC; /* make recognizable */
                }

                return log_error_errno(errno, "Failed to truncate home image %s: %m", path);
        }

        return 0;
}

int home_create_luks(
                UserRecord *h,
                PasswordCache *cache,
                char **effective_passwords,
                UserRecord **ret_home) {

        _cleanup_free_ char *dm_name = NULL, *dm_node = NULL, *subdir = NULL, *disk_uuid_path = NULL, *temporary_image_path = NULL;
        uint64_t host_size, encrypted_size, partition_offset, partition_size;
        bool image_created = false, dm_activated = false, mounted = false;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        sd_id128_t partition_uuid, fs_uuid, luks_uuid, disk_uuid;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_close_ int image_fd = -1, root_fd = -1;
        const char *fstype, *ip;
        struct statfs sfs;
        int r;

        assert(h);
        assert(h->storage < 0 || h->storage == USER_LUKS);
        assert(ret_home);

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

        r = make_dm_names(h->user_name, &dm_name, &dm_node);
        if (r < 0)
                return r;

        r = access(dm_node, F_OK);
        if (r < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to determine whether %s exists: %m", dm_node);
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Device mapper device %s already exists, refusing.", dm_node);

        if (path_startswith(ip, "/dev/")) {
                _cleanup_free_ char *sysfs = NULL;
                uint64_t block_device_size;
                struct stat st;

                /* Let's place the home directory on a real device, i.e. an USB stick or such */

                image_fd = open(ip, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (image_fd < 0)
                        return log_error_errno(errno, "Failed to open device %s: %m", ip);

                if (fstat(image_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat device %s: %m", ip);
                if (!S_ISBLK(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Device is not a block device, refusing.");

                if (asprintf(&sysfs, "/sys/dev/block/%u:%u/partition", major(st.st_rdev), minor(st.st_rdev)) < 0)
                        return log_oom();
                if (access(sysfs, F_OK) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to check whether %s exists: %m", sysfs);
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Operating on partitions is currently not supported, sorry. Please specify a top-level block device.");

                if (flock(image_fd, LOCK_EX) < 0) /* make sure udev doesn't read from it while we operate on the device */
                        return log_error_errno(errno, "Failed to lock block device %s: %m", ip);

                if (ioctl(image_fd, BLKGETSIZE64, &block_device_size) < 0)
                        return log_error_errno(errno, "Failed to read block device size: %m");

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

                if (!supported_fs_size(fstype, host_size))
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                               "Selected file system size too small for %s.", fstype);

                /* After creation we should reference this partition by its UUID instead of the block
                 * device. That's preferable since the user might have specified a device node such as
                 * /dev/sdb to us, which might look very different when replugged. */
                if (asprintf(&disk_uuid_path, "/dev/disk/by-uuid/" SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(luks_uuid)) < 0)
                        return log_oom();

                if (user_record_luks_discard(h) || user_record_luks_offline_discard(h)) {
                        /* If we want online or offline discard, discard once before we start using things. */

                        if (ioctl(image_fd, BLKDISCARD, (uint64_t[]) { 0, block_device_size }) < 0)
                                log_full_errno(errno == EOPNOTSUPP ? LOG_DEBUG : LOG_WARNING, errno,
                                               "Failed to issue full-device BLKDISCARD on device, ignoring: %m");
                        else
                                log_info("Full device discard completed.");
                }
        } else {
                _cleanup_free_ char *parent = NULL;

                parent = dirname_malloc(ip);
                if (!parent)
                        return log_oom();

                r = mkdir_p(parent, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create parent directory %s: %m", parent);

                r = calculate_disk_size(h, parent, &host_size);
                if (r < 0)
                        return r;

                if (!supported_fs_size(fstype, host_size))
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Selected file system size too small for %s.", fstype);

                r = tempfn_random(ip, "homework", &temporary_image_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive temporary file name for %s: %m", ip);

                image_fd = open(temporary_image_path, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
                if (image_fd < 0)
                        return log_error_errno(errno, "Failed to create home image %s: %m", temporary_image_path);

                image_created = true;

                r = chattr_fd(image_fd, FS_NOCOW_FL, FS_NOCOW_FL, NULL);
                if (r < 0)
                        log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to set file attributes on %s, ignoring: %m", temporary_image_path);

                r = home_truncate(h, image_fd, temporary_image_path, host_size);
                if (r < 0)
                        goto fail;

                log_info("Allocating image file completed.");
        }

        r = make_partition_table(
                        image_fd,
                        user_record_user_name_and_realm(h),
                        partition_uuid,
                        &partition_offset,
                        &partition_size,
                        &disk_uuid);
        if (r < 0)
                goto fail;

        log_info("Writing of partition table completed.");

        r = loop_device_make(image_fd, O_RDWR, partition_offset, partition_size, 0, &loop);
        if (r < 0) {
                if (r == -ENOENT) { /* this means /dev/loop-control doesn't exist, i.e. we are in a container
                                     * or similar and loopback bock devices are not available, return a
                                     * recognizable error in this case. */
                        log_error_errno(r, "Loopback block device support is not available on this system.");
                        r = -ENOLINK;
                        goto fail;
                }

                log_error_errno(r, "Failed to set up loopback device for %s: %m", temporary_image_path);
                goto fail;
        }

        r = loop_device_flock(loop, LOCK_EX); /* make sure udev won't read before we are done */
        if (r < 0) {
                log_error_errno(r, "Failed to take lock on loop device: %m");
                goto fail;
        }

        log_info("Setting up loopback device %s completed.", loop->node ?: ip);

        r = luks_format(loop->node,
                        dm_name,
                        luks_uuid,
                        user_record_user_name_and_realm(h),
                        cache,
                        effective_passwords,
                        user_record_luks_discard(h) || user_record_luks_offline_discard(h),
                        h,
                        &cd);
        if (r < 0)
                goto fail;

        dm_activated = true;

        r = block_get_size_by_path(dm_node, &encrypted_size);
        if (r < 0) {
                log_error_errno(r, "Failed to get encrypted block device size: %m");
                goto fail;
        }

        log_info("Setting up LUKS device %s completed.", dm_node);

        r = make_filesystem(dm_node, fstype, user_record_user_name_and_realm(h), fs_uuid, user_record_luks_discard(h));
        if (r < 0)
                goto fail;

        log_info("Formatting file system completed.");

        r = home_unshare_and_mount(dm_node, fstype, user_record_luks_discard(h), user_record_mount_flags(h));
        if (r < 0)
                goto fail;

        mounted = true;

        subdir = path_join("/run/systemd/user-home-mount/", user_record_user_name_and_realm(h));
        if (!subdir) {
                r = log_oom();
                goto fail;
        }

        /* Prefer using a btrfs subvolume if we can, fall back to directory otherwise */
        r = btrfs_subvol_make_fallback(subdir, 0700);
        if (r < 0) {
                log_error_errno(r, "Failed to create user directory in mounted image file: %m");
                goto fail;
        }

        root_fd = open(subdir, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (root_fd < 0) {
                r = log_error_errno(errno, "Failed to open user directory in mounted image file: %m");
                goto fail;
        }

        r = home_populate(h, root_fd);
        if (r < 0)
                goto fail;

        r = home_sync_and_statfs(root_fd, &sfs);
        if (r < 0)
                goto fail;

        r = user_record_clone(h, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_LOG, &new_home);
        if (r < 0) {
                log_error_errno(r, "Failed to clone record: %m");
                goto fail;
        }

        r = user_record_add_binding(
                        new_home,
                        USER_LUKS,
                        disk_uuid_path ?: ip,
                        partition_uuid,
                        luks_uuid,
                        fs_uuid,
                        crypt_get_cipher(cd),
                        crypt_get_cipher_mode(cd),
                        luks_volume_key_size_convert(cd),
                        fstype,
                        NULL,
                        h->uid,
                        (gid_t) h->uid);
        if (r < 0) {
                log_error_errno(r, "Failed to add binding to record: %m");
                goto fail;
        }

        if (user_record_luks_offline_discard(h)) {
                r = run_fitrim(root_fd);
                if (r < 0)
                        goto fail;
        }

        root_fd = safe_close(root_fd);

        r = umount_verbose(LOG_ERR, "/run/systemd/user-home-mount", UMOUNT_NOFOLLOW);
        if (r < 0)
                goto fail;

        mounted = false;

        r = crypt_deactivate(cd, dm_name);
        if (r < 0) {
                log_error_errno(r, "Failed to deactivate LUKS device: %m");
                goto fail;
        }

        crypt_free(cd);
        cd = NULL;

        dm_activated = false;

        loop = loop_device_unref(loop);

        if (!user_record_luks_offline_discard(h)) {
                r = run_fallocate(image_fd, NULL /* refresh stat() data */);
                if (r < 0)
                        goto fail;
        }

        /* Sync everything to disk before we move things into place under the final name. */
        if (fsync(image_fd) < 0) {
                r = log_error_errno(r, "Failed to synchronize image to disk: %m");
                goto fail;
        }

        if (disk_uuid_path)
                (void) ioctl(image_fd, BLKRRPART, 0);
        else {
                /* If we operate on a file, sync the containing directory too. */
                r = fsync_directory_of_file(image_fd);
                if (r < 0) {
                        log_error_errno(r, "Failed to synchronize directory of image file to disk: %m");
                        goto fail;
                }
        }

        /* Let's close the image fd now. If we are operating on a real block device this will release the BSD
         * lock that ensures udev doesn't interfere with what we are doing */
        image_fd = safe_close(image_fd);

        if (temporary_image_path) {
                if (rename(temporary_image_path, ip) < 0) {
                        log_error_errno(errno, "Failed to rename image file: %m");
                        goto fail;
                }

                log_info("Moved image file into place.");
        }

        if (disk_uuid_path)
                (void) wait_for_devlink(disk_uuid_path);

        log_info("Everything completed.");

        print_size_summary(host_size, encrypted_size, &sfs);

        *ret_home = TAKE_PTR(new_home);
        return 0;

fail:
        /* Let's close all files before we unmount the file system, to avoid EBUSY */
        root_fd = safe_close(root_fd);

        if (mounted)
                (void) umount_verbose(LOG_WARNING, "/run/systemd/user-home-mount", UMOUNT_NOFOLLOW);

        if (dm_activated)
                (void) crypt_deactivate(cd, dm_name);

        loop = loop_device_unref(loop);

        if (image_created)
                (void) unlink(temporary_image_path);

        return r;
}

int home_validate_update_luks(UserRecord *h, HomeSetup *setup) {
        _cleanup_free_ char *dm_name = NULL, *dm_node = NULL;
        int r;

        assert(h);
        assert(setup);

        r = make_dm_names(h->user_name, &dm_name, &dm_node);
        if (r < 0)
                return r;

        r = access(dm_node, F_OK);
        if (r < 0 && errno != ENOENT)
                return log_error_errno(errno, "Failed to determine whether %s exists: %m", dm_node);

        free_and_replace(setup->dm_name, dm_name);
        free_and_replace(setup->dm_node, dm_node);

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

static int ext4_offline_resize_fs(HomeSetup *setup, uint64_t new_size, bool discard, unsigned long flags) {
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
                r = umount_verbose(LOG_ERR, "/run/systemd/user-home-mount", UMOUNT_NOFOLLOW);
                if (r < 0)
                        return r;

                setup->undo_mount = false;
                re_mount = true;
        }

        log_info("Temporary unmounting of file system completed.");

        /* resize2fs requires that the file system is force checked first, do so. */
        r = safe_fork("(e2fsck)",
                      FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_LOG|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS,
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
                      FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_LOG|FORK_WAIT|FORK_STDOUT_TO_STDERR|FORK_CLOSE_ALL_FDS,
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
                r = home_mount_node(setup->dm_node, "ext4", discard, flags);
                if (r < 0)
                        return r;

                setup->undo_mount = true;
        }

        if (re_open) {
                setup->root_fd = open("/run/systemd/user-home-mount", O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
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
                uint64_t new_partition_size,
                sd_id128_t *ret_disk_uuid,
                struct fdisk_table **ret_table) {

        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        _cleanup_free_ char *path = NULL, *disk_uuid_as_string = NULL;
        size_t n_partitions;
        sd_id128_t disk_uuid;
        bool found = false;
        int r;

        assert(fd >= 0);
        assert(ret_disk_uuid);
        assert(ret_table);

        assert((partition_offset & 511) == 0);
        assert((old_partition_size & 511) == 0);
        assert((new_partition_size & 511) == 0);
        assert(UINT64_MAX - old_partition_size >= partition_offset);
        assert(UINT64_MAX - new_partition_size >= partition_offset);

        if (partition_offset == 0) {
                /* If the offset is at the beginning we assume no partition table, let's exit early. */
                log_debug("Not rewriting partition table, operating on naked device.");
                *ret_disk_uuid = SD_ID128_NULL;
                *ret_table = NULL;
                return 0;
        }

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        if (asprintf(&path, "/proc/self/fd/%i", fd) < 0)
                return log_oom();

        r = fdisk_assign_device(c, path, 0);
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

                        /* Found our partition, now patch it */
                        r = fdisk_partition_size_explicit(p, 1);
                        if (r < 0)
                                return log_error_errno(r, "Failed to enable explicit partition size: %m");

                        r = fdisk_partition_set_size(p, new_partition_size / 512U);
                        if (r < 0)
                                return log_error_errno(r, "Failed to change partition size: %m");

                        found = true;
                        continue;

                } else {
                        if (fdisk_partition_get_start(p) < partition_offset + new_partition_size / 512U &&
                            fdisk_partition_get_end(p) >= partition_offset / 512)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't extend, conflicting partition found.");
                }
        }

        if (!found)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "Failed to find matching partition to resize.");

        *ret_table = TAKE_PTR(t);
        *ret_disk_uuid = disk_uuid;

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

                fdisk_ask_string_set_result(ask, id128_to_uuid_string(*(sd_id128_t*) userdata, result));
                break;

        default:
                log_debug("Unexpected question from libfdisk, ignoring.");
        }

        return 0;
}

static int apply_resize_partition(int fd, sd_id128_t disk_uuids, struct fdisk_table *t) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_free_ void *two_zero_lbas = NULL;
        _cleanup_free_ char *path = NULL;
        ssize_t n;
        int r;

        assert(fd >= 0);

        if (!t) /* no partition table to apply, exit early */
                return 0;

        two_zero_lbas = malloc0(1024U);
        if (!two_zero_lbas)
                return log_oom();

        /* libfdisk appears to get confused by the existing PMBR. Let's explicitly flush it out. */
        n = pwrite(fd, two_zero_lbas, 1024U, 0);
        if (n < 0)
                return log_error_errno(errno, "Failed to wipe partition table: %m");
        if (n != 1024)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while wiping partition table.");

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        if (asprintf(&path, "/proc/self/fd/%i", fd) < 0)
                return log_oom();

        r = fdisk_assign_device(c, path, 0);
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

int home_resize_luks(
                UserRecord *h,
                bool already_activated,
                PasswordCache *cache,
                HomeSetup *setup,
                UserRecord **ret_home) {

        char buffer1[FORMAT_BYTES_MAX], buffer2[FORMAT_BYTES_MAX], buffer3[FORMAT_BYTES_MAX],
                buffer4[FORMAT_BYTES_MAX], buffer5[FORMAT_BYTES_MAX], buffer6[FORMAT_BYTES_MAX];
        uint64_t old_image_size, new_image_size, old_fs_size, new_fs_size, crypto_offset, new_partition_size;
        _cleanup_(user_record_unrefp) UserRecord *header_home = NULL, *embedded_home = NULL, *new_home = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *table = NULL;
        _cleanup_free_ char *whole_disk = NULL;
        _cleanup_close_ int image_fd = -1;
        sd_id128_t disk_uuid;
        const char *ip, *ipo;
        struct statfs sfs;
        struct stat st;
        int r, resize_type;

        assert(h);
        assert(user_record_storage(h) == USER_LUKS);
        assert(setup);
        assert(ret_home);

        assert_se(ipo = user_record_image_path(h));
        ip = strdupa(ipo); /* copy out since original might change later in home record object */

        image_fd = open(ip, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (image_fd < 0)
                return log_error_errno(errno, "Failed to open image file %s: %m", ip);

        if (fstat(image_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat image file %s: %m", ip);
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

                        r = device_path_make_major_minor(st.st_mode, parent, &whole_disk);
                        if (r < 0)
                                return log_error_errno(r, "Failed to derive whole disk path for %s: %m", ip);

                        safe_close(image_fd);

                        image_fd = open(whole_disk, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                        if (image_fd < 0)
                                return log_error_errno(errno, "Failed to open whole block device %s: %m", whole_disk);

                        if (fstat(image_fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat whole block device %s: %m", whole_disk);
                        if (!S_ISBLK(st.st_mode))
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Whole block device %s is not actually a block device, refusing.", whole_disk);
                } else
                        log_info("Operating on whole block device %s.", ip);

                if (ioctl(image_fd, BLKGETSIZE64, &old_image_size) < 0)
                        return log_error_errno(errno, "Failed to determine size of original block device: %m");

                if (flock(image_fd, LOCK_EX) < 0) /* make sure udev doesn't read from it while we operate on the device */
                        return log_error_errno(errno, "Failed to lock block device %s: %m", ip);

                new_image_size = old_image_size; /* we can't resize physical block devices */
        } else {
                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Image %s is not a block device nor regular file: %m", ip);

                old_image_size = st.st_size;

                /* Note an asymetry here: when we operate on loopback files the specified disk size we get we
                 * apply onto the loopback file as a whole. When we operate on block devices we instead apply
                 * to the partition itself only. */

                new_image_size = DISK_SIZE_ROUND_DOWN(h->disk_size);
                if (new_image_size == old_image_size) {
                        log_info("Image size already matching, skipping operation.");
                        return 0;
                }
        }

        r = home_prepare_luks(h, already_activated, whole_disk, cache, setup, &header_home);
        if (r < 0)
                return r;

        r = home_load_embedded_identity(h, setup->root_fd, header_home, USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL, cache, &embedded_home, &new_home);
        if (r < 0)
                return r;

        log_info("offset = %" PRIu64 ", size = %" PRIu64 ", image = %" PRIu64, setup->partition_offset, setup->partition_size, old_image_size);

        if ((UINT64_MAX - setup->partition_offset) < setup->partition_size ||
            setup->partition_offset + setup->partition_size > old_image_size)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Old partition doesn't fit in backing storage, refusing.");

        if (S_ISREG(st.st_mode)) {
                uint64_t partition_table_extra;

                partition_table_extra = old_image_size - setup->partition_size;
                if (new_image_size <= partition_table_extra)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "New size smaller than partition table metadata.");

                new_partition_size = new_image_size - partition_table_extra;
        } else {
                assert(S_ISBLK(st.st_mode));

                new_partition_size = DISK_SIZE_ROUND_DOWN(h->disk_size);
                if (new_partition_size == setup->partition_size) {
                        log_info("Partition size already matching, skipping operation.");
                        return 0;
                }
        }

        if ((UINT64_MAX - setup->partition_offset) < new_partition_size ||
            setup->partition_offset + new_partition_size > new_image_size)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "New partition doesn't fit into backing storage, refusing.");

        crypto_offset = crypt_get_data_offset(setup->crypt_device);
        if (setup->partition_size / 512U <= crypto_offset)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Weird, old crypto payload offset doesn't actually fit in partition size?");
        if (new_partition_size / 512U <= crypto_offset)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "New size smaller than crypto payload offset?");

        old_fs_size = (setup->partition_size / 512U - crypto_offset) * 512U;
        new_fs_size = (new_partition_size / 512U - crypto_offset) * 512U;

        /* Before we start doing anything, let's figure out if we actually can */
        resize_type = can_resize_fs(setup->root_fd, old_fs_size, new_fs_size);
        if (resize_type < 0)
                return resize_type;
        if (resize_type == CAN_RESIZE_OFFLINE && already_activated)
                return log_error_errno(SYNTHETIC_ERRNO(ETXTBSY), "File systems of this type can only be resized offline, but is currently online.");

        log_info("Ready to resize image size %s → %s, partition size %s → %s, file system size %s → %s.",
                 format_bytes(buffer1, sizeof(buffer1), old_image_size),
                 format_bytes(buffer2, sizeof(buffer2), new_image_size),
                 format_bytes(buffer3, sizeof(buffer3), setup->partition_size),
                 format_bytes(buffer4, sizeof(buffer4), new_partition_size),
                 format_bytes(buffer5, sizeof(buffer5), old_fs_size),
                 format_bytes(buffer6, sizeof(buffer6), new_fs_size));

        r = prepare_resize_partition(
                        image_fd,
                        setup->partition_offset,
                        setup->partition_size,
                        new_partition_size,
                        &disk_uuid,
                        &table);
        if (r < 0)
                return r;

        if (new_fs_size > old_fs_size) {

                if (S_ISREG(st.st_mode)) {
                        /* Grow file size */
                        r = home_truncate(h, image_fd, ip, new_image_size);
                        if (r < 0)
                                return r;

                        log_info("Growing of image file completed.");
                }

                /* Make sure loopback device sees the new bigger size */
                r = loop_device_refresh_size(setup->loop, UINT64_MAX, new_partition_size);
                if (r == -ENOTTY)
                        log_debug_errno(r, "Device is not a loopback device, not refreshing size.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to refresh loopback device size: %m");
                else
                        log_info("Refreshing loop device size completed.");

                r = apply_resize_partition(image_fd, disk_uuid, table);
                if (r < 0)
                        return r;
                if (r > 0)
                        log_info("Growing of partition completed.");

                if (ioctl(image_fd, BLKRRPART, 0) < 0)
                        log_debug_errno(errno, "BLKRRPART failed on block device, ignoring: %m");

                /* Tell LUKS about the new bigger size too */
                r = crypt_resize(setup->crypt_device, setup->dm_name, new_fs_size / 512U);
                if (r < 0)
                        return log_error_errno(r, "Failed to grow LUKS device: %m");

                log_info("LUKS device growing completed.");
        } else {
                r = home_store_embedded_identity(new_home, setup->root_fd, h->uid, embedded_home);
                if (r < 0)
                        return r;

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

        /* Now resize the file system */
        if (resize_type == CAN_RESIZE_ONLINE)
                r = resize_fs(setup->root_fd, new_fs_size, NULL);
        else
                r = ext4_offline_resize_fs(setup, new_fs_size, user_record_luks_discard(h), user_record_mount_flags(h));
        if (r < 0)
                return log_error_errno(r, "Failed to resize file system: %m");

        log_info("File system resizing completed.");

        /* Immediately sync afterwards */
        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        if (new_fs_size < old_fs_size) {

                /* Shrink the LUKS device now, matching the new file system size */
                r = crypt_resize(setup->crypt_device, setup->dm_name, new_fs_size / 512);
                if (r < 0)
                        return log_error_errno(r, "Failed to shrink LUKS device: %m");

                log_info("LUKS device shrinking completed.");

                if (S_ISREG(st.st_mode)) {
                        /* Shrink the image file */
                        if (ftruncate(image_fd, new_image_size) < 0)
                                return log_error_errno(errno, "Failed to shrink image file %s: %m", ip);

                        log_info("Shrinking of image file completed.");
                }

                /* Refresh the loop devices size */
                r = loop_device_refresh_size(setup->loop, UINT64_MAX, new_partition_size);
                if (r == -ENOTTY)
                        log_debug_errno(r, "Device is not a loopback device, not refreshing size.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to refresh loopback device size: %m");
                else
                        log_info("Refreshing loop device size completed.");

                r = apply_resize_partition(image_fd, disk_uuid, table);
                if (r < 0)
                        return r;
                if (r > 0)
                        log_info("Shrinking of partition completed.");

                if (ioctl(image_fd, BLKRRPART, 0) < 0)
                        log_debug_errno(errno, "BLKRRPART failed on block device, ignoring: %m");
        } else {
                r = home_store_embedded_identity(new_home, setup->root_fd, h->uid, embedded_home);
                if (r < 0)
                        return r;
        }

        r = home_store_header_identity_luks(new_home, setup, header_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, setup);
        if (r < 0)
                return r;

        if (user_record_luks_discard(h))
                (void) run_fitrim(setup->root_fd);

        r = home_sync_and_statfs(setup->root_fd, &sfs);
        if (r < 0)
                return r;

        r = home_setup_undo(setup);
        if (r < 0)
                return r;

        log_info("Everything completed.");

        print_size_summary(new_image_size, new_fs_size, &sfs);

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_passwd_luks(
                UserRecord *h,
                HomeSetup *setup,
                PasswordCache *cache,      /* the passwords acquired via PKCS#11/FIDO2 security tokens */
                char **effective_passwords /* new passwords */) {

        size_t volume_key_size, max_key_slots, n_effective;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        struct crypt_pbkdf_type good_pbkdf, minimal_pbkdf;
        const char *type;
        char **list;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_LUKS);
        assert(setup);

        type = crypt_get_type(setup->crypt_device);
        if (!type)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine crypto device type.");

        r = crypt_keyslot_max(type);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine number of key slots.");
        max_key_slots = r;

        r = crypt_get_volume_key_size(setup->crypt_device);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine volume key size.");
        volume_key_size = (size_t) r;

        volume_key = malloc(volume_key_size);
        if (!volume_key)
                return log_oom();

        r = -ENOKEY;
        FOREACH_POINTER(list, cache->pkcs11_passwords, cache->fido2_passwords, h->password) {
                r = luks_try_passwords(setup->crypt_device, list, volume_key, &volume_key_size);
                if (r != -ENOKEY)
                        break;
        }
        if (r == -ENOKEY)
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Failed to unlock LUKS superblock with supplied passwords.");
        if (r < 0)
                return log_error_errno(r, "Failed to unlocks LUKS superblock: %m");

        n_effective = strv_length(effective_passwords);

        build_good_pbkdf(&good_pbkdf, h);
        build_minimal_pbkdf(&minimal_pbkdf, h);

        for (size_t i = 0; i < max_key_slots; i++) {
                r = crypt_keyslot_destroy(setup->crypt_device, i);
                if (r < 0 && !IN_SET(r, -ENOENT, -EINVAL)) /* Returns EINVAL or ENOENT if there's no key in this slot already */
                        return log_error_errno(r, "Failed to destroy LUKS password: %m");

                if (i >= n_effective) {
                        if (r >= 0)
                                log_info("Destroyed LUKS key slot %zu.", i);
                        continue;
                }

                if (strv_contains(cache->pkcs11_passwords, effective_passwords[i]) ||
                    strv_contains(cache->fido2_passwords, effective_passwords[i])) {
                        log_debug("Using minimal PBKDF for slot %zu", i);
                        r = crypt_set_pbkdf_type(setup->crypt_device, &minimal_pbkdf);
                } else {
                        log_debug("Using good PBKDF for slot %zu", i);
                        r = crypt_set_pbkdf_type(setup->crypt_device, &good_pbkdf);
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to tweak PBKDF for slot %zu: %m", i);

                r = crypt_keyslot_add_by_volume_key(
                                setup->crypt_device,
                                i,
                                volume_key,
                                volume_key_size,
                                effective_passwords[i],
                                strlen(effective_passwords[i]));
                if (r < 0)
                        return log_error_errno(r, "Failed to set up LUKS password: %m");

                log_info("Updated LUKS key slot %zu.", i);
        }

        return 1;
}

int home_lock_luks(UserRecord *h) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_free_ char *dm_name = NULL, *dm_node = NULL;
        _cleanup_close_ int root_fd = -1;
        const char *p;
        int r;

        assert(h);

        assert_se(p = user_record_home_directory(h));
        root_fd = open(p, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        r = make_dm_names(h->user_name, &dm_name, &dm_node);
        if (r < 0)
                return r;

        r = crypt_init_by_name(&cd, dm_name);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize cryptsetup context for %s: %m", dm_name);

        log_info("Discovered used LUKS device %s.", dm_node);
        cryptsetup_enable_logging(cd);

        if (syncfs(root_fd) < 0) /* Snake oil, but let's better be safe than sorry */
                return log_error_errno(errno, "Failed to synchronize file system %s: %m", p);

        root_fd = safe_close(root_fd);

        log_info("File system synchronized.");

        /* Note that we don't invoke FIFREEZE here, it appears libcryptsetup/device-mapper already does that on its own for us */

        r = crypt_suspend(cd, dm_name);
        if (r < 0)
                return log_error_errno(r, "Failed to suspend cryptsetup device: %s: %m", dm_node);

        log_info("LUKS device suspended.");
        return 0;
}

static int luks_try_resume(
                struct crypt_device *cd,
                const char *dm_name,
                char **password) {

        char **pp;
        int r;

        assert(cd);
        assert(dm_name);

        STRV_FOREACH(pp, password) {
                r = crypt_resume_by_passphrase(
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

int home_unlock_luks(UserRecord *h, PasswordCache *cache) {
        _cleanup_free_ char *dm_name = NULL, *dm_node = NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        char **list;
        int r;

        assert(h);

        r = make_dm_names(h->user_name, &dm_name, &dm_node);
        if (r < 0)
                return r;

        r = crypt_init_by_name(&cd, dm_name);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize cryptsetup context for %s: %m", dm_name);

        log_info("Discovered used LUKS device %s.", dm_node);
        cryptsetup_enable_logging(cd);

        r = -ENOKEY;
        FOREACH_POINTER(list, cache->pkcs11_passwords, cache->fido2_passwords, h->password) {
                r = luks_try_resume(cd, dm_name, list);
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
