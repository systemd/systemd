/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>

#include "errno-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "homework-fscrypt.h"
#include "homework-mount.h"
#include "homework-quota.h"
#include "memory-util.h"
#include "missing_keyctl.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "openssl-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "xattr-util.h"

static int fscrypt_upload_volume_key(
                const uint8_t key_descriptor[static FS_KEY_DESCRIPTOR_SIZE],
                const void *volume_key,
                size_t volume_key_size,
                key_serial_t where) {

        _cleanup_free_ char *hex = NULL;
        const char *description;
        struct fscrypt_key key;
        key_serial_t serial;

        assert(key_descriptor);
        assert(volume_key);
        assert(volume_key_size > 0);

        if (volume_key_size > sizeof(key.raw))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume key too long.");

        hex = hexmem(key_descriptor, FS_KEY_DESCRIPTOR_SIZE);
        if (!hex)
                return log_oom();

        description = strjoina("fscrypt:", hex);

        key = (struct fscrypt_key) {
                .size = volume_key_size,
        };
        memcpy(key.raw, volume_key, volume_key_size);

        CLEANUP_ERASE(key);

        /* Upload to the kernel */
        serial = add_key("logon", description, &key, sizeof(key), where);
        if (serial < 0)
                return log_error_errno(errno, "Failed to install master key in keyring: %m");

        log_info("Uploaded encryption key to kernel.");

        return 0;
}

static void calculate_key_descriptor(
                const void *key,
                size_t key_size,
                uint8_t ret_key_descriptor[static FS_KEY_DESCRIPTOR_SIZE]) {

        uint8_t hashed[512 / 8] = {}, hashed2[512 / 8] = {};

        /* Derive the key descriptor from the volume key via double SHA512, in order to be compatible with e4crypt */

        assert_se(SHA512(key, key_size, hashed) == hashed);
        assert_se(SHA512(hashed, sizeof(hashed), hashed2) == hashed2);

        assert_cc(sizeof(hashed2) >= FS_KEY_DESCRIPTOR_SIZE);

        memcpy(ret_key_descriptor, hashed2, FS_KEY_DESCRIPTOR_SIZE);
}

static int fscrypt_slot_try_one(
                const char *password,
                const void *salt, size_t salt_size,
                const void *encrypted, size_t encrypted_size,
                const uint8_t match_key_descriptor[static FS_KEY_DESCRIPTOR_SIZE],
                void **ret_decrypted, size_t *ret_decrypted_size) {


        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(erase_and_freep) void *decrypted = NULL;
        uint8_t key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
        int decrypted_size_out1, decrypted_size_out2;
        uint8_t derived[512 / 8] = {};
        size_t decrypted_size;
        const EVP_CIPHER *cc;
        int r;

        assert(password);
        assert(salt);
        assert(salt_size > 0);
        assert(encrypted);
        assert(encrypted_size > 0);
        assert(match_key_descriptor);

        /* Our construction is like this:
         *
         *   1. In each key slot we store a salt value plus the encrypted volume key
         *
         *   2. Unlocking is via calculating PBKDF2-HMAC-SHA512 of the supplied password (in combination with
         *      the salt), then using the first 256 bit of the hash as key for decrypting the encrypted
         *      volume key in AES256 counter mode.
         *
         *   3. Writing a password is similar: calculate PBKDF2-HMAC-SHA512 of the supplied password (in
         *      combination with the salt), then encrypt the volume key in AES256 counter mode with the
         *      resulting hash.
         */

        CLEANUP_ERASE(derived);

        if (PKCS5_PBKDF2_HMAC(
                            password, strlen(password),
                            salt, salt_size,
                            0xFFFF, EVP_sha512(),
                            sizeof(derived), derived) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "PBKDF2 failed");

        context = EVP_CIPHER_CTX_new();
        if (!context)
                return log_oom();

        /* We use AES256 in counter mode */
        assert_se(cc = EVP_aes_256_ctr());

        /* We only use the first half of the derived key */
        assert(sizeof(derived) >= (size_t) EVP_CIPHER_key_length(cc));

        if (EVP_DecryptInit_ex(context, cc, NULL, derived, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize decryption context.");

        decrypted_size = encrypted_size + EVP_CIPHER_key_length(cc) * 2;
        decrypted = malloc(decrypted_size);
        if (!decrypted)
                return log_oom();

        if (EVP_DecryptUpdate(context, (uint8_t*) decrypted, &decrypted_size_out1, encrypted, encrypted_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decrypt volume key.");

        assert((size_t) decrypted_size_out1 <= decrypted_size);

        if (EVP_DecryptFinal_ex(context, (uint8_t*) decrypted_size + decrypted_size_out1, &decrypted_size_out2) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finish decryption of volume key.");

        assert((size_t) decrypted_size_out1 + (size_t) decrypted_size_out2 < decrypted_size);
        decrypted_size = (size_t) decrypted_size_out1 + (size_t) decrypted_size_out2;

        calculate_key_descriptor(decrypted, decrypted_size, key_descriptor);

        if (memcmp(key_descriptor, match_key_descriptor, FS_KEY_DESCRIPTOR_SIZE) != 0)
                return -ENOANO; /* don't log here */

        r = fscrypt_upload_volume_key(key_descriptor, decrypted, decrypted_size, KEY_SPEC_THREAD_KEYRING);
        if (r < 0)
                return r;

        if (ret_decrypted)
                *ret_decrypted = TAKE_PTR(decrypted);
        if (ret_decrypted_size)
                *ret_decrypted_size = decrypted_size;

        return 0;
}

static int fscrypt_slot_try_many(
                char **passwords,
                const void *salt, size_t salt_size,
                const void *encrypted, size_t encrypted_size,
                const uint8_t match_key_descriptor[static FS_KEY_DESCRIPTOR_SIZE],
                void **ret_decrypted, size_t *ret_decrypted_size) {

        int r;

        STRV_FOREACH(i, passwords) {
                r = fscrypt_slot_try_one(*i, salt, salt_size, encrypted, encrypted_size, match_key_descriptor, ret_decrypted, ret_decrypted_size);
                if (r != -ENOANO)
                        return r;
        }

        return -ENOANO;
}

static int fscrypt_setup(
                const PasswordCache *cache,
                char **password,
                HomeSetup *setup,
                void **ret_volume_key,
                size_t *ret_volume_key_size) {

        _cleanup_free_ char *xattr_buf = NULL;
        int r;

        assert(setup);
        assert(setup->root_fd >= 0);

        r = flistxattr_malloc(setup->root_fd, &xattr_buf);
        if (r < 0)
                return log_error_errno(errno, "Failed to retrieve xattr list: %m");

        NULSTR_FOREACH(xa, xattr_buf) {
                _cleanup_free_ void *salt = NULL, *encrypted = NULL;
                _cleanup_free_ char *value = NULL;
                size_t salt_size, encrypted_size;
                const char *nr, *e;
                char **list;
                int n;

                /* Check if this xattr has the format 'trusted.fscrypt_slot<nr>' where '<nr>' is a 32-bit unsigned integer */
                nr = startswith(xa, "trusted.fscrypt_slot");
                if (!nr)
                        continue;
                if (safe_atou32(nr, NULL) < 0)
                        continue;

                n = fgetxattr_malloc(setup->root_fd, xa, &value);
                if (n == -ENODATA) /* deleted by now? */
                        continue;
                if (n < 0)
                        return log_error_errno(n, "Failed to read %s xattr: %m", xa);

                e = memchr(value, ':', n);
                if (!e)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "xattr %s lacks ':' separator: %m", xa);

                r = unbase64mem(value, e - value, &salt, &salt_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode salt of %s: %m", xa);
                r = unbase64mem(e+1, n - (e - value) - 1, &encrypted, &encrypted_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode encrypted key of %s: %m", xa);

                r = -ENOANO;
                FOREACH_POINTER(list, cache->pkcs11_passwords, cache->fido2_passwords, password) {
                        r = fscrypt_slot_try_many(
                                        list,
                                        salt, salt_size,
                                        encrypted, encrypted_size,
                                        setup->fscrypt_key_descriptor,
                                        ret_volume_key, ret_volume_key_size);
                        if (r != -ENOANO)
                                break;
                }
                if (r < 0) {
                        if (r != -ENOANO)
                                return r;
                } else
                        return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Failed to set up home directory with provided passwords.");
}

int home_setup_fscrypt(
                UserRecord *h,
                HomeSetup *setup,
                const PasswordCache *cache) {

        _cleanup_(erase_and_freep) void *volume_key = NULL;
        struct fscrypt_policy policy = {};
        size_t volume_key_size = 0;
        const char *ip;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);
        assert(setup);
        assert(setup->root_fd < 0);

        assert_se(ip = user_record_image_path(h));

        setup->root_fd = open(ip, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        if (ioctl(setup->root_fd, FS_IOC_GET_ENCRYPTION_POLICY, &policy) < 0) {
                if (errno == ENODATA)
                        return log_error_errno(errno, "Home directory %s is not encrypted.", ip);
                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        log_error_errno(errno, "File system does not support fscrypt: %m");
                        return -ENOLINK; /* make recognizable */
                }
                return log_error_errno(errno, "Failed to acquire encryption policy of %s: %m", ip);
        }

        memcpy(setup->fscrypt_key_descriptor, policy.master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE);

        r = fscrypt_setup(
                        cache,
                        h->password,
                        setup,
                        &volume_key,
                        &volume_key_size);
        if (r < 0)
                return r;

        /* Also install the access key in the user's own keyring */

        if (uid_is_valid(h->uid)) {
                r = safe_fork("(sd-addkey)",
                              FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_REOPEN_LOG,
                              NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed install encryption key in user's keyring: %m");
                if (r == 0) {
                        /* Child */

                        r = fully_set_uid_gid(h->uid, user_record_gid(h), /* supplementary_gids= */ NULL, /* n_supplementary_gids= */ 0);
                        if (r < 0) {
                                log_error_errno(r, "Failed to change UID/GID to " UID_FMT "/" GID_FMT ": %m", h->uid, user_record_gid(h));
                                _exit(EXIT_FAILURE);
                        }

                        r = fscrypt_upload_volume_key(
                                        setup->fscrypt_key_descriptor,
                                        volume_key,
                                        volume_key_size,
                                        KEY_SPEC_USER_KEYRING);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        _exit(EXIT_SUCCESS);
                }
        }

        /* We'll bind mount the image directory to a new mount point where we'll start adjusting it. Only
         * once that's complete we'll move the thing to its final place eventually. */
        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        r = mount_follow_verbose(LOG_ERR, ip, HOME_RUNTIME_WORK_DIR, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        setup->undo_mount = true;

        /* Turn off any form of propagation for this */
        r = mount_nofollow_verbose(LOG_ERR, NULL, HOME_RUNTIME_WORK_DIR, NULL, MS_PRIVATE, NULL);
        if (r < 0)
                return r;

        /* Adjust MS_SUID and similar flags */
        r = mount_nofollow_verbose(LOG_ERR, NULL, HOME_RUNTIME_WORK_DIR, NULL, MS_BIND|MS_REMOUNT|user_record_mount_flags(h), NULL);
        if (r < 0)
                return r;

        safe_close(setup->root_fd);
        setup->root_fd = open(HOME_RUNTIME_WORK_DIR, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        return 0;
}

static int fscrypt_slot_set(
                int root_fd,
                const void *volume_key,
                size_t volume_key_size,
                const char *password,
                uint32_t nr) {

        _cleanup_free_ char *salt_base64 = NULL, *encrypted_base64 = NULL, *joined = NULL;
        char label[STRLEN("trusted.fscrypt_slot") + DECIMAL_STR_MAX(nr) + 1];
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        int r, encrypted_size_out1, encrypted_size_out2;
        uint8_t salt[64], derived[512 / 8] = {};
        _cleanup_free_ void *encrypted = NULL;
        const EVP_CIPHER *cc;
        size_t encrypted_size;
        ssize_t ss;

        r = crypto_random_bytes(salt, sizeof(salt));
        if (r < 0)
                return log_error_errno(r, "Failed to generate salt: %m");

        CLEANUP_ERASE(derived);

        if (PKCS5_PBKDF2_HMAC(
                            password, strlen(password),
                            salt, sizeof(salt),
                            0xFFFF, EVP_sha512(),
                            sizeof(derived), derived) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "PBKDF2 failed");

        context = EVP_CIPHER_CTX_new();
        if (!context)
                return log_oom();

        /* We use AES256 in counter mode */
        cc = EVP_aes_256_ctr();

        /* We only use the first half of the derived key */
        assert(sizeof(derived) >= (size_t) EVP_CIPHER_key_length(cc));

        if (EVP_EncryptInit_ex(context, cc, NULL, derived, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize encryption context.");

        encrypted_size = volume_key_size + EVP_CIPHER_key_length(cc) * 2;
        encrypted = malloc(encrypted_size);
        if (!encrypted)
                return log_oom();

        if (EVP_EncryptUpdate(context, (uint8_t*) encrypted, &encrypted_size_out1, volume_key, volume_key_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to encrypt volume key.");

        assert((size_t) encrypted_size_out1 <= encrypted_size);

        if (EVP_EncryptFinal_ex(context, (uint8_t*) encrypted_size + encrypted_size_out1, &encrypted_size_out2) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finish encryption of volume key.");

        assert((size_t) encrypted_size_out1 + (size_t) encrypted_size_out2 < encrypted_size);
        encrypted_size = (size_t) encrypted_size_out1 + (size_t) encrypted_size_out2;

        ss = base64mem(salt, sizeof(salt), &salt_base64);
        if (ss < 0)
                return log_oom();

        ss = base64mem(encrypted, encrypted_size, &encrypted_base64);
        if (ss < 0)
                return log_oom();

        joined = strjoin(salt_base64, ":", encrypted_base64);
        if (!joined)
                return log_oom();

        xsprintf(label, "trusted.fscrypt_slot%" PRIu32, nr);
        if (fsetxattr(root_fd, label, joined, strlen(joined), 0) < 0)
                return log_error_errno(errno, "Failed to write xattr %s: %m", label);

        log_info("Written key slot %s.", label);

        return 0;
}

int home_create_fscrypt(
                UserRecord *h,
                HomeSetup *setup,
                char **effective_passwords,
                UserRecord **ret_home) {

        _cleanup_(rm_rf_physical_and_freep) char *temporary = NULL;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        _cleanup_(erase_and_freep) void *volume_key = NULL;
        _cleanup_close_ int mount_fd = -EBADF;
        struct fscrypt_policy policy = {};
        size_t volume_key_size = 512 / 8;
        _cleanup_free_ char *d = NULL;
        uint32_t nr = 0;
        const char *ip;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);
        assert(setup);
        assert(ret_home);

        assert_se(ip = user_record_image_path(h));

        r = tempfn_random(ip, "homework", &d);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate temporary directory: %m");

        (void) mkdir_parents(d, 0755);

        if (mkdir(d, 0700) < 0)
                return log_error_errno(errno, "Failed to create temporary home directory %s: %m", d);

        temporary = TAKE_PTR(d); /* Needs to be destroyed now */

        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        setup->root_fd = open(temporary, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open temporary home directory: %m");

        if (ioctl(setup->root_fd, FS_IOC_GET_ENCRYPTION_POLICY, &policy) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        log_error_errno(errno, "File system does not support fscrypt: %m");
                        return -ENOLINK; /* make recognizable */
                }
                if (errno != ENODATA)
                        return log_error_errno(errno, "Failed to get fscrypt policy of directory: %m");
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Parent of %s already encrypted, refusing.", d);

        volume_key = malloc(volume_key_size);
        if (!volume_key)
                return log_oom();

        r = crypto_random_bytes(volume_key, volume_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire volume key: %m");

        log_info("Generated volume key of size %zu.", volume_key_size);

        policy = (struct fscrypt_policy) {
                .contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS,
                .filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS,
                .flags = FS_POLICY_FLAGS_PAD_32,
        };

        calculate_key_descriptor(volume_key, volume_key_size, policy.master_key_descriptor);

        r = fscrypt_upload_volume_key(policy.master_key_descriptor, volume_key, volume_key_size, KEY_SPEC_THREAD_KEYRING);
        if (r < 0)
                return r;

        log_info("Uploaded volume key to kernel.");

        if (ioctl(setup->root_fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy) < 0)
                return log_error_errno(errno, "Failed to set fscrypt policy on directory: %m");

        log_info("Encryption policy set.");

        STRV_FOREACH(i, effective_passwords) {
                r = fscrypt_slot_set(setup->root_fd, volume_key, volume_key_size, *i, nr);
                if (r < 0)
                        return r;

                nr++;
        }

        (void) home_update_quota_classic(h, temporary);

        r = home_shift_uid(setup->root_fd, HOME_RUNTIME_WORK_DIR, h->uid, h->uid, &mount_fd);
        if (r > 0)
                setup->undo_mount = true; /* If uidmaps worked we have a mount to undo again */

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

        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        r = user_record_clone(h, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, &new_home);
        if (r < 0)
                return log_error_errno(r, "Failed to clone record: %m");

        r = user_record_add_binding(
                        new_home,
                        USER_FSCRYPT,
                        ip,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        NULL,
                        NULL,
                        UINT64_MAX,
                        NULL,
                        NULL,
                        h->uid,
                        (gid_t) h->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to add binding to record: %m");

        setup->root_fd = safe_close(setup->root_fd);

        r = home_setup_undo_mount(setup, LOG_ERR);
        if (r < 0)
                return r;

        if (rename(temporary, ip) < 0)
                return log_error_errno(errno, "Failed to rename %s to %s: %m", temporary, ip);

        temporary = mfree(temporary);

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_passwd_fscrypt(
                UserRecord *h,
                HomeSetup *setup,
                const PasswordCache *cache,         /* the passwords acquired via PKCS#11/FIDO2 security tokens */
                char **effective_passwords          /* new passwords */) {

        _cleanup_(erase_and_freep) void *volume_key = NULL;
        _cleanup_free_ char *xattr_buf = NULL;
        size_t volume_key_size = 0;
        uint32_t slot = 0;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);
        assert(setup);

        r = fscrypt_setup(
                        cache,
                        h->password,
                        setup,
                        &volume_key,
                        &volume_key_size);
        if (r < 0)
                return r;

        STRV_FOREACH(p, effective_passwords) {
                r = fscrypt_slot_set(setup->root_fd, volume_key, volume_key_size, *p, slot);
                if (r < 0)
                        return r;

                slot++;
        }

        r = flistxattr_malloc(setup->root_fd, &xattr_buf);
        if (r < 0)
                return log_error_errno(errno, "Failed to retrieve xattr list: %m");

        NULSTR_FOREACH(xa, xattr_buf) {
                const char *nr;
                uint32_t z;

                /* Check if this xattr has the format 'trusted.fscrypt_slot<nr>' where '<nr>' is a 32-bit unsigned integer */
                nr = startswith(xa, "trusted.fscrypt_slot");
                if (!nr)
                        continue;
                if (safe_atou32(nr, &z) < 0)
                        continue;

                if (z < slot)
                        continue;

                if (fremovexattr(setup->root_fd, xa) < 0)
                        if (errno != ENODATA)
                                log_warning_errno(errno, "Failed to remove xattr %s: %m", xa);
        }

        return 0;
}
