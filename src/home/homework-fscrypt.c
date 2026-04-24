/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fscrypt.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "homework-fscrypt.h"
#include "homework-mount.h"
#include "homework-password-cache.h"
#include "homework-quota.h"
#include "homework.h"
#include "keyring-util.h"
#include "log.h"
#include "memory-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-record-util.h"
#include "user-record.h"
#include "user-util.h"
#include "xattr-util.h"

static int fscrypt_unlink_key(UserRecord *h) {
        _cleanup_free_ void *keyring = NULL;
        size_t keyring_size = 0, n_keys = 0;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);

        r = fully_set_uid_gid(
                        h->uid,
                        user_record_gid(h),
                        /* supplementary_gids= */ NULL,
                        /* n_supplementary_gids= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to change UID/GID to " UID_FMT "/" GID_FMT ": %m",
                                       h->uid, user_record_gid(h));

        r = keyring_read(KEY_SPEC_USER_KEYRING, &keyring, &keyring_size);
        if (r < 0)
                return log_error_errno(r, "Failed to read the keyring of user " UID_FMT ": %m", h->uid);

        n_keys = keyring_size / sizeof(key_serial_t);
        assert(keyring_size % sizeof(key_serial_t) == 0);

        /* Find any key with a description starting with 'fscrypt:' and unlink it. We need to iterate as we
         * store the key with a description that uses the hash of the secret key, that we do not have when
         * we are deactivating. */
        FOREACH_ARRAY(key, ((key_serial_t *) keyring), n_keys) {
                _cleanup_free_ char *description = NULL;
                char *d;

                r = keyring_describe(*key, &description);
                if (r == -ENOKEY) /* Something else deleted it already, that's ok. */
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to describe key id %d: %m", *key);

                /* The description is the final element as per manpage. */
                d = strrchr(description, ';');
                if (!d)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EINVAL),
                                        "Failed to parse description of key id %d: %s",
                                        *key,
                                        description);

                if (!startswith(d + 1, "fscrypt:"))
                        continue;

                r = keyctl(KEYCTL_UNLINK, *key, KEY_SPEC_USER_KEYRING, 0, 0);
                if (r < 0) {
                        if (errno == ENOKEY) /* Something else deleted it already, that's ok. */
                                continue;

                        return log_error_errno(
                                        errno,
                                        "Failed to delete encryption key with id '%d' from the keyring of user " UID_FMT ": %m",
                                        *key,
                                        h->uid);
                }

                log_debug("Deleted encryption key with id '%d' from the keyring of user " UID_FMT ".", *key, h->uid);
        }

        return 0;
}

int home_flush_keyring_fscrypt(UserRecord *h) {
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);

        if (!uid_is_valid(h->uid))
                return 0;

        r = pidref_safe_fork(
                        "(sd-delkey)",
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_REOPEN_LOG,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                if (fscrypt_unlink_key(h) < 0)
                        _exit(EXIT_FAILURE);
                _exit(EXIT_SUCCESS);
        }

        return 0;
}

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

        assert_se(sym_SHA512(key, key_size, hashed) == hashed);
        assert_se(sym_SHA512(hashed, sizeof(hashed), hashed2) == hashed2);

        assert_cc(sizeof(hashed2) >= FS_KEY_DESCRIPTOR_SIZE);

        memcpy(ret_key_descriptor, hashed2, FS_KEY_DESCRIPTOR_SIZE);
}

/* fscrypt slot wrapping
 *
 * Two on-disk formats are supported. New slots are always written in v2, which improves offline security.
 *
 *   v1 (legacy, read-only):
 *      <salt_b64>:<ciphertext_b64>
 *      KDF: PBKDF2-HMAC-SHA512, 0xFFFF iterations
 *      Cipher: AES-256-CTR, all-zero IV (relies on per-slot random salt for key uniqueness)
 *      Integrity: 64-bit truncated double-SHA512 key descriptor comparison only
 *
 *   v2:
 *      v2:<iterations_dec>:<salt_b64>:<iv_b64>:<ciphertext_b64>:<tag_b64>
 *      KDF: PBKDF2-HMAC-SHA512, FSCRYPT_SLOT_PBKDF2_ITERATIONS iterations (cost stored per slot)
 *      Cipher: AES-256-GCM with explicit random 96-bit IV and 128-bit authentication tag
 */

#define FSCRYPT_SLOT_PBKDF2_ITERATIONS 600000u
#define FSCRYPT_SLOT_SALT_SIZE 64u
#define FSCRYPT_SLOT_GCM_IV_SIZE 12u
#define FSCRYPT_SLOT_GCM_TAG_SIZE 16u

static int fscrypt_slot_try_v1(
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

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

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

        if (sym_PKCS5_PBKDF2_HMAC(
                            password, strlen(password),
                            salt, salt_size,
                            0xFFFF, sym_EVP_sha512(),
                            sizeof(derived), derived) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "PBKDF2 failed.");

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return log_oom();

        /* We use AES256 in counter mode */
        assert_se(cc = sym_EVP_aes_256_ctr());

        /* We only use the first half of the derived key */
        assert(sizeof(derived) >= (size_t) sym_EVP_CIPHER_get_key_length(cc));

        if (sym_EVP_DecryptInit_ex(context, cc, NULL, derived, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize decryption context.");

        decrypted_size = encrypted_size + sym_EVP_CIPHER_get_key_length(cc) * 2;
        decrypted = malloc(decrypted_size);
        if (!decrypted)
                return log_oom();

        if (sym_EVP_DecryptUpdate(context, (uint8_t*) decrypted, &decrypted_size_out1, encrypted, encrypted_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decrypt volume key.");

        assert((size_t) decrypted_size_out1 <= decrypted_size);

        if (sym_EVP_DecryptFinal_ex(context, (uint8_t*) decrypted + decrypted_size_out1, &decrypted_size_out2) != 1)
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

static int fscrypt_slot_try_v2(
                const char *password,
                uint32_t iterations,
                const void *salt, size_t salt_size,
                const void *iv, size_t iv_size,
                const void *encrypted, size_t encrypted_size,
                const void *tag, size_t tag_size,
                const uint8_t match_key_descriptor[static FS_KEY_DESCRIPTOR_SIZE],
                void **ret_decrypted, size_t *ret_decrypted_size) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(erase_and_freep) void *decrypted = NULL;
        uint8_t key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
        int decrypted_size_out1 = 0, decrypted_size_out2 = 0;
        uint8_t derived[512 / 8] = {};
        size_t decrypted_size;
        const EVP_CIPHER *cc;
        int r;

        assert(password);
        assert(iterations > 0);
        assert(salt && salt_size > 0);
        assert(iv && iv_size > 0);
        assert(encrypted && encrypted_size > 0);
        assert(tag && tag_size > 0);
        assert(match_key_descriptor);

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        CLEANUP_ERASE(derived);

        if (sym_PKCS5_PBKDF2_HMAC(
                            password, strlen(password),
                            salt, salt_size,
                            (int) iterations, sym_EVP_sha512(),
                            sizeof(derived), derived) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "PBKDF2 failed.");

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return log_oom();

        assert_se(cc = sym_EVP_aes_256_gcm());

        /* We only use the first 256 bit of the derived key */
        assert(sizeof(derived) >= (size_t) sym_EVP_CIPHER_get_key_length(cc));

        if (sym_EVP_DecryptInit_ex(context, cc, NULL, NULL, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize decryption context.");

        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int) iv_size, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set GCM IV length.");

        if (sym_EVP_DecryptInit_ex(context, NULL, NULL, derived, iv) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set decryption key/IV.");

        decrypted_size = encrypted_size + sym_EVP_CIPHER_get_block_size(cc);
        decrypted = malloc(decrypted_size);
        if (!decrypted)
                return log_oom();

        if (sym_EVP_DecryptUpdate(context, (uint8_t*) decrypted, &decrypted_size_out1, encrypted, encrypted_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decrypt volume key.");

        assert((size_t) decrypted_size_out1 <= decrypted_size);

        /* Set the expected GCM tag before finalisation, as an authentication failure here means the wrong
         * password (or a tampered slot). */
        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, (int) tag_size, (void*) tag) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set GCM tag.");

        if (sym_EVP_DecryptFinal_ex(context, (uint8_t*) decrypted + decrypted_size_out1, &decrypted_size_out2) != 1)
                return -ENOANO; /* GCM authentication failed: wrong password or tampered slot */

        assert((size_t) decrypted_size_out1 + (size_t) decrypted_size_out2 <= decrypted_size);
        decrypted_size = (size_t) decrypted_size_out1 + (size_t) decrypted_size_out2;

        calculate_key_descriptor(decrypted, decrypted_size, key_descriptor);

        if (memcmp(key_descriptor, match_key_descriptor, FS_KEY_DESCRIPTOR_SIZE) != 0)
                /* Authenticated decryption succeeded but the resulting volume key does not match the policy
                 * descriptor. Treat as a non-match (e.g. leftover slot from a different fscrypt setup). */
                return -ENOANO;

        r = fscrypt_upload_volume_key(key_descriptor, decrypted, decrypted_size, KEY_SPEC_THREAD_KEYRING);
        if (r < 0)
                return r;

        if (ret_decrypted)
                *ret_decrypted = TAKE_PTR(decrypted);
        if (ret_decrypted_size)
                *ret_decrypted_size = decrypted_size;

        return 0;
}

static int fscrypt_slot_try_one(
                const char *password,
                const char *xattr_value, size_t xattr_size,
                const uint8_t match_key_descriptor[static FS_KEY_DESCRIPTOR_SIZE],
                void **ret_decrypted, size_t *ret_decrypted_size) {

        _cleanup_free_ void *salt = NULL, *iv = NULL, *encrypted = NULL, *tag = NULL;
        size_t salt_size, iv_size, encrypted_size, tag_size;
        const char *p, *e;
        int r;

        assert(password);
        assert(xattr_value);
        assert(xattr_size > 0);
        assert(match_key_descriptor);

        /* Legacy v1 format: "<salt_b64>:<ciphertext_b64>" */
        if (xattr_size <= 3 || memcmp(xattr_value, "v2:", 3) != 0) {
                e = memchr(xattr_value, ':', xattr_size);
                if (!e)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Malformed legacy fscrypt slot (no separator).");

                r = unbase64mem_full(xattr_value, e - xattr_value, /* secure= */ false, &salt, &salt_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode legacy salt: %m");

                r = unbase64mem_full(e + 1, xattr_size - (e - xattr_value) - 1, /* secure= */ false, &encrypted, &encrypted_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode legacy ciphertext: %m");

                return fscrypt_slot_try_v1(password,
                                           salt, salt_size,
                                           encrypted, encrypted_size,
                                           match_key_descriptor,
                                           ret_decrypted, ret_decrypted_size);
        }

        /* v2 format: "v2:<iterations>:<salt_b64>:<iv_b64>:<ct_b64>:<tag_b64>" */
        _cleanup_free_ char *iter_str = NULL, *salt_b64 = NULL, *iv_b64 = NULL,
                            *encrypted_b64 = NULL, *tag_b64 = NULL;
        uint32_t iterations;

        p = xattr_value + 3;
        r = extract_many_words(&p, ":", EXTRACT_DONT_COALESCE_SEPARATORS,
                               &iter_str, &salt_b64, &iv_b64, &encrypted_b64, &tag_b64);
        if (r < 0)
                return log_error_errno(r, "Failed to parse v2 fscrypt slot: %m");
        if (r < 5)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Malformed v2 fscrypt slot.");

        if (safe_atou32(iter_str, &iterations) < 0 || iterations == 0 || iterations > INT_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid iteration count in v2 fscrypt slot.");

        r = unbase64mem(salt_b64, &salt, &salt_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode v2 salt: %m");

        r = unbase64mem(iv_b64, &iv, &iv_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode v2 IV: %m");
        if (iv_size != FSCRYPT_SLOT_GCM_IV_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid v2 IV size.");

        r = unbase64mem(encrypted_b64, &encrypted, &encrypted_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode v2 ciphertext: %m");

        r = unbase64mem(tag_b64, &tag, &tag_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode v2 tag: %m");
        if (tag_size != FSCRYPT_SLOT_GCM_TAG_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid v2 tag size.");

        return fscrypt_slot_try_v2(password,
                                   iterations,
                                   salt, salt_size,
                                   iv, iv_size,
                                   encrypted, encrypted_size,
                                   tag, tag_size,
                                   match_key_descriptor,
                                   ret_decrypted, ret_decrypted_size);
}

static int fscrypt_slot_try_many(
                char **passwords,
                const char *xattr_value, size_t xattr_size,
                const uint8_t match_key_descriptor[static FS_KEY_DESCRIPTOR_SIZE],
                void **ret_decrypted, size_t *ret_decrypted_size) {

        int r;

        STRV_FOREACH(i, passwords) {
                r = fscrypt_slot_try_one(*i, xattr_value, xattr_size, match_key_descriptor, ret_decrypted, ret_decrypted_size);
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
                return log_error_errno(r, "Failed to retrieve xattr list: %m");

        NULSTR_FOREACH(xa, xattr_buf) {
                _cleanup_free_ char *value = NULL;
                size_t vsize;
                const char *nr;

                /* Check if this xattr has the format 'trusted.fscrypt_slot<nr>' where '<nr>' is a 32-bit unsigned integer */
                nr = startswith(xa, "trusted.fscrypt_slot");
                if (!nr)
                        continue;
                if (safe_atou32(nr, NULL) < 0)
                        continue;

                r = fgetxattr_malloc(setup->root_fd, xa, &value, &vsize);
                if (r == -ENODATA) /* deleted by now? */
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s xattr: %m", xa);
                if (vsize == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "xattr %s is empty.", xa);

                r = -ENOANO;
                char **list;
                FOREACH_ARGUMENT(list, cache->pkcs11_passwords, cache->fido2_passwords, password) {
                        r = fscrypt_slot_try_many(
                                        list,
                                        value, vsize,
                                        setup->fscrypt_key_descriptor,
                                        ret_volume_key, ret_volume_key_size);
                        if (r >= 0)
                                return 0;
                        if (r != -ENOANO)
                                return r;
                }
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
                r = pidref_safe_fork(
                                "(sd-addkey)",
                                FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_REOPEN_LOG,
                                /* ret= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to install encryption key in user's keyring: %m");
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

        _cleanup_free_ char *salt_base64 = NULL, *iv_base64 = NULL,
                            *encrypted_base64 = NULL, *tag_base64 = NULL,
                            *joined = NULL;
        char label[STRLEN("trusted.fscrypt_slot") + DECIMAL_STR_MAX(nr) + 1];
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        int r, encrypted_size_out1 = 0, encrypted_size_out2 = 0;
        uint8_t salt[FSCRYPT_SLOT_SALT_SIZE];
        uint8_t iv[FSCRYPT_SLOT_GCM_IV_SIZE];
        uint8_t tag[FSCRYPT_SLOT_GCM_TAG_SIZE];
        uint8_t derived[512 / 8] = {};
        _cleanup_free_ void *encrypted = NULL;
        const EVP_CIPHER *cc;
        size_t encrypted_size;
        ssize_t ss;

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        r = crypto_random_bytes(salt, sizeof(salt));
        if (r < 0)
                return log_error_errno(r, "Failed to generate salt: %m");

        r = crypto_random_bytes(iv, sizeof(iv));
        if (r < 0)
                return log_error_errno(r, "Failed to generate IV: %m");

        CLEANUP_ERASE(derived);

        if (sym_PKCS5_PBKDF2_HMAC(
                            password, strlen(password),
                            salt, sizeof(salt),
                            (int) FSCRYPT_SLOT_PBKDF2_ITERATIONS, sym_EVP_sha512(),
                            sizeof(derived), derived) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "PBKDF2 failed");

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return log_oom();

        /* AES-256-GCM: authenticated encryption with explicit random IV */
        assert_se(cc = sym_EVP_aes_256_gcm());

        /* We only use the first 256 bit of the derived key */
        assert(sizeof(derived) >= (size_t) sym_EVP_CIPHER_get_key_length(cc));

        if (sym_EVP_EncryptInit_ex(context, cc, NULL, NULL, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize encryption context.");

        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int) sizeof(iv), NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set GCM IV length.");

        if (sym_EVP_EncryptInit_ex(context, NULL, NULL, derived, iv) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set encryption key/IV.");

        encrypted_size = volume_key_size + sym_EVP_CIPHER_get_block_size(cc);
        encrypted = malloc(encrypted_size);
        if (!encrypted)
                return log_oom();

        if (sym_EVP_EncryptUpdate(context, (uint8_t*) encrypted, &encrypted_size_out1, volume_key, volume_key_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to encrypt volume key.");

        assert((size_t) encrypted_size_out1 <= encrypted_size);

        if (sym_EVP_EncryptFinal_ex(context, (uint8_t*) encrypted + encrypted_size_out1, &encrypted_size_out2) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finish encryption of volume key.");

        assert((size_t) encrypted_size_out1 + (size_t) encrypted_size_out2 <= encrypted_size);
        encrypted_size = (size_t) encrypted_size_out1 + (size_t) encrypted_size_out2;

        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, (int) sizeof(tag), tag) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to retrieve GCM tag.");

        ss = base64mem(salt, sizeof(salt), &salt_base64);
        if (ss < 0)
                return log_oom();

        ss = base64mem(iv, sizeof(iv), &iv_base64);
        if (ss < 0)
                return log_oom();

        ss = base64mem(encrypted, encrypted_size, &encrypted_base64);
        if (ss < 0)
                return log_oom();

        ss = base64mem(tag, sizeof(tag), &tag_base64);
        if (ss < 0)
                return log_oom();

        if (asprintf(&joined, "v2:%u:%s:%s:%s:%s",
                     FSCRYPT_SLOT_PBKDF2_ITERATIONS,
                     salt_base64, iv_base64, encrypted_base64, tag_base64) < 0)
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

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

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

        (void) home_update_quota_classic(h, setup->root_fd, temporary);

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
                return log_error_errno(r, "Failed to retrieve xattr list: %m");

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
