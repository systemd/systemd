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
#include "iovec-util.h"
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

/* fscrypt policy versions
 *
 * v1 is the legacy policy. The kernel binds keys via the calling process's keyring, which means access is
 * effectively per-process: files opened in containers, bind-mounted into other namespaces, or read by users
 * other than the one that unlocked the home will fail with ENOKEY until they are first read from a context
 * that has the key (issue #18280).
 *
 * v2 (Linux 5.4+) routes keys through the filesystem keyring instead, via FS_IOC_ADD_ENCRYPTION_KEY /
 * FS_IOC_REMOVE_ENCRYPTION_KEY ioctls. Once added, the key is visible to every process accessing the
 * filesystem, which fixes the bind-mount / container case. New homes default to v2; existing v1 homes
 * keep working but stay on v1 (see home_setup_fscrypt for the on-disk format and unlock details). */

static void compute_fscrypt_key_descriptor_v1(
                const struct iovec *key,
                uint8_t ret_descriptor[static FSCRYPT_KEY_DESCRIPTOR_SIZE]) {

        uint8_t hashed[512 / 8] = {}, hashed2[512 / 8] = {};

        assert(iovec_is_set(key));
        assert(ret_descriptor);

        CLEANUP_ERASE(hashed);
        CLEANUP_ERASE(hashed2);

        /* v1 descriptor: first 8 bytes of SHA-512(SHA-512(key)). Matches the e4crypt-style derivation. */

        assert_se(sym_SHA512(key->iov_base, key->iov_len, hashed) == hashed);
        assert_se(sym_SHA512(hashed, sizeof(hashed), hashed2) == hashed2);

        assert_cc(sizeof(hashed2) >= FSCRYPT_KEY_DESCRIPTOR_SIZE);

        memcpy(ret_descriptor, hashed2, FSCRYPT_KEY_DESCRIPTOR_SIZE);
}

int compute_fscrypt_key_identifier_v2(
                const struct iovec *key,
                uint8_t ret_identifier[static FSCRYPT_KEY_IDENTIFIER_SIZE]) {

        /* HKDF-SHA512 with empty salt and info string "fscrypt\0\x01" (\x01 ==
         * HKDF_CONTEXT_KEY_IDENTIFIER). Mirrors the kernel computation in fs/crypto/hkdf.c. */

        static const uint8_t fscrypt_hkdf_info[] = {
                'f', 's', 'c', 'r', 'y', 'p', 't', 0x00,
                0x01,   /* HKDF_CONTEXT_KEY_IDENTIFIER */
        };
        _cleanup_(iovec_done_erase) struct iovec derived = {};
        int r;

        assert(iovec_is_set(key));
        assert(ret_identifier);

        r = kdf_hkdf_derive(
                        "SHA512",
                        key,
                        /* salt= */ NULL,
                        &IOVEC_MAKE((void*) fscrypt_hkdf_info, sizeof(fscrypt_hkdf_info)),
                        FSCRYPT_KEY_IDENTIFIER_SIZE,
                        &derived);
        if (r < 0)
                return log_error_errno(r, "Failed to derive fscrypt v2 key identifier: %m");

        assert(derived.iov_len == FSCRYPT_KEY_IDENTIFIER_SIZE);
        memcpy(ret_identifier, derived.iov_base, FSCRYPT_KEY_IDENTIFIER_SIZE);
        return 0;
}

/* Returns >0 if 'key' is the master key matching 'spec', 0 if not, <0 on error. */
static int fscrypt_key_spec_matches(
                const struct fscrypt_key_specifier *spec,
                const struct iovec *key) {

        int r;

        assert(spec);
        assert(iovec_is_set(key));

        switch (spec->type) {

        case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR: {
                uint8_t descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];

                compute_fscrypt_key_descriptor_v1(key, descriptor);
                return memcmp(descriptor, spec->u.descriptor, FSCRYPT_KEY_DESCRIPTOR_SIZE) == 0;
        }

        case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER: {
                uint8_t identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];

                r = compute_fscrypt_key_identifier_v2(key, identifier);
                if (r < 0)
                        return r;

                return memcmp(identifier, spec->u.identifier, FSCRYPT_KEY_IDENTIFIER_SIZE) == 0;
        }

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unexpected fscrypt key specifier type %u.", spec->type);
        }
}

static int fscrypt_v1_keyring_add(
                const uint8_t descriptor[static FSCRYPT_KEY_DESCRIPTOR_SIZE],
                const struct iovec *volume_key,
                key_serial_t where,
                key_serial_t *ret_serial) {

        _cleanup_free_ char *hex = NULL;
        const char *description;
        struct fscrypt_key key;
        key_serial_t serial;

        assert(descriptor);
        assert(iovec_is_set(volume_key));

        if (volume_key->iov_len > sizeof(key.raw))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume key too long.");

        hex = hexmem(descriptor, FSCRYPT_KEY_DESCRIPTOR_SIZE);
        if (!hex)
                return log_oom();

        description = strjoina(FSCRYPT_KEY_DESC_PREFIX, hex);

        key = (struct fscrypt_key) {
                .size = volume_key->iov_len,
        };
        memcpy(key.raw, volume_key->iov_base, volume_key->iov_len);

        CLEANUP_ERASE(key);

        serial = add_key("logon", description, &key, sizeof(key), where);
        if (serial < 0)
                return log_error_errno(errno, "Failed to install master key in keyring: %m");

        log_debug("Uploaded fscrypt v1 master key to keyring %" PRIi32 ".", (int32_t) where);
        if (ret_serial)
                *ret_serial = serial;
        return 0;
}

static int fscrypt_v2_ioctl_remove(int dir_fd, const uint8_t identifier[static FSCRYPT_KEY_IDENTIFIER_SIZE]);

/* If 'expected_identifier' is non-NULL, the kernel-computed identifier is compared against it and the call
 * fails (with the key removed again) when they disagree. */
static int fscrypt_v2_ioctl_add(
                int dir_fd,
                const uint8_t *expected_identifier,
                const struct iovec *volume_key) {

        _cleanup_free_ struct fscrypt_add_key_arg *arg = NULL;
        size_t arg_size;

        assert(dir_fd >= 0);
        assert(iovec_is_set(volume_key));

        if (volume_key->iov_len > FSCRYPT_MAX_KEY_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume key too long.");

        arg_size = sizeof(*arg) + volume_key->iov_len;
        arg = malloc0(arg_size);
        if (!arg)
                return log_oom();

        CLEANUP_ERASE_PTR(&arg, arg_size);

        arg->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
        arg->raw_size = volume_key->iov_len;
        memcpy(arg->raw, volume_key->iov_base, volume_key->iov_len);

        if (ioctl(dir_fd, FS_IOC_ADD_ENCRYPTION_KEY, arg) < 0)
                return log_debug_errno(errno, "FS_IOC_ADD_ENCRYPTION_KEY failed: %m");

        if (expected_identifier &&
            memcmp(arg->key_spec.u.identifier, expected_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE) != 0) {
                /* Roll back the unrelated key we just installed. The caller decides whether this gets
                 * surfaced at error level. */
                (void) fscrypt_v2_ioctl_remove(dir_fd, arg->key_spec.u.identifier);
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Kernel-computed fscrypt v2 identifier did not match policy.");
        }

        log_debug("Added fscrypt v2 master key to filesystem keyring.");
        return 0;
}

static int fscrypt_v2_ioctl_remove(
                int dir_fd,
                const uint8_t identifier[static FSCRYPT_KEY_IDENTIFIER_SIZE]) {

        struct fscrypt_remove_key_arg arg = {
                .key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER,
        };

        assert(dir_fd >= 0);
        assert(identifier);

        memcpy(arg.key_spec.u.identifier, identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);

        if (ioctl(dir_fd, FS_IOC_REMOVE_ENCRYPTION_KEY, &arg) < 0) {
                if (errno == ENOKEY) /* already gone */
                        return 0;
                return log_error_errno(errno, "FS_IOC_REMOVE_ENCRYPTION_KEY failed: %m");
        }

        if (arg.removal_status_flags & FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY)
                log_debug("fscrypt v2 master key removal reported files still in use; "
                          "encrypted contents will be inaccessible once the last reference goes away.");
        if (arg.removal_status_flags & FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS)
                log_debug("fscrypt v2 master key is still claimed by other users.");

        return 0;
}

static int fscrypt_v1_keyring_unlink_all(UserRecord *h) {
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

        /* Find any key with a description starting with FSCRYPT_KEY_DESC_PREFIX and unlink it. We need to
         * iterate as we store the key with a description that uses the hash of the secret key, that we do
         * not have when we are deactivating. */
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

                if (!startswith(d + 1, FSCRYPT_KEY_DESC_PREFIX))
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

/* Reads the fscrypt policy on dir_fd into ret_spec, returning the policy version (1 or 2) or:
 *   -ENODATA: the directory is not encrypted
 *   -ENOLINK: the filesystem does not support fscrypt
 * Both of these are returned silently (so callers can probe), every other failure is logged. */
static int fscrypt_policy_get(int dir_fd, struct fscrypt_key_specifier *ret_spec) {
        struct fscrypt_get_policy_ex_arg ex = {
                .policy_size = sizeof(ex.policy),
        };

        assert(dir_fd >= 0);
        assert(ret_spec);

        if (ioctl(dir_fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &ex) >= 0) {
                if (ex.policy.version == FSCRYPT_POLICY_V1) {
                        *ret_spec = (struct fscrypt_key_specifier) {
                                .type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR,
                        };
                        memcpy(ret_spec->u.descriptor, ex.policy.v1.master_key_descriptor,
                               FSCRYPT_KEY_DESCRIPTOR_SIZE);
                        return FSCRYPT_POLICY_V1;
                }
                if (ex.policy.version == FSCRYPT_POLICY_V2) {
                        *ret_spec = (struct fscrypt_key_specifier) {
                                .type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER,
                        };
                        memcpy(ret_spec->u.identifier, ex.policy.v2.master_key_identifier,
                               FSCRYPT_KEY_IDENTIFIER_SIZE);
                        return FSCRYPT_POLICY_V2;
                }

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unsupported fscrypt policy version %u.", ex.policy.version);
        }
        /* Both ENODATA and the "fscrypt unsupported" errno return silently; see the function header. */
        if (errno == ENODATA)
                return -ENODATA;
        if (ERRNO_IS_NOT_SUPPORTED(errno))
                return -ENOLINK;
        if (errno != ENOTTY)
                return log_error_errno(errno, "FS_IOC_GET_ENCRYPTION_POLICY_EX failed: %m");

        /* Kernel too old to support the _EX ioctl. Fall back to the legacy variant, which only knows v1. */
        struct fscrypt_policy_v1 v1 = {};
        if (ioctl(dir_fd, FS_IOC_GET_ENCRYPTION_POLICY, &v1) < 0) {
                /* Same silent-return contract as above. */
                if (errno == ENODATA)
                        return -ENODATA;
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return -ENOLINK;
                return log_error_errno(errno, "FS_IOC_GET_ENCRYPTION_POLICY failed: %m");
        }

        *ret_spec = (struct fscrypt_key_specifier) {
                .type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR,
        };
        memcpy(ret_spec->u.descriptor, v1.master_key_descriptor, FSCRYPT_KEY_DESCRIPTOR_SIZE);
        return FSCRYPT_POLICY_V1;
}

int home_flush_keyring_fscrypt(UserRecord *h) {
        struct fscrypt_key_specifier spec = {};
        const char *ip;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);

        if (!uid_is_valid(h->uid))
                return 0;

        assert_se(ip = user_record_image_path(h));

        _cleanup_close_ int dir_fd = open(ip, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (dir_fd < 0) {
                log_debug_errno(errno,
                                "Failed to open home directory %s to flush keyring, skipping: %m", ip);
                return 0;
        }

        r = fscrypt_policy_get(dir_fd, &spec);
        if (r == FSCRYPT_POLICY_V2)
                return fscrypt_v2_ioctl_remove(dir_fd, spec.u.identifier);

        /* Fall through for v1 policies and for ENODATA/ENOLINK (which can only happen for v1-era
         * setups): the v1 keyring walk is a safe no-op when nothing matches. */
        if (r < 0 && !IN_SET(r, -ENODATA, -ENOLINK))
                return r;

        r = pidref_safe_fork(
                        "(sd-delkey)",
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_REOPEN_LOG,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                if (fscrypt_v1_keyring_unlink_all(h) < 0)
                        _exit(EXIT_FAILURE);
                _exit(EXIT_SUCCESS);
        }

        return 0;
}

/* fscrypt key-slot on-disk wrapping
 *
 * Two on-disk slot formats are supported. These are independent of the kernel fscrypt policy version: the
 * slot is just a password-encrypted blob holding the master key. New slots are always written in v2, which
 * improves offline security.
 *
 *   v1 (legacy, read-only):
 *      <salt_b64>:<ciphertext_b64>
 *      KDF: PBKDF2-HMAC-SHA512, 0xFFFF iterations
 *      Cipher: AES-256-CTR, all-zero IV (relies on per-slot random salt for key uniqueness)
 *      Integrity: 64-bit truncated double-SHA512 key descriptor comparison only
 *
 *   v2:
 *      $v2:<iterations_dec>:<salt_b64>:<iv_b64>:<ciphertext_b64>:<tag_b64>
 *      KDF: PBKDF2-HMAC-SHA512, FSCRYPT_SLOT_PBKDF2_ITERATIONS iterations (cost stored per slot)
 *      Cipher: AES-256-GCM with explicit random 96-bit IV and 128-bit authentication tag
 */

#define FSCRYPT_SLOT_PBKDF2_ITERATIONS UINT32_C(600000)
#define FSCRYPT_SLOT_SALT_SIZE 64u
#define FSCRYPT_SLOT_GCM_IV_SIZE 12u
#define FSCRYPT_SLOT_GCM_TAG_SIZE 16u

static int fscrypt_slot_try_v1(
                const char *password,
                const void *salt, size_t salt_size,
                const void *encrypted, size_t encrypted_size,
                const struct fscrypt_key_specifier *match,
                struct iovec *ret_decrypted) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(erase_and_freep) void *decrypted = NULL;
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
        assert(match);

        r = DLOPEN_LIBCRYPTO(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED);
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

        r = fscrypt_key_spec_matches(match, &IOVEC_MAKE(decrypted, decrypted_size));
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOANO; /* don't log here */

        if (ret_decrypted) {
                ret_decrypted->iov_base = TAKE_PTR(decrypted);
                ret_decrypted->iov_len = decrypted_size;
        }

        return 0;
}

static int fscrypt_slot_try_v2(
                const char *password,
                uint32_t iterations,
                const struct iovec *salt,
                const struct iovec *iv,
                const struct iovec *encrypted,
                const struct iovec *tag,
                const struct fscrypt_key_specifier *match,
                struct iovec *ret_decrypted) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(erase_and_freep) void *decrypted = NULL;
        int decrypted_size_out1 = 0, decrypted_size_out2 = 0;
        uint8_t derived[512 / 8] = {};
        size_t decrypted_size;
        const EVP_CIPHER *cc;
        int r;

        assert(password);
        assert(iterations > 0);
        assert(iovec_is_set(salt));
        assert(iovec_is_set(iv));
        assert(iovec_is_set(encrypted));
        assert(iovec_is_set(tag));
        assert(match);

        r = DLOPEN_LIBCRYPTO(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED);
        if (r < 0)
                return r;

        CLEANUP_ERASE(derived);

        if (sym_PKCS5_PBKDF2_HMAC(
                            password, strlen(password),
                            salt->iov_base, salt->iov_len,
                            (int) iterations, sym_EVP_sha512(),
                            sizeof(derived), derived) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "PBKDF2 failed.");

        context = sym_EVP_CIPHER_CTX_new();
        if (!context)
                return log_oom();

        assert_se(cc = sym_EVP_aes_256_gcm());

        /* We only use the first 256 bit of the derived key */
        assert(sizeof(derived) >= (size_t) sym_EVP_CIPHER_get_key_length(cc));

        if (sym_EVP_DecryptInit_ex(context, cc, /* impl= */ NULL, /* key= */ NULL, /* iv= */ NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize decryption context.");

        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int) iv->iov_len, /* ptr= */ NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set GCM IV length.");

        if (sym_EVP_DecryptInit_ex(context, /* type= */ NULL, /* impl= */ NULL, derived, iv->iov_base) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set decryption key/IV.");

        if (__builtin_add_overflow(encrypted->iov_len, (size_t) sym_EVP_CIPHER_get_block_size(cc), &decrypted_size))
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Decrypted buffer size would overflow.");

        decrypted = malloc(decrypted_size);
        if (!decrypted)
                return log_oom();

        if (sym_EVP_DecryptUpdate(context, (uint8_t*) decrypted, &decrypted_size_out1, encrypted->iov_base, encrypted->iov_len) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decrypt volume key.");

        assert((size_t) decrypted_size_out1 <= decrypted_size);

        /* Set the expected GCM tag before finalisation, as an authentication failure here means the wrong
         * password (or a tampered slot). */
        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, (int) tag->iov_len, tag->iov_base) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set GCM tag.");

        if (sym_EVP_DecryptFinal_ex(context, (uint8_t*) decrypted + decrypted_size_out1, &decrypted_size_out2) != 1)
                return -ENOANO; /* GCM authentication failed: wrong password or tampered slot */

        assert((size_t) decrypted_size_out1 + (size_t) decrypted_size_out2 <= decrypted_size);
        decrypted_size = (size_t) decrypted_size_out1 + (size_t) decrypted_size_out2;

        r = fscrypt_key_spec_matches(match, &IOVEC_MAKE(decrypted, decrypted_size));
        if (r < 0)
                return r;
        if (r == 0)
                /* Authenticated decryption succeeded but the resulting volume key does not match the policy
                 * descriptor/identifier. Treat as a non-match (e.g. leftover slot from a different fscrypt
                 * setup). */
                return -ENOANO;

        if (ret_decrypted) {
                ret_decrypted->iov_base = TAKE_PTR(decrypted);
                ret_decrypted->iov_len = decrypted_size;
        }

        return 0;
}

static int fscrypt_slot_try_one(
                const char *password,
                const char *xattr_value, size_t xattr_size,
                const struct fscrypt_key_specifier *match,
                struct iovec *ret_decrypted) {

        _cleanup_free_ void *salt = NULL, *iv = NULL, *encrypted = NULL, *tag = NULL;
        size_t salt_size, iv_size, encrypted_size, tag_size;
        const char *p, *e;
        const void *body;
        int r;

        assert(password);
        assert(xattr_value);
        assert(xattr_size > 0);
        assert(match);

        body = memory_startswith(xattr_value, xattr_size, "$v2:");
        if (!body) {
                /* Legacy v1 format: "<salt_b64>:<ciphertext_b64>" */
                log_debug("fscrypt slot uses legacy v1 format, will upgrade to v2 on next password change.");

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
                                           match,
                                           ret_decrypted);
        }

        /* v2 format: "$v2:<iterations>:<salt_b64>:<iv_b64>:<ct_b64>:<tag_b64>". Reject if it has NULs. */
        _cleanup_free_ char *body_str = NULL;
        r = make_cstring(body, xattr_size - STRLEN("$v2:"), MAKE_CSTRING_REFUSE_TRAILING_NUL, &body_str);
        if (r < 0)
                return log_error_errno(r, "Malformed v2 fscrypt slot: %m");

        _cleanup_free_ char *iter_str = NULL, *salt_b64 = NULL, *iv_b64 = NULL,
                            *encrypted_b64 = NULL, *tag_b64 = NULL;
        uint32_t iterations;

        p = body_str;
        r = extract_many_words(&p, ":", EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_RETAIN_ESCAPE,
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
        if (salt_size == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid v2 salt size.");

        r = unbase64mem(iv_b64, &iv, &iv_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode v2 IV: %m");
        if (iv_size != FSCRYPT_SLOT_GCM_IV_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid v2 IV size.");

        r = unbase64mem(encrypted_b64, &encrypted, &encrypted_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode v2 ciphertext: %m");
        if (encrypted_size == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty v2 ciphertext.");

        r = unbase64mem(tag_b64, &tag, &tag_size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode v2 tag: %m");
        if (tag_size != FSCRYPT_SLOT_GCM_TAG_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid v2 tag size.");

        _cleanup_(iovec_done_erase) struct iovec decrypted = {};
        r = fscrypt_slot_try_v2(password,
                                iterations,
                                &IOVEC_MAKE(salt, salt_size),
                                &IOVEC_MAKE(iv, iv_size),
                                &IOVEC_MAKE(encrypted, encrypted_size),
                                &IOVEC_MAKE(tag, tag_size),
                                match,
                                &decrypted);
        if (r < 0)
                return r;

        if (ret_decrypted)
                *ret_decrypted = TAKE_STRUCT(decrypted);

        return 0;
}

static int fscrypt_slot_try_many(
                char **passwords,
                const char *xattr_value, size_t xattr_size,
                const struct fscrypt_key_specifier *match,
                struct iovec *ret_decrypted) {

        int r;

        STRV_FOREACH(i, passwords) {
                r = fscrypt_slot_try_one(*i, xattr_value, xattr_size, match, ret_decrypted);
                if (r != -ENOANO)
                        return r;
        }

        return -ENOANO;
}

static int fscrypt_setup(
                const PasswordCache *cache,
                char **password,
                HomeSetup *setup,
                struct iovec *ret_volume_key) {

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
                                        &setup->fscrypt_key_spec,
                                        ret_volume_key);
                        if (r >= 0)
                                return 0;
                        if (r != -ENOANO)
                                return r;
                }
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Failed to set up home directory with provided passwords.");
}

static int fscrypt_install_master_key(
                UserRecord *h,
                HomeSetup *setup,
                const struct iovec *volume_key) {

        int r;

        assert(h);
        assert(setup);
        assert(setup->root_fd >= 0);
        assert(volume_key);
        assert(iovec_is_set(volume_key));

        switch (setup->fscrypt_key_spec.type) {

        case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
                /* Thread keyring upload for the current process, plus a forked uid-drop to install into
                 * the user's session keyring so user processes can also read encrypted files. */
                r = fscrypt_v1_keyring_add(
                                setup->fscrypt_key_spec.u.descriptor,
                                volume_key,
                                KEY_SPEC_THREAD_KEYRING,
                                /* ret_serial= */ NULL);
                if (r < 0)
                        return r;

                if (uid_is_valid(h->uid)) {
                        r = pidref_safe_fork(
                                        "(sd-addkey)",
                                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_REOPEN_LOG,
                                        /* ret= */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to install encryption key in user's keyring: %m");
                        if (r == 0) {
                                r = fully_set_uid_gid(h->uid, user_record_gid(h), /* supplementary_gids= */ NULL, /* n_supplementary_gids= */ 0);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to change UID/GID to " UID_FMT "/" GID_FMT ": %m",
                                                        h->uid, user_record_gid(h));
                                        _exit(EXIT_FAILURE);
                                }

                                r = fscrypt_v1_keyring_add(
                                                setup->fscrypt_key_spec.u.descriptor,
                                                volume_key,
                                                KEY_SPEC_USER_KEYRING,
                                                /* ret_serial= */ NULL);
                                if (r < 0)
                                        _exit(EXIT_FAILURE);

                                _exit(EXIT_SUCCESS);
                        }
                }
                return 0;

        case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
                /* fscrypt_v2_ioctl_add already logs about all errors at debug level; let them propagate
                 * without an extra layer of error logging here. */
                return fscrypt_v2_ioctl_add(
                                setup->root_fd,
                                setup->fscrypt_key_spec.u.identifier,
                                volume_key);

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unexpected fscrypt key specifier type %u.",
                                       setup->fscrypt_key_spec.type);
        }
}

int home_setup_fscrypt(
                UserRecord *h,
                HomeSetup *setup,
                const PasswordCache *cache) {

        _cleanup_(iovec_done_erase) struct iovec volume_key = {};
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

        /* fscrypt has v1 and v2 policy versions with different on-disk formats, and no in-place upgrade:
         * v1 binds the master key by an 8-byte descriptor (truncated double SHA-512), v2 by a 16-byte
         * identifier (HKDF-SHA512). The version is baked into the existing policy, so we read it here and
         * unlock via the matching code path: add_key() on the thread keyring for v1, the
         * FS_IOC_ADD_ENCRYPTION_KEY ioctl for v2. A v1 home cannot be unlocked with v2 calls (and vice
         * versa), independent of kernel version. New homes default to v2 (see home_create_fscrypt). */
        r = fscrypt_policy_get(setup->root_fd, &setup->fscrypt_key_spec);
        if (r == -ENODATA)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "Home directory %s is not encrypted.", ip);
        if (r == -ENOLINK) {
                log_error_errno(r, "File system does not support fscrypt.");
                return r;
        }
        if (r < 0)
                return r;

        log_debug("Detected fscrypt policy v%i on %s.", r == FSCRYPT_POLICY_V2 ? 2 : 1, ip);

        r = fscrypt_setup(
                        cache,
                        h->password,
                        setup,
                        &volume_key);
        if (r < 0)
                return r;

        r = fscrypt_install_master_key(h, setup, &volume_key);
        if (r < 0)
                return r;

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
                const struct iovec *volume_key,
                const char *password,
                uint32_t nr) {

        _cleanup_free_ char *salt_base64 = NULL, *iv_base64 = NULL,
                            *encrypted_base64 = NULL, *tag_base64 = NULL,
                            *joined = NULL;
        char label[STRLEN("trusted.fscrypt_slot") + DECIMAL_STR_MAX(nr) + 1];
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        int r, encrypted_size_out1 = 0, encrypted_size_out2 = 0;
        uint8_t salt[FSCRYPT_SLOT_SALT_SIZE], iv[FSCRYPT_SLOT_GCM_IV_SIZE],
                tag[FSCRYPT_SLOT_GCM_TAG_SIZE], derived[512 / 8] = {};
        _cleanup_free_ void *encrypted = NULL;
        const EVP_CIPHER *cc;
        size_t encrypted_size;
        ssize_t ss;

        assert(root_fd >= 0);
        assert(iovec_is_set(volume_key));
        assert(password);

        r = DLOPEN_LIBCRYPTO(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED);
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

        if (sym_EVP_EncryptInit_ex(context, cc, /* impl= */ NULL, /* key= */ NULL, /* iv= */ NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize encryption context.");

        if (sym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int) sizeof(iv), /* ptr= */ NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set GCM IV length.");

        if (sym_EVP_EncryptInit_ex(context, /* type= */ NULL, /* impl= */ NULL, derived, iv) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set encryption key/IV.");

        if (!ADD_SAFE(&encrypted_size, volume_key->iov_len, (size_t) sym_EVP_CIPHER_get_block_size(cc)))
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "Encrypted buffer size would overflow.");

        encrypted = malloc(encrypted_size);
        if (!encrypted)
                return log_oom();

        if (sym_EVP_EncryptUpdate(context, (uint8_t*) encrypted, &encrypted_size_out1, volume_key->iov_base, volume_key->iov_len) != 1)
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

        if (asprintf(&joined, "$v2:%" PRIu32 ":%s:%s:%s:%s",
                     FSCRYPT_SLOT_PBKDF2_ITERATIONS,
                     salt_base64, iv_base64, encrypted_base64, tag_base64) < 0)
                return log_oom();

        xsprintf(label, "trusted.fscrypt_slot%" PRIu32, nr);
        if (fsetxattr(root_fd, label, joined, strlen(joined), 0) < 0)
                return log_error_errno(errno, "Failed to write xattr %s: %m", label);

        log_info("Written key slot %s.", label);

        return 0;
}

static int fscrypt_create_policy_v2(
                int dir_fd,
                const struct iovec *volume_key,
                struct fscrypt_key_specifier *ret_spec) {

        struct fscrypt_policy_v2 policy_v2 = {
                .version = FSCRYPT_POLICY_V2,
                .contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS,
                .filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS,
                .flags = FSCRYPT_POLICY_FLAGS_PAD_32,
        };
        int r;

        assert(dir_fd >= 0);
        assert(iovec_is_set(volume_key));
        assert(ret_spec);

        /* Derive the identifier locally first so we know what to remove on failure paths below, and so
         * fscrypt_v2_ioctl_add can verify the kernel agrees with us. */
        r = compute_fscrypt_key_identifier_v2(volume_key, policy_v2.master_key_identifier);
        if (r < 0)
                return r;

        r = fscrypt_v2_ioctl_add(dir_fd, policy_v2.master_key_identifier, volume_key);
        if (r < 0)
                return r;

        r = RET_NERRNO(ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy_v2));
        if (r < 0) {
                (void) fscrypt_v2_ioctl_remove(dir_fd, policy_v2.master_key_identifier);
                return r;
        }

        ret_spec->type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
        memcpy(ret_spec->u.identifier, policy_v2.master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);
        return 0;
}

static int fscrypt_create_policy_v1(
                int dir_fd,
                const struct iovec *volume_key,
                struct fscrypt_key_specifier *ret_spec) {

        struct fscrypt_policy_v1 policy_v1 = {
                .version = FSCRYPT_POLICY_V1,
                .contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS,
                .filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS,
                .flags = FSCRYPT_POLICY_FLAGS_PAD_32,
        };
        key_serial_t serial;
        int r;

        assert(dir_fd >= 0);
        assert(iovec_is_set(volume_key));
        assert(ret_spec);

        compute_fscrypt_key_descriptor_v1(volume_key, policy_v1.master_key_descriptor);

        r = fscrypt_v1_keyring_add(
                        policy_v1.master_key_descriptor,
                        volume_key,
                        KEY_SPEC_THREAD_KEYRING,
                        &serial);
        if (r < 0)
                return r;

        r = RET_NERRNO(ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy_v1));
        if (r < 0) {
                if (keyctl(KEYCTL_UNLINK, serial, KEY_SPEC_THREAD_KEYRING, 0, 0) < 0)
                        log_debug_errno(errno, "Failed to roll back fscrypt v1 master key from thread keyring, ignoring: %m");
                return r;
        }

        ret_spec->type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
        memcpy(ret_spec->u.descriptor, policy_v1.master_key_descriptor, FSCRYPT_KEY_DESCRIPTOR_SIZE);
        return 0;
}

int home_create_fscrypt(
                UserRecord *h,
                HomeSetup *setup,
                char **effective_passwords,
                UserRecord **ret_home) {

        _cleanup_(rm_rf_physical_and_freep) char *temporary = NULL;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        _cleanup_(iovec_done_erase) struct iovec volume_key = {};
        _cleanup_close_ int mount_fd = -EBADF;
        struct fscrypt_policy_v1 existing = {};
        _cleanup_free_ char *d = NULL;
        uint32_t nr = 0;
        const char *ip;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);
        assert(setup);
        assert(ret_home);

        r = DLOPEN_LIBCRYPTO(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED);
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

        /* Refuse if the parent directory is already encrypted (we'd inherit its policy). */
        if (ioctl(setup->root_fd, FS_IOC_GET_ENCRYPTION_POLICY, &existing) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        log_error_errno(errno, "File system does not support fscrypt: %m");
                        return -ENOLINK; /* make recognizable */
                }
                if (errno != ENODATA)
                        return log_error_errno(errno, "Failed to get fscrypt policy of directory: %m");
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Parent of %s already encrypted, refusing.", temporary);

        volume_key.iov_len = 512 / 8;
        volume_key.iov_base = malloc(volume_key.iov_len);
        if (!volume_key.iov_base)
                return log_oom();

        r = crypto_random_bytes(volume_key.iov_base, volume_key.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire volume key: %m");

        log_info("Generated volume key of size %zu.", volume_key.iov_len);

        /* Default to v2 (Linux 5.4+), fall back to v1 only when the kernel/fs truly does not understand
         * the FS_IOC_ADD_ENCRYPTION_KEY ioctl. Anything else (e.g. -EINVAL from SET_POLICY, which can mean
         * "directory not empty" or "conflicting flags") is a real failure and must propagate. See the
         * policy version comment at the top of the file for why we prefer v2. */
        r = fscrypt_create_policy_v2(setup->root_fd, &volume_key, &setup->fscrypt_key_spec);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_notice_errno(r, "Kernel does not support fscrypt v2 policies, falling back to v1.");
                r = fscrypt_create_policy_v1(setup->root_fd, &volume_key, &setup->fscrypt_key_spec);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to set fscrypt policy on directory: %m");

        log_info("Encryption policy set (v%d).",
                 setup->fscrypt_key_spec.type == FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER ? 2 : 1);

        STRV_FOREACH(i, effective_passwords) {
                r = fscrypt_slot_set(setup->root_fd, &volume_key, *i, nr);
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

        _cleanup_(iovec_done_erase) struct iovec volume_key = {};
        _cleanup_free_ char *xattr_buf = NULL;
        uint32_t slot = 0;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_FSCRYPT);
        assert(setup);

        r = fscrypt_setup(
                        cache,
                        h->password,
                        setup,
                        &volume_key);
        if (r < 0)
                return r;

        STRV_FOREACH(p, effective_passwords) {
                r = fscrypt_slot_set(setup->root_fd, &volume_key, *p, slot);
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
