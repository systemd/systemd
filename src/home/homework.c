/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>
#include <sys/mount.h>

#include "chown-recursive.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "home-util.h"
#include "homework-cifs.h"
#include "homework-directory.h"
#include "homework-fido2.h"
#include "homework-fscrypt.h"
#include "homework-luks.h"
#include "homework-mount.h"
#include "homework-pkcs11.h"
#include "homework.h"
#include "libcrypt-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "missing_magic.h"
#include "mount-util.h"
#include "path-util.h"
#include "recovery-key.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "virt.h"

/* Make sure a bad password always results in a 3s delay, no matter what */
#define BAD_PASSWORD_DELAY_USEC (3 * USEC_PER_SEC)

void password_cache_free(PasswordCache *cache) {
        if (!cache)
                return;

        cache->pkcs11_passwords = strv_free_erase(cache->pkcs11_passwords);
        cache->fido2_passwords = strv_free_erase(cache->fido2_passwords);
}

int user_record_authenticate(
                UserRecord *h,
                UserRecord *secret,
                PasswordCache *cache,
                bool strict_verify) {

        bool need_password = false, need_recovery_key = false, need_token = false, need_pin = false, need_protected_authentication_path_permitted = false, need_user_presence_permitted = false,
                pin_locked = false, pin_incorrect = false, pin_incorrect_few_tries_left = false, pin_incorrect_one_try_left = false, token_action_timeout = false;
        int r;

        assert(h);
        assert(secret);

        /* Tries to authenticate a user record with the supplied secrets. i.e. checks whether at least one
         * supplied plaintext passwords matches a hashed password field of the user record. Or if a
         * configured PKCS#11 or FIDO2 token is around and can unlock the record.
         *
         * Note that the 'cache' parameter is both an input and output parameter: it contains lists of
         * configured, decrypted PKCS#11/FIDO2 passwords. We typically have to call this function multiple
         * times over the course of an operation (think: on login we authenticate the host user record, the
         * record embedded in the LUKS record and the one embedded in $HOME). Hence we keep a list of
         * passwords we already decrypted, so that we don't have to do the (slow and potentially interactive)
         * PKCS#11/FIDO2 dance for the relevant token again and again. */

        /* First, let's see if the supplied plain-text passwords work? */
        r = user_record_test_password(h, secret);
        if (r == -ENOKEY)
                need_password = true;
        else if (r == -ENXIO)
                log_debug_errno(r, "User record has no hashed passwords, plaintext passwords not tested.");
        else if (r < 0)
                return log_error_errno(r, "Failed to validate password of record: %m");
        else {
                log_info("Provided password unlocks user record.");
                return 1;
        }

        /* Similar, but test against the recovery keys */
        r = user_record_test_recovery_key(h, secret);
        if (r == -ENOKEY)
                need_recovery_key = true;
        else if (r == -ENXIO)
                log_debug_errno(r, "User record has no recovery keys, plaintext passwords not tested against it.");
        else if (r < 0)
                return log_error_errno(r, "Failed to validate the recovery key of the record: %m");
        else {
                log_info("Provided password is a recovery key that unlocks the user record.");
                return 1;
        }

        if (need_password && need_recovery_key)
                log_info("None of the supplied plaintext passwords unlock the user record's hashed passwords or recovery keys.");
        else if (need_password)
                log_info("None of the supplied plaintext passwords unlock the user record's hashed passwords.");
        else
                log_info("None of the supplied plaintext passwords unlock the user record's hashed recovery keys.");

        /* Second, test cached PKCS#11 passwords */
        for (size_t n = 0; n < h->n_pkcs11_encrypted_key; n++) {
                char **pp;

                STRV_FOREACH(pp, cache->pkcs11_passwords) {
                        r = test_password_one(h->pkcs11_encrypted_key[n].hashed_password, *pp);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check supplied PKCS#11 password: %m");
                        if (r > 0) {
                                log_info("Previously acquired PKCS#11 password unlocks user record.");
                                return 1;
                        }
                }
        }

        /* Third, test cached FIDO2 passwords */
        for (size_t n = 0; n < h->n_fido2_hmac_salt; n++) {
                char **pp;

                /* See if any of the previously calculated passwords work */
                STRV_FOREACH(pp, cache->fido2_passwords) {
                        r = test_password_one(h->fido2_hmac_salt[n].hashed_password, *pp);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check supplied FIDO2 password: %m");
                        if (r > 0) {
                                log_info("Previously acquired FIDO2 password unlocks user record.");
                                return 0;
                        }
                }
        }

        /* Fourth, let's see if any of the PKCS#11 security tokens are plugged in and help us */
        for (size_t n = 0; n < h->n_pkcs11_encrypted_key; n++) {
#if HAVE_P11KIT
                _cleanup_(pkcs11_callback_data_release) struct pkcs11_callback_data data = {
                        .user_record = h,
                        .secret = secret,
                        .encrypted_key = h->pkcs11_encrypted_key + n,
                };

                r = pkcs11_find_token(data.encrypted_key->uri, pkcs11_callback, &data);
                switch (r) {
                case -EAGAIN:
                        need_token = true;
                        break;
                case -ENOANO:
                        need_pin = true;
                        break;
                case -ERFKILL:
                        need_protected_authentication_path_permitted = true;
                        break;
                case -EOWNERDEAD:
                        pin_locked = true;
                        break;
                case -ENOLCK:
                        pin_incorrect = true;
                        break;
                case -ETOOMANYREFS:
                        pin_incorrect = pin_incorrect_few_tries_left = true;
                        break;
                case -EUCLEAN:
                        pin_incorrect = pin_incorrect_few_tries_left = pin_incorrect_one_try_left = true;
                        break;
                default:
                        if (r < 0)
                                return r;

                        r = test_password_one(data.encrypted_key->hashed_password, data.decrypted_password);
                        if (r < 0)
                                return log_error_errno(r, "Failed to test PKCS#11 password: %m");
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Configured PKCS#11 security token %s does not decrypt encrypted key correctly.", data.encrypted_key->uri);

                        log_info("Decrypted password from PKCS#11 security token %s unlocks user record.", data.encrypted_key->uri);

                        r = strv_extend(&cache->pkcs11_passwords, data.decrypted_password);
                        if (r < 0)
                                return log_oom();

                        return 0;
                }
#else
                need_token = true;
                break;
#endif
        }

        /* Fifth, let's see if any of the FIDO2 security tokens are plugged in and help us */
        for (size_t n = 0; n < h->n_fido2_hmac_salt; n++) {
#if HAVE_LIBFIDO2
                _cleanup_(erase_and_freep) char *decrypted_password = NULL;

                r = fido2_use_token(h, secret, h->fido2_hmac_salt + n, &decrypted_password);
                switch (r) {
                case -EAGAIN:
                        need_token = true;
                        break;
                case -ENOANO:
                        need_pin = true;
                        break;
                case -EOWNERDEAD:
                        pin_locked = true;
                        break;
                case -ENOLCK:
                        pin_incorrect = true;
                        break;
                case -EMEDIUMTYPE:
                        need_user_presence_permitted = true;
                        break;
                case -ENOSTR:
                        token_action_timeout = true;
                        break;
                default:
                        if (r < 0)
                                return r;

                        r = test_password_one(h->fido2_hmac_salt[n].hashed_password, decrypted_password);
                        if (r < 0)
                                return log_error_errno(r, "Failed to test FIDO2 password: %m");
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Configured FIDO2 security token does not decrypt encrypted key correctly.");

                        log_info("Decrypted password from FIDO2 security token unlocks user record.");

                        r = strv_extend(&cache->fido2_passwords, decrypted_password);
                        if (r < 0)
                                return log_oom();

                        return 1;
                }
#else
                need_token = true;
                break;
#endif
        }

        /* Ordered by "relevance", i.e. the most "important" or "interesting" error condition is returned. */
        if (pin_incorrect_one_try_left)
                return -EUCLEAN;
        if (pin_incorrect_few_tries_left)
                return -ETOOMANYREFS;
        if (pin_incorrect)
                return -ENOLCK;
        if (pin_locked)
                return -EOWNERDEAD;
        if (token_action_timeout)
                return -ENOSTR;
        if (need_protected_authentication_path_permitted)
                return -ERFKILL;
        if (need_user_presence_permitted)
                return -EMEDIUMTYPE;
        if (need_pin)
                return -ENOANO;
        if (need_token)
                return -EBADSLT;
        if (need_password)
                return -ENOKEY;
        if (need_recovery_key)
                return -EREMOTEIO;

        /* Hmm, this means neither PCKS#11/FIDO2 nor classic hashed passwords or recovery keys were supplied,
         * we cannot authenticate this reasonably */
        if (strict_verify)
                return log_debug_errno(SYNTHETIC_ERRNO(EKEYREVOKED),
                                       "No hashed passwords, no recovery keys and no PKCS#11/FIDO2 tokens defined, cannot authenticate user record, refusing.");

        /* If strict verification is off this means we are possibly in the case where we encountered an
         * unfixated record, i.e. a synthetic one that accordingly lacks any authentication data. In this
         * case, allow the authentication to pass for now, so that the second (or third) authentication level
         * (the ones of the user record in the LUKS header or inside the home directory) will then catch
         * invalid passwords. The second/third authentication always runs in strict verification mode. */
        log_debug("No hashed passwords, not recovery keys and no PKCS#11 tokens defined in record, cannot authenticate user record. "
                  "Deferring to embedded user record.");
        return 0;
}

int home_setup_undo(HomeSetup *setup) {
        int r = 0, q;

        assert(setup);

        if (setup->root_fd >= 0) {
                if (setup->do_offline_fitrim) {
                        q = run_fitrim(setup->root_fd);
                        if (q < 0)
                                r = q;
                }

                setup->root_fd = safe_close(setup->root_fd);
        }

        if (setup->undo_mount) {
                q = umount_verbose(LOG_DEBUG, "/run/systemd/user-home-mount", UMOUNT_NOFOLLOW);
                if (q < 0)
                        r = q;
        }

        if (setup->undo_dm && setup->crypt_device && setup->dm_name) {
                q = crypt_deactivate(setup->crypt_device, setup->dm_name);
                if (q < 0)
                        r = q;
        }

        if (setup->image_fd >= 0) {
                if (setup->do_offline_fallocate) {
                        q = run_fallocate(setup->image_fd, NULL);
                        if (q < 0)
                                r = q;
                }

                if (setup->do_mark_clean) {
                        q = run_mark_dirty(setup->image_fd, false);
                        if (q < 0)
                                r = q;
                }

                setup->image_fd = safe_close(setup->image_fd);
        }

        setup->undo_mount = false;
        setup->undo_dm = false;
        setup->do_offline_fitrim = false;
        setup->do_offline_fallocate = false;
        setup->do_mark_clean = false;

        setup->dm_name = mfree(setup->dm_name);
        setup->dm_node = mfree(setup->dm_node);

        setup->loop = loop_device_unref(setup->loop);
        crypt_free(setup->crypt_device);
        setup->crypt_device = NULL;

        explicit_bzero_safe(setup->volume_key, setup->volume_key_size);
        setup->volume_key = mfree(setup->volume_key);
        setup->volume_key_size = 0;

        return r;
}

int home_prepare(
                UserRecord *h,
                bool already_activated,
                PasswordCache *cache,
                HomeSetup *setup,
                UserRecord **ret_header_home) {

        int r;

        assert(h);
        assert(setup);
        assert(!setup->loop);
        assert(!setup->crypt_device);
        assert(setup->root_fd < 0);
        assert(!setup->undo_dm);
        assert(!setup->undo_mount);

        /* Makes a home directory accessible (through the root_fd file descriptor, not by path!). */

        switch (user_record_storage(h)) {

        case USER_LUKS:
                return home_prepare_luks(h, already_activated, NULL, cache, setup, ret_header_home);

        case USER_SUBVOLUME:
        case USER_DIRECTORY:
                r = home_prepare_directory(h, already_activated, setup);
                break;

        case USER_FSCRYPT:
                r = home_prepare_fscrypt(h, already_activated, cache, setup);
                break;

        case USER_CIFS:
                r = home_prepare_cifs(h, already_activated, setup);
                break;

        default:
                return log_error_errno(SYNTHETIC_ERRNO(ENOLINK), "Processing home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));
        }

        if (r < 0)
                return r;

        if (ret_header_home)
                *ret_header_home = NULL;

        return r;
}

int home_sync_and_statfs(int root_fd, struct statfs *ret) {
        assert(root_fd >= 0);

        /* Let's sync this to disk, so that the disk space reported by fstatfs() below is accurate (for file
         * systems such as btrfs where this is determined lazily). */

        if (syncfs(root_fd) < 0)
                return log_error_errno(errno, "Failed to synchronize file system: %m");

        if (ret)
                if (fstatfs(root_fd, ret) < 0)
                        return log_error_errno(errno, "Failed to statfs() file system: %m");

        log_info("Synchronized disk.");

        return 0;
}

static int read_identity_file(int root_fd, JsonVariant **ret) {
        _cleanup_(fclosep) FILE *identity_file = NULL;
        _cleanup_close_ int identity_fd = -1;
        unsigned line, column;
        int r;

        assert(root_fd >= 0);
        assert(ret);

        identity_fd = openat(root_fd, ".identity", O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK);
        if (identity_fd < 0)
                return log_error_errno(errno, "Failed to open .identity file in home directory: %m");

        r = fd_verify_regular(identity_fd);
        if (r < 0)
                return log_error_errno(r, "Embedded identity file is not a regular file, refusing: %m");

        identity_file = take_fdopen(&identity_fd, "r");
        if (!identity_file)
                return log_oom();

        r = json_parse_file(identity_file, ".identity", JSON_PARSE_SENSITIVE, ret, &line, &column);
        if (r < 0)
                return log_error_errno(r, "[.identity:%u:%u] Failed to parse JSON data: %m", line, column);

        log_info("Read embedded .identity file.");

        return 0;
}

static int write_identity_file(int root_fd, JsonVariant *v, uid_t uid) {
        _cleanup_(json_variant_unrefp) JsonVariant *normalized = NULL;
        _cleanup_(fclosep) FILE *identity_file = NULL;
        _cleanup_close_ int identity_fd = -1;
        _cleanup_free_ char *fn = NULL;
        int r;

        assert(root_fd >= 0);
        assert(v);

        normalized = json_variant_ref(v);

        r = json_variant_normalize(&normalized);
        if (r < 0)
                log_warning_errno(r, "Failed to normalize user record, ignoring: %m");

        r = tempfn_random(".identity", NULL, &fn);
        if (r < 0)
                return r;

        identity_fd = openat(root_fd, fn, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
        if (identity_fd < 0)
                return log_error_errno(errno, "Failed to create .identity file in home directory: %m");

        identity_file = take_fdopen(&identity_fd, "w");
        if (!identity_file) {
                r = log_oom();
                goto fail;
        }

        json_variant_dump(normalized, JSON_FORMAT_PRETTY, identity_file, NULL);

        r = fflush_and_check(identity_file);
        if (r < 0) {
                log_error_errno(r, "Failed to write .identity file: %m");
                goto fail;
        }

        if (fchown(fileno(identity_file), uid, uid) < 0) {
                log_error_errno(r, "Failed to change ownership of identity file: %m");
                goto fail;
        }

        if (renameat(root_fd, fn, root_fd, ".identity") < 0) {
                r = log_error_errno(errno, "Failed to move identity file into place: %m");
                goto fail;
        }

        log_info("Wrote embedded .identity file.");

        return 0;

fail:
        (void) unlinkat(root_fd, fn, 0);
        return r;
}

int home_load_embedded_identity(
                UserRecord *h,
                int root_fd,
                UserRecord *header_home,
                UserReconcileMode mode,
                PasswordCache *cache,
                UserRecord **ret_embedded_home,
                UserRecord **ret_new_home) {

        _cleanup_(user_record_unrefp) UserRecord *embedded_home = NULL, *intermediate_home = NULL, *new_home = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(h);
        assert(root_fd >= 0);

        r = read_identity_file(root_fd, &v);
        if (r < 0)
                return r;

        embedded_home = user_record_new();
        if (!embedded_home)
                return log_oom();

        r = user_record_load(embedded_home, v, USER_RECORD_LOAD_EMBEDDED);
        if (r < 0)
                return r;

        if (!user_record_compatible(h, embedded_home))
                return log_error_errno(SYNTHETIC_ERRNO(EREMCHG), "Embedded home record not compatible with host record, refusing.");

        /* Insist that credentials the user supplies also unlocks any embedded records. */
        r = user_record_authenticate(embedded_home, h, cache, /* strict_verify= */ true);
        if (r < 0)
                return r;
        assert(r > 0); /* Insist that a password was verified */

        /* At this point we have three records to deal with:
         *
         *      · The record we got passed from the host
         *      · The record included in the LUKS header (only if LUKS is used)
         *      · The record in the home directory itself (~.identity)
         *
         *  Now we have to reconcile all three, and let the newest one win. */

        if (header_home) {
                /* Note we relax the requirements here. Instead of insisting that the host record is strictly
                 * newer, let's also be OK if its equally new. If it is, we'll however insist that the
                 * embedded record must be newer, so that we update at least one of the two. */

                r = user_record_reconcile(h, header_home, mode == USER_RECONCILE_REQUIRE_NEWER ? USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL : mode, &intermediate_home);
                if (r == -EREMCHG) /* this was supposed to be checked earlier already, but let's check this again */
                        return log_error_errno(r, "Identity stored on host and in header don't match, refusing.");
                if (r == -ESTALE)
                        return log_error_errno(r, "Embedded identity record is newer than supplied record, refusing.");
                if (r < 0)
                        return log_error_errno(r, "Failed to reconcile host and header identities: %m");
                if (r == USER_RECONCILE_EMBEDDED_WON)
                        log_info("Reconciling header user identity completed (header version was newer).");
                else if (r == USER_RECONCILE_HOST_WON) {
                        log_info("Reconciling header user identity completed (host version was newer).");

                        if (mode == USER_RECONCILE_REQUIRE_NEWER) /* Host version is newer than the header
                                                                   * version, hence we'll update
                                                                   * something. This means we can relax the
                                                                   * requirements on the embedded
                                                                   * identity. */
                                mode = USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL;
                } else {
                        assert(r == USER_RECONCILE_IDENTICAL);
                        log_info("Reconciling user identities completed (host and header version were identical).");
                }

                h = intermediate_home;
        }

        r = user_record_reconcile(h, embedded_home, mode, &new_home);
        if (r == -EREMCHG)
                return log_error_errno(r, "Identity stored on host and in home don't match, refusing.");
        if (r == -ESTALE)
                return log_error_errno(r, "Embedded identity record is equally new or newer than supplied record, refusing.");
        if (r < 0)
                return log_error_errno(r, "Failed to reconcile host and embedded identities: %m");
        if (r == USER_RECONCILE_EMBEDDED_WON)
                log_info("Reconciling embedded user identity completed (embedded version was newer).");
        else if (r == USER_RECONCILE_HOST_WON)
                log_info("Reconciling embedded user identity completed (host version was newer).");
        else {
                assert(r == USER_RECONCILE_IDENTICAL);
                log_info("Reconciling embedded user identity completed (host and embedded version were identical).");
        }

        if (ret_embedded_home)
                *ret_embedded_home = TAKE_PTR(embedded_home);

        if (ret_new_home)
                *ret_new_home = TAKE_PTR(new_home);

        return 0;
}

int home_store_embedded_identity(UserRecord *h, int root_fd, uid_t uid, UserRecord *old_home) {
        _cleanup_(user_record_unrefp) UserRecord *embedded = NULL;
        int r;

        assert(h);
        assert(root_fd >= 0);
        assert(uid_is_valid(uid));

        r = user_record_clone(h, USER_RECORD_EXTRACT_EMBEDDED, &embedded);
        if (r < 0)
                return log_error_errno(r, "Failed to determine new embedded record: %m");

        if (old_home && user_record_equal(old_home, embedded)) {
                log_debug("Not updating embedded home record.");
                return 0;
        }

        /* The identity has changed, let's update it in the image */
        r = write_identity_file(root_fd, embedded->json, h->uid);
        if (r < 0)
                return r;

        return 1;
}

static const char *file_system_type_fd(int fd) {
        struct statfs sfs;

        assert(fd >= 0);

        if (fstatfs(fd, &sfs) < 0) {
                log_debug_errno(errno, "Failed to statfs(): %m");
                return NULL;
        }

        if (is_fs_type(&sfs, XFS_SB_MAGIC))
                return "xfs";
        if (is_fs_type(&sfs, EXT4_SUPER_MAGIC))
                return "ext4";
        if (is_fs_type(&sfs, BTRFS_SUPER_MAGIC))
                return "btrfs";

        return NULL;
}

int home_extend_embedded_identity(UserRecord *h, UserRecord *used, HomeSetup *setup) {
        int r;

        assert(h);
        assert(used);
        assert(setup);

        r = user_record_add_binding(
                        h,
                        user_record_storage(used),
                        user_record_image_path(used),
                        setup->found_partition_uuid,
                        setup->found_luks_uuid,
                        setup->found_fs_uuid,
                        setup->crypt_device ? crypt_get_cipher(setup->crypt_device) : NULL,
                        setup->crypt_device ? crypt_get_cipher_mode(setup->crypt_device) : NULL,
                        setup->crypt_device ? luks_volume_key_size_convert(setup->crypt_device) : UINT64_MAX,
                        file_system_type_fd(setup->root_fd),
                        user_record_home_directory(used),
                        used->uid,
                        (gid_t) used->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to update binding in record: %m");

        return 0;
}

static int chown_recursive_directory(int root_fd, uid_t uid) {
        int r;

        assert(root_fd >= 0);
        assert(uid_is_valid(uid));

        r = fd_chown_recursive(root_fd, uid, (gid_t) uid, 0777);
        if (r < 0)
                return log_error_errno(r, "Failed to change ownership of files and directories: %m");
        if (r == 0)
                log_info("Recursive changing of ownership not necessary, skipped.");
        else
                log_info("Recursive changing of ownership completed.");

        return 0;
}

int home_refresh(
                UserRecord *h,
                HomeSetup *setup,
                UserRecord *header_home,
                PasswordCache *cache,
                struct statfs *ret_statfs,
                UserRecord **ret_new_home) {

        _cleanup_(user_record_unrefp) UserRecord *embedded_home = NULL, *new_home = NULL;
        int r;

        assert(h);
        assert(setup);
        assert(ret_new_home);

        /* When activating a home directory, does the identity work: loads the identity from the $HOME
         * directory, reconciles it with our idea, chown()s everything. */

        r = home_load_embedded_identity(h, setup->root_fd, header_home, USER_RECONCILE_ANY, cache, &embedded_home, &new_home);
        if (r < 0)
                return r;

        r = home_store_header_identity_luks(new_home, setup, header_home);
        if (r < 0)
                return r;

        r = home_store_embedded_identity(new_home, setup->root_fd, h->uid, embedded_home);
        if (r < 0)
                return r;

        r = chown_recursive_directory(setup->root_fd, h->uid);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup->root_fd, ret_statfs);
        if (r < 0)
                return r;

        *ret_new_home = TAKE_PTR(new_home);
        return 0;
}

static int home_activate(UserRecord *h, UserRecord **ret_home) {
        _cleanup_(password_cache_free) PasswordCache cache = {};
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        int r;

        assert(h);

        if (!h->user_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks user name, refusing.");
        if (!uid_is_valid(h->uid))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks UID, refusing.");
        if (!IN_SET(user_record_storage(h), USER_LUKS, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT, USER_CIFS))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Activating home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));

        r = user_record_authenticate(h, h, &cache, /* strict_verify= */ false);
        if (r < 0)
                return r;

        r = user_record_test_home_directory_and_warn(h);
        if (r < 0)
                return r;
        if (r == USER_TEST_MOUNTED)
                return log_error_errno(SYNTHETIC_ERRNO(EALREADY), "Home directory %s is already mounted, refusing.", user_record_home_directory(h));

        r = user_record_test_image_path_and_warn(h);
        if (r < 0)
                return r;
        if (r == USER_TEST_ABSENT)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Image path %s is missing, refusing.", user_record_image_path(h));

        switch (user_record_storage(h)) {

        case USER_LUKS:
                r = home_activate_luks(h, &cache, &new_home);
                if (r < 0)
                        return r;

                break;

        case USER_SUBVOLUME:
        case USER_DIRECTORY:
        case USER_FSCRYPT:
                r = home_activate_directory(h, &cache, &new_home);
                if (r < 0)
                        return r;

                break;

        case USER_CIFS:
                r = home_activate_cifs(h, &cache, &new_home);
                if (r < 0)
                        return r;

                break;

        default:
                assert_not_reached("unexpected type");
        }

        /* Note that the returned object might either be a reference to an updated version of the existing
         * home object, or a reference to a newly allocated home object. The caller has to be able to deal
         * with both, and consider the old object out-of-date. */
        if (user_record_equal(h, new_home)) {
                *ret_home = NULL;
                return 0; /* no identity change */
        }

        *ret_home = TAKE_PTR(new_home);
        return 1; /* identity updated */
}

static int home_deactivate(UserRecord *h, bool force) {
        bool done = false;
        int r;

        assert(h);

        if (!h->user_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record incomplete, refusing.");
        if (!IN_SET(user_record_storage(h), USER_LUKS, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT, USER_CIFS))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Deactivating home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));

        r = user_record_test_home_directory_and_warn(h);
        if (r < 0)
                return r;
        if (r == USER_TEST_MOUNTED) {
                if (user_record_storage(h) == USER_LUKS) {
                        r = home_trim_luks(h);
                        if (r < 0)
                                return r;
                }

                if (umount2(user_record_home_directory(h), UMOUNT_NOFOLLOW | (force ? MNT_FORCE|MNT_DETACH : 0)) < 0)
                        return log_error_errno(errno, "Failed to unmount %s: %m", user_record_home_directory(h));

                log_info("Unmounting completed.");
                done = true;
        } else
                log_info("Directory %s is already unmounted.", user_record_home_directory(h));

        if (user_record_storage(h) == USER_LUKS) {
                r = home_deactivate_luks(h);
                if (r < 0)
                        return r;
                if (r > 0)
                        done = true;
        }

        if (!done)
                return log_error_errno(SYNTHETIC_ERRNO(ENOEXEC), "Home is not active.");

        log_info("Everything completed.");
        return 0;
}

static int copy_skel(int root_fd, const char *skel) {
        int r;

        assert(root_fd >= 0);

        r = copy_tree_at(AT_FDCWD, skel, root_fd, ".", UID_INVALID, GID_INVALID, COPY_MERGE|COPY_REPLACE);
        if (r == -ENOENT) {
                log_info("Skeleton directory %s missing, ignoring.", skel);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to copy in %s: %m", skel);

        log_info("Copying in %s completed.", skel);
        return 0;
}

static int change_access_mode(int root_fd, mode_t m) {
        assert(root_fd >= 0);

        if (fchmod(root_fd, m) < 0)
                return log_error_errno(errno, "Failed to change access mode of top-level directory: %m");

        log_info("Changed top-level directory access mode to 0%o.", m);
        return 0;
}

int home_populate(UserRecord *h, int dir_fd) {
        int r;

        assert(h);
        assert(dir_fd >= 0);

        r = copy_skel(dir_fd, user_record_skeleton_directory(h));
        if (r < 0)
                return r;

        r = home_store_embedded_identity(h, dir_fd, h->uid, NULL);
        if (r < 0)
                return r;

        r = chown_recursive_directory(dir_fd, h->uid);
        if (r < 0)
                return r;

        r = change_access_mode(dir_fd, user_record_access_mode(h));
        if (r < 0)
                return r;

        return 0;
}

static int user_record_compile_effective_passwords(
                UserRecord *h,
                PasswordCache *cache,
                char ***ret_effective_passwords) {

        _cleanup_(strv_free_erasep) char **effective = NULL;
        size_t n;
        char **i;
        int r;

        assert(h);
        assert(cache);

        /* We insist on at least one classic hashed password to be defined in addition to any PKCS#11 one, as
         * a safe fallback, but also to simplify the password changing algorithm: there we require providing
         * the old literal password only (and do not care for the old PKCS#11 token) */

        if (strv_isempty(h->hashed_password))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "User record has no hashed passwords, refusing.");

        /* Generates the list of plaintext passwords to propagate to LUKS/fscrypt devices, and checks whether
         * we have a plaintext password for each hashed one. If we are missing one we'll fail, since we
         * couldn't sync fscrypt/LUKS to the login account properly. */

        STRV_FOREACH(i, h->hashed_password) {
                bool found = false;
                char **j;

                log_debug("Looking for plaintext password for: %s", *i);

                /* Let's scan all provided plaintext passwords */
                STRV_FOREACH(j, h->password) {
                        r = test_password_one(*i, *j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to test plaintext password: %m");
                        if (r > 0) {
                                if (ret_effective_passwords) {
                                        r = strv_extend(&effective, *j);
                                        if (r < 0)
                                                return log_oom();
                                }

                                log_debug("Found literal plaintext password.");
                                found = true;
                                break;
                        }
                }

                if (!found)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Missing plaintext password for defined hashed password");
        }

        for (n = 0; n < h->n_recovery_key; n++) {
                bool found = false;
                char **j;

                log_debug("Looking for plaintext recovery key for: %s", h->recovery_key[n].hashed_password);

                STRV_FOREACH(j, h->password) {
                        _cleanup_(erase_and_freep) char *mangled = NULL;
                        const char *p;

                        if (streq(h->recovery_key[n].type, "modhex64")) {

                                r = normalize_recovery_key(*j, &mangled);
                                if (r == -EINVAL) /* Not properly formatted, probably a regular password. */
                                        continue;
                                if (r < 0)
                                        return log_error_errno(r, "Failed to normalize recovery key: %m");

                                p = mangled;
                        } else
                                p = *j;

                        r = test_password_one(h->recovery_key[n].hashed_password, p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to test plaintext recovery key: %m");
                        if (r > 0) {
                                if (ret_effective_passwords) {
                                        r = strv_extend(&effective, p);
                                        if (r < 0)
                                                return log_oom();
                                }

                                log_debug("Found plaintext recovery key.");
                                found = true;
                                break;
                        }
                }

                if (!found)
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTEIO), "Missing plaintext recovery key for defined recovery key");
        }

        for (n = 0; n < h->n_pkcs11_encrypted_key; n++) {
#if HAVE_P11KIT
                _cleanup_(pkcs11_callback_data_release) struct pkcs11_callback_data data = {
                        .user_record = h,
                        .secret = h,
                        .encrypted_key = h->pkcs11_encrypted_key + n,
                };

                r = pkcs11_find_token(data.encrypted_key->uri, pkcs11_callback, &data);
                if (r == -EAGAIN)
                        return -EBADSLT;
                if (r < 0)
                        return r;

                r = test_password_one(data.encrypted_key->hashed_password, data.decrypted_password);
                if (r < 0)
                        return log_error_errno(r, "Failed to test PKCS#11 password: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Decrypted password from token is not correct, refusing.");

                if (ret_effective_passwords) {
                        r = strv_extend(&effective, data.decrypted_password);
                        if (r < 0)
                                return log_oom();
                }

                r = strv_extend(&cache->pkcs11_passwords, data.decrypted_password);
                if (r < 0)
                        return log_oom();
#else
                return -EBADSLT;
#endif
        }

        for (n = 0; n < h->n_fido2_hmac_salt; n++) {
#if HAVE_LIBFIDO2
                _cleanup_(erase_and_freep) char *decrypted_password = NULL;

                r = fido2_use_token(h, h, h->fido2_hmac_salt + n, &decrypted_password);
                if (r < 0)
                        return r;

                r = test_password_one(h->fido2_hmac_salt[n].hashed_password, decrypted_password);
                if (r < 0)
                        return log_error_errno(r, "Failed to test FIDO2 password: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Decrypted password from token is not correct, refusing.");

                if (ret_effective_passwords) {
                        r = strv_extend(&effective, decrypted_password);
                        if (r < 0)
                                return log_oom();
                }

                r = strv_extend(&cache->fido2_passwords, decrypted_password);
                if (r < 0)
                        return log_oom();
#else
                return -EBADSLT;
#endif
        }

        if (ret_effective_passwords)
                *ret_effective_passwords = TAKE_PTR(effective);

        return 0;
}

static int determine_default_storage(UserStorage *ret) {
        UserStorage storage = _USER_STORAGE_INVALID;
        const char *e;
        int r;

        assert(ret);

        /* homed tells us via an environment variable which default storage to use */
        e = getenv("SYSTEMD_HOME_DEFAULT_STORAGE");
        if (e) {
                storage = user_storage_from_string(e);
                if (storage < 0)
                        log_warning("$SYSTEMD_HOME_DEFAULT_STORAGE set to invalid storage type, ignoring: %s", e);
                else {
                        log_info("Using configured default storage '%s'.", user_storage_to_string(storage));
                        *ret = storage;
                        return 0;
                }
        }

        /* When neither user nor admin specified the storage type to use, fix it to be LUKS — unless we run
         * in a container where loopback devices and LUKS/DM are not available. Also, if /home is encrypted
         * anyway, let's avoid duplicate encryption. Note that we typically default to the assumption of
         * "classic" storage for most operations. However, if we create a new home, then let's user LUKS if
         * nothing is specified. */

        r = detect_container();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether we are in a container: %m");
        if (r == 0) {
                r = path_is_encrypted("/home");
                if (r < 0)
                        log_warning_errno(r, "Failed to determine if /home is encrypted, ignoring: %m");
                if (r <= 0) {
                        log_info("Using automatic default storage of '%s'.", user_storage_to_string(USER_LUKS));
                        *ret = USER_LUKS;
                        return 0;
                }

                log_info("/home is encrypted, not using '%s' storage, in order to avoid double encryption.", user_storage_to_string(USER_LUKS));
        } else
                log_info("Running in container, not using '%s' storage.", user_storage_to_string(USER_LUKS));

        r = path_is_fs_type("/home", BTRFS_SUPER_MAGIC);
        if (r < 0)
                log_warning_errno(r, "Failed to determine file system of /home, ignoring: %m");
        if (r > 0) {
                log_info("/home is on btrfs, using '%s' as storage.", user_storage_to_string(USER_SUBVOLUME));
                *ret = USER_SUBVOLUME;
        } else {
                log_info("/home is on simple file system, using '%s' as storage.", user_storage_to_string(USER_DIRECTORY));
                *ret = USER_DIRECTORY;
        }

        return 0;
}

static int home_create(UserRecord *h, UserRecord **ret_home) {
        _cleanup_(strv_free_erasep) char **effective_passwords = NULL;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        _cleanup_(password_cache_free) PasswordCache cache = {};
        UserStorage new_storage = _USER_STORAGE_INVALID;
        const char *new_fs = NULL;
        int r;

        assert(h);

        if (!h->user_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks name, refusing.");
        if (!uid_is_valid(h->uid))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks UID, refusing.");

        r = user_record_compile_effective_passwords(h, &cache, &effective_passwords);
        if (r < 0)
                return r;

        r = user_record_test_home_directory_and_warn(h);
        if (r < 0)
                return r;
        if (r != USER_TEST_ABSENT)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Home directory %s already exists, refusing.", user_record_home_directory(h));

        if (h->storage < 0) {
                r = determine_default_storage(&new_storage);
                if (r < 0)
                        return r;
        }

        if ((h->storage == USER_LUKS ||
             (h->storage < 0 && new_storage == USER_LUKS)) &&
            !h->file_system_type)
                new_fs = getenv("SYSTEMD_HOME_DEFAULT_FILE_SYSTEM_TYPE");

        if (new_storage >= 0 || new_fs) {
                r = user_record_add_binding(
                                h,
                                new_storage,
                                NULL,
                                SD_ID128_NULL,
                                SD_ID128_NULL,
                                SD_ID128_NULL,
                                NULL,
                                NULL,
                                UINT64_MAX,
                                new_fs,
                                NULL,
                                UID_INVALID,
                                GID_INVALID);
                if (r < 0)
                        return log_error_errno(r, "Failed to change storage type to LUKS: %m");
        }

        r = user_record_test_image_path_and_warn(h);
        if (r < 0)
                return r;
        if (!IN_SET(r, USER_TEST_ABSENT, USER_TEST_UNDEFINED, USER_TEST_MAYBE))
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Image path %s already exists, refusing.", user_record_image_path(h));

        switch (user_record_storage(h)) {

        case USER_LUKS:
                r = home_create_luks(h, &cache, effective_passwords, &new_home);
                break;

        case USER_DIRECTORY:
        case USER_SUBVOLUME:
                r = home_create_directory_or_subvolume(h, &new_home);
                break;

        case USER_FSCRYPT:
                r = home_create_fscrypt(h, effective_passwords, &new_home);
                break;

        case USER_CIFS:
                r = home_create_cifs(h, &new_home);
                break;

        default:
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                       "Creating home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));
        }
        if (r < 0)
                return r;

        if (user_record_equal(h, new_home)) {
                *ret_home = NULL;
                return 0;
        }

        *ret_home = TAKE_PTR(new_home);
        return 1;
}

static int home_remove(UserRecord *h) {
        bool deleted = false;
        const char *ip, *hd;
        int r;

        assert(h);

        if (!h->user_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks user name, refusing.");
        if (!IN_SET(user_record_storage(h), USER_LUKS, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT, USER_CIFS))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Removing home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));

        hd = user_record_home_directory(h);

        r = user_record_test_home_directory_and_warn(h);
        if (r < 0)
                return r;
        if (r == USER_TEST_MOUNTED)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Directory %s is still mounted, refusing.", hd);

        assert(hd);

        r = user_record_test_image_path_and_warn(h);
        if (r < 0)
                return r;

        ip = user_record_image_path(h);

        switch (user_record_storage(h)) {

        case USER_LUKS: {
                struct stat st;

                assert(ip);

                if (stat(ip, &st) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to stat() %s: %m", ip);

                } else {
                        if (S_ISREG(st.st_mode)) {
                                if (unlink(ip) < 0) {
                                        if (errno != ENOENT)
                                                return log_error_errno(errno, "Failed to remove %s: %m", ip);
                                } else
                                        deleted = true;

                        } else if (S_ISBLK(st.st_mode))
                                log_info("Not removing file system on block device %s.", ip);
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Image file %s is neither block device, nor regular, refusing removal.", ip);
                }

                break;
        }

        case USER_SUBVOLUME:
        case USER_DIRECTORY:
        case USER_FSCRYPT:
                assert(ip);

                r = rm_rf(ip, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                if (r < 0) {
                        if (r != -ENOENT)
                                return log_warning_errno(r, "Failed to remove %s: %m", ip);
                } else
                        deleted = true;

                /* If the image path and the home directory are the same invalidate the home directory, so
                 * that we don't remove it anymore */
                if (path_equal(ip, hd))
                        hd = NULL;

                break;

        case USER_CIFS:
                /* Nothing else to do here: we won't remove remote stuff. */
                log_info("Not removing home directory on remote server.");
                break;

        default:
                assert_not_reached("unknown storage type");
        }

        if (hd) {
                if (rmdir(hd) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to remove %s, ignoring: %m", hd);
                } else
                        deleted = true;
        }

        if (deleted)
                log_info("Everything completed.");
        else
                return log_notice_errno(SYNTHETIC_ERRNO(EALREADY),
                                        "Nothing to remove.");

        return 0;
}

static int home_validate_update(UserRecord *h, HomeSetup *setup) {
        bool has_mount = false;
        int r;

        assert(h);
        assert(setup);

        if (!h->user_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks user name, refusing.");
        if (!uid_is_valid(h->uid))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks UID, refusing.");
        if (!IN_SET(user_record_storage(h), USER_LUKS, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT, USER_CIFS))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Processing home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));

        r = user_record_test_home_directory_and_warn(h);
        if (r < 0)
                return r;

        has_mount = r == USER_TEST_MOUNTED;

        r = user_record_test_image_path_and_warn(h);
        if (r < 0)
                return r;
        if (r == USER_TEST_ABSENT)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Image path %s does not exist", user_record_image_path(h));

        switch (user_record_storage(h)) {

        case USER_DIRECTORY:
        case USER_SUBVOLUME:
        case USER_FSCRYPT:
        case USER_CIFS:
                break;

        case USER_LUKS: {
                r = home_validate_update_luks(h, setup);
                if (r < 0)
                        return r;
                if ((r > 0) != has_mount)
                        return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Home mount incompletely set up.");

                break;
        }

        default:
                assert_not_reached("unexpected storage type");
        }

        return has_mount; /* return true if the home record is already active */
}

static int home_update(UserRecord *h, UserRecord **ret) {
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL, *header_home = NULL, *embedded_home = NULL;
        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        _cleanup_(password_cache_free) PasswordCache cache = {};
        bool already_activated = false;
        int r;

        assert(h);
        assert(ret);

        r = user_record_authenticate(h, h, &cache, /* strict_verify= */ true);
        if (r < 0)
                return r;
        assert(r > 0); /* Insist that a password was verified */

        r = home_validate_update(h, &setup);
        if (r < 0)
                return r;

        already_activated = r > 0;

        r = home_prepare(h, already_activated, &cache, &setup, &header_home);
        if (r < 0)
                return r;

        r = home_load_embedded_identity(h, setup.root_fd, header_home, USER_RECONCILE_REQUIRE_NEWER, &cache, &embedded_home, &new_home);
        if (r < 0)
                return r;

        r = home_store_header_identity_luks(new_home, &setup, header_home);
        if (r < 0)
                return r;

        r = home_store_embedded_identity(new_home, setup.root_fd, h->uid, embedded_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, &setup);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup.root_fd, NULL);
        if (r < 0)
                return r;

        r = home_setup_undo(&setup);
        if (r < 0)
                return r;

        log_info("Everything completed.");

        *ret = TAKE_PTR(new_home);
        return 0;
}

static int home_resize(UserRecord *h, UserRecord **ret) {
        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        _cleanup_(password_cache_free) PasswordCache cache = {};
        bool already_activated = false;
        int r;

        assert(h);
        assert(ret);

        if (h->disk_size == UINT64_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No target size specified, refusing.");

        r = user_record_authenticate(h, h, &cache, /* strict_verify= */ true);
        if (r < 0)
                return r;
        assert(r > 0); /* Insist that a password was verified */

        r = home_validate_update(h, &setup);
        if (r < 0)
                return r;

        already_activated = r > 0;

        switch (user_record_storage(h)) {

        case USER_LUKS:
                return home_resize_luks(h, already_activated, &cache, &setup, ret);

        case USER_DIRECTORY:
        case USER_SUBVOLUME:
        case USER_FSCRYPT:
                return home_resize_directory(h, already_activated, &cache, &setup, ret);

        default:
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Resizing home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));
        }
}

static int home_passwd(UserRecord *h, UserRecord **ret_home) {
        _cleanup_(user_record_unrefp) UserRecord *header_home = NULL, *embedded_home = NULL, *new_home = NULL;
        _cleanup_(strv_free_erasep) char **effective_passwords = NULL;
        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        _cleanup_(password_cache_free) PasswordCache cache = {};
        bool already_activated = false;
        int r;

        assert(h);
        assert(ret_home);

        if (!IN_SET(user_record_storage(h), USER_LUKS, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Changing password of home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));

        r = user_record_compile_effective_passwords(h, &cache, &effective_passwords);
        if (r < 0)
                return r;

        r = home_validate_update(h, &setup);
        if (r < 0)
                return r;

        already_activated = r > 0;

        r = home_prepare(h, already_activated, &cache, &setup, &header_home);
        if (r < 0)
                return r;

        r = home_load_embedded_identity(h, setup.root_fd, header_home, USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL, &cache, &embedded_home, &new_home);
        if (r < 0)
                return r;

        switch (user_record_storage(h)) {

        case USER_LUKS:
                r = home_passwd_luks(h, &setup, &cache, effective_passwords);
                if (r < 0)
                        return r;
                break;

        case USER_FSCRYPT:
                r = home_passwd_fscrypt(h, &setup, &cache, effective_passwords);
                if (r < 0)
                        return r;
                break;

        default:
                break;
        }

        r = home_store_header_identity_luks(new_home, &setup, header_home);
        if (r < 0)
                return r;

        r = home_store_embedded_identity(new_home, setup.root_fd, h->uid, embedded_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, &setup);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup.root_fd, NULL);
        if (r < 0)
                return r;

        r = home_setup_undo(&setup);
        if (r < 0)
                return r;

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 1;
}

static int home_inspect(UserRecord *h, UserRecord **ret_home) {
        _cleanup_(user_record_unrefp) UserRecord *header_home = NULL, *new_home = NULL;
        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        _cleanup_(password_cache_free) PasswordCache cache = {};
        bool already_activated = false;
        int r;

        assert(h);
        assert(ret_home);

        r = user_record_authenticate(h, h, &cache, /* strict_verify= */ false);
        if (r < 0)
                return r;

        r = home_validate_update(h, &setup);
        if (r < 0)
                return r;

        already_activated = r > 0;

        r = home_prepare(h, already_activated, &cache, &setup, &header_home);
        if (r < 0)
                return r;

        r = home_load_embedded_identity(h, setup.root_fd, header_home, USER_RECONCILE_ANY, &cache, NULL, &new_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, &setup);
        if (r < 0)
                return r;

        r = home_setup_undo(&setup);
        if (r < 0)
                return r;

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 1;
}

static int home_lock(UserRecord *h) {
        int r;

        assert(h);

        if (!h->user_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record incomplete, refusing.");
        if (user_record_storage(h) != USER_LUKS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Locking home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));

        r = user_record_test_home_directory_and_warn(h);
        if (r < 0)
                return r;
        if (r != USER_TEST_MOUNTED)
                return log_error_errno(SYNTHETIC_ERRNO(ENOEXEC), "Home directory of %s is not mounted, can't lock.", h->user_name);

        r = home_lock_luks(h);
        if (r < 0)
                return r;

        log_info("Everything completed.");
        return 1;
}

static int home_unlock(UserRecord *h) {
        _cleanup_(password_cache_free) PasswordCache cache = {};
        int r;

        assert(h);

        if (!h->user_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record incomplete, refusing.");
        if (user_record_storage(h) != USER_LUKS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Unlocking home directories of type '%s' currently not supported.", user_storage_to_string(user_record_storage(h)));

        /* Note that we don't check if $HOME is actually mounted, since we want to avoid disk accesses on
         * that mount until we have resumed the device. */

        r = user_record_authenticate(h, h, &cache, /* strict_verify= */ false);
        if (r < 0)
                return r;

        r = home_unlock_luks(h, &cache);
        if (r < 0)
                return r;

        log_info("Everything completed.");
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(user_record_unrefp) UserRecord *home = NULL, *new_home = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(fclosep) FILE *opened_file = NULL;
        unsigned line = 0, column = 0;
        const char *json_path = NULL;
        FILE *json_file;
        usec_t start;
        int r;

        start = now(CLOCK_MONOTONIC);

        log_setup();

        umask(0022);

        if (argc < 2 || argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes one or two arguments.");

        if (argc > 2) {
                json_path = argv[2];

                opened_file = fopen(json_path, "re");
                if (!opened_file)
                        return log_error_errno(errno, "Failed to open %s: %m", json_path);

                json_file = opened_file;
        } else {
                json_path = "<stdin>";
                json_file = stdin;
        }

        r = json_parse_file(json_file, json_path, JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return log_error_errno(r, "[%s:%u:%u] Failed to parse JSON data: %m", json_path, line, column);

        home = user_record_new();
        if (!home)
                return log_oom();

        r = user_record_load(home, v, USER_RECORD_LOAD_FULL|USER_RECORD_LOG);
        if (r < 0)
                return r;

        /* Well known return values of these operations, that systemd-homed knows and converts to proper D-Bus errors:
         *
         * EMSGSIZE        → file systems of this type cannot be shrunk
         * ETXTBSY         → file systems of this type can only be shrunk offline
         * ERANGE          → file system size too small
         * ENOLINK         → system does not support selected storage backend
         * EPROTONOSUPPORT → system does not support selected file system
         * ENOTTY          → operation not support on this storage
         * ESOCKTNOSUPPORT → operation not support on this file system
         * ENOKEY          → password incorrect (or not sufficient, or not supplied)
         * EREMOTEIO       → recovery key incorrect (or not sufficeint, or not supplied — only if no passwords defined)
         * EBADSLT         → similar, but PKCS#11 device is defined and might be able to provide password, if it was plugged in which it is not
         * ENOANO          → suitable PKCS#11/FIDO2 device found, but PIN is missing to unlock it
         * ERFKILL         → suitable PKCS#11 device found, but OK to ask for on-device interactive authentication not given
         * EMEDIUMTYPE     → suitable FIDO2 device found, but OK to ask for user presence not given
         * ENOSTR          → suitable FIDO2 device found, but user didn't react to action request on token quickly enough
         * EOWNERDEAD      → suitable PKCS#11/FIDO2 device found, but its PIN is locked
         * ENOLCK          → suitable PKCS#11/FIDO2 device found, but PIN incorrect
         * ETOOMANYREFS    → suitable PKCS#11 device found, but PIN incorrect, and only few tries left
         * EUCLEAN         → suitable PKCS#11 device found, but PIN incorrect, and only one try left
         * EBUSY           → file system is currently active
         * ENOEXEC         → file system is currently not active
         * ENOSPC          → not enough disk space for operation
         * EKEYREVOKED     → user record has not suitable hashed password or pkcs#11 entry, we cannot authenticate
         */

        if (streq(argv[1], "activate"))
                r = home_activate(home, &new_home);
        else if (streq(argv[1], "deactivate"))
                r = home_deactivate(home, false);
        else if (streq(argv[1], "deactivate-force"))
                r = home_deactivate(home, true);
        else if (streq(argv[1], "create"))
                r = home_create(home, &new_home);
        else if (streq(argv[1], "remove"))
                r = home_remove(home);
        else if (streq(argv[1], "update"))
                r = home_update(home, &new_home);
        else if (streq(argv[1], "resize"))
                r = home_resize(home, &new_home);
        else if (streq(argv[1], "passwd"))
                r = home_passwd(home, &new_home);
        else if (streq(argv[1], "inspect"))
                r = home_inspect(home, &new_home);
        else if (streq(argv[1], "lock"))
                r = home_lock(home);
        else if (streq(argv[1], "unlock"))
                r = home_unlock(home);
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb '%s'.", argv[1]);
        if (IN_SET(r, -ENOKEY, -EREMOTEIO) && !strv_isempty(home->password) ) { /* There were passwords specified but they were incorrect */
                usec_t end, n, d;

                /* Make sure bad password replies always take at least 3s, and if longer multiples of 3s, so
                 * that it's not clear how long we actually needed for our calculations. */
                n = now(CLOCK_MONOTONIC);
                assert(n >= start);

                d = usec_sub_unsigned(n, start);
                if (d > BAD_PASSWORD_DELAY_USEC)
                        end = start + DIV_ROUND_UP(d, BAD_PASSWORD_DELAY_USEC) * BAD_PASSWORD_DELAY_USEC;
                else
                        end = start + BAD_PASSWORD_DELAY_USEC;

                if (n < end)
                        (void) usleep(usec_sub_unsigned(end, n));
        }
        if (r < 0)
                return r;

        /* We always pass the new record back, regardless if it changed or not. This allows our caller to
         * prepare a fresh record, send to us, and only if it works use it without having to keep a local
         * copy. */
        if (new_home)
                json_variant_dump(new_home->json, JSON_FORMAT_NEWLINE, stdout, NULL);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
