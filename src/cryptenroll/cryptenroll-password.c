/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptenroll-password.h"
#include "cryptsetup-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fileio.h"
#include "iovec-util.h"
#include "log.h"
#include "password-quality-util.h"
#include "string-util.h"
#include "strv.h"

int load_volume_key_empty(
                const EnrollContext *c,
                struct crypt_device *cd,
                struct iovec *ret_vk) {

        int r;

        assert_se(c);
        assert_se(cd);
        assert_se(ret_vk);

        r = sym_crypt_volume_key_get(
                        cd,
                        CRYPT_ANY_SLOT,
                        ret_vk->iov_base,
                        &ret_vk->iov_len,
                        "",
                        0);
        if (r < 0)
                return log_error_errno(r, "Provided empty password did not work: %m");

        return r;
}

int load_volume_key_keyfile(
                const EnrollContext *c,
                struct crypt_device *cd,
                struct iovec *ret_vk) {

        _cleanup_(erase_and_freep) char *password = NULL;
        size_t password_len;
        int r;

        assert_se(c);
        assert_se(cd);
        assert_se(ret_vk);

        r = read_full_file_full(
                        AT_FDCWD,
                        c->unlock_keyfile,
                        UINT64_MAX,
                        SIZE_MAX,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                        NULL,
                        &password,
                        &password_len);
        if (r < 0)
                return log_error_errno(r, "Reading keyfile %s failed: %m", c->unlock_keyfile);

        r = sym_crypt_volume_key_get(
                        cd,
                        CRYPT_ANY_SLOT,
                        ret_vk->iov_base,
                        &ret_vk->iov_len,
                        password,
                        password_len);
        if (r < 0)
                return log_error_errno(r, "Unlocking via keyfile failed: %m");

        return r;
}

int load_volume_key_password(
                const EnrollContext *c,
                struct crypt_device *cd,
                struct iovec *ret_vk) {

        _cleanup_(erase_and_freep) char *envpw = NULL;
        int r;

        assert_se(c);
        assert_se(c->node);
        assert_se(cd);
        assert_se(ret_vk);

        if (c->unlock_password) {
                r = sym_crypt_volume_key_get(
                                cd,
                                CRYPT_ANY_SLOT,
                                ret_vk->iov_base,
                                &ret_vk->iov_len,
                                c->unlock_password,
                                strlen(c->unlock_password));
                if (r < 0)
                        return log_error_errno(r, "Provided unlock password did not work: %m");

                return r;
        }

        r = getenv_steal_erase("PASSWORD", &envpw);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r > 0) {
                r = sym_crypt_volume_key_get(
                                cd,
                                CRYPT_ANY_SLOT,
                                ret_vk->iov_base,
                                &ret_vk->iov_len,
                                envpw,
                                strlen(envpw));
                if (r < 0)
                        return log_error_errno(r, "Password from environment variable $PASSWORD did not work: %m");
        } else {
                AskPasswordFlags ask_password_flags = ASK_PASSWORD_PUSH_CACHE|ASK_PASSWORD_ACCEPT_CACHED;

                if (!c->interactive)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                               "Password querying disabled via 'headless' option, but no password provided for disk %s.",
                                               c->node);
                _cleanup_free_ char *question = NULL, *id = NULL, *disk_path = NULL;
                unsigned i = 5;

                question = strjoin("Please enter current passphrase for disk ", c->node, ":");
                if (!question)
                        return log_oom();

                disk_path = cescape(c->node);
                if (!disk_path)
                        return log_oom();

                id = strjoin("cryptenroll:", disk_path);
                if (!id)
                        return log_oom();

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .message = question,
                        .icon = "drive-harddisk",
                        .id = id,
                        .keyring = "cryptenroll",
                        .credential = "cryptenroll.passphrase",
                        .until = USEC_INFINITY,
                        .hup_fd = -EBADF,
                };

                for (;;) {
                        _cleanup_strv_free_erase_ char **passwords = NULL;

                        if (--i == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                                       "Too many attempts, giving up.");

                        r = ask_password_auto(&req, ask_password_flags, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        r = -EPERM;
                        STRV_FOREACH(p, passwords) {
                                r = sym_crypt_volume_key_get(
                                                cd,
                                                CRYPT_ANY_SLOT,
                                                ret_vk->iov_base,
                                                &ret_vk->iov_len,
                                                *p,
                                                strlen(*p));
                                if (r >= 0)
                                        break;
                        }
                        if (r >= 0)
                                break;

                        log_error_errno(r, "Password not correct, please try again: %m");
                        ask_password_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
                }
        }

        return r;
}

int enroll_password(
                const EnrollContext *c,
                struct crypt_device *cd,
                const struct iovec *volume_key) {

        _cleanup_(erase_and_freep) char *new_password = NULL;
        _cleanup_free_ char *error = NULL;
        const char *node;
        int r, keyslot;

        assert(c);
        assert(cd);
        assert(iovec_is_set(volume_key));

        assert_se(node = sym_crypt_get_device_name(cd));

        if (c->passphrase) {
                new_password = memdup_suffix0(c->passphrase, c->passphrase_size);
                if (!new_password)
                        return log_oom();
        } else {
                r = getenv_steal_erase("NEWPASSWORD", &new_password);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire password from environment: %m");
        }

        if (!new_password) {
                _cleanup_free_ char *disk_path = NULL, *id = NULL;
                unsigned i = 5;

                if (!c->interactive)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                               "Password querying disabled via 'headless' option, but no new password provided.");

                assert_se(node = sym_crypt_get_device_name(cd));

                (void) suggest_passwords();

                disk_path = cescape(node);
                if (!disk_path)
                        return log_oom();

                id = strjoin("cryptenroll-new:", disk_path);
                if (!id)
                        return log_oom();

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .icon = "drive-harddisk",
                        .id = id,
                        .keyring = "cryptenroll",
                        .credential = "cryptenroll.new-passphrase",
                        .until = USEC_INFINITY,
                        .hup_fd = -EBADF,
                };

                for (;;) {
                        _cleanup_strv_free_erase_ char **passwords = NULL, **passwords2 = NULL;
                        _cleanup_free_ char *question = NULL;

                        if (--i == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                                       "Too many attempts, giving up.");

                        question = strjoin("Please enter new passphrase for disk ", node, ":");
                        if (!question)
                                return log_oom();

                        req.message = question;

                        r = ask_password_auto(&req, /* flags= */ 0, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        assert(strv_length(passwords) == 1);

                        free(question);
                        question = strjoin("Please enter new passphrase for disk ", node, " (repeat):");
                        if (!question)
                                return log_oom();

                        req.message = question;

                        r = ask_password_auto(&req, /* flags= */ 0, &passwords2);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        assert(strv_length(passwords2) == 1);

                        if (strv_equal(passwords, passwords2)) {
                                new_password = passwords2[0];
                                passwords2 = mfree(passwords2);
                                break;
                        }

                        log_error("Password didn't match, try again.");
                }
        }

        r = check_password_quality(new_password, /* old= */ NULL, /* user= */ NULL, &error);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                log_warning("Password quality check is not supported, proceeding anyway.");
        else if (r < 0)
                return log_error_errno(r, "Failed to check password quality: %m");
        else if (r == 0)
                log_warning("Specified password does not pass quality checks (%s), proceeding anyway.", error);

        keyslot = sym_crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        new_password,
                        strlen(new_password));
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new password to %s: %m", node);

        log_info("New password enrolled as key slot %i.", keyslot);
        return keyslot;
}
