/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "cryptenroll-password.h"
#include "escape.h"
#include "memory-util.h"
#include "pwquality-util.h"
#include "strv.h"

int enroll_password(
                struct crypt_device *cd,
                const void *volume_key,
                size_t volume_key_size) {

        _cleanup_(erase_and_freep) char *new_password = NULL;
        _cleanup_free_ char *error = NULL;
        const char *node;
        int r, keyslot;
        char *e;

        assert_se(node = crypt_get_device_name(cd));

        e = getenv("NEWPASSWORD");
        if (e) {

                new_password = strdup(e);
                if (!new_password)
                        return log_oom();

                string_erase(e);
                assert_se(unsetenv("NEWPASSWORD") == 0);

        } else {
                _cleanup_free_ char *disk_path = NULL;
                unsigned i = 5;
                const char *id;

                assert_se(node = crypt_get_device_name(cd));

                (void) suggest_passwords();

                disk_path = cescape(node);
                if (!disk_path)
                        return log_oom();

                id = strjoina("cryptsetup:", disk_path);

                for (;;) {
                        _cleanup_strv_free_erase_ char **passwords = NULL, **passwords2 = NULL;
                        _cleanup_free_ char *question = NULL;

                        if (--i == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                                       "Too many attempts, giving up:");

                        question = strjoin("Please enter new passphrase for disk ", node, ":");
                        if (!question)
                                return log_oom();

                        r = ask_password_auto(question, "drive-harddisk", id, "cryptenroll", USEC_INFINITY, 0, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        assert(strv_length(passwords) == 1);

                        free(question);
                        question = strjoin("Please enter new passphrase for disk ", node, " (repeat):");
                        if (!question)
                                return log_oom();

                        r = ask_password_auto(question, "drive-harddisk", id, "cryptenroll", USEC_INFINITY, 0, &passwords2);
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

        r = quality_check_password(new_password, NULL, &error);
        if (r < 0)
                return log_error_errno(r, "Failed to check password for quality: %m");
        if (r == 0)
                log_warning_errno(r, "Specified password does not pass quality checks (%s), proceeding anyway.", error);

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key,
                        volume_key_size,
                        new_password,
                        strlen(new_password));
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new password to %s: %m", node);

        log_info("New password enrolled as key slot %i.", keyslot);
        return keyslot;
}
