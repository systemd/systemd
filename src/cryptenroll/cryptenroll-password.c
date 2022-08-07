/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "cryptenroll-password.h"
#include "env-util.h"
#include "escape.h"
#include "json.h"
#include "memory-util.h"
#include "pwquality-util.h"
#include "strv.h"

/* NBO: Now takes a @share in addition.*/
int enroll_password(
                struct crypt_device *cd,
                const void *volume_key,
                size_t volume_key_size,
                Factor *factor, int keyslot) {

        _cleanup_(erase_and_freep) char *new_password = NULL;
        _cleanup_free_ char *error = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;
        _cleanup_(erase_and_freep) unsigned char *encrypted_share = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        const char *node;
        int q, r;

        assert_se(cd);
        assert_se(volume_key);
        assert_se(volume_key_size > 0);
        assert_se(node = crypt_get_device_name(cd));

        r = getenv_steal_erase("NEWPASSWORD", &new_password);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r == 0) {
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

                        r = ask_password_auto(question, "drive-harddisk", id, "cryptenroll", "cryptenroll.new-passphrase", USEC_INFINITY, 0, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        assert(strv_length(passwords) == 1);

                        free(question);
                        question = strjoin("Please enter new passphrase for disk ", node, " (repeat):");
                        if (!question)
                                return log_oom();

                        r = ask_password_auto(question, "drive-harddisk", id, "cryptenroll", "cryptenroll.new-passphrase", USEC_INFINITY, 0, &passwords2);
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

        if (factor->share) {
            encrypted_share = malloc0(sizeof(sss_share));
            if (!encrypted_share)
                return log_oom();

            encrypt_share(new_password, strlen(new_password), factor, encrypted_share);
            if (asprintf(&keyslot_as_string, "%i", keyslot) < 0) {
                    r = log_oom();
                    goto rollback;
            }

            r = json_build(&v,
                           JSON_BUILD_OBJECT(
                                           JSON_BUILD_PAIR("type", JSON_BUILD_STRING("systemd-passphrase")),
                                           JSON_BUILD_PAIR("keyslots", JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_as_string))),
                                           JSON_BUILD_PAIR("sss-share", JSON_BUILD_BASE64(encrypted_share, sizeof(sss_share))),
                                           JSON_BUILD_PAIR("sss-nonce", JSON_BUILD_BASE64(factor->nonce, NONCE_LEN)),
                                           JSON_BUILD_PAIR("sss-tag", JSON_BUILD_BASE64(factor->tag, TAG_LEN)),
                                           JSON_BUILD_PAIR("sss-salt", JSON_BUILD_BASE64(factor->salt, SALT_LEN)),
                                           JSON_BUILD_PAIR("sss-combination-type", JSON_BUILD_STRING(factor->combination_type == MANDATORY ? "mandatory" : "shared"))));
            if (r < 0) {
                    log_error_errno(r, "Failed to prepare password key JSON token object: %m");
                    goto rollback;
            }

            r = cryptsetup_add_token_json(cd, v);
            if (r < 0) {
                    log_error_errno(r, "Failed to add password JSON token to LUKS2 header: %m");
                    goto rollback;
            }
            return keyslot;
rollback:
            q = crypt_keyslot_destroy(cd, keyslot);
            if (q < 0)
                    log_debug_errno(q, "Unable to remove key slot we just added again, can't rollback, sorry: %m");

            log_info("New password enrolled as key slot %i.", keyslot);
            return keyslot;
        } else {
            keyslot = crypt_keyslot_add_by_volume_key(
                            cd,
                            CRYPT_ANY_SLOT,
                            volume_key,
                            volume_key_size,
                            new_password,
                            strlen(new_password));
            if (keyslot < 0)
                    return log_error_errno(keyslot, "Failed to add new password to %s: %m", node);
        }
        return keyslot;
}
