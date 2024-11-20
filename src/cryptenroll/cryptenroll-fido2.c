/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "cryptenroll-fido2.h"
#include "cryptsetup-fido2.h"
#include "fido2-util.h"
#include "glyph-util.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "json-util.h"
#include "libfido2-util.h"
#include "memory-util.h"
#include "pretty-print.h"
#include "random-util.h"

int load_volume_key_fido2(
                struct crypt_device *cd,
                const char *cd_node,
                const char *device,
                void *ret_vk,
                size_t *ret_vks) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *passphrase = NULL;
        size_t decrypted_key_size;
        ssize_t passphrase_size;
        int r;

        assert_se(cd);
        assert_se(cd_node);
        assert_se(ret_vk);
        assert_se(ret_vks);

        r = acquire_fido2_key_auto(
                        cd,
                        cd_node,
                        cd_node,
                        device,
                        /* until= */ 0,
                        "cryptenroll.fido2-pin",
                        ASK_PASSWORD_PUSH_CACHE|ASK_PASSWORD_ACCEPT_CACHED,
                        &decrypted_key,
                        &decrypted_key_size);
        if (r == -EAGAIN)
                return log_error_errno(r, "FIDO2 token does not exist, or UV is blocked. Please try again.");
        if (r < 0)
                return r;

        /* Because cryptenroll requires a LUKS header, we can assume that this device is not
         * a PLAIN device. In this case, we need to base64 encode the secret to use as the passphrase */
        passphrase_size = base64mem(decrypted_key, decrypted_key_size, &passphrase);
        if (passphrase_size < 0)
                return log_oom();

        r = crypt_volume_key_get(
                        cd,
                        CRYPT_ANY_SLOT,
                        ret_vk,
                        ret_vks,
                        passphrase,
                        passphrase_size);
        if (r < 0)
                return log_error_errno(r, "Unlocking via FIDO2 device failed: %m");

        return r;
}

int enroll_fido2(
                struct crypt_device *cd,
                const struct iovec *volume_key,
                const char *device,
                Fido2EnrollFlags lock_with,
                int cred_alg,
                const char *salt_file,
                bool parameters_in_header) {

        _cleanup_(iovec_done_erase) struct iovec salt = {};
        _cleanup_(erase_and_freep) void *secret = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;
        size_t cid_size, secret_size;
        _cleanup_free_ void *cid = NULL;
        ssize_t base64_encoded_size;
        const char *node, *un;
        int r, keyslot;

        assert_se(cd);
        assert_se(iovec_is_set(volume_key));
        assert_se(device);

        assert_se(node = crypt_get_device_name(cd));

        un = strempty(crypt_get_uuid(cd));

        if (salt_file)
                r = fido2_read_salt_file(
                                salt_file,
                                /* offset= */ UINT64_MAX,
                                /* client= */ "cryptenroll",
                                /* node= */ un,
                                &salt);
        else
                r = fido2_generate_salt(&salt);
        if (r < 0)
                return r;

        r = fido2_generate_hmac_hash(
                        device,
                        /* rp_id= */ "io.systemd.cryptsetup",
                        /* rp_name= */ "Encrypted Volume",
                        /* user_id= */ un, strlen(un), /* We pass the user ID and name as the same: the disk's UUID if we have it */
                        /* user_name= */ un,
                        /* user_display_name= */ node,
                        /* user_icon_name= */ NULL,
                        /* askpw_icon_name= */ "drive-harddisk",
                        /* askpw_credential= */ "cryptenroll.fido2-pin",
                        lock_with,
                        cred_alg,
                        &salt,
                        &cid, &cid_size,
                        &secret, &secret_size,
                        NULL,
                        &lock_with);
        if (r < 0)
                return r;

        /* Before we use the secret, we base64 encode it, for compat with homed, and to make it easier to type in manually */
        base64_encoded_size = base64mem(secret, secret_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        base64_encoded,
                        base64_encoded_size);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new FIDO2 key to %s: %m", node);

        if (parameters_in_header) {
                if (asprintf(&keyslot_as_string, "%i", keyslot) < 0)
                        return log_oom();

                r = sd_json_buildo(&v,
                                SD_JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-fido2")),
                                SD_JSON_BUILD_PAIR("keyslots", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING(keyslot_as_string))),
                                SD_JSON_BUILD_PAIR("fido2-credential", SD_JSON_BUILD_BASE64(cid, cid_size)),
                                SD_JSON_BUILD_PAIR("fido2-salt", JSON_BUILD_IOVEC_BASE64(&salt)),
                                SD_JSON_BUILD_PAIR("fido2-rp", JSON_BUILD_CONST_STRING("io.systemd.cryptsetup")),
                                SD_JSON_BUILD_PAIR("fido2-clientPin-required", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_PIN))),
                                SD_JSON_BUILD_PAIR("fido2-up-required", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UP))),
                                SD_JSON_BUILD_PAIR("fido2-uv-required", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UV))));
                if (r < 0)
                        return log_error_errno(r, "Failed to prepare FIDO2 JSON token object: %m");

                r = cryptsetup_add_token_json(cd, v);
                if (r < 0)
                        return log_error_errno(r, "Failed to add FIDO2 JSON token to LUKS2 header: %m");
        } else {
                _cleanup_free_ char *base64_encoded_cid = NULL, *link = NULL;

                r = base64mem(cid, cid_size, &base64_encoded_cid);
                if (r < 0)
                        return log_error_errno(r, "Failed to base64 encode FIDO2 credential ID: %m");

                r = terminal_urlify_man("crypttab", "5", &link);
                if (r < 0)
                        return log_oom();

                fflush(stdout);
                fprintf(stderr,
                        "A FIDO2 credential has been registered for this volume:\n\n"
                        "    %s%sfido2-cid=%s",
                        emoji_enabled() ? special_glyph(SPECIAL_GLYPH_LOCK_AND_KEY) : "",
                        emoji_enabled() ? " " : "",
                        ansi_highlight());
                fflush(stderr);

                fputs(base64_encoded_cid, stdout);
                fflush(stdout);

                fputs(ansi_normal(), stderr);
                fflush(stderr);

                fputc('\n', stdout);
                fflush(stdout);

                fprintf(stderr,
                        "\nPlease save this FIDO2 credential ID. It is required when unlocking the volume\n"
                        "using the associated FIDO2 keyslot which we just created. To configure automatic\n"
                        "unlocking using this FIDO2 token, add an appropriate entry to your /etc/crypttab\n"
                        "file, see %s for details.\n", link);
                fflush(stderr);
        }

        log_info("New FIDO2 token enrolled as key slot %i.", keyslot);
        return keyslot;
}
