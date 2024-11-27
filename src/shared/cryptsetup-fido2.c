/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "ask-password-api.h"
#include "cryptsetup-fido2.h"
#include "env-util.h"
#include "fido2-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "libfido2-util.h"
#include "parse-util.h"
#include "random-util.h"
#include "strv.h"

int acquire_fido2_key(
                const char *volume_name,
                const char *friendly_name,
                const char *device,
                const char *rp_id,
                const void *cid,
                size_t cid_size,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const struct iovec *key_data,
                usec_t until,
                Fido2EnrollFlags required,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(erase_and_freep) char *envpw = NULL;
        _cleanup_strv_free_erase_ char **pins = NULL;
        _cleanup_(iovec_done_erase) struct iovec loaded_salt = {};
        bool device_exists = false;
        struct iovec salt;
        int r;

        if ((required & (FIDO2ENROLL_PIN | FIDO2ENROLL_UP | FIDO2ENROLL_UV)) && FLAGS_SET(askpw_flags, ASK_PASSWORD_HEADLESS))
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                        "Local verification is required to unlock this volume, but the 'headless' parameter was set.");

        assert(cid);
        assert(key_file || iovec_is_set(key_data));

        if (iovec_is_set(key_data))
                salt = *key_data;
        else {
                if (key_file_size > 0)
                        log_debug("Ignoring 'keyfile-size=' option for a FIDO2 salt file.");

                r = fido2_read_salt_file(
                                key_file, key_file_offset,
                                /* client= */ "cryptsetup",
                                /* node= */ volume_name,
                                &loaded_salt);
                if (r < 0)
                        return r;

                salt = loaded_salt;
        }

        r = getenv_steal_erase("PIN", &envpw);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r > 0) {
                pins = strv_new(envpw);
                if (!pins)
                        return log_oom();
        }

        for (;;) {
                if (!device_exists) {
                        /* Before we inquire for the PIN we'll need, if we never talked to the device, check
                         * if the device actually is plugged in. Otherwise we'll ask for the PIN already when
                         * the device is not plugged in, which is confusing. */

                        r = fido2_have_device(device);
                        if (r < 0)
                                return r;
                        if (r == 0) /* no device found, return EAGAIN so that caller will wait/watch udev */
                                return -EAGAIN;

                        device_exists = true;  /* now we know for sure, a device exists, no need to ask again */
                }

                /* Always make an attempt before asking for PIN.
                 * fido2_use_hmac_hash() will perform a pre-flight check for whether the credential for
                 * can be found on one of the connected devices. This way, we can avoid prompting the user
                 * for a PIN when we are sure that no device can be used. */
                r = fido2_use_hmac_hash(
                                device,
                                rp_id ?: "io.systemd.cryptsetup",
                                salt.iov_base, salt.iov_len,
                                cid, cid_size,
                                pins,
                                required,
                                ret_decrypted_key,
                                ret_decrypted_key_size);
                if (!IN_SET(r,
                            -ENOANO,   /* needs pin */
                            -ENOLCK))  /* pin incorrect */
                        return r;

                device_exists = true; /* that a PIN is needed/wasn't correct means that we managed to
                                       * talk to a device */

                if (FLAGS_SET(askpw_flags, ASK_PASSWORD_HEADLESS))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "PIN querying disabled via 'headless' option. Use the '$PIN' environment variable.");

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .message = "Please enter security token PIN:",
                        .icon = "drive-harddisk",
                        .keyring = "fido2-pin",
                        .credential = "cryptsetup.fido2-pin",
                        .until = until,
                        .hup_fd = -EBADF,
                };

                pins = strv_free_erase(pins);
                r = ask_password_auto(&req, askpw_flags, &pins);
                if (r < 0)
                        return log_error_errno(r, "Failed to ask for user password: %m");

                askpw_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
        }
}

int acquire_fido2_key_auto(
                struct crypt_device *cd,
                const char *name,
                const char *friendly_name,
                const char *fido2_device,
                usec_t until,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_free_ void *cid = NULL;
        size_t cid_size = 0;
        int r, ret = -ENOENT;
        Fido2EnrollFlags required = 0;

        assert(cd);
        assert(name);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        /* Loads FIDO2 metadata from LUKS2 JSON token headers. */

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                sd_json_variant *w;
                _cleanup_free_ void *salt = NULL;
                _cleanup_free_ char *rp = NULL;
                size_t salt_size = 0;
                int ks;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-fido2", &v);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                ks = cryptsetup_get_keyslot_from_token(v);
                if (ks < 0) {
                        /* Handle parsing errors of the keyslots field gracefully, since it's not 'owned' by
                         * us, but by the LUKS2 spec */
                        log_warning_errno(ks, "Failed to extract keyslot index from FIDO2 JSON data token %i, skipping: %m", token);
                        continue;
                }

                w = sd_json_variant_by_key(v, "fido2-credential");
                if (!w)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "FIDO2 token data lacks 'fido2-credential' field.");

                r = sd_json_variant_unbase64(w, &cid, &cid_size);
                if (r < 0)
                        return log_error_errno(r, "Invalid base64 data in 'fido2-credential' field: %m");

                w = sd_json_variant_by_key(v, "fido2-salt");
                if (!w)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "FIDO2 token data lacks 'fido2-salt' field.");

                assert(!salt);
                assert(salt_size == 0);
                r = sd_json_variant_unbase64(w, &salt, &salt_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode base64 encoded salt: %m");

                w = sd_json_variant_by_key(v, "fido2-rp");
                if (w) {
                        /* The "rp" field is optional. */

                        if (!sd_json_variant_is_string(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-rp' field is not a string.");

                        assert(!rp);
                        rp = strdup(sd_json_variant_string(w));
                        if (!rp)
                                return log_oom();
                }

                w = sd_json_variant_by_key(v, "fido2-clientPin-required");
                if (w) {
                        /* The "fido2-clientPin-required" field is optional. */

                        if (!sd_json_variant_is_boolean(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-clientPin-required' field is not a boolean.");

                        SET_FLAG(required, FIDO2ENROLL_PIN, sd_json_variant_boolean(w));
                } else
                        required |= FIDO2ENROLL_PIN_IF_NEEDED; /* compat with 248, where the field was unset */

                w = sd_json_variant_by_key(v, "fido2-up-required");
                if (w) {
                        /* The "fido2-up-required" field is optional. */

                        if (!sd_json_variant_is_boolean(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-up-required' field is not a boolean.");

                        SET_FLAG(required, FIDO2ENROLL_UP, sd_json_variant_boolean(w));
                } else
                        required |= FIDO2ENROLL_UP_IF_NEEDED; /* compat with 248 */

                w = sd_json_variant_by_key(v, "fido2-uv-required");
                if (w) {
                        /* The "fido2-uv-required" field is optional. */

                        if (!sd_json_variant_is_boolean(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-uv-required' field is not a boolean.");

                        SET_FLAG(required, FIDO2ENROLL_UV, sd_json_variant_boolean(w));
                } else
                        required |= FIDO2ENROLL_UV_OMIT; /* compat with 248 */

                ret = acquire_fido2_key(
                                name,
                                friendly_name,
                                fido2_device,
                                rp,
                                cid, cid_size,
                                /* key_file= */ NULL, /* salt is read from LUKS header instead of key_file */
                                /* key_file_size= */ 0,
                                /* key_file_offset= */ 0,
                                &IOVEC_MAKE(salt, salt_size),
                                until,
                                required,
                                "cryptsetup.fido2-pin",
                                askpw_flags,
                                ret_decrypted_key,
                                ret_decrypted_key_size);
                if (ret == 0)
                        break;
        }

        if (!cid)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "No valid FIDO2 token data found.");

        if (ret == -EAGAIN) /* fido2 device does not exist, or UV is blocked; caller will prompt for retry */
                return log_debug_errno(ret, "FIDO2 token does not exist, or UV is blocked.");
        if (ret < 0)
                return log_error_errno(ret, "Failed to unlock LUKS volume with FIDO2 token: %m");

        log_info("Unlocked volume via automatically discovered security FIDO2 token.");
        return ret;
}
