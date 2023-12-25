/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "cryptsetup-fido2.h"
#include "env-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "json.h"
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
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                bool headless,
                Fido2EnrollFlags required,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                AskPasswordFlags ask_password_flags) {

        _cleanup_(erase_and_freep) char *envpw = NULL;
        _cleanup_strv_free_erase_ char **pins = NULL;
        _cleanup_free_ void *loaded_salt = NULL;
        bool device_exists = false;
        const char *salt;
        size_t salt_size;
        int r;

        if ((required & (FIDO2ENROLL_PIN | FIDO2ENROLL_UP | FIDO2ENROLL_UV)) && headless)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                        "Local verification is required to unlock this volume, but the 'headless' parameter was set.");

        ask_password_flags |= ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_ACCEPT_CACHED;

        assert(cid);
        assert(key_file || key_data);

        if (key_data) {
                salt = key_data;
                salt_size = key_data_size;
        } else {
                _cleanup_free_ char *bindname = NULL;

                /* If we read the salt via AF_UNIX, make this client recognizable */
                if (asprintf(&bindname, "@%" PRIx64"/cryptsetup-fido2/%s", random_u64(), volume_name) < 0)
                        return log_oom();

                r = read_full_file_full(
                                AT_FDCWD, key_file,
                                key_file_offset == 0 ? UINT64_MAX : key_file_offset,
                                key_file_size == 0 ? SIZE_MAX : key_file_size,
                                READ_FULL_FILE_CONNECT_SOCKET,
                                bindname,
                                (char**) &loaded_salt, &salt_size);
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
                                salt, salt_size,
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

                if (headless)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "PIN querying disabled via 'headless' option. Use the '$PIN' environment variable.");

                pins = strv_free_erase(pins);
                r = ask_password_auto("Please enter security token PIN:", "drive-harddisk", NULL, "fido2-pin", "cryptsetup.fido2-pin", until, ask_password_flags, &pins);
                if (r < 0)
                        return log_error_errno(r, "Failed to ask for user password: %m");

                ask_password_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
        }
}

int acquire_fido2_key_auto(
                struct crypt_device *cd,
                const char *name,
                const char *friendly_name,
                const char *fido2_device,
                usec_t until,
                bool headless,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                AskPasswordFlags ask_password_flags) {

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
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                JsonVariant *w;
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

                w = json_variant_by_key(v, "fido2-credential");
                if (!w || !json_variant_is_string(w))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "FIDO2 token data lacks 'fido2-credential' field.");

                r = unbase64mem(json_variant_string(w), SIZE_MAX, &cid, &cid_size);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid base64 data in 'fido2-credential' field.");

                w = json_variant_by_key(v, "fido2-salt");
                if (!w || !json_variant_is_string(w))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "FIDO2 token data lacks 'fido2-salt' field.");

                assert(!salt);
                assert(salt_size == 0);
                r = unbase64mem(json_variant_string(w), SIZE_MAX, &salt, &salt_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode base64 encoded salt.");

                w = json_variant_by_key(v, "fido2-rp");
                if (w) {
                        /* The "rp" field is optional. */

                        if (!json_variant_is_string(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-rp' field is not a string.");

                        assert(!rp);
                        rp = strdup(json_variant_string(w));
                        if (!rp)
                                return log_oom();
                }

                w = json_variant_by_key(v, "fido2-clientPin-required");
                if (w) {
                        /* The "fido2-clientPin-required" field is optional. */

                        if (!json_variant_is_boolean(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-clientPin-required' field is not a boolean.");

                        SET_FLAG(required, FIDO2ENROLL_PIN, json_variant_boolean(w));
                } else
                        required |= FIDO2ENROLL_PIN_IF_NEEDED; /* compat with 248, where the field was unset */

                w = json_variant_by_key(v, "fido2-up-required");
                if (w) {
                        /* The "fido2-up-required" field is optional. */

                        if (!json_variant_is_boolean(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-up-required' field is not a boolean.");

                        SET_FLAG(required, FIDO2ENROLL_UP, json_variant_boolean(w));
                } else
                        required |= FIDO2ENROLL_UP_IF_NEEDED; /* compat with 248 */

                w = json_variant_by_key(v, "fido2-uv-required");
                if (w) {
                        /* The "fido2-uv-required" field is optional. */

                        if (!json_variant_is_boolean(w))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "FIDO2 token data's 'fido2-uv-required' field is not a boolean.");

                        SET_FLAG(required, FIDO2ENROLL_UV, json_variant_boolean(w));
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
                                salt, salt_size,
                                until,
                                headless,
                                required,
                                ret_decrypted_key, ret_decrypted_key_size,
                                ask_password_flags);
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
