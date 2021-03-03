/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "cryptsetup-fido2.h"
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
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        AskPasswordFlags flags = ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_ACCEPT_CACHED;
        _cleanup_strv_free_erase_ char **pins = NULL;
        _cleanup_free_ void *loaded_salt = NULL;
        const char *salt;
        size_t salt_size;
        char *e;
        int r;

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

        e = getenv("PIN");
        if (e) {
                pins = strv_new(e);
                if (!pins)
                        return log_oom();

                string_erase(e);
                if (unsetenv("PIN") < 0)
                        return log_error_errno(errno, "Failed to unset $PIN: %m");
        }

        for (;;) {
                r = fido2_use_hmac_hash(
                                device,
                                rp_id ?: "io.systemd.cryptsetup",
                                salt, salt_size,
                                cid, cid_size,
                                pins,
                                /* up= */ true,
                                ret_decrypted_key,
                                ret_decrypted_key_size);
                if (!IN_SET(r,
                            -ENOANO,   /* needs pin */
                            -ENOLCK))  /* pin incorrect */
                        return r;

                pins = strv_free_erase(pins);

                r = ask_password_auto("Please enter security token PIN:", "drive-harddisk", NULL, "fido2-pin", until, flags, &pins);
                if (r < 0)
                        return log_error_errno(r, "Failed to ask for user password: %m");

                flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
        }
}

int find_fido2_auto_data(
                struct crypt_device *cd,
                char **ret_rp_id,
                void **ret_salt,
                size_t *ret_salt_size,
                void **ret_cid,
                size_t *ret_cid_size,
                int *ret_keyslot) {

        _cleanup_free_ void *cid = NULL, *salt = NULL;
        size_t cid_size = 0, salt_size = 0;
        _cleanup_free_ char *rp = NULL;
        int r, keyslot = -1;

        assert(cd);
        assert(ret_salt);
        assert(ret_salt_size);
        assert(ret_cid);
        assert(ret_cid_size);
        assert(ret_keyslot);

        /* Loads FIDO2 metadata from LUKS2 JSON token headers. */

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token ++) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                JsonVariant *w;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-fido2", &v);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                if (cid)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                               "Multiple FIDO2 tokens enrolled, cannot automatically determine token.");

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

                assert(keyslot < 0);
                keyslot = cryptsetup_get_keyslot_from_token(v);
                if (keyslot < 0)
                        return log_error_errno(keyslot, "Failed to extract keyslot index from FIDO2 JSON data: %m");

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
        }

        if (!cid)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "No valid FIDO2 token data found.");

        log_info("Automatically discovered security FIDO2 token unlocks volume.");

        *ret_rp_id = TAKE_PTR(rp);
        *ret_cid = TAKE_PTR(cid);
        *ret_cid_size = cid_size;
        *ret_salt = TAKE_PTR(salt);
        *ret_salt_size = salt_size;
        *ret_keyslot = keyslot;
        return 0;
}
