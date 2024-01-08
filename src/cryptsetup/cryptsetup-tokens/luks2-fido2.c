/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <libcryptsetup.h>

#include "cryptsetup-token-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "luks2-fido2.h"
#include "memory-util.h"
#include "strv.h"

int acquire_luks2_key(
                struct crypt_device *cd,
                const char *json,
                const char *device,
                const char *pin,
                char **ret_keyslot_passphrase,
                size_t *ret_keyslot_passphrase_size) {

        int r;
        Fido2EnrollFlags required;
        size_t cid_size, salt_size, decrypted_key_size;
        _cleanup_free_ void *cid = NULL, *salt = NULL;
        _cleanup_free_ char *rp_id = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_strv_free_erase_ char **pins = NULL;
        ssize_t base64_encoded_size;

        assert(ret_keyslot_passphrase);
        assert(ret_keyslot_passphrase_size);

        r = parse_luks2_fido2_data(cd, json, &rp_id, &salt, &salt_size, &cid, &cid_size, &required);
        if (r < 0)
                return r;

        if (pin) {
                pins = strv_new(pin);
                if (!pins)
                        return crypt_log_oom(cd);
        }

        /* configured to use pin but none was provided */
        if ((required & FIDO2ENROLL_PIN) && strv_isempty(pins))
                return -ENOANO;

        r = fido2_use_hmac_hash(
                        device,
                        rp_id ?: "io.systemd.cryptsetup",
                        salt, salt_size,
                        cid, cid_size,
                        pins,
                        required,
                        &decrypted_key,
                        &decrypted_key_size);
        if (r == -ENOLCK) /* libcryptsetup returns -ENOANO also on wrong PIN */
                r = -ENOANO;
        if (r < 0)
                return r;

        /* Before using this key as passphrase we base64 encode it, for compat with homed */
        base64_encoded_size = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return crypt_log_error_errno(cd, (int) base64_encoded_size, "Failed to base64 encode key: %m");

        *ret_keyslot_passphrase = TAKE_PTR(base64_encoded);
        *ret_keyslot_passphrase_size = base64_encoded_size;

        return 0;
}

/* this function expects valid "systemd-fido2" in json */
int parse_luks2_fido2_data(
                struct crypt_device *cd,
                const char *json,
                char **ret_rp_id,
                void **ret_salt,
                size_t *ret_salt_size,
                void **ret_cid,
                size_t *ret_cid_size,
                Fido2EnrollFlags *ret_required) {

        _cleanup_free_ void *cid = NULL, *salt = NULL;
        size_t cid_size = 0, salt_size = 0;
        _cleanup_free_ char *rp = NULL;
        int r;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        JsonVariant *w;
        Fido2EnrollFlags required = 0;

        assert(json);
        assert(ret_rp_id);
        assert(ret_salt);
        assert(ret_salt_size);
        assert(ret_cid);
        assert(ret_cid_size);
        assert(ret_required);

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return crypt_log_error_errno(cd, r, "Failed to parse JSON token data: %m");

        w = json_variant_by_key(v, "fido2-credential");
        if (!w)
                return -EINVAL;

        r = unbase64mem(json_variant_string(w), &cid, &cid_size);
        if (r < 0)
                return crypt_log_error_errno(cd, r, "Failed to parse 'fido2-credentials' field: %m");

        w = json_variant_by_key(v, "fido2-salt");
        if (!w)
                return -EINVAL;

        r = unbase64mem(json_variant_string(w), &salt, &salt_size);
        if (r < 0)
                return crypt_log_error_errno(cd, r, "Failed to parse 'fido2-salt' field: %m");

        w = json_variant_by_key(v, "fido2-rp");
        if (w) {
                /* The "rp" field is optional. */
                rp = strdup(json_variant_string(w));
                if (!rp) {
                        crypt_log_error(cd, "Not enough memory.");
                        return -ENOMEM;
                }
        }

        w = json_variant_by_key(v, "fido2-clientPin-required");
        if (w)
                /* The "fido2-clientPin-required" field is optional. */
                SET_FLAG(required, FIDO2ENROLL_PIN, json_variant_boolean(w));
        else
                required |= FIDO2ENROLL_PIN_IF_NEEDED; /* compat with 248, where the field was unset */

        w = json_variant_by_key(v, "fido2-up-required");
        if (w)
                /* The "fido2-up-required" field is optional. */
                SET_FLAG(required, FIDO2ENROLL_UP, json_variant_boolean(w));
        else
                required |= FIDO2ENROLL_UP_IF_NEEDED; /* compat with 248 */

        w = json_variant_by_key(v, "fido2-uv-required");
        if (w)
                /* The "fido2-uv-required" field is optional. */
                SET_FLAG(required, FIDO2ENROLL_UV, json_variant_boolean(w));
        else
                required |= FIDO2ENROLL_UV_OMIT; /* compat with 248 */

        *ret_rp_id = TAKE_PTR(rp);
        *ret_cid = TAKE_PTR(cid);
        *ret_cid_size = cid_size;
        *ret_salt = TAKE_PTR(salt);
        *ret_salt_size = salt_size;
        *ret_required = required;

        return 0;
}
