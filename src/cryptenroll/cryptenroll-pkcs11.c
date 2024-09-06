/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptenroll-pkcs11.h"
#include "hexdecoct.h"
#include "json-util.h"
#include "memory-util.h"
#include "openssl-util.h"
#include "pkcs11-util.h"

static int uri_set_private_class(const char *uri, char **ret_uri) {
        _cleanup_(sym_p11_kit_uri_freep) P11KitUri *p11kit_uri = NULL;
        _cleanup_free_ char *private_uri = NULL;
        int r;

        r = uri_from_string(uri, &p11kit_uri);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PKCS#11 URI '%s': %m", uri);

        if (sym_p11_kit_uri_get_attribute(p11kit_uri, CKA_CLASS)) {
                CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
                CK_ATTRIBUTE attribute = { CKA_CLASS, &class, sizeof(class) };

                if (sym_p11_kit_uri_set_attribute(p11kit_uri, &attribute) != P11_KIT_URI_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set class for URI '%s'.", uri);

                if (sym_p11_kit_uri_format(p11kit_uri, P11_KIT_URI_FOR_ANY, &private_uri) != P11_KIT_URI_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to format PKCS#11 URI.");
        }

        *ret_uri = TAKE_PTR(private_uri);
        return 0;
}

int enroll_pkcs11(
                struct crypt_device *cd,
                const struct iovec *volume_key,
                const char *uri) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL, *private_uri = NULL;
        size_t decrypted_key_size, saved_key_size;
        _cleanup_free_ void *saved_key = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        ssize_t base64_encoded_size;
        const char *node;
        int r;

        assert_se(cd);
        assert_se(iovec_is_set(volume_key));
        assert_se(uri);

        assert_se(node = crypt_get_device_name(cd));

        r = pkcs11_acquire_public_key(
                        uri,
                        "volume enrollment operation",
                        "drive-harddisk",
                        "cryptenroll.pkcs11-pin",
                        /* askpw_flags= */ 0,
                        &pkey,
                        /* ret_pin_used= */ NULL);
        if (r < 0)
                return r;

        r = pkey_generate_volume_keys(pkey, &decrypted_key, &decrypted_key_size, &saved_key, &saved_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to generate volume keys: %m");

        /* Let's base64 encode the key to use, for compat with homed (and it's easier to type it in by
         * keyboard, if that might ever end up being necessary.) */
        base64_encoded_size = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        int keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        base64_encoded,
                        base64_encoded_size);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new PKCS#11 key to %s: %m", node);

        if (asprintf(&keyslot_as_string, "%i", keyslot) < 0)
                return log_oom();

        /* Change 'type=cert' or 'type=public' in the provided URI to 'type=private' before storing in
           a LUKS2 header. This allows users to use output of some PKCS#11 tools directly without
           modifications. */
        r = uri_set_private_class(uri, &private_uri);
        if (r < 0)
                return r;

        r = sd_json_buildo(&v,
                           SD_JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-pkcs11")),
                           SD_JSON_BUILD_PAIR("keyslots", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING(keyslot_as_string))),
                           SD_JSON_BUILD_PAIR("pkcs11-uri", SD_JSON_BUILD_STRING(private_uri ?: uri)),
                           SD_JSON_BUILD_PAIR("pkcs11-key", SD_JSON_BUILD_BASE64(saved_key, saved_key_size)));
        if (r < 0)
                return log_error_errno(r, "Failed to prepare PKCS#11 JSON token object: %m");

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0)
                return log_error_errno(r, "Failed to add PKCS#11 JSON token to LUKS2 header: %m");

        log_info("New PKCS#11 token enrolled as key slot %i.", keyslot);
        return keyslot;
}
